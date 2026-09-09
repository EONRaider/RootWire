"""Compile a small, explicitly-bounded subset of tcpdump-style filter
expressions to classic BPF (cBPF).

## Supported grammar

    expr       := or_expr
    or_expr    := and_expr ( "or" and_expr )*
    and_expr   := not_expr ( "and" not_expr )*
    not_expr   := "not" not_expr | primary
    primary    := "(" expr ")" | primitive
    primitive  := proto
                | [ dir ] "host" ipv4
                | [ dir ] "port" number
    proto      := "tcp" | "udp" | "icmp" | "arp" | "ip" | "ip6"
    dir        := "src" | "dst"
    ipv4       := DIGITS "." DIGITS "." DIGITS "." DIGITS   (each 0-255)
    number     := DIGITS                                    (0-65535)

Anything outside this grammar — an IPv6 literal, a bare address without
``host``, a protocol this subset doesn't name, mismatched parentheses —
is a compile error, never a best-effort guess. A wrong filter makes a
security tool lie about what it captured, so an expression this
compiler cannot represent exactly is rejected, not approximated.

## Deliberately out of scope (see tests/test_bpf_compiler.py for why)

- IPv6 ``host``/``port`` addresses: ``host``/``src``/``dst`` match only
  IPv4 network-layer addresses.
- ARP's embedded sender/target protocol addresses: ``host`` matches
  IPv4 packets' addresses only, not an ARP payload's.
- IPv6 extension headers before the transport header: ``port`` reads
  IPv6's ``next_header`` directly at the fixed post-header offset,
  the same simplification tcpdump's own compiler makes for this
  primitive (confirmed by comparing against ``tcpdump -dd``).

## Correctness strategy

tcpdump's own compiler (libpcap's ``gencode.c``/``optimize.c``) is a
decades-old peephole optimizer; reproducing its exact instruction
sequence byte-for-byte is not a realistic bar for anything beyond a
single bare primitive (confirmed empirically — even ``tcp or udp``
reorders and merges branches no hand-rolled compiler will happen to
replicate). What must match is *behavior*: this compiler's output is
validated by interpreting both tcpdump's bytecode and this compiler's
bytecode (via the small cBPF VM in ``tests/bpf_vm.py``) against the
project's real captured-frame corpus, for every expression in this
grammar, and asserting they always agree on accept/reject. See
``tests/test_bpf_compiler.py``.

## Implementation

A standard two-pass "assembler with symbolic jump labels" — the well
understood technique for compiling short-circuit boolean expressions
to jump-based code, not an attempt to imitate tcpdump's specific
optimizations:

- Each AST node compiles against two labels, ``on_true``/``on_false``,
  and is free to lay down whatever loads and conditional jumps it
  needs, ending every path at one of the two.
- ``and``/``or`` thread the labels so each operand but the last falls
  through into the next operand's code (a label pointing at the very
  next instruction resolves to a zero relative offset, i.e. an
  ordinary fallthrough — no unconditional jump instruction needed).
- ``not`` swaps which label means "true" for its operand — free,  no
  instructions emitted.
- The whole expression compiles once against two fixed labels, ACCEPT
  (``ret BUFFER_SIZE``) and REJECT (``ret 0``), placed last.
- A resolution pass turns every label reference into the relative
  instruction-count offset classic BPF's 8-bit ``jt``/``jf`` fields
  need. Every jump this compiler emits points forward only (the
  layout above never needs a backward jump), which easily stays
  within that 8-bit range for expressions of the size this grammar
  can even express — checked, not assumed: resolution asserts the
  computed offset fits, so a future change that breaks the assumption
  fails loudly instead of emitting a silently wrong offset.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from rootwire.bpf import SockFilter

__all__ = ["BPFCompileError", "compile_expression"]

#: Ethernet header length; IPv4/ARP/IPv6 headers all start here.
_ETH_LEN = 14
_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_ETHERTYPE_ARP = 0x0806
_IPPROTO_TCP = 6
_IPPROTO_UDP = 17
_IPPROTO_ICMP = 1

_PROTOCOLS: Final = ("tcp", "udp", "icmp", "arp", "ip", "ip6")
_KEYWORDS: Final = frozenset(
    {*_PROTOCOLS, "host", "port", "src", "dst", "and", "or", "not"}
)


class BPFCompileError(ValueError):
    """The expression is outside this compiler's supported grammar."""


# --------------------------------------------------------------------
# Lexer
# --------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"""
    (?P<ipv4>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
  | (?P<number>\d+)
  | (?P<word>[a-zA-Z][a-zA-Z0-9]*)
  | (?P<lparen>\()
  | (?P<rparen>\))
  | (?P<space>\s+)
    """,
    re.VERBOSE,
)


@dataclass(frozen=True)
class _Token:
    kind: str
    text: str


def _tokenize(expr: str) -> list[_Token]:
    tokens: list[_Token] = []
    pos = 0
    while pos < len(expr):
        match = _TOKEN_RE.match(expr, pos)
        if match is None:
            raise BPFCompileError(
                f"unexpected character {expr[pos]!r} at position {pos} "
                f"in {expr!r}"
            )
        kind = match.lastgroup
        assert kind is not None
        if kind != "space":
            tokens.append(_Token(kind, match.group()))
        pos = match.end()
    return tokens


# --------------------------------------------------------------------
# AST
# --------------------------------------------------------------------


class _Node:
    """Marker base for AST nodes."""


@dataclass(frozen=True)
class _Proto(_Node):
    name: str


@dataclass(frozen=True)
class _Host(_Node):
    addr: int  # packed big-endian IPv4 address
    direction: str | None  # None, "src", or "dst"


@dataclass(frozen=True)
class _Port(_Node):
    port: int
    direction: str | None


@dataclass(frozen=True)
class _Not(_Node):
    operand: _Node


@dataclass(frozen=True)
class _And(_Node):
    left: _Node
    right: _Node


@dataclass(frozen=True)
class _Or(_Node):
    left: _Node
    right: _Node


# --------------------------------------------------------------------
# Parser (recursive descent)
# --------------------------------------------------------------------


class _Parser:
    def __init__(self, tokens: list[_Token], source: str) -> None:
        self._tokens = tokens
        self._source = source
        self._pos = 0

    def parse(self) -> _Node:
        node = self._or_expr()
        if self._pos != len(self._tokens):
            raise self._error(f"unexpected {self._peek().text!r}")
        return node

    def _peek(self) -> _Token:
        if self._pos >= len(self._tokens):  # pragma: no cover
            # Every current call site already checks _at_end() (or
            # short-circuits an `at_end() or peek()...` expression)
            # before reaching here, so this never actually fires today
            # -- it's a defensive invariant for _peek(), not dead code
            # to delete: a future call site that forgets that check
            # gets a clear parser error instead of a raw IndexError.
            raise self._error("unexpected end of expression")
        return self._tokens[self._pos]

    def _at_end(self) -> bool:
        return self._pos >= len(self._tokens)

    def _advance(self) -> _Token:
        token = self._peek()
        self._pos += 1
        return token

    def _error(self, message: str) -> BPFCompileError:
        return BPFCompileError(f"{message} in {self._source!r}")

    def _match_word(self, *words: str) -> bool:
        if (
            not self._at_end()
            and self._peek().kind == "word"
            and self._peek().text in words
        ):
            self._advance()
            return True
        return False

    def _or_expr(self) -> _Node:
        node = self._and_expr()
        while self._match_word("or"):
            node = _Or(node, self._and_expr())
        return node

    def _and_expr(self) -> _Node:
        node = self._not_expr()
        while self._match_word("and"):
            node = _And(node, self._not_expr())
        return node

    def _not_expr(self) -> _Node:
        if self._match_word("not"):
            return _Not(self._not_expr())
        return self._primary()

    def _primary(self) -> _Node:
        if not self._at_end() and self._peek().kind == "lparen":
            self._advance()
            node = self._or_expr()
            if self._at_end() or self._peek().kind != "rparen":
                raise self._error("unclosed '('")
            self._advance()
            return node
        return self._primitive()

    def _primitive(self) -> _Node:
        direction: str | None = None
        if self._match_word("src"):
            direction = "src"
        elif self._match_word("dst"):
            direction = "dst"

        if self._at_end():
            if direction is not None:
                raise self._error(f"expected a primitive after {direction!r}")
            raise self._error("expected a primitive")
        token = self._peek()

        if (
            direction is None
            and token.kind == "word"
            and token.text in _PROTOCOLS
        ):
            self._advance()
            return _Proto(token.text)

        if self._match_word("host"):
            return _Host(self._parse_ipv4(), direction)

        if self._match_word("port"):
            return _Port(self._parse_port(), direction)

        if token.kind == "word" and token.text not in _KEYWORDS:
            raise self._error(
                f"unknown primitive {token.text!r} -- supported: "
                f"{', '.join(_PROTOCOLS)}, host, port (each optionally "
                f"prefixed with src/dst), and/or/not, parentheses"
            )
        raise self._error(f"expected a primitive, found {token.text!r}")

    def _parse_ipv4(self) -> int:
        if self._at_end() or self._peek().kind != "ipv4":
            found = "end of expression" if self._at_end() else self._peek().text
            raise self._error(
                f"expected an IPv4 address after 'host', found {found!r} "
                f"-- IPv6 addresses are not supported"
            )
        text = self._advance().text
        octets = [int(part) for part in text.split(".")]
        if any(octet > 255 for octet in octets):
            raise self._error(f"{text!r} is not a valid IPv4 address")
        value = 0
        for octet in octets:
            value = (value << 8) | octet
        return value

    def _parse_port(self) -> int:
        if self._at_end() or self._peek().kind != "number":
            found = "end of expression" if self._at_end() else self._peek().text
            raise self._error(
                f"expected a port number after 'port', found {found!r}"
            )
        text = self._advance().text
        port = int(text)
        if port > 0xFFFF:
            raise self._error(f"port {port} is out of range (0-65535)")
        return port


# --------------------------------------------------------------------
# Codegen: a two-pass assembler over symbolic jump labels
# --------------------------------------------------------------------

# cBPF opcodes actually used here (see linux/filter.h / linux/bpf_common.h):
_LDH_ABS = 0x28  #: A <- packet[k:2]
_LDB_ABS = 0x30  #: A <- packet[k:1]
_LDW_ABS = 0x20  #: A <- packet[k:4]
_LDH_IND = 0x48  #: A <- packet[X+k:2]
_LDXB_MSH = 0xB1  #: X <- 4 * (packet[k:1] & 0xf)  (IPv4 IHL -> header length)
_JEQ_K = 0x15  #: jt/jf on A == k
_JSET_K = 0x45  #: jt/jf on (A & k) != 0
_RET_K = 0x06  #: return k (bytes of the frame to keep; 0 rejects it)

#: cBPF's conventional "accept, keep the whole frame" return value —
#: the same literal `bpf.py`'s canned filters already use (and what
#: `tcpdump -dd` itself emits), unrelated to and not tied to RootWire's
#: own userspace read-buffer size (`capture.BUFFER_SIZE`).
_ACCEPT_LENGTH = 0x00040000

_IPV4_SRC_OFFSET = 26  #: 14 (Ethernet) + 12
_IPV4_DST_OFFSET = 30  #: 14 (Ethernet) + 16
_IPV4_PROTO_OFFSET = 23  #: 14 + 9, fixed regardless of IHL
_IPV4_FRAG_OFFSET = 20  #: 14 + 6, the flags+fragment-offset half-word
_IPV4_FRAG_MASK = 0x1FFF  #: low 13 bits: the fragment-offset field alone
_IPV4_IHL_BYTE = 14  #: version+IHL byte; ldxb here gives X = IHL*4
_IPV4_SRC_PORT_IND = 14  #: added to X (= IHL*4) by the BPF_IND load
_IPV4_DST_PORT_IND = 16
_IPV6_NEXT_HEADER_OFFSET = 20  #: 14 + 6
_IPV6_FRAGMENT_EXT_HEADER = 44  #: IPPROTO_FRAGMENT
_IPV6_SRC_PORT_OFFSET = 54  #: 14 + 40 (fixed IPv6 base header length)
_IPV6_DST_PORT_OFFSET = 56


class _Label:
    """A symbolic jump target, resolved to a relative offset once the
    whole instruction stream is known. Identity, not value, is what
    matters — never compared or hashed by name."""

    __slots__ = ("hint",)

    def __init__(self, hint: str) -> None:
        self.hint = hint

    def __repr__(self) -> str:
        return f"<Label {self.hint}>"


@dataclass
class _PInsn:
    """One pseudo-instruction: a real cBPF opcode, but ``jt``/``jf``
    are still symbolic labels (or ``None`` for a non-jump instruction)
    until :func:`_resolve` runs."""

    code: int
    k: int = 0
    jt: _Label | None = None
    jf: _Label | None = None


class _Emitter:
    """Accumulates labels and pseudo-instructions in emission order —
    which, given how ``_compile`` lays out ``and``/``or``/``not``, is
    already a valid forward-flowing instruction stream. Nothing here
    reorders or optimizes; :func:`_resolve` only ever turns a label
    reference into the relative offset from the instruction that
    references it to wherever that label ended up."""

    def __init__(self) -> None:
        self.items: list[_Label | _PInsn] = []
        self._counter = 0

    def new_label(self, hint: str) -> _Label:
        self._counter += 1
        return _Label(f"{hint}{self._counter}")

    def place(self, label: _Label) -> None:
        self.items.append(label)

    def emit(self, insn: _PInsn) -> None:
        self.items.append(insn)


def _test_at(
    e: _Emitter,
    code: int,
    offset: int,
    value: int,
    on_true: _Label,
    on_false: _Label,
) -> None:
    """Load a value at a fixed offset and branch on equality — the one
    pattern nearly every primitive here reduces to. Always reloads
    rather than assuming the accumulator still holds something useful
    from an earlier instruction: BPF register state does persist
    across a jump, and tcpdump's own compiler exploits that, but
    relying on it here would mean proving what's live at every jump
    target by hand. A handful of extra load instructions is a small
    price for not having to.
    """
    e.emit(_PInsn(code, k=offset))
    e.emit(_PInsn(_JEQ_K, k=value, jt=on_true, jf=on_false))


def _compile_proto(
    name: str, on_true: _Label, on_false: _Label, e: _Emitter
) -> None:
    if name == "ip":
        _test_at(e, _LDH_ABS, 12, _ETHERTYPE_IPV4, on_true, on_false)
    elif name == "arp":
        _test_at(e, _LDH_ABS, 12, _ETHERTYPE_ARP, on_true, on_false)
    elif name == "ip6":
        _test_at(e, _LDH_ABS, 12, _ETHERTYPE_IPV6, on_true, on_false)
    elif name == "icmp":
        # IPv4-only in this grammar: ICMPv4 and ICMPv6 are different IP
        # protocol numbers, and there is no separate "icmp6" keyword
        # here to disambiguate — matching what plain "icmp" means in
        # tcpdump itself (confirmed via `tcpdump -dd icmp`).
        v4 = e.new_label("icmp_v4")
        _test_at(e, _LDH_ABS, 12, _ETHERTYPE_IPV4, v4, on_false)
        e.place(v4)
        _test_at(
            e, _LDB_ABS, _IPV4_PROTO_OFFSET, _IPPROTO_ICMP, on_true, on_false
        )
    else:
        proto_num = _IPPROTO_TCP if name == "tcp" else _IPPROTO_UDP
        _compile_tcp_or_udp(proto_num, on_true, on_false, e)


def _compile_tcp_or_udp(
    proto_num: int, on_true: _Label, on_false: _Label, e: _Emitter
) -> None:
    """TCP and UDP protocol numbers mean the same thing in IPv4's
    ``protocol`` field and IPv6's ``next_header`` field, so (unlike
    ``icmp``) this checks both stacks — mirroring the already-shipped,
    tcpdump-golden-tested canned filters in ``bpf.py`` exactly,
    including the one-hop peek past a lone IPv6 Fragment extension
    header (real, legitimately fragmented traffic can put the real
    next header there instead of directly in the base header)."""
    v6 = e.new_label("v6")
    v4 = e.new_label("v4")
    _test_at(e, _LDH_ABS, 12, _ETHERTYPE_IPV6, v6, v4)

    e.place(v6)
    after_frag = e.new_label("v6_after_frag")
    _test_at(
        e, _LDB_ABS, _IPV6_NEXT_HEADER_OFFSET, proto_num, on_true, after_frag
    )
    e.place(after_frag)
    peek = e.new_label("v6_frag_peek")
    _test_at(
        e,
        _LDB_ABS,
        _IPV6_NEXT_HEADER_OFFSET,
        _IPV6_FRAGMENT_EXT_HEADER,
        peek,
        on_false,
    )
    e.place(peek)
    _test_at(e, _LDB_ABS, 0x36, proto_num, on_true, on_false)

    e.place(v4)
    v4_proto = e.new_label("v4_proto")
    _test_at(e, _LDH_ABS, 12, _ETHERTYPE_IPV4, v4_proto, on_false)
    e.place(v4_proto)
    _test_at(e, _LDB_ABS, _IPV4_PROTO_OFFSET, proto_num, on_true, on_false)


def _compile_host(
    addr: int,
    direction: str | None,
    on_true: _Label,
    on_false: _Label,
    e: _Emitter,
) -> None:
    v4 = e.new_label("host_v4")
    _test_at(e, _LDH_ABS, 12, _ETHERTYPE_IPV4, v4, on_false)
    e.place(v4)
    if direction == "src":
        _test_at(e, _LDW_ABS, _IPV4_SRC_OFFSET, addr, on_true, on_false)
    elif direction == "dst":
        _test_at(e, _LDW_ABS, _IPV4_DST_OFFSET, addr, on_true, on_false)
    else:
        check_dst = e.new_label("host_dst")
        _test_at(e, _LDW_ABS, _IPV4_SRC_OFFSET, addr, on_true, check_dst)
        e.place(check_dst)
        _test_at(e, _LDW_ABS, _IPV4_DST_OFFSET, addr, on_true, on_false)


def _compile_port_value(
    code: int,
    src_offset: int,
    dst_offset: int,
    direction: str | None,
    port: int,
    on_true: _Label,
    on_false: _Label,
    e: _Emitter,
) -> None:
    """The src/dst port comparison shared by the IPv4 and IPv6 paths of
    ``port`` — they differ only in how the port fields are addressed
    (a fixed offset for IPv6; ``X + offset`` for IPv4, once ``X`` holds
    the variable IPv4 header length), not in this comparison logic."""
    if direction == "src":
        _test_at(e, code, src_offset, port, on_true, on_false)
    elif direction == "dst":
        _test_at(e, code, dst_offset, port, on_true, on_false)
    else:
        check_dst = e.new_label("port_dst")
        _test_at(e, code, src_offset, port, on_true, check_dst)
        e.place(check_dst)
        _test_at(e, code, dst_offset, port, on_true, on_false)


def _compile_port_v6(
    port: int,
    direction: str | None,
    on_true: _Label,
    on_false: _Label,
    e: _Emitter,
) -> None:
    """No extension-header walk and no fragmentation check here — this
    matches tcpdump's own ``port`` compilation for IPv6 exactly
    (confirmed via `tcpdump -dd port N`), not an extra simplification
    on top of it. IPv6 fragmentation instead uses its own dedicated
    Fragment extension header, entirely absent from a non-fragmented
    packet's header chain, so a plain ``next_header`` check already
    behaves correctly for the common case this primitive targets."""
    check_udp = e.new_label("v6_check_udp")
    matched = e.new_label("v6_matched_transport")
    _test_at(
        e, _LDB_ABS, _IPV6_NEXT_HEADER_OFFSET, _IPPROTO_TCP, matched, check_udp
    )
    e.place(check_udp)
    _test_at(
        e, _LDB_ABS, _IPV6_NEXT_HEADER_OFFSET, _IPPROTO_UDP, matched, on_false
    )
    e.place(matched)
    _compile_port_value(
        _LDH_ABS,
        _IPV6_SRC_PORT_OFFSET,
        _IPV6_DST_PORT_OFFSET,
        direction,
        port,
        on_true,
        on_false,
        e,
    )


def _compile_port_v4(
    port: int,
    direction: str | None,
    on_true: _Label,
    on_false: _Label,
    e: _Emitter,
) -> None:
    check_udp = e.new_label("v4_check_udp")
    matched = e.new_label("v4_matched_transport")
    _test_at(e, _LDB_ABS, _IPV4_PROTO_OFFSET, _IPPROTO_TCP, matched, check_udp)
    e.place(check_udp)
    _test_at(e, _LDB_ABS, _IPV4_PROTO_OFFSET, _IPPROTO_UDP, matched, on_false)

    e.place(matched)
    not_fragment = e.new_label("v4_not_fragment")
    e.emit(_PInsn(_LDH_ABS, k=_IPV4_FRAG_OFFSET))
    # JSET's jt fires when (A & mask) != 0 -- a nonzero fragment offset,
    # i.e. every fragment except the first, which is the only one
    # carrying a real TCP/UDP header to read a port out of.
    e.emit(_PInsn(_JSET_K, k=_IPV4_FRAG_MASK, jt=on_false, jf=not_fragment))
    e.place(not_fragment)
    e.emit(_PInsn(_LDXB_MSH, k=_IPV4_IHL_BYTE))  # X <- IHL * 4
    _compile_port_value(
        _LDH_IND,
        _IPV4_SRC_PORT_IND,
        _IPV4_DST_PORT_IND,
        direction,
        port,
        on_true,
        on_false,
        e,
    )


def _compile_port(
    port: int,
    direction: str | None,
    on_true: _Label,
    on_false: _Label,
    e: _Emitter,
) -> None:
    v6 = e.new_label("port_v6")
    v4 = e.new_label("port_v4")
    _test_at(e, _LDH_ABS, 12, _ETHERTYPE_IPV6, v6, v4)
    e.place(v6)
    _compile_port_v6(port, direction, on_true, on_false, e)
    e.place(v4)
    _compile_port_v4(port, direction, on_true, on_false, e)


def _compile(
    node: _Node, on_true: _Label, on_false: _Label, e: _Emitter
) -> None:
    """Compile one AST node against two continuation labels: every path
    through the emitted code ends at ``on_true`` or ``on_false``. The
    standard short-circuit technique for boolean expressions — ``and``
    threads its left operand's true-continuation into its right
    operand's code (falling straight through, no jump instruction
    needed, since the right operand's code is laid down immediately
    after); ``or`` does the mirror image for the false-continuation;
    ``not`` costs nothing at all, just swapping which label its
    operand should call "true"."""
    if isinstance(node, _Proto):
        _compile_proto(node.name, on_true, on_false, e)
    elif isinstance(node, _Host):
        _compile_host(node.addr, node.direction, on_true, on_false, e)
    elif isinstance(node, _Port):
        _compile_port(node.port, node.direction, on_true, on_false, e)
    elif isinstance(node, _Not):
        _compile(node.operand, on_false, on_true, e)
    elif isinstance(node, _And):
        mid = e.new_label("and")
        _compile(node.left, mid, on_false, e)
        e.place(mid)
        _compile(node.right, on_true, on_false, e)
    elif isinstance(node, _Or):
        mid = e.new_label("or")
        _compile(node.left, on_true, mid, e)
        e.place(mid)
        _compile(node.right, on_true, on_false, e)
    else:  # pragma: no cover -- exhaustive over _Node's only subclasses
        raise AssertionError(f"unhandled AST node: {node!r}")


def _resolve(items: list[_Label | _PInsn]) -> tuple[SockFilter, ...]:
    """Turn every label reference into the relative instruction-count
    offset classic BPF's 8-bit ``jt``/``jf`` fields need. Every jump
    this compiler emits points forward (the layout in ``_compile``
    never needs a backward jump — booleans compile to a strictly
    forward-flowing sequence of tests), so every resolved offset comes
    out non-negative by construction; the range check below is a
    correctness assertion on that claim, not a feature."""
    positions: dict[int, int] = {}
    index = 0
    for item in items:
        if isinstance(item, _Label):
            positions[id(item)] = index
        else:
            index += 1

    instructions = [item for item in items if isinstance(item, _PInsn)]

    def offset_to(label: _Label, from_index: int) -> int:
        target = positions[id(label)]
        offset = target - (from_index + 1)
        if not (0 <= offset <= 255):
            raise AssertionError(
                f"jump offset {offset} for label {label!r} is out of "
                f"cBPF's 8-bit range -- expression is too large for "
                f"this codegen's forward-only, unoptimized layout"
            )
        return offset

    program: list[SockFilter] = []
    for i, insn in enumerate(instructions):
        jt = offset_to(insn.jt, i) if insn.jt is not None else 0
        jf = offset_to(insn.jf, i) if insn.jf is not None else 0
        program.append((insn.code, jt, jf, insn.k))
    return tuple(program)


def compile_expression(expr: str) -> tuple[SockFilter, ...]:
    """Compile a filter expression (see the module docstring's grammar)
    to a cBPF program, ready for :class:`rootwire.bpf.FilterProgram`.

    :raises BPFCompileError: If ``expr`` uses syntax outside this
        compiler's supported grammar.
    """
    tokens = _tokenize(expr)
    if not tokens:
        raise BPFCompileError("empty expression")
    ast = _Parser(tokens, expr).parse()

    e = _Emitter()
    accept = e.new_label("ACCEPT")
    reject = e.new_label("REJECT")
    _compile(ast, accept, reject, e)
    e.place(accept)
    e.emit(_PInsn(_RET_K, k=_ACCEPT_LENGTH))
    e.place(reject)
    e.emit(_PInsn(_RET_K, k=0))

    return _resolve(e.items)
