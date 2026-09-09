"""Differential correctness tests for rootwire.bpf_compiler.

The compiler's own module docstring explains why matching tcpdump's
exact instruction sequence isn't the right bar (its compiler is a
decades-old peephole optimizer; nothing hand-rolled will happen to
reproduce its specific choices past a single bare primitive). What
must match is behavior, so this file interprets both tcpdump's
bytecode and this compiler's bytecode — via the small cBPF VM in
bpf_vm.py — against every frame in the project's real captured-frame
corpus, for a representative battery of expressions across the whole
grammar, and asserts they always agree on accept/reject.

_TCPDUMP_GOLDEN is transcribed byte-for-byte from real `tcpdump -dd
<expr>` runs (tcpdump 4.99.1 / libpcap 1.10.1) -- a golden fixture
generated once and pinned here, the same approach test_bpf.py already
uses for the canned filters, deliberately not re-invoked at test time
so this suite has no tcpdump dependency in CI.
"""

import ipaddress

import pytest
from netprotocols import ARP, IPv4, IPv6

from bpf_vm import run as vm_run
from conftest import corpus_frames
from rootwire.bpf import SockFilter
from rootwire.bpf_compiler import BPFCompileError, compile_expression
from rootwire.decoder import decode_frame

_TCPDUMP_GOLDEN: dict[str, tuple[SockFilter, ...]] = {
    "tcp": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 5, 0x000086DD),
        (0x30, 0, 0, 0x00000014),
        (0x15, 6, 0, 0x00000006),
        (0x15, 0, 6, 0x0000002C),
        (0x30, 0, 0, 0x00000036),
        (0x15, 3, 4, 0x00000006),
        (0x15, 0, 3, 0x00000800),
        (0x30, 0, 0, 0x00000017),
        (0x15, 0, 1, 0x00000006),
        (0x6, 0, 0, 0x00040000),
        (0x6, 0, 0, 0x00000000),
    ),
    "udp": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 5, 0x000086DD),
        (0x30, 0, 0, 0x00000014),
        (0x15, 6, 0, 0x00000011),
        (0x15, 0, 6, 0x0000002C),
        (0x30, 0, 0, 0x00000036),
        (0x15, 3, 4, 0x00000011),
        (0x15, 0, 3, 0x00000800),
        (0x30, 0, 0, 0x00000017),
        (0x15, 0, 1, 0x00000011),
        (0x6, 0, 0, 0x00040000),
        (0x6, 0, 0, 0x00000000),
    ),
    "icmp": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 3, 0x00000800),
        (0x30, 0, 0, 0x00000017),
        (0x15, 0, 1, 0x00000001),
        (0x6, 0, 0, 0x00040000),
        (0x6, 0, 0, 0x00000000),
    ),
    "arp": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 1, 0x00000806),
        (0x6, 0, 0, 0x00040000),
        (0x6, 0, 0, 0x00000000),
    ),
    "ip": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 1, 0x00000800),
        (0x6, 0, 0, 0x00040000),
        (0x6, 0, 0, 0x00000000),
    ),
    "ip6": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 1, 0x000086DD),
        (0x6, 0, 0, 0x00040000),
        (0x6, 0, 0, 0x00000000),
    ),
    "host 192.168.1.96": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 4, 0x00000800),
        (0x20, 0, 0, 0x0000001A),
        (0x15, 8, 0, 0xC0A80160),
        (0x20, 0, 0, 0x0000001E),
        (0x15, 6, 7, 0xC0A80160),
        (0x15, 1, 0, 0x00000806),
        (0x15, 0, 5, 0x00008035),
        (0x20, 0, 0, 0x0000001C),
        (0x15, 2, 0, 0xC0A80160),
        (0x20, 0, 0, 0x00000026),
        (0x15, 0, 1, 0xC0A80160),
        (0x6, 0, 0, 0x00040000),
        (0x6, 0, 0, 0x00000000),
    ),
    "src host 192.168.1.96": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 2, 0x00000800),
        (0x20, 0, 0, 0x0000001A),
        (0x15, 4, 5, 0xC0A80160),
        (0x15, 1, 0, 0x00000806),
        (0x15, 0, 3, 0x00008035),
        (0x20, 0, 0, 0x0000001C),
        (0x15, 0, 1, 0xC0A80160),
        (0x6, 0, 0, 0x00040000),
        (0x6, 0, 0, 0x00000000),
    ),
    "dst host 192.168.1.254": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 2, 0x00000800),
        (0x20, 0, 0, 0x0000001E),
        (0x15, 4, 5, 0xC0A801FE),
        (0x15, 1, 0, 0x00000806),
        (0x15, 0, 3, 0x00008035),
        (0x20, 0, 0, 0x00000026),
        (0x15, 0, 1, 0xC0A801FE),
        (0x6, 0, 0, 0x00040000),
        (0x6, 0, 0, 0x00000000),
    ),
    "port 80": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 8, 0x000086DD),
        (0x30, 0, 0, 0x00000014),
        (0x15, 2, 0, 0x00000084),
        (0x15, 1, 0, 0x00000006),
        (0x15, 0, 17, 0x00000011),
        (0x28, 0, 0, 0x00000036),
        (0x15, 14, 0, 0x00000050),
        (0x28, 0, 0, 0x00000038),
        (0x15, 12, 13, 0x00000050),
        (0x15, 0, 12, 0x00000800),
        (0x30, 0, 0, 0x00000017),
        (0x15, 2, 0, 0x00000084),
        (0x15, 1, 0, 0x00000006),
        (0x15, 0, 8, 0x00000011),
        (0x28, 0, 0, 0x00000014),
        (0x45, 6, 0, 0x00001FFF),
        (0xB1, 0, 0, 0x0000000E),
        (0x48, 0, 0, 0x0000000E),
        (0x15, 2, 0, 0x00000050),
        (0x48, 0, 0, 0x00000010),
        (0x15, 0, 1, 0x00000050),
        (0x6, 0, 0, 0x00040000),
        (0x6, 0, 0, 0x00000000),
    ),
    "src port 51888": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 6, 0x000086DD),
        (0x30, 0, 0, 0x00000014),
        (0x15, 2, 0, 0x00000084),
        (0x15, 1, 0, 0x00000006),
        (0x15, 0, 13, 0x00000011),
        (0x28, 0, 0, 0x00000036),
        (0x15, 10, 11, 0x0000CAB0),
        (0x15, 0, 10, 0x00000800),
        (0x30, 0, 0, 0x00000017),
        (0x15, 2, 0, 0x00000084),
        (0x15, 1, 0, 0x00000006),
        (0x15, 0, 6, 0x00000011),
        (0x28, 0, 0, 0x00000014),
        (0x45, 4, 0, 0x00001FFF),
        (0xB1, 0, 0, 0x0000000E),
        (0x48, 0, 0, 0x0000000E),
        (0x15, 0, 1, 0x0000CAB0),
        (0x6, 0, 0, 0x00040000),
        (0x6, 0, 0, 0x00000000),
    ),
    "dst port 80": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 6, 0x000086DD),
        (0x30, 0, 0, 0x00000014),
        (0x15, 2, 0, 0x00000084),
        (0x15, 1, 0, 0x00000006),
        (0x15, 0, 13, 0x00000011),
        (0x28, 0, 0, 0x00000038),
        (0x15, 10, 11, 0x00000050),
        (0x15, 0, 10, 0x00000800),
        (0x30, 0, 0, 0x00000017),
        (0x15, 2, 0, 0x00000084),
        (0x15, 1, 0, 0x00000006),
        (0x15, 0, 6, 0x00000011),
        (0x28, 0, 0, 0x00000014),
        (0x45, 4, 0, 0x00001FFF),
        (0xB1, 0, 0, 0x0000000E),
        (0x48, 0, 0, 0x00000010),
        (0x15, 0, 1, 0x00000050),
        (0x6, 0, 0, 0x00040000),
        (0x6, 0, 0, 0x00000000),
    ),
    "tcp and port 80": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 6, 0x000086DD),
        (0x30, 0, 0, 0x00000014),
        (0x15, 0, 15, 0x00000006),
        (0x28, 0, 0, 0x00000036),
        (0x15, 12, 0, 0x00000050),
        (0x28, 0, 0, 0x00000038),
        (0x15, 10, 11, 0x00000050),
        (0x15, 0, 10, 0x00000800),
        (0x30, 0, 0, 0x00000017),
        (0x15, 0, 8, 0x00000006),
        (0x28, 0, 0, 0x00000014),
        (0x45, 6, 0, 0x00001FFF),
        (0xB1, 0, 0, 0x0000000E),
        (0x48, 0, 0, 0x0000000E),
        (0x15, 2, 0, 0x00000050),
        (0x48, 0, 0, 0x00000010),
        (0x15, 0, 1, 0x00000050),
        (0x6, 0, 0, 0x00040000),
        (0x6, 0, 0, 0x00000000),
    ),
    "udp or icmp": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 5, 0x000086DD),
        (0x30, 0, 0, 0x00000014),
        (0x15, 7, 0, 0x00000011),
        (0x15, 0, 7, 0x0000002C),
        (0x30, 0, 0, 0x00000036),
        (0x15, 4, 5, 0x00000011),
        (0x15, 0, 4, 0x00000800),
        (0x30, 0, 0, 0x00000017),
        (0x15, 1, 0, 0x00000011),
        (0x15, 0, 1, 0x00000001),
        (0x6, 0, 0, 0x00040000),
        (0x6, 0, 0, 0x00000000),
    ),
    "not arp": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 1, 0x00000806),
        (0x6, 0, 0, 0x00000000),
        (0x6, 0, 0, 0x00040000),
    ),
    "(tcp or udp) and port 53": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 8, 0x000086DD),
        (0x30, 0, 0, 0x00000014),
        (0x15, 2, 0, 0x00000006),
        (0x15, 17, 0, 0x0000002C),
        (0x15, 0, 16, 0x00000011),
        (0x28, 0, 0, 0x00000036),
        (0x15, 13, 0, 0x00000035),
        (0x28, 0, 0, 0x00000038),
        (0x15, 11, 12, 0x00000035),
        (0x15, 0, 11, 0x00000800),
        (0x30, 0, 0, 0x00000017),
        (0x15, 1, 0, 0x00000006),
        (0x15, 0, 8, 0x00000011),
        (0x28, 0, 0, 0x00000014),
        (0x45, 6, 0, 0x00001FFF),
        (0xB1, 0, 0, 0x0000000E),
        (0x48, 0, 0, 0x0000000E),
        (0x15, 2, 0, 0x00000035),
        (0x48, 0, 0, 0x00000010),
        (0x15, 0, 1, 0x00000035),
        (0x6, 0, 0, 0x00040000),
        (0x6, 0, 0, 0x00000000),
    ),
    "tcp and not port 22": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 9, 0x000086DD),
        (0x30, 0, 0, 0x00000014),
        (0x15, 0, 4, 0x00000006),
        (0x28, 0, 0, 0x00000036),
        (0x15, 16, 0, 0x00000016),
        (0x28, 0, 0, 0x00000038),
        (0x15, 14, 13, 0x00000016),
        (0x15, 0, 13, 0x0000002C),
        (0x30, 0, 0, 0x00000036),
        (0x15, 10, 11, 0x00000006),
        (0x15, 0, 10, 0x00000800),
        (0x30, 0, 0, 0x00000017),
        (0x15, 0, 8, 0x00000006),
        (0x28, 0, 0, 0x00000014),
        (0x45, 5, 0, 0x00001FFF),
        (0xB1, 0, 0, 0x0000000E),
        (0x48, 0, 0, 0x0000000E),
        (0x15, 3, 0, 0x00000016),
        (0x48, 0, 0, 0x00000010),
        (0x15, 1, 0, 0x00000016),
        (0x6, 0, 0, 0x00040000),
        (0x6, 0, 0, 0x00000000),
    ),
    "host 192.168.1.96 and port 443": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 16, 0x00000800),
        (0x20, 0, 0, 0x0000001A),
        (0x15, 2, 0, 0xC0A80160),
        (0x20, 0, 0, 0x0000001E),
        (0x15, 0, 12, 0xC0A80160),
        (0x30, 0, 0, 0x00000017),
        (0x15, 2, 0, 0x00000084),
        (0x15, 1, 0, 0x00000006),
        (0x15, 0, 8, 0x00000011),
        (0x28, 0, 0, 0x00000014),
        (0x45, 6, 0, 0x00001FFF),
        (0xB1, 0, 0, 0x0000000E),
        (0x48, 0, 0, 0x0000000E),
        (0x15, 2, 0, 0x000001BB),
        (0x48, 0, 0, 0x00000010),
        (0x15, 0, 1, 0x000001BB),
        (0x6, 0, 0, 0x00040000),
        (0x6, 0, 0, 0x00000000),
    ),
    "not (tcp or udp)": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 5, 0x000086DD),
        (0x30, 0, 0, 0x00000014),
        (0x15, 7, 0, 0x00000006),
        (0x15, 0, 5, 0x0000002C),
        (0x30, 0, 0, 0x00000036),
        (0x15, 4, 3, 0x00000006),
        (0x15, 0, 4, 0x00000800),
        (0x30, 0, 0, 0x00000017),
        (0x15, 1, 0, 0x00000006),
        (0x15, 0, 1, 0x00000011),
        (0x6, 0, 0, 0x00000000),
        (0x6, 0, 0, 0x00040000),
    ),
    "src host 192.168.1.96 and dst port 80": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 12, 0x00000800),
        (0x20, 0, 0, 0x0000001A),
        (0x15, 0, 10, 0xC0A80160),
        (0x30, 0, 0, 0x00000017),
        (0x15, 2, 0, 0x00000084),
        (0x15, 1, 0, 0x00000006),
        (0x15, 0, 6, 0x00000011),
        (0x28, 0, 0, 0x00000014),
        (0x45, 4, 0, 0x00001FFF),
        (0xB1, 0, 0, 0x0000000E),
        (0x48, 0, 0, 0x00000010),
        (0x15, 0, 1, 0x00000050),
        (0x6, 0, 0, 0x00040000),
        (0x6, 0, 0, 0x00000000),
    ),
}

_CORPUS_FRAMES: list[bytes] = [frame for _, _, frame in corpus_frames()]


class TestDifferentialAgainstTcpdump:
    """For every expression, this compiler's bytecode and tcpdump's own
    must agree on accept/reject for every frame in the real captured
    corpus -- not just the frames each expression happens to match."""

    @pytest.mark.parametrize("expr", sorted(_TCPDUMP_GOLDEN))
    def test_agrees_with_tcpdump_over_the_whole_corpus(self, expr):
        mine = compile_expression(expr)
        golden = _TCPDUMP_GOLDEN[expr]
        disagreements = [
            frame.hex()
            for frame in _CORPUS_FRAMES
            if bool(vm_run(mine, frame)) != bool(vm_run(golden, frame))
        ]
        assert not disagreements, (
            f"{expr!r} disagreed with tcpdump on "
            f"{len(disagreements)}/{len(_CORPUS_FRAMES)} corpus frames"
        )


def _decoded_ground_truth(frame: bytes):
    return decode_frame(frame, number=1, timestamp=0, interface=None)


class TestCrossCheckAgainstTheDecoder:
    """A second, independent oracle for the primitives simple enough to
    derive ground truth from the project's own (separately, extensively
    tested) protocol decoder -- not just tcpdump's bytecode, so a bug
    shared by this compiler and a misremembered golden fixture would
    still be caught.

    Ground truth here is the IP-level protocol/next_header field, not
    "the decoder produced a fully-parsed upper-layer object" — those
    are different questions. A packet filter classifies by protocol
    *number* alone, the same thing tcpdump does; the decoder correctly
    declines to synthesize an ICMPv4/TCP/UDP layer for a non-first IP
    fragment, since there is no such header at that offset to parse —
    but the fragment's protocol number is still ICMP/TCP/UDP, and a
    filter is right to accept it. Using layer presence as ground truth
    here breaks on exactly that case (caught by first writing the test
    the naive way and finding real corpus fragments it flagged as
    "wrong" — they weren't; the assumption was)."""

    @pytest.mark.parametrize(
        ("expr", "proto_number"),
        [("tcp", 6), ("udp", 17)],
    )
    def test_tcp_udp_matches_ip_protocol_number_in_both_stacks(
        self, expr, proto_number
    ):
        program = compile_expression(expr)
        for frame in _CORPUS_FRAMES:
            decoded = _decoded_ground_truth(frame)
            ip = decoded.layer(IPv4)
            ip6 = decoded.layer(IPv6)
            expected = (ip is not None and ip.protocol == proto_number) or (
                ip6 is not None and ip6.next_header == proto_number
            )
            actual = bool(vm_run(program, frame))
            assert actual == expected, (
                f"{expr!r} {'accepted' if actual else 'rejected'} a frame "
                f"with IP protocol/next_header "
                f"{'==' if expected else '!='} {proto_number}"
            )

    def test_icmp_matches_ipv4_protocol_number(self):
        """IPv4-only ground truth, matching what "icmp" means in this
        grammar (no icmp6 keyword) -- and in tcpdump itself."""
        program = compile_expression("icmp")
        for frame in _CORPUS_FRAMES:
            decoded = _decoded_ground_truth(frame)
            ip = decoded.layer(IPv4)
            expected = ip is not None and ip.protocol == 1
            actual = bool(vm_run(program, frame))
            assert actual == expected

    def test_arp_matches_decoded_arp_layer(self):
        """ARP has no fragmentation concept, so layer presence and
        protocol classification coincide -- unlike tcp/udp/icmp above,
        there's no fragment-continuation case to trip over here."""
        program = compile_expression("arp")
        for frame in _CORPUS_FRAMES:
            decoded = _decoded_ground_truth(frame)
            expected = decoded.layer(ARP) is not None
            actual = bool(vm_run(program, frame))
            assert actual == expected

    def test_host_matches_decoded_ipv4_addresses(self):
        program = compile_expression("host 192.168.1.96")
        target = ipaddress.IPv4Address("192.168.1.96")
        for frame in _CORPUS_FRAMES:
            decoded = _decoded_ground_truth(frame)
            ip = decoded.layer(IPv4)
            expected = ip is not None and target in (
                ipaddress.IPv4Address(ip.src),
                ipaddress.IPv4Address(ip.dst),
            )
            actual = bool(vm_run(program, frame))
            assert actual == expected


class TestGrammarRejection:
    """Anything outside the documented grammar is a compile error, never
    a best-effort guess -- exercised directly, not just implied by what
    the differential tests above don't cover."""

    @pytest.mark.parametrize(
        "expr",
        [
            "",
            "sctp",  # not one of the six supported protocol keywords
            "host ::1",  # IPv6 host addresses are out of scope
            "192.168.1.1",  # bare address without 'host' is not supported
            "host",  # missing address
            "port",  # missing port number
            "port 99999",  # out of range
            "port abc",  # not a number
            "(tcp",  # unclosed paren
            "tcp)",  # unbalanced paren
            "tcp and",  # dangling operator
            "tcp tcp",  # two primitives with no operator between them
            "src",  # dangling direction qualifier
            "host 999.1.1.1",  # octet out of range
            "tcp $ udp",  # unexpected character
        ],
    )
    def test_rejects_unsupported_syntax(self, expr):
        with pytest.raises(BPFCompileError):
            compile_expression(expr)

    def test_error_message_names_the_expression(self):
        with pytest.raises(BPFCompileError, match="sctp"):
            compile_expression("sctp")

    def test_directionless_dangling_operator_names_the_right_gap(self):
        """'expected a primitive after src/dst' would be a misleading
        message for a dangling 'and' with no direction qualifier
        involved at all -- caught by writing this message-content
        check, not just the earlier tests' bare pytest.raises."""
        with pytest.raises(BPFCompileError) as excinfo:
            compile_expression("tcp and")
        assert "expected a primitive in" in str(excinfo.value)
        assert "src" not in str(excinfo.value).split(" in ")[0]

    def test_directional_dangling_qualifier_names_the_direction(self):
        with pytest.raises(BPFCompileError, match="after 'src'"):
            compile_expression("src")

    def test_expression_too_large_for_this_codegen_fails_loudly(self):
        """A long enough chain overflows cBPF's 8-bit conditional-jump
        offset -- confirmed by finding the exact breaking point (22
        ORed primitives; 21 still compiles). This codegen deliberately
        never emits an unconditional JA to work around the limit (see
        the module docstring): the failure mode for an expression this
        large must be a loud, immediate error, never a silently wrong
        offset, so this test exists to prove the guard actually fires
        rather than assume it would. This grammar has no bound on
        expression length, so a real (if unusual) user input can reach
        this -- it's BPFCompileError, the same as every other
        rejection, not an internal-only AssertionError."""
        compile_expression(" or ".join(["tcp"] * 21))  # still fits
        with pytest.raises(BPFCompileError, match="8-bit range"):
            compile_expression(" or ".join(["tcp"] * 22))


class TestParserAcceptsTheDocumentedGrammar:
    """A quick sanity pass over the grammar's own examples, independent
    of the corpus -- if these ever fail to even *compile*, the
    differential tests below would never get the chance to run."""

    @pytest.mark.parametrize(
        "expr",
        [
            "tcp",
            "udp",
            "icmp",
            "arp",
            "ip",
            "ip6",
            "host 1.2.3.4",
            "src host 1.2.3.4",
            "dst host 1.2.3.4",
            "port 80",
            "src port 80",
            "dst port 80",
            "tcp and udp",
            "tcp or udp",
            "not tcp",
            "not (tcp or udp)",
            "(tcp and port 80) or (udp and port 53)",
            "  tcp   and   port   80  ",  # whitespace is insignificant
        ],
    )
    def test_compiles_without_error(self, expr):
        program = compile_expression(expr)
        assert len(program) > 0
        # Every program must end in a ret; nothing else guarantees the
        # VM always terminates instead of running off the end.
        assert program[-1][0] == 0x06


class TestVMRejectsUnsupportedOperandForms:
    """This compiler and the canned filters only ever emit K-form JMP
    and RET instructions -- these confirm the VM actually notices an
    X-form or A-form one instead of silently misinterpreting its
    operand, since a differential test is only as trustworthy as the
    interpreter running both sides."""

    def test_x_form_jmp_is_rejected(self):
        # jeq %x (source bit set) instead of jeq #k
        program = ((0x1D, 0, 0, 0),)  # 0x15 | 0x08 (BPF_X)
        with pytest.raises(NotImplementedError, match="X-form"):
            vm_run(program, b"\x00" * 20)

    def test_a_form_ret_is_rejected(self):
        # ret %a (rval bits 0x10) instead of ret #k
        program = ((0x16, 0, 0, 0),)  # 0x06 | 0x10 (BPF_A)
        with pytest.raises(NotImplementedError, match="X/A-form"):
            vm_run(program, b"\x00" * 20)
