"""A tiny classic-BPF (cBPF) interpreter — test-only.

Exists purely to validate ``rootwire.bpf_compiler``'s output by
*behavior*: interpreting both tcpdump's compiled bytecode and this
project's compiled bytecode against real captured frames and checking
they agree on accept/reject. See ``rootwire.bpf_compiler``'s module
docstring for why matching tcpdump's exact instruction sequence isn't
the right correctness bar, and ``test_bpf_compiler.py`` for the
differential tests this VM makes possible.

Supports exactly the opcode subset ``rootwire.bpf.CANNED_FILTERS`` and
``rootwire.bpf_compiler`` actually emit (``ldb``/``ldh``/``ldw``
absolute, ``ldh`` indirect, the IHL-nibble ``ldxb`` trick, ``jeq``,
``jset``, ``ret`` — all ``K``-form, no ``X``-form comparisons or ``ja``)
— not the full cBPF instruction set. An opcode outside that set raises
rather than silently misinterpreting it, so a gap here is loud, not a
false "they agree."
"""

from __future__ import annotations

from rootwire.bpf import SockFilter

_LD = 0x00
_LDX = 0x01
_JMP = 0x05
_RET = 0x06

_CLASS_MASK = 0x07

_SIZE_MASK = 0x18
_SIZE_W = 0x00
_SIZE_H = 0x08
_SIZE_B = 0x10
_SIZE_BYTES = {_SIZE_W: 4, _SIZE_H: 2, _SIZE_B: 1}

_MODE_MASK = 0xE0
_MODE_ABS = 0x20
_MODE_IND = 0x40
_MODE_MSH = 0xA0

_JMP_OP_MASK = 0xF0
_JMP_JEQ = 0x10
_JMP_JSET = 0x40
#: JMP/ALU "source" bit: 0 = K (immediate operand), 8 = X (register
#: operand). This compiler and the canned filters only ever emit
#: K-form; an X-form op here would silently compare against the wrong
#: operand if not checked explicitly.
_SRC_MASK = 0x08

#: RET's return-value source is a *2-bit* field (0x18: K/X/A) that
#: overlaps but is not the same as JMP's 1-bit _SRC_MASK -- reusing
#: that check for RET would miss BPF_A (0x10) uncaught.
_RET_RVAL_MASK = 0x18


class _Reject(Exception):
    """An out-of-bounds load: the real kernel terminates the whole
    filter and rejects the packet, rather than continuing with some
    substitute value — a filter compiled from a bounds-respecting
    grammar relies on exactly this to stay safe on truncated input."""


def run(program: tuple[SockFilter, ...], packet: bytes) -> int:
    """Execute ``program`` against ``packet``; returns the number of
    bytes the kernel would keep (0 rejects the packet)."""
    try:
        return _run(program, packet)
    except _Reject:
        return 0


def _run(program: tuple[SockFilter, ...], packet: bytes) -> int:
    accumulator = 0
    index_reg = 0
    pc = 0
    length = len(program)
    steps = 0
    while pc < length:
        steps += 1
        if steps > 10_000:
            raise AssertionError(
                "cBPF program did not terminate within 10,000 steps -- "
                "almost certainly a resolver bug (e.g. a jump loop), "
                "since this VM's opcode subset has no backward jumps"
            )
        code, jt, jf, k = program[pc]
        instruction_class = code & _CLASS_MASK

        if instruction_class == _LD:
            mode = code & _MODE_MASK
            size = _SIZE_BYTES[code & _SIZE_MASK]
            if mode == _MODE_ABS:
                offset = k
            elif mode == _MODE_IND:
                offset = index_reg + k
            else:
                raise NotImplementedError(f"unsupported LD mode in {code:#x}")
            accumulator = _load(packet, offset, size)
            pc += 1

        elif instruction_class == _LDX:
            if code & _MODE_MASK != _MODE_MSH:
                raise NotImplementedError(f"unsupported LDX mode in {code:#x}")
            index_reg = 4 * (_load(packet, k, 1) & 0x0F)
            pc += 1

        elif instruction_class == _JMP:
            if code & _SRC_MASK:
                raise NotImplementedError(
                    f"unsupported JMP source (X-form) in {code:#x}"
                )
            op = code & _JMP_OP_MASK
            if op == _JMP_JEQ:
                taken = accumulator == k
            elif op == _JMP_JSET:
                taken = (accumulator & k) != 0
            else:
                raise NotImplementedError(f"unsupported JMP op in {code:#x}")
            pc += (jt if taken else jf) + 1

        elif instruction_class == _RET:
            if code & _RET_RVAL_MASK:
                raise NotImplementedError(
                    f"unsupported RET source (X/A-form) in {code:#x}"
                )
            return k

        else:
            raise NotImplementedError(
                f"unsupported instruction class in {code:#x}"
            )

    raise AssertionError("cBPF program ran off the end without a RET")


def _load(packet: bytes, offset: int, size: int) -> int:
    if offset < 0 or offset + size > len(packet):
        raise _Reject
    return int.from_bytes(packet[offset : offset + size], "big")
