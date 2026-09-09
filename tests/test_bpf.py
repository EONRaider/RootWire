"""cBPF canned filters: bytecode goldens and the (unprivileged) attach
path.

``SO_ATTACH_FILTER`` is not ``PF_PACKET``-only — it attaches to an
ordinary socket, so the attach path itself is exercised for real here,
no root required. The end-to-end "a real PF_PACKET socket actually
drops non-matching frames" behavior is a separate, privilege-gated
concern this file does not cover.
"""

import ctypes
import socket
import struct
import sys

import pytest

from rootwire.bpf import (
    CANNED_FILTERS,
    SO_ATTACH_FILTER,
    SO_LOCK_FILTER,
    FilterProgram,
    SockFilter,
    _SockFprog,
)

_INSTRUCTION = struct.Struct("=HBBI")


def _resolve(program: FilterProgram) -> tuple[SockFilter, ...]:
    """Dereference a FilterProgram's sock_fprog pointer back into its
    instructions, proving the buffer it points at is intact -- rather
    than only checking the outer sock_fprog's fixed-size bytes, which
    say nothing about what the pointer still points to."""
    fprog = _SockFprog.from_buffer_copy(program.as_bytes())
    raw = ctypes.string_at(fprog.filter, fprog.len * _INSTRUCTION.size)
    return tuple(
        _INSTRUCTION.unpack_from(raw, i * _INSTRUCTION.size)
        for i in range(fprog.len)
    )


#: Transcribed byte-for-byte from a real `tcpdump -dd <expr>` run
#: (tcpdump 4.99.1 / libpcap 1.10.1), compiled against Ethernet — the
#: linktype RootWire always captures ("Warning: assuming Ethernet" is
#: exactly tcpdump confirming that assumption when compiling offline).
#: This is the golden fixture `bpf.py`'s canned programs must match;
#: it is independent of `bpf.py` itself, not derived from it.
_GOLDEN_TCPDUMP_DD = {
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
        (0x06, 0, 0, 0x00040000),
        (0x06, 0, 0, 0x00000000),
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
        (0x06, 0, 0, 0x00040000),
        (0x06, 0, 0, 0x00000000),
    ),
    "arp": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 1, 0x00000806),
        (0x06, 0, 0, 0x00040000),
        (0x06, 0, 0, 0x00000000),
    ),
    "ip6": (
        (0x28, 0, 0, 0x0000000C),
        (0x15, 0, 1, 0x000086DD),
        (0x06, 0, 0, 0x00040000),
        (0x06, 0, 0, 0x00000000),
    ),
}


class TestCannedBytecodeMatchesTcpdump:
    @pytest.mark.parametrize("name", sorted(CANNED_FILTERS))
    def test_matches_golden_tcpdump_dd_output(self, name):
        assert CANNED_FILTERS[name] == _GOLDEN_TCPDUMP_DD[name]


class TestFilterProgram:
    def test_as_bytes_is_a_valid_sock_fprog(self):
        program = FilterProgram(CANNED_FILTERS["arp"])
        packed = program.as_bytes()
        # struct sock_fprog { unsigned short len; struct sock_filter *f; }:
        # 2-byte len, padded to the pointer's alignment, then the pointer.
        length = struct.unpack_from("=H", packed)[0]
        assert length == len(CANNED_FILTERS["arp"])

    def test_keeps_the_instruction_buffer_alive(self):
        """Nothing but FilterProgram's own reference should keep the
        packed instructions from being garbage-collected between
        construction and attach. Actually dereferences the pointer
        after a collection cycle and checks the recovered instructions
        still match -- checking only sock_fprog's own fixed-size bytes
        would pass even if the pointed-to buffer had been freed and
        the pointer now dangled."""
        import gc

        program = FilterProgram(CANNED_FILTERS["tcp"])
        gc.collect()
        assert _resolve(program) == CANNED_FILTERS["tcp"]


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="SO_ATTACH_FILTER/SO_LOCK_FILTER are Linux-specific socket options",
)
class TestAttachPath:
    """SO_ATTACH_FILTER attaches to any socket, not just PF_PACKET, so
    the attach path is tested for real here, unprivileged."""

    @pytest.mark.parametrize("name", sorted(CANNED_FILTERS))
    def test_each_canned_filter_attaches_to_an_ordinary_socket(self, name):
        program = FilterProgram(CANNED_FILTERS[name])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(
                socket.SOL_SOCKET, SO_ATTACH_FILTER, program.as_bytes()
            )

    def test_lock_filter_also_attaches(self):
        program = FilterProgram(CANNED_FILTERS["arp"])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(
                socket.SOL_SOCKET, SO_ATTACH_FILTER, program.as_bytes()
            )
            sock.setsockopt(socket.SOL_SOCKET, SO_LOCK_FILTER, 1)

    def test_kernel_rejects_a_malformed_program(self):
        """Proves the kernel is actually validating the program, not
        just accepting arbitrary bytes -- a jump target here (200) is
        far past the single instruction's end."""
        malformed = FilterProgram([(0x15, 200, 0, 0x1)])
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock,
            pytest.raises(OSError),
        ):
            sock.setsockopt(
                socket.SOL_SOCKET, SO_ATTACH_FILTER, malformed.as_bytes()
            )
