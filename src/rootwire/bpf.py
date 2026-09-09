"""Kernel-side capture filtering via classic BPF (cBPF).

Attaching a cBPF program to the capture socket (``SO_ATTACH_FILTER``)
drops non-matching frames in the kernel, before they are copied to
userspace — the same mechanism ``tcpdump`` itself uses. This module
ships a small, canned set of pre-compiled programs; compiling arbitrary
filter *expressions* is a separate, larger piece of work.

Each canned program's bytecode is a golden fixture: it must match
``tcpdump -dd <expression>`` exactly (see ``tests/test_bpf.py``),
compiled against the Ethernet linktype RootWire always captures.
Hand-verifying cBPF bytecode does not scale past a handful of
obviously-correct, hand-picked expressions — which is exactly the
line this module stays on the safe side of.
"""

from __future__ import annotations

import ctypes
import struct
from collections.abc import Sequence
from typing import Final

__all__ = [
    "CANNED_FILTERS",
    "SO_ATTACH_FILTER",
    "SO_LOCK_FILTER",
    "FilterProgram",
    "SockFilter",
]

#: CPython's ``socket`` module does not expose the ``SO_ATTACH_FILTER``
#: family at all (checked through 3.14; the same gap as
#: ``SO_TIMESTAMPNS`` in ``capture.py``). These are the raw Linux
#: ``asm-generic/socket.h`` values, stable across every architecture
#: (unlike the timestamp options, they have no 64-bit-``time_t``
#: old/new split). Verified against a live kernel via an unprivileged
#: ``AF_INET``/``SOCK_DGRAM`` socket before use.
SO_ATTACH_FILTER: Final = 26
SO_LOCK_FILTER: Final = 44

#: One classic-BPF instruction: ``(code, jt, jf, k)``, matching the
#: kernel's ``struct sock_filter``.
SockFilter = tuple[int, int, int, int]

#: ``struct sock_filter { __u16 code; __u8 jt; __u8 jf; __u32 k; }`` —
#: 8 bytes, no padding on any architecture (the ``__u32`` is already
#: 4-byte aligned at offset 4). ``=`` pins standard sizes with no
#: alignment padding while keeping native byte order.
_INSTRUCTION = struct.Struct("=HBBI")


def _pack_instructions(instructions: Sequence[SockFilter]) -> bytes:
    return b"".join(_INSTRUCTION.pack(*insn) for insn in instructions)


class _SockFprog(ctypes.Structure):
    """``struct sock_fprog { unsigned short len; struct sock_filter *f; }``.

    A real ``ctypes.Structure`` (not a hand-picked ``struct`` format
    string) so the platform's own alignment/padding rules produce the
    byte-exact layout the kernel expects, whatever that padding is.
    """

    _fields_ = (("len", ctypes.c_ushort), ("filter", ctypes.c_void_p))


class FilterProgram:
    """A compiled cBPF program, ready to attach via ``SO_ATTACH_FILTER``.

    Keeps the packed instruction buffer alive for as long as this
    object exists: the ``sock_fprog`` handed to ``setsockopt`` embeds a
    raw pointer into that buffer, and nothing but this reference stops
    the garbage collector from freeing it out from under the kernel.
    """

    def __init__(self, instructions: Sequence[SockFilter]) -> None:
        packed = _pack_instructions(instructions)
        self._buffer = ctypes.create_string_buffer(packed, len(packed))
        self._fprog = _SockFprog(
            len(instructions), ctypes.cast(self._buffer, ctypes.c_void_p)
        )

    def as_bytes(self) -> bytes:
        """The ``sock_fprog`` value to pass to ``setsockopt``."""
        return bytes(self._fprog)


#: Golden bytecode from ``tcpdump -dd <expr>``, compiled against the
#: Ethernet linktype RootWire always captures (``tcpdump`` prints
#: "Warning: assuming Ethernet" when compiling offline, confirming the
#: assumption). Regenerate with, e.g., ``tcpdump -dd tcp`` if this set
#: ever needs to change — never hand-edit the instructions themselves.
_TCP: tuple[SockFilter, ...] = (
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
)

_UDP: tuple[SockFilter, ...] = (
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
)

_ARP: tuple[SockFilter, ...] = (
    (0x28, 0, 0, 0x0000000C),
    (0x15, 0, 1, 0x00000806),
    (0x06, 0, 0, 0x00040000),
    (0x06, 0, 0, 0x00000000),
)

_IP6: tuple[SockFilter, ...] = (
    (0x28, 0, 0, 0x0000000C),
    (0x15, 0, 1, 0x000086DD),
    (0x06, 0, 0, 0x00040000),
    (0x06, 0, 0, 0x00000000),
)

#: Canned filter names accepted by ``--filter``.
CANNED_FILTERS: Final[dict[str, tuple[SockFilter, ...]]] = {
    "tcp": _TCP,
    "udp": _UDP,
    "arp": _ARP,
    "ip6": _IP6,
}
