"""Raw-socket frame source.

This is the only module in the application that touches ``PF_PACKET``
(a Linux-only socket family) — everything else works with plain bytes
and runs on any OS, which is what keeps the decoder and renderers
testable without root privileges.
"""

from __future__ import annotations

import struct
import time
from collections.abc import Iterator
from socket import (
    CMSG_SPACE,
    PF_PACKET,
    SOCK_RAW,
    SOL_SOCKET,
    htons,
    socket,
)

from rootwire.bpf import SO_ATTACH_FILTER, SO_LOCK_FILTER, FilterProgram

__all__ = ["BUFFER_SIZE", "capture"]

#: Every EtherType (linux/if_ether.h).
_ETH_P_ALL = 0x0003

#: Largest capturable frame: a maximum-size IP datagram (65,535 bytes)
#: behind an Ethernet header, with headroom. The loopback interface
#: carries frames far larger than any physical MTU, so anything smaller
#: silently truncates local traffic.
BUFFER_SIZE = 65_550

#: CPython's ``socket`` module does not expose the ``SO_TIMESTAMP*``
#: option family at all (checked through 3.14) — these are the raw
#: Linux ``asm-generic/socket.h`` values. ``SO_TIMESTAMPNS`` is
#: ``SO_TIMESTAMPNS_OLD`` (35) whenever ``time_t`` matches the kernel's
#: native ``long`` width, true on every 64-bit architecture RootWire
#: targets (x86_64, aarch64); ``SCM_TIMESTAMPNS`` is defined as the same
#: value. Verified against a live kernel via an unprivileged
#: ``socketpair`` round trip. A 32-bit userspace would need the
#: ``_NEW`` variant (64) instead for post-2038 safety, out of scope
#: here.
SO_TIMESTAMPNS = 35
SCM_TIMESTAMPNS = 35

#: ``SCM_TIMESTAMPNS`` carries a ``struct timespec``: two native
#: ``long``s (``tv_sec``, ``tv_nsec``). ``CMSG_SPACE(16)`` sizes the
#: ancillary buffer generously for that on both 32- and 64-bit ``long``.
_TIMESPEC = struct.Struct("ll")
_ANCILLARY_BUFSIZE = CMSG_SPACE(16)


def _parse_timestamp(ancdata: list[tuple[int, int, bytes]]) -> int | None:
    """Extract a kernel capture timestamp (nanoseconds since epoch) from
    ``recvmsg``'s ancillary data, or ``None`` if no ``SCM_TIMESTAMPNS``
    entry is present — a pure function, testable with synthetic
    ``ancdata`` tuples and no socket."""
    for level, kind, data in ancdata:
        if level == SOL_SOCKET and kind == SCM_TIMESTAMPNS:
            tv_sec: int
            tv_nsec: int
            tv_sec, tv_nsec = _TIMESPEC.unpack(data[: _TIMESPEC.size])
            return tv_sec * 1_000_000_000 + tv_nsec
    return None


def capture(
    interface: str | None, filter_program: FilterProgram | None = None
) -> Iterator[tuple[bytes, int]]:
    """Yield ``(frame, timestamp)`` pairs from a raw socket, forever.

    Each frame is one freshly allocated, immutable ``bytes`` object —
    never a reused buffer — so frames remain valid for as long as any
    consumer holds them. ``timestamp`` is nanoseconds since the Unix
    epoch, taken from the kernel at the moment the frame arrived
    (``SO_TIMESTAMPNS``) rather than from a userspace clock read after
    ``recv`` returns — the latter includes scheduler and interpreter
    latency between arrival and this code running. A missing timestamp
    ancillary message (some interfaces/paths don't provide one) falls
    back to :func:`time.time_ns` rather than crashing the loop.

    :param interface: Interface to bind to, or ``None`` to capture on
        all interfaces.
    :param filter_program: A compiled cBPF program to attach
        (``SO_ATTACH_FILTER``) before binding, so non-matching frames
        are dropped in the kernel and never reach userspace. ``None``
        captures everything, as before.
    :raises PermissionError: If the process lacks the privileges for a
        raw socket (root or ``CAP_NET_RAW``).
    """
    with socket(PF_PACKET, SOCK_RAW, htons(_ETH_P_ALL)) as sock:
        sock.setsockopt(SOL_SOCKET, SO_TIMESTAMPNS, 1)
        if filter_program is not None:
            sock.setsockopt(
                SOL_SOCKET, SO_ATTACH_FILTER, filter_program.as_bytes()
            )
            # Defence in depth: once a filter is attached, nothing on
            # this socket should ever replace or remove it for the
            # rest of its lifetime.
            sock.setsockopt(SOL_SOCKET, SO_LOCK_FILTER, 1)
        if interface is not None:
            sock.bind((interface, 0))
        while True:
            data, ancdata, _flags, _addr = sock.recvmsg(
                BUFFER_SIZE, _ANCILLARY_BUFSIZE
            )
            timestamp = _parse_timestamp(ancdata)
            yield data, timestamp if timestamp is not None else time.time_ns()
