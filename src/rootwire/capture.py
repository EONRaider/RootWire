"""Raw-socket frame source.

This is the only module in the application that touches ``PF_PACKET``
(a Linux-only socket family) — everything else works with plain bytes
and runs on any OS, which is what keeps the decoder and renderers
testable without root privileges.
"""

from __future__ import annotations

import asyncio
import struct
import time
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import ExitStack
from socket import (
    CMSG_SPACE,
    PF_PACKET,
    SOCK_RAW,
    SOL_SOCKET,
    htons,
    socket,
)

from rootwire.bpf import SO_ATTACH_FILTER, SO_LOCK_FILTER, FilterProgram

__all__ = ["BUFFER_SIZE", "capture_async"]

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

#: One live frame, tagged with the interface it arrived on.
_CapturedFrame = tuple[bytes, int, "str | None"]


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


def _open_socket(
    interface: str | None, filter_program: FilterProgram | None
) -> socket:
    """Build one capture socket: timestamps and an optional filter
    attached, bound to ``interface`` (or left unbound for "all
    interfaces"), set non-blocking for use with ``add_reader``."""
    sock = socket(PF_PACKET, SOCK_RAW, htons(_ETH_P_ALL))
    sock.setsockopt(SOL_SOCKET, SO_TIMESTAMPNS, 1)
    if filter_program is not None:
        sock.setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, filter_program.as_bytes())
        # Defence in depth: once a filter is attached, nothing on this
        # socket should ever replace or remove it for the rest of its
        # lifetime.
        sock.setsockopt(SOL_SOCKET, SO_LOCK_FILTER, 1)
    if interface is not None:
        sock.bind((interface, 0))
    sock.setblocking(False)
    return sock


def _make_reader(
    sock: socket,
    interface: str | None,
    queue: asyncio.Queue[_CapturedFrame | OSError],
) -> Callable[[], None]:
    """Build the ``add_reader`` callback for one socket.

    Reads one datagram — non-blocking is safe here, the fd was just
    confirmed readable — and pushes the result onto the shared queue
    :func:`capture_async` drains, tagged with which interface it came
    from. A read error is pushed too, rather than raised here, so it
    surfaces through the async generator's ordinary control flow
    instead of being silently logged by asyncio's default handler for
    callback exceptions.
    """

    def _on_readable() -> None:
        try:
            data, ancdata, _flags, _addr = sock.recvmsg(
                BUFFER_SIZE, _ANCILLARY_BUFSIZE
            )
        except (BlockingIOError, InterruptedError):
            # Transient, not a real failure: either a spurious wakeup
            # (no data actually available) or the syscall was
            # interrupted by a signal (EINTR) -- exactly what SIGTERM
            # delivery itself can cause here, since this socket's fd is
            # registered with the same event loop that just received
            # it. The reader stays registered; epoll will re-signal
            # readiness on its own if data is still waiting.
            return
        except OSError as error:
            queue.put_nowait(error)
            return
        timestamp = _parse_timestamp(ancdata)
        queue.put_nowait(
            (
                data,
                timestamp if timestamp is not None else time.time_ns(),
                interface,
            )
        )

    return _on_readable


async def capture_async(
    interfaces: Sequence[str] | None,
    filter_program: FilterProgram | None = None,
) -> AsyncIterator[_CapturedFrame]:
    """Yield ``(frame, timestamp, interface)`` triples, merged from one
    or more raw sockets, forever.

    ``interfaces`` names one or more interfaces to bind to
    individually and capture concurrently; ``None`` or empty opens a
    single unbound socket listening on everything, as before, and
    tags every frame's interface ``None``. A single-element sequence
    is the ordinary single-interface case, handled by the same
    machinery as N > 1 — there is no separate code path to keep in
    sync, and no meaningful "just one interface" fast path to bypass.

    Each socket is registered with the running event loop
    (``add_reader``); when any becomes readable, its frame is read and
    pushed onto a shared queue this generator drains — merging the
    streams while keeping each frame tagged with the interface it
    actually arrived on. Frame order across interfaces reflects
    readiness order (whichever socket the kernel had data for first),
    not any fixed round-robin.

    :param interfaces: Interfaces to bind to, or ``None``/empty to
        capture on all interfaces through one unbound socket.
    :param filter_program: A compiled cBPF program to attach
        (``SO_ATTACH_FILTER``) to every socket before binding, so
        non-matching frames are dropped in the kernel and never reach
        userspace. ``None`` captures everything, as before.
    :raises PermissionError: If the process lacks the privileges for a
        raw socket (root or ``CAP_NET_RAW``).
    """
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[_CapturedFrame | OSError] = asyncio.Queue()
    names: Sequence[str | None] = interfaces if interfaces else (None,)

    with ExitStack() as stack:
        for name in names:
            sock = _open_socket(name, filter_program)
            stack.enter_context(sock)
            loop.add_reader(sock.fileno(), _make_reader(sock, name, queue))
            stack.callback(loop.remove_reader, sock.fileno())

        while True:
            item = await queue.get()
            if isinstance(item, OSError):
                raise item
            yield item
