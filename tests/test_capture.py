"""Raw-socket frame source, exercised without a real socket.

``capture_async`` is the only function that touches ``PF_PACKET``, which
needs ``CAP_NET_RAW`` — so the loop logic (bind, ``recvmsg``, kernel
timestamp extraction, filter attach, multi-interface merge) is tested
against fake sockets swapped in for the module-global ``socket`` name.
Each fake is backed by a real ``socketpair()`` peer so the *real*
running event loop has a genuine fd to poll with ``add_reader`` —
canned data still comes from a scripted ``recvmsg``, regardless of what
real bytes (if any) woke the fd. Nothing here opens a kernel socket, so
it runs unprivileged on any Linux runner. The real
``PF_PACKET``/``SCM_TIMESTAMPNS`` round trip belongs in a separate,
privilege-gated integration test.
"""

import asyncio
import contextlib
import socket as socket_module
import struct

import pytest

import rootwire.capture as capture_mod
from rootwire.bpf import CANNED_FILTERS, FilterProgram
from rootwire.capture import (
    SCM_TIMESTAMPNS,
    SOL_SOCKET,
    _parse_timestamp,
    capture_async,
)


def _timestampns_ancdata(seconds: int, nanoseconds: int) -> list:
    """One canned ``recvmsg`` ancillary-data entry carrying an
    ``SCM_TIMESTAMPNS`` cmsg, shaped exactly as the kernel would hand
    it back."""
    return [
        (SOL_SOCKET, SCM_TIMESTAMPNS, struct.pack("ll", seconds, nanoseconds))
    ]


class _FakeSocket:
    """Stand-in raw socket for the real, running event loop.

    ``fileno()`` is backed by one half of a real ``socketpair()`` so
    ``loop.add_reader`` has a genuine fd to watch; ``push_frame`` wakes
    it by writing a byte down the peer. ``recvmsg`` always serves the
    next canned frame regardless of the real bytes that woke the fd —
    those are drained and discarded, never interpreted as frame data.
    """

    def __init__(self, *args: int) -> None:
        self.init_args = args
        self.bind_args: tuple[str, int] | None = None
        self.setsockopt_calls: list[tuple[int, int, int | bytes]] = []
        self.closed = False
        self._real, self._peer = socket_module.socketpair()
        self._real.setblocking(False)
        self._frames: list[tuple[bytes, list, int, None] | OSError] = []

    def setsockopt(self, level: int, optname: int, value: int | bytes) -> None:
        self.setsockopt_calls.append((level, optname, value))

    def bind(self, address: tuple[str, int]) -> None:
        self.bind_args = address

    def setblocking(self, flag: bool) -> None:
        pass

    def fileno(self) -> int:
        return self._real.fileno()

    def recvmsg(
        self, bufsize: int, ancbufsize: int
    ) -> tuple[bytes, list, int, None]:
        # Exactly one wake byte per push_frame()/push_error() call:
        # draining more than one at a time would collapse several
        # already-queued wake signals into a single readability event
        # (level-triggered epoll keeps the fd readable as long as any
        # byte remains, so under-draining is what correctly makes the
        # loop call this again for the rest).
        with contextlib.suppress(BlockingIOError):
            self._real.recv(1)
        item = self._frames.pop(0)
        if isinstance(item, OSError):
            raise item
        return item

    def push_frame(
        self, data: bytes, ancdata: list, flags: int = 0, addr: None = None
    ) -> None:
        self._frames.append((data, ancdata, flags, addr))
        self._peer.send(b"x")

    def push_error(self, error: OSError) -> None:
        self._frames.append(error)
        self._peer.send(b"x")

    def close(self) -> None:
        self.closed = True
        self._real.close()
        self._peer.close()

    def __enter__(self) -> "_FakeSocket":
        return self

    def __exit__(self, *exc: object) -> bool:
        self.close()
        return False


def _install_fake_sockets(monkeypatch) -> list[_FakeSocket]:
    created: list[_FakeSocket] = []

    def factory(*args: int) -> _FakeSocket:
        sock = _FakeSocket(*args)
        created.append(sock)
        return sock

    monkeypatch.setattr(capture_mod, "socket", factory)
    return created


async def _collect(agen, count: int, timeout: float = 2.0) -> list:
    results = []
    async with asyncio.timeout(timeout):
        for _ in range(count):
            results.append(await anext(agen))
    return results


class TestCaptureAsync:
    def test_single_interface_binds_and_yields_kernel_timestamped_frames(
        self, monkeypatch
    ):
        created = _install_fake_sockets(monkeypatch)

        async def body():
            agen = capture_async(["eth0"])
            frames = []
            task = asyncio.ensure_future(_collect(agen, 3))
            await asyncio.sleep(0)  # let capture_async's setup run
            created[0].push_frame(
                b"\xaa\xbb",
                _timestampns_ancdata(1_700_000_000, 100_000_000),
            )
            created[0].push_frame(
                b"\xcc\xdd",
                _timestampns_ancdata(1_700_000_000, 200_000_000),
            )
            created[0].push_frame(
                b"\xee\xff",
                _timestampns_ancdata(1_700_000_000, 300_000_000),
            )
            frames = await task
            await agen.aclose()
            return frames

        frames = asyncio.run(body())

        assert len(created) == 1
        assert created[0].bind_args == ("eth0", 0)
        assert frames == [
            (b"\xaa\xbb", 1_700_000_000_100_000_000, "eth0"),
            (b"\xcc\xdd", 1_700_000_000_200_000_000, "eth0"),
            (b"\xee\xff", 1_700_000_000_300_000_000, "eth0"),
        ]

    def test_no_interfaces_opens_one_unbound_socket(self, monkeypatch):
        created = _install_fake_sockets(monkeypatch)

        async def body():
            agen = capture_async(None)
            task = asyncio.ensure_future(_collect(agen, 1))
            await asyncio.sleep(0)
            created[0].push_frame(b"\xaa\xbb", [])
            frame = (await task)[0]
            await agen.aclose()
            return frame

        frame = asyncio.run(body())

        assert len(created) == 1
        assert created[0].bind_args is None
        assert frame[2] is None  # interface tag: "all interfaces"

    def test_merges_frames_from_several_interfaces_tagging_each(
        self, monkeypatch
    ):
        created = _install_fake_sockets(monkeypatch)

        async def body():
            agen = capture_async(["eth0", "wlan0"])
            task = asyncio.ensure_future(_collect(agen, 2))
            await asyncio.sleep(0)
            # Pushed and awaited one at a time so the order is
            # deterministic rather than a race between two ready fds.
            created[0].push_frame(b"\xaa\xbb", [])
            await asyncio.sleep(0.05)
            created[1].push_frame(b"\xcc\xdd", [])
            frames = await task
            await agen.aclose()
            return frames

        frames = asyncio.run(body())

        assert len(created) == 2
        assert created[0].bind_args == ("eth0", 0)
        assert created[1].bind_args == ("wlan0", 0)
        assert frames[0] == (b"\xaa\xbb", frames[0][1], "eth0")
        assert frames[1] == (b"\xcc\xdd", frames[1][1], "wlan0")

    def test_missing_timestamp_ancillary_falls_back_to_time_time_ns(
        self, monkeypatch
    ):
        created = _install_fake_sockets(monkeypatch)
        monkeypatch.setattr(capture_mod.time, "time_ns", lambda: 999)

        async def body():
            agen = capture_async(["eth0"])
            task = asyncio.ensure_future(_collect(agen, 1))
            await asyncio.sleep(0)
            created[0].push_frame(b"\xaa\xbb", [])  # no SCM_TIMESTAMPNS entry
            frame = (await task)[0]
            await agen.aclose()
            return frame

        frame = asyncio.run(body())

        assert frame == (b"\xaa\xbb", 999, "eth0")

    def test_no_filter_program_attaches_nothing(self, monkeypatch):
        created = _install_fake_sockets(monkeypatch)

        async def body():
            agen = capture_async(["eth0"])
            task = asyncio.ensure_future(_collect(agen, 1))
            await asyncio.sleep(0)
            created[0].push_frame(b"\xaa\xbb", [])
            await task
            await agen.aclose()

        asyncio.run(body())

        assert created[0].setsockopt_calls == [
            (SOL_SOCKET, capture_mod.SO_TIMESTAMPNS, 1)
        ]

    def test_filter_program_is_attached_and_locked_on_every_socket(
        self, monkeypatch
    ):
        created = _install_fake_sockets(monkeypatch)
        program = FilterProgram(CANNED_FILTERS["tcp"])

        async def body():
            agen = capture_async(["eth0", "wlan0"], program)
            task = asyncio.ensure_future(_collect(agen, 2))
            await asyncio.sleep(0)
            created[0].push_frame(b"\xaa\xbb", [])
            created[1].push_frame(b"\xcc\xdd", [])
            await task
            await agen.aclose()

        asyncio.run(body())

        for sock in created:
            assert sock.setsockopt_calls == [
                (SOL_SOCKET, capture_mod.SO_TIMESTAMPNS, 1),
                (
                    SOL_SOCKET,
                    capture_mod.SO_ATTACH_FILTER,
                    program.as_bytes(),
                ),
                (SOL_SOCKET, capture_mod.SO_LOCK_FILTER, 1),
            ]

    def test_transient_blocking_or_interrupted_errors_are_swallowed(
        self, monkeypatch
    ):
        """BlockingIOError (spurious wakeup) and InterruptedError
        (EINTR -- exactly what SIGTERM delivery to this same process
        can cause mid-recvmsg) are not real failures: the generator
        must keep running afterward, not propagate them."""
        created = _install_fake_sockets(monkeypatch)

        async def body():
            agen = capture_async(["eth0"])
            task = asyncio.ensure_future(_collect(agen, 1))
            await asyncio.sleep(0)
            created[0].push_error(BlockingIOError())
            created[0].push_error(InterruptedError())
            created[0].push_frame(b"\xaa\xbb", [])
            frame = (await task)[0]
            await agen.aclose()
            return frame

        frame = asyncio.run(body())

        assert frame[0] == b"\xaa\xbb"

    def test_socket_error_during_read_is_raised_from_the_generator(
        self, monkeypatch
    ):
        created = _install_fake_sockets(monkeypatch)

        async def body():
            agen = capture_async(["eth0"])
            task = asyncio.ensure_future(_collect(agen, 1))
            await asyncio.sleep(0)
            created[0].push_error(OSError("simulated read failure"))
            with pytest.raises(OSError, match="simulated read failure"):
                await task
            await agen.aclose()

        asyncio.run(body())

    def test_sockets_closed_when_the_generator_is_closed(self, monkeypatch):
        created = _install_fake_sockets(monkeypatch)

        async def body():
            agen = capture_async(["eth0", "wlan0"])
            task = asyncio.ensure_future(_collect(agen, 1))
            await asyncio.sleep(0)
            created[0].push_frame(b"\xaa\xbb", [])
            await task
            await agen.aclose()

        asyncio.run(body())

        assert all(sock.closed for sock in created)


class TestParseTimestamp:
    def test_extracts_seconds_and_nanoseconds(self):
        ancdata = _timestampns_ancdata(1_700_000_000, 123_456_789)
        assert _parse_timestamp(ancdata) == 1_700_000_000_123_456_789

    def test_returns_none_when_absent(self):
        assert _parse_timestamp([]) is None

    def test_ignores_non_matching_cmsg_entries(self):
        unrelated = (SOL_SOCKET, 999, b"\x00" * 16)
        assert _parse_timestamp([unrelated]) is None

    def test_finds_the_matching_entry_among_others(self):
        unrelated = (SOL_SOCKET, 999, b"\x00" * 16)
        matching = _timestampns_ancdata(1_700_000_000, 500_000_000)[0]
        assert (
            _parse_timestamp([unrelated, matching]) == 1_700_000_000_500_000_000
        )
