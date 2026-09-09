"""Raw-socket frame source, exercised without a real socket.

``capture`` is the only module that touches ``PF_PACKET``, which needs
``CAP_NET_RAW`` — so the loop logic (bind, ``recvmsg``, kernel
timestamp extraction, tuple shape) is tested against a fake socket
swapped in for the module-global ``socket`` name. Nothing here opens a
kernel socket, so it runs unprivileged on any Linux runner. The real
``PF_PACKET``/``SCM_TIMESTAMPNS`` round trip belongs in a separate,
privilege-gated integration test.
"""

import struct
from itertools import islice

import rootwire.capture as capture_mod
from rootwire.capture import (
    BUFFER_SIZE,
    SCM_TIMESTAMPNS,
    SOL_SOCKET,
    _parse_timestamp,
    capture,
)


def _timestampns_ancdata(seconds: int, nanoseconds: int) -> list:
    """One canned ``recvmsg`` ancillary-data entry carrying an
    ``SCM_TIMESTAMPNS`` cmsg, shaped exactly as the kernel would hand
    it back."""
    return [
        (SOL_SOCKET, SCM_TIMESTAMPNS, struct.pack("ll", seconds, nanoseconds))
    ]


class _FakeSocket:
    """Stand-in for the raw socket: records how it was called and serves
    a fixed run of canned ``(frame, ancdata)`` pairs from ``recvmsg``."""

    def __init__(self, *args: int) -> None:
        self.init_args = args
        self.bind_args: tuple[str, int] | None = None
        self.setsockopt_calls: list[tuple[int, int, int]] = []
        self.recvmsg_calls: list[tuple[int, int]] = []
        self.closed = False
        self._frames: list[tuple[bytes, list]] = [
            (b"\xaa\xbb", _timestampns_ancdata(1_700_000_000, 100_000_000)),
            (b"\xcc\xdd", _timestampns_ancdata(1_700_000_000, 200_000_000)),
            (b"\xee\xff", _timestampns_ancdata(1_700_000_000, 300_000_000)),
        ]
        self._index = 0

    def setsockopt(self, level: int, optname: int, value: int) -> None:
        self.setsockopt_calls.append((level, optname, value))

    def bind(self, address: tuple[str, int]) -> None:
        self.bind_args = address

    def recvmsg(
        self, bufsize: int, ancbufsize: int
    ) -> tuple[bytes, list, int, None]:
        self.recvmsg_calls.append((bufsize, ancbufsize))
        data, ancdata = self._frames[self._index % len(self._frames)]
        self._index += 1
        return data, ancdata, 0, None

    def __enter__(self) -> "_FakeSocket":
        return self

    def __exit__(self, *exc: object) -> bool:
        self.closed = True
        return False


def _install_fake_socket(monkeypatch) -> dict[str, _FakeSocket]:
    created: dict[str, _FakeSocket] = {}
    monkeypatch.setattr(
        capture_mod,
        "socket",
        lambda *args: created.setdefault("sock", _FakeSocket(*args)),
    )
    return created


class TestCapture:
    def test_enables_kernel_timestamps_before_binding(self, monkeypatch):
        created = _install_fake_socket(monkeypatch)

        next(iter(capture("eth0")))

        sock = created["sock"]
        assert sock.setsockopt_calls == [
            (SOL_SOCKET, capture_mod.SO_TIMESTAMPNS, 1)
        ]
        assert sock.bind_args == ("eth0", 0)

    def test_binds_to_interface_and_yields_kernel_timestamped_frames(
        self, monkeypatch
    ):
        created = _install_fake_socket(monkeypatch)

        frames = list(islice(capture("eth0"), 3))

        sock = created["sock"]
        assert sock.bind_args == ("eth0", 0)
        assert (
            sock.recvmsg_calls
            == [(BUFFER_SIZE, capture_mod._ANCILLARY_BUFSIZE)] * 3
        )
        assert frames == [
            (b"\xaa\xbb", 1_700_000_000_100_000_000),
            (b"\xcc\xdd", 1_700_000_000_200_000_000),
            (b"\xee\xff", 1_700_000_000_300_000_000),
        ]

    def test_all_interfaces_capture_does_not_bind(self, monkeypatch):
        created = _install_fake_socket(monkeypatch)

        next(iter(capture(None)))

        assert created["sock"].bind_args is None  # None -> capture on all

    def test_socket_is_closed_when_the_generator_is_closed(self, monkeypatch):
        created = _install_fake_socket(monkeypatch)

        frames = capture(None)
        next(frames)
        frames.close()  # unwinds the `with`, closing the socket

        assert created["sock"].closed is True

    def test_missing_timestamp_ancillary_falls_back_to_time_time_ns(
        self, monkeypatch
    ):
        monkeypatch.setattr(capture_mod.time, "time_ns", lambda: 999)

        def make_socket_with_no_ancdata(*args: int) -> _FakeSocket:
            sock = _FakeSocket(*args)
            sock._frames = [(b"\xaa\xbb", [])]  # no SCM_TIMESTAMPNS entry
            return sock

        monkeypatch.setattr(capture_mod, "socket", make_socket_with_no_ancdata)

        frame, timestamp = next(iter(capture(None)))

        assert frame == b"\xaa\xbb"
        assert timestamp == 999


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
