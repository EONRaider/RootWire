"""Raw-socket frame source, exercised without a real socket.

``capture`` is the only module that touches ``PF_PACKET``, which needs
``CAP_NET_RAW`` — so the loop logic (bind, ``recv``, timestamp, tuple
shape) is tested against a fake socket swapped in for the module-global
``socket`` name. Nothing here opens a kernel socket, so it runs
unprivileged on any Linux runner. The real ``PF_PACKET`` round trip
belongs in a separate, privilege-gated integration test.
"""

from itertools import islice

import rootwire.capture as capture_mod
from rootwire.capture import BUFFER_SIZE, capture


class _FakeSocket:
    """Stand-in for the raw socket: records how it was called and serves
    a fixed run of canned frames from ``recv``."""

    def __init__(self, *args: int) -> None:
        self.init_args = args
        self.bind_args: tuple[str, int] | None = None
        self.recv_sizes: list[int] = []
        self.closed = False
        self._frames = [b"\xaa\xbb", b"\xcc\xdd", b"\xee\xff"]
        self._index = 0

    def bind(self, address: tuple[str, int]) -> None:
        self.bind_args = address

    def recv(self, size: int) -> bytes:
        self.recv_sizes.append(size)
        frame = self._frames[self._index % len(self._frames)]
        self._index += 1
        return frame

    def __enter__(self) -> "_FakeSocket":
        return self

    def __exit__(self, *exc: object) -> bool:
        self.closed = True
        return False


class TestCapture:
    def test_binds_to_interface_and_yields_timestamped_frames(
        self, monkeypatch
    ):
        created: dict[str, _FakeSocket] = {}
        monkeypatch.setattr(
            capture_mod,
            "socket",
            lambda *args: created.setdefault("sock", _FakeSocket(*args)),
        )
        monkeypatch.setattr(capture_mod.time, "time", lambda: 123.5)

        frames = list(islice(capture("eth0"), 3))

        sock = created["sock"]
        assert sock.bind_args == ("eth0", 0)
        assert sock.recv_sizes == [BUFFER_SIZE] * 3  # full buffer each recv
        assert frames == [
            (b"\xaa\xbb", 123.5),
            (b"\xcc\xdd", 123.5),
            (b"\xee\xff", 123.5),
        ]

    def test_all_interfaces_capture_does_not_bind(self, monkeypatch):
        created: dict[str, _FakeSocket] = {}
        monkeypatch.setattr(
            capture_mod,
            "socket",
            lambda *args: created.setdefault("sock", _FakeSocket(*args)),
        )

        next(iter(capture(None)))

        assert created["sock"].bind_args is None  # None -> capture on all

    def test_socket_is_closed_when_the_generator_is_closed(self, monkeypatch):
        created: dict[str, _FakeSocket] = {}
        monkeypatch.setattr(
            capture_mod,
            "socket",
            lambda *args: created.setdefault("sock", _FakeSocket(*args)),
        )

        frames = capture(None)
        next(frames)
        frames.close()  # unwinds the `with`, closing the socket

        assert created["sock"].closed is True
