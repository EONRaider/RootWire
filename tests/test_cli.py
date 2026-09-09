import contextlib
import ctypes
import os
import shutil
import signal
import socket as socket_module
import struct
import threading
from typing import ClassVar

import pytest

import rootwire.capture as capture_mod
from conftest import FIXTURES
from rootwire import __version__, cli
from rootwire.bpf import CANNED_FILTERS, SockFilter, _SockFprog
from rootwire.cli import build_parser

_INSTRUCTION = struct.Struct("=HBBI")


class TestCLI:
    def test_defaults(self):
        args = build_parser().parse_args([])
        assert args.interface is None
        assert args.data is False

    def test_interface_and_data_flags(self):
        args = build_parser().parse_args(["-i", "eth0", "-d"])
        assert args.interface == ["eth0"]
        assert args.data is True

    def test_interface_is_repeatable(self):
        args = build_parser().parse_args(["-i", "eth0", "-i", "wlan0"])
        assert args.interface == ["eth0", "wlan0"]

    def test_version(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            build_parser().parse_args(["--version"])
        assert excinfo.value.code == 0
        assert __version__ in capsys.readouterr().out


class _FakeSocket:
    """Fake capture socket for driving cli.main() end to end through the
    real asyncio event loop.

    Backed by one half of a real ``socketpair()`` so ``add_reader`` has
    a genuine fd to poll; nothing is ever pushed through it unless a
    test calls ``push_error``, so the fd simply never becomes readable
    on its own. Every ``SO_ATTACH_FILTER`` call has its ``sock_fprog``
    pointer resolved back to plain instructions immediately —
    synchronously, while the originating ``FilterProgram`` is still
    alive on ``capture_async``'s frame — since the raw pointer bytes
    themselves are meaningless once that buffer is gone and differ
    across otherwise-identical ``FilterProgram`` instances regardless.
    """

    attached_programs: ClassVar[list[tuple[SockFilter, ...]]] = []

    def __init__(self, *args: int) -> None:
        self.setsockopt_calls: list[tuple[int, int, int | bytes]] = []
        self._real, self._peer = socket_module.socketpair()
        self._real.setblocking(False)
        self._pending: list[OSError] = []

    def setsockopt(self, level: int, optname: int, value: int | bytes) -> None:
        self.setsockopt_calls.append((level, optname, value))
        if optname == capture_mod.SO_ATTACH_FILTER:
            assert isinstance(value, bytes)
            fprog = _SockFprog.from_buffer_copy(value)
            raw = ctypes.string_at(fprog.filter, fprog.len * _INSTRUCTION.size)
            _FakeSocket.attached_programs.append(
                tuple(
                    _INSTRUCTION.unpack_from(raw, i * _INSTRUCTION.size)
                    for i in range(fprog.len)
                )
            )

    def bind(self, address: tuple[str, int]) -> None:
        pass

    def setblocking(self, flag: bool) -> None:
        pass

    def fileno(self) -> int:
        return self._real.fileno()

    def recvmsg(
        self, bufsize: int, ancbufsize: int
    ) -> tuple[bytes, list, int, None]:
        with contextlib.suppress(BlockingIOError):
            self._real.recv(1)
        raise self._pending.pop(0)

    def push_error(self, error: OSError) -> None:
        self._pending.append(error)
        self._peer.send(b"x")

    def close(self) -> None:
        self._real.close()
        self._peer.close()

    def __enter__(self) -> "_FakeSocket":
        return self

    def __exit__(self, *exc: object) -> bool:
        self.close()
        return False


class TestFilterFlag:
    def test_canned_filter_names_are_valid_choices(self):
        for name in CANNED_FILTERS:
            args = build_parser().parse_args(["--filter", name])
            assert args.filter == name

    def test_unknown_filter_name_is_rejected(self):
        with pytest.raises(SystemExit) as excinfo:
            build_parser().parse_args(["--filter", "not-a-real-filter"])
        assert excinfo.value.code == 2

    def test_read_and_filter_are_exclusive(self):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["-r", "x.pcap", "--filter", "tcp"])
        assert excinfo.value.code == 2

    def test_filter_is_attached_to_the_capture_socket(self, monkeypatch):
        _FakeSocket.attached_programs = []
        created: list[_FakeSocket] = []

        def factory(*args: int) -> _FakeSocket:
            sock = _FakeSocket(*args)
            created.append(sock)
            return sock

        monkeypatch.setattr(capture_mod, "socket", factory)

        def push_error_once_ready() -> None:
            created[0].push_error(OSError("stop after setup"))

        threading.Timer(0.05, push_error_once_ready).start()

        with pytest.raises(OSError, match="stop after setup"):
            cli.main(["-i", "eth0", "--filter", "tcp"])

        assert _FakeSocket.attached_programs == [CANNED_FILTERS["tcp"]]


class TestSameFileGuard:
    def test_read_and_write_same_file_refused_without_truncating(
        self, tmp_path
    ):
        target = tmp_path / "cap.pcap"
        shutil.copy(FIXTURES / "udp_dns.pcap", target)
        original = target.read_bytes()
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["-r", str(target), "-w", str(target)])
        assert excinfo.value.code == 2  # usage error, before any open()
        assert target.read_bytes() == original  # capture left intact

    def test_same_file_detected_through_different_spelling(self, tmp_path):
        target = tmp_path / "cap.pcap"
        shutil.copy(FIXTURES / "udp_dns.pcap", target)
        (tmp_path / "sub").mkdir()
        spelled = tmp_path / "sub" / ".." / "cap.pcap"
        original = target.read_bytes()
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["-r", str(target), "-w", str(spelled)])
        assert excinfo.value.code == 2
        assert target.read_bytes() == original


class TestWriteErrorHandling:
    def test_bad_write_path_is_a_clean_error_not_a_traceback(
        self, tmp_path, capsys
    ):
        bad = tmp_path / "no-such-dir" / "out.pcap"
        assert (
            cli.main(["-r", str(FIXTURES / "udp_dns.pcap"), "-w", str(bad)])
            == 1
        )
        err = capsys.readouterr().err
        assert "for writing" in err
        assert "sudo" not in err  # not misdiagnosed as a privilege problem

    def test_stats_not_reported_when_an_unexpected_error_propagates(
        self, capsys, monkeypatch
    ):
        def boom(*_args, **_kwargs):
            raise RuntimeError("decode exploded")

        monkeypatch.setattr(cli, "run", boom)
        with pytest.raises(RuntimeError, match="decode exploded"):
            cli.main(["-r", str(FIXTURES / "udp_dns.pcap")])
        # No stats summary should disguise the crash as a clean run.
        assert "[=]" not in capsys.readouterr().err


class TestAbortHandling:
    """Ctrl-C (KeyboardInterrupt) and a service manager's SIGTERM both
    abort main()'s capture loop through the same shutdown path: flush
    outputs, report stats, exit 0.

    Real OS signals are sent from a background thread here, rather than
    invoking a handler function directly: asyncio's add_signal_handler
    is dispatched through an internal self-pipe, not a plain Python
    signal.signal() callback, so a real signal is both the simplest and
    the most faithful way to exercise it -- it is also exactly how a
    service manager or Ctrl-C would actually reach this process.
    """

    def test_keyboard_interrupt_flushes_and_reports_then_exits_cleanly(
        self, capsys, monkeypatch
    ):
        def raise_interrupt(*_args, **_kwargs):
            raise KeyboardInterrupt

        monkeypatch.setattr(cli, "run", raise_interrupt)
        assert cli.main(["-r", str(FIXTURES / "udp_dns.pcap")]) == 0
        err = capsys.readouterr().err
        assert "[!] Capture aborted." in err
        assert "frames/s" in err  # stats were reported: outputs flushed

    def _send_sigterm_shortly(self) -> None:
        threading.Timer(
            0.05, os.kill, args=(os.getpid(), signal.SIGTERM)
        ).start()

    def test_sigterm_flushes_and_reports_then_exits_cleanly(
        self, capsys, monkeypatch
    ):
        monkeypatch.setattr(capture_mod, "socket", _FakeSocket)
        self._send_sigterm_shortly()

        assert cli.main(["-i", "eth0"]) == 0

        err = capsys.readouterr().err
        assert "[!] Terminated." in err
        assert "[!] Capture aborted." not in err
        assert "frames/s" in err  # stats were reported: outputs flushed

    def test_sigterm_handler_is_restored_after_main_returns(self, monkeypatch):
        monkeypatch.setattr(capture_mod, "socket", _FakeSocket)
        original_handler = signal.getsignal(signal.SIGTERM)
        self._send_sigterm_shortly()

        cli.main(["-i", "eth0"])

        assert signal.getsignal(signal.SIGTERM) is original_handler

    def test_sigterm_still_flushes_a_pcap_writer(self, monkeypatch, tmp_path):
        monkeypatch.setattr(capture_mod, "socket", _FakeSocket)
        out = tmp_path / "out.pcap"
        self._send_sigterm_shortly()

        assert cli.main(["-i", "eth0", "-w", str(out)]) == 0

        # PcapWriter's global header is 24 bytes and no frame was ever
        # captured (SIGTERM lands before the fake socket ever becomes
        # readable). Seeing exactly 24 bytes on disk proves close() ran
        # and flushed the writer, rather than the process exiting with
        # the write still sitting in an unflushed buffer.
        assert out.stat().st_size == 24
