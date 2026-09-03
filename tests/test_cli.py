import shutil
import signal

import pytest

import rootwire.capture as capture_mod
from conftest import FIXTURES
from rootwire import __version__, cli
from rootwire.cli import build_parser


class TestCLI:
    def test_defaults(self):
        args = build_parser().parse_args([])
        assert args.interface is None
        assert args.data is False

    def test_interface_and_data_flags(self):
        args = build_parser().parse_args(["-i", "eth0", "-d"])
        assert args.interface == "eth0"
        assert args.data is True

    def test_version(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            build_parser().parse_args(["--version"])
        assert excinfo.value.code == 0
        assert __version__ in capsys.readouterr().out


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


class _SignalDeliveringSocket:
    """Fake capture socket whose recv() simulates real SIGTERM delivery
    by invoking whatever handler main() currently has installed for it
    (fetched dynamically via signal.getsignal), instead of blocking.

    This exercises the exact function main() registers and the exact
    exception-propagation path a live interruption would take — through
    capture()'s generator, out of recv(), through run()'s loop — without
    sending a real signal to the test process.
    """

    def __init__(self, *args: int) -> None:
        pass

    def bind(self, address: tuple[str, int]) -> None:
        pass

    def recv(self, size: int) -> bytes:
        handler = signal.getsignal(signal.SIGTERM)
        if not callable(handler):
            raise AssertionError(
                "main() did not install a callable SIGTERM handler"
            )
        handler(signal.SIGTERM, None)
        raise AssertionError("SIGTERM handler returned instead of raising")

    def __enter__(self) -> "_SignalDeliveringSocket":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


class TestAbortHandling:
    """Ctrl-C (KeyboardInterrupt) and a service manager's SIGTERM both
    abort main()'s capture loop through the same shutdown path: flush
    outputs, report stats, exit 0."""

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

    def test_sigterm_flushes_and_reports_then_exits_cleanly(
        self, capsys, monkeypatch
    ):
        monkeypatch.setattr(
            capture_mod, "socket", lambda *args: _SignalDeliveringSocket()
        )
        assert cli.main(["-i", "eth0"]) == 0
        err = capsys.readouterr().err
        assert "[!] Terminated." in err
        assert "[!] Capture aborted." not in err
        assert "frames/s" in err  # stats were reported: outputs flushed

    def test_sigterm_handler_is_restored_after_main_returns(self, monkeypatch):
        monkeypatch.setattr(
            capture_mod, "socket", lambda *args: _SignalDeliveringSocket()
        )
        original_handler = signal.getsignal(signal.SIGTERM)
        cli.main(["-i", "eth0"])
        assert signal.getsignal(signal.SIGTERM) is original_handler

    def test_sigterm_still_flushes_a_pcap_writer(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            capture_mod, "socket", lambda *args: _SignalDeliveringSocket()
        )
        out = tmp_path / "out.pcap"
        assert cli.main(["-i", "eth0", "-w", str(out)]) == 0
        # PcapWriter's global header is 24 bytes and no frame was ever
        # captured (the fake socket raises on its first recv). Seeing
        # exactly 24 bytes on disk proves close() ran and flushed the
        # writer, rather than the process exiting with the write still
        # sitting in an unflushed buffer.
        assert out.stat().st_size == 24
