import shutil

import pytest

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
