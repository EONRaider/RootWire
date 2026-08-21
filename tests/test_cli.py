import pytest

from packet_sniffer import __version__
from packet_sniffer.cli import build_parser


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
