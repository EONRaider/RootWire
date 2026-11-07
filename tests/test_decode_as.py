"""``--decode-as``: parsing an override, applying it to the walk, and the
best-effort rule for the classes it maps to a port.

NETProtocols registers HTTP on no port and TFTP's replies leave port 69,
so ``tests/fixtures/http/http.pcap`` (vendored with NETProtocols 2.9.0;
see fixtures/MANIFEST.md) and ``tftp.pcap`` are what this flag is for:
the first decodes HTTP only when told to, the second follows a transfer
past its request.
"""

from __future__ import annotations

import pytest
from netprotocols import DNS, HTTP, TFTP, UDP, IPv4
from netprotocols.registry import WITHHELD

from conftest import FIXTURES, read_pcap
from rootwire import cli
from rootwire.decode_as import DecodeAsError, decoder_names, parse_decode_as
from rootwire.decoder import decode_frame, decode_options

HTTP_PCAP = FIXTURES / "http" / "http.pcap"

#: The server's transfer ID of the first transfer in tftp.pcap: the
#: port it answers the RRQ for boot.bin from.
_TFTP_SERVER_TID = 43394


def decode_all(path, options):
    """Every frame of the capture at *path*, decoded with *options*."""
    return [
        decode_frame(
            data, number=i, timestamp=0, interface=None, options=options
        )
        for i, data in enumerate(read_pcap(path), 1)
    ]


# --- parsing ---------------------------------------------------------------


def test_parse_one_override() -> None:
    """The example in the help text parses to the library's form."""
    assert parse_decode_as(["udp.port=40000:TFTP"]) == {
        "udp.port": {40000: TFTP}
    }


def test_parse_hex_key_any_case_and_several_tables() -> None:
    """A key in any base ``int(x, 0)`` reads, a class name in any case,
    and overrides for several tables in one set."""
    overrides = parse_decode_as(
        ["tcp.port=0x1f90:http", "udp.port=5353:dns", "udp.port=6969:DNS"]
    )
    assert overrides == {
        "tcp.port": {8080: HTTP},
        "udp.port": {5353: DNS, 6969: DNS},
    }


def test_parse_none_withholds() -> None:
    """``none`` maps a key to WITHHELD, in any case."""
    assert parse_decode_as(["udp.port=1812:None"]) == {
        "udp.port": {1812: WITHHELD}
    }


def test_parse_nothing_is_empty() -> None:
    """No flag, no overrides."""
    assert parse_decode_as([]) == {}


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ("udp.port:40000=TFTP", "expected TABLE=KEY:CLASS"),
        ("udp.port=40000", "expected TABLE=KEY:CLASS"),
        ("=40000:TFTP", "expected TABLE=KEY:CLASS"),
        ("udp.port=:TFTP", "expected TABLE=KEY:CLASS"),
        ("udp.port=40000:", "expected TABLE=KEY:CLASS"),
        ("sctp.port=1:TFTP", "unknown table 'sctp.port'"),
        ("udp.port=forty:TFTP", "key 'forty' is not an integer"),
        ("udp.port=65536:TFTP", "outside udp.port's range 0-0xffff"),
        ("udp.port=-1:TFTP", "outside udp.port's range"),
        ("ip.proto=256:TFTP", "outside ip.proto's range 0-0xff"),
        ("llc.snap=0x10000000000:SNAP", "outside llc.snap's range"),
        ("udp.port=1:Nope", "unknown decoder 'Nope'"),
        ("udp.port=1:Protocol", "unknown decoder 'Protocol'"),
    ],
)
def test_parse_rejects(spec: str, message: str) -> None:
    """Each malformed value is refused with a message naming it."""
    with pytest.raises(DecodeAsError, match="--decode-as") as caught:
        parse_decode_as([spec])
    assert message in str(caught.value)


def test_parse_rejects_a_key_given_twice() -> None:
    """The same table and key twice is an error, not last-wins."""
    with pytest.raises(DecodeAsError, match=r"udp\.port key 69 is given twice"):
        parse_decode_as(["udp.port=69:TFTP", "udp.port=0x45:none"])


def test_decoder_names_are_the_exported_protocols() -> None:
    """The accepted names are NETProtocols' decoders, Protocol excluded."""
    names = decoder_names()
    assert {"HTTP", "TFTP", "AHv6", "DNSOverTCP"} <= set(names)
    assert "Protocol" not in names
    assert names == sorted(names)


# --- decode options --------------------------------------------------------


def test_default_options_do_not_decode_http() -> None:
    """Without an override, port 80 ends the walk at TCP."""
    frames = decode_all(HTTP_PCAP, decode_options())
    assert not any(frame.layer(HTTP) for frame in frames)


def test_http_mapped_to_a_port_is_best_effort() -> None:
    """Every bare ACK and every response body segment on port 80 reaches
    the HTTP decoder: those are misses, not malformed frames."""
    options = decode_options({"tcp.port": {80: HTTP}})
    assert HTTP in options.best_effort
    frames = decode_all(HTTP_PCAP, options)
    assert sum(1 for frame in frames if frame.layer(HTTP)) == 8
    assert all(frame.error is None for frame in frames)
    assert any(frame.l7_miss for frame in frames)


def test_a_typed_class_mapped_to_a_port_is_not_best_effort() -> None:
    """Mapping a port to IPv4 must not make every IPv4 fault a miss: the
    rule matches on the class, so a class a type field also reaches is
    left out."""
    options = decode_options({"udp.port": {4000: IPv4}})
    assert IPv4 not in options.best_effort


def test_dns_stays_out_of_the_best_effort_set() -> None:
    """DNS on an extra port keeps DNS's rule: its faults are signal."""
    assert DNS not in decode_options({"udp.port": {6969: DNS}}).best_effort


def test_withheld_port_ends_the_walk() -> None:
    """``udp.port=69:none`` stops a TFTP request at UDP."""
    options = decode_options({"udp.port": {69: WITHHELD}})
    first = decode_all(FIXTURES / "tftp.pcap", options)[0]
    assert isinstance(first.layers[-1], UDP)
    assert first.error is None


def test_tftp_transfer_followed_by_its_server_tid() -> None:
    """Naming the server's transfer ID decodes the whole transfer, both
    directions, not just the request to port 69."""
    plain = decode_all(FIXTURES / "tftp.pcap", decode_options())
    followed = decode_all(
        FIXTURES / "tftp.pcap",
        decode_options({"udp.port": {_TFTP_SERVER_TID: TFTP}}),
    )
    assert sum(1 for f in followed if f.layer(TFTP)) > sum(
        1 for f in plain if f.layer(TFTP)
    )
    assert all(frame.error is None for frame in followed)


# --- the CLI ---------------------------------------------------------------


def test_cli_http_capture_renders_every_message(capsys) -> None:
    """End to end: the flag reaches the decoder, every one of the eight
    whole messages renders, and no frame reads as malformed."""
    assert (
        cli.main(["-r", str(HTTP_PCAP), "--decode-as", "tcp.port=80:HTTP"]) == 0
    )
    out, err = capsys.readouterr()
    assert out.count("[+] HTTP ") == 8
    assert "Malformed" not in out
    assert "malformed:" not in err


def test_cli_without_the_flag_shows_no_http(capsys) -> None:
    """The same capture without the flag has no HTTP layer at all."""
    assert cli.main(["-r", str(HTTP_PCAP)]) == 0
    assert "[+] HTTP " not in capsys.readouterr().out


def test_cli_json_serializes_http(capsys) -> None:
    """``--json`` carries the HTTP layers with no unencodable warning."""
    argv = ["-r", str(HTTP_PCAP), "--json", "--decode-as", "tcp.port=80:HTTP"]
    assert cli.main(argv) == 0
    out, err = capsys.readouterr()
    assert out.count('"type":"HTTP"') == 8
    assert "[!]" not in err


def test_cli_bad_value_is_a_usage_error(capsys) -> None:
    """A bad value exits 2 with argparse's usage message."""
    with pytest.raises(SystemExit) as caught:
        cli.main(["-r", str(HTTP_PCAP), "--decode-as", "tcp.port=80"])
    assert caught.value.code == 2
    err = capsys.readouterr().err
    assert "usage:" in err
    assert "expected TABLE=KEY:CLASS" in err


def test_cli_registry_refusal_is_a_usage_error(capsys, monkeypatch) -> None:
    """Whatever the registry itself refuses when deriving is reported
    the same way, not as a traceback."""

    def refuse(_overrides):
        """Stand in for decode_options, refusing as derive can."""
        raise TypeError("decode_as maps a key to None")

    monkeypatch.setattr(cli, "decode_options", refuse)
    with pytest.raises(SystemExit) as caught:
        cli.main(["-r", str(HTTP_PCAP)])
    assert caught.value.code == 2
    assert "maps a key to None" in capsys.readouterr().err
