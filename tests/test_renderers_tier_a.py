"""Tier A screen renderers (TLS, SCTP, NTP), the TLS SNI peek, SCTP in
the statistics, and the NDJSON fallback warning.

Real corpus frames carry the happy paths; crafted frames cover what a
corpus never holds on purpose: attacker-chosen text that must reach the
terminal escaped (C1), lazily parsed sections that turn out malformed
(C2), and amplification-shaped input such as hundreds of SCTP chunks.
"""

from __future__ import annotations

import io
import json

import pytest
from netprotocols import NTP, SCTP, UDP, Packet, Protocol

from conftest import FIXTURES, _eth, _ipv4, read_pcap
from rootwire.decoder import decode_frame
from rootwire.frame import DecodedFrame
from rootwire.output import (
    _LIST_LIMIT,
    OutputToNDJSON,
    OutputToScreen,
    StatsCollector,
    _json_default,
)

_SNI = b"tls.np196.test"
#: Same length as _SNI, so patching it in keeps every length field true.
_HOSTILE_SNI = b"\x1b[2Jevil.tests"
assert len(_HOSTILE_SNI) == len(_SNI)


def decode(data: bytes) -> DecodedFrame:
    """Decode *data* as frame 1 of a capture on ``eth0``."""
    return decode_frame(data, number=1, timestamp=0, interface="eth0")


def render(data: bytes) -> str:
    """Screen rendering of *data*, payload display off."""
    stream = io.StringIO()
    OutputToScreen(display_payload=False, stream=stream).update(decode(data))
    return stream.getvalue()


def corpus(name: str, index: int) -> bytes:
    """Frame *index* of the vendored capture *name*."""
    return read_pcap(FIXTURES / name)[index]


def ndjson(data: bytes) -> dict[str, object]:
    """The NDJSON record for *data*, parsed."""
    stream = io.StringIO()
    OutputToNDJSON(stream).update(decode(data))
    record = json.loads(stream.getvalue())
    assert isinstance(record, dict)
    return record


def tcp_payload_frame(port: int, payload: bytes) -> bytes:
    """Ethernet/IPv4/TCP to *port* carrying *payload*; checksums are
    the library's own, so no unrelated mismatch note appears."""
    from netprotocols import TCP

    tcp = TCP(
        src_port=50000,
        dst_port=port,
        seq=1,
        ack=1,
        data_offset=5,
        reserved=0,
        flags=0x018,
        window=512,
        checksum=0,
        urgent_pointer=0,
    )
    ip = _ipv4(protocol=6, total_length=40 + len(payload))
    packet = Packet(_eth(0x0800), ip, tcp).with_checksums(payload)
    return bytes(packet) + payload


def udp_frame(port: int, upper: Protocol) -> bytes:
    """Ethernet/IPv4/UDP to *port* carrying *upper*, checksummed."""
    body = bytes(upper)
    udp = UDP(src_port=50000, dst_port=port, length=8 + len(body), checksum=0)
    ip = _ipv4(protocol=17, total_length=28 + len(body))
    return bytes(Packet(_eth(0x0800), ip, udp, upper).with_checksums())


class TestTLSRenderer:
    def test_client_hello_shows_what_an_analyst_triages_on(self):
        text = render(corpus("tls.pcap", 2))
        assert "[+] TLS handshake (client_hello) | TLS 1.0 | 512 bytes" in text
        assert "ClientHello: TLS 1.2 | SNI: tls.np196.test" in text
        assert "Cipher suites: 31" in text
        assert "Extensions: server_name, ec_point_formats" in text

    def test_one_line_per_record_in_a_multi_record_segment(self):
        text = render(corpus("tls.pcap", 0))
        assert text.count("[+] TLS ") == 6
        assert "server_hello" in text
        assert "change_cipher_spec | TLS 1.2 | 1 byte\n" in text

    def test_hostile_sni_is_escaped(self):
        """C1: SNI is ASCII by the library's check, but ESC is ASCII."""
        data = corpus("tls.pcap", 2).replace(_SNI, _HOSTILE_SNI)
        text = render(data)
        assert "\x1b" not in text
        assert "SNI: \\x1b[2Jevil.tests" in text

    def test_malformed_client_hello_is_contained(self):
        """C2: a Handshake record starting with type 1 parses as a
        ClientHello on demand; one too short to be one renders a [!]
        line instead of raising out of the renderer."""
        record = bytes.fromhex("16030300050100001000")
        text = render(tcp_payload_frame(443, record))
        assert "[+] TLS handshake (client_hello)" in text
        assert "[!] ClientHello malformed:" in text

    def test_client_hello_without_extensions(self):
        """TLS 1.2 and earlier allow a ClientHello with no extensions
        block: SNI and the extension list read 'none'."""
        body = (
            bytes.fromhex("0303")
            + bytes(32)  # random
            + b"\x00"  # empty session ID
            + bytes.fromhex("0002c02f")  # one cipher suite
            + b"\x01\x00"  # null compression only
        )
        handshake = b"\x01" + len(body).to_bytes(3, "big") + body
        record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
        text = render(tcp_payload_frame(443, record))
        assert "SNI: none | Cipher suites: 1" in text
        assert "Extensions: none" in text
        assert "[!]" not in text


class TestSNIPeek:
    """A ClientHello larger than one segment (Chromium's) is a TLS miss;
    its host name is still read from the first segment."""

    def test_split_client_hello_yields_its_server_name(self):
        frame = decode(corpus("tls_session.pcap", 3))
        assert frame.l7_miss is not None
        assert frame.error is None
        assert frame.sni_peek == "tls.np196.test"
        text = render(corpus("tls_session.pcap", 3))
        assert (
            "[+] TLS ClientHello (continues in a later segment) "
            "SNI: tls.np196.test"
        ) in text

    def test_name_past_the_first_segment_is_not_reached(self):
        """Frame 15's ClientHello puts server_name after its first 1448
        bytes: 'not reached' is not 'no SNI', and nothing is shown."""
        frame = decode(corpus("tls_session.pcap", 15))
        assert frame.l7_miss is not None
        assert frame.sni_peek is None

    def test_continuation_segment_peeks_nothing(self):
        """The second half of a split ClientHello starts mid-record; the
        peek raises inside, which is contained."""
        frame = decode(corpus("tls_session.pcap", 4))
        assert frame.l7_miss is not None and frame.sni_peek is None

    def test_hostile_peeked_sni_is_escaped(self):
        data = corpus("tls_session.pcap", 3).replace(_SNI, _HOSTILE_SNI)
        assert decode(data).sni_peek == _HOSTILE_SNI.decode()
        text = render(data)
        assert "\x1b" not in text
        assert "SNI: \\x1b[2Jevil.tests" in text

    def test_only_tls_misses_are_peeked(self):
        """The same ClientHello prefix on BGP's port is a BGP miss; the
        peek is TLS's alone."""
        prefix = corpus("tls_session.pcap", 3)[66:]
        frame = decode(tcp_payload_frame(179, prefix))
        assert frame.l7_miss is not None
        assert frame.sni_peek is None

    def test_whole_client_hello_is_not_peeked(self):
        """A ClientHello that fits decodes as a TLS layer, which carries
        the name itself; sni_peek stays None."""
        frame = decode(corpus("tls.pcap", 2))
        assert frame.l7_miss is None and frame.sni_peek is None

    def test_peek_reaches_ndjson(self):
        assert ndjson(corpus("tls_session.pcap", 3))["sni_peek"] == (
            "tls.np196.test"
        )
        assert ndjson(corpus("tls.pcap", 2))["sni_peek"] is None


def sctp_frame(chunks: bytes) -> bytes:
    """Ethernet/IPv4/SCTP carrying raw *chunks*, CRC32c filled in."""
    sctp = SCTP(
        src_port=40000,
        dst_port=7,
        verification_tag=0x01020304,
        checksum=0,
        chunks=chunks,
    )
    ip = _ipv4(protocol=132, total_length=20 + sctp.header_len)
    return bytes(Packet(_eth(0x0800), ip, sctp).with_checksums())


class TestSCTPRenderer:
    def test_data_chunk_with_flags(self):
        text = render(corpus("sctp.pcap", 4))
        assert "[+] SCTP 54770 -> 7" in text
        assert "Verification Tag: 0x3aca38f7" in text
        assert "Chunks: DATA [B E]" in text
        assert "mismatch" not in text

    def test_unknown_chunk_type(self):
        assert "Chunks: unknown (63)" in render(corpus("sctp.pcap", 15))

    def test_bad_crc32c_is_flagged(self):
        """The checksum is the last 4 bytes of the 12-byte common header,
        at frame offset 14 + 20 + 8."""
        data = bytearray(corpus("sctp.pcap", 4))
        data[42] ^= 0xFF
        assert "[!] mismatch (expected 0x" in render(bytes(data))

    def test_chunk_list_is_capped(self):
        """Hundreds of 4-byte chunks fit one packet; the line names the
        first _LIST_LIMIT and summarizes the rest."""
        count = _LIST_LIMIT + 24
        text = render(sctp_frame(b"\x7e\x00\x00\x04" * count))
        assert f"(+{count - _LIST_LIMIT} more)" in text
        assert text.count("unknown (126)") == _LIST_LIMIT

    def test_malformed_chunks_are_contained(self):
        """A chunk declaring 16 bytes with 4 present: the header decodes
        (the remainder is kept verbatim), parsing chunks raises."""
        text = render(sctp_frame(b"\x00\x00\x00\x10"))
        assert "[+] SCTP 40000 -> 7" in text
        assert "[!] Chunks malformed:" in text

    def test_sctp_has_its_own_stats_bucket(self):
        stats = StatsCollector()
        for data in read_pcap(FIXTURES / "sctp.pcap"):
            stats.update(decode(data))
        stream = io.StringIO()
        stats.report(stream)
        assert "SCTP: 16" in stream.getvalue()


def ntp_message(*, stratum: int, reference_id: int, mode: int = 4) -> NTP:
    """A bare 48-byte NTPv4 message with the given stratum and
    Reference ID."""
    return NTP(
        leap=0,
        version=4,
        mode=mode,
        stratum=stratum,
        poll=6,
        precision=-20,
        root_delay=0,
        root_dispersion=0,
        reference_id=reference_id,
        reference_timestamp=0,
        origin_timestamp=0,
        receive_timestamp=0,
        transmit_timestamp=0,
        body=b"",
    )


class TestNTPRenderer:
    def test_symmetric_mac_is_shown(self):
        text = render(corpus("ntp.pcap", 2))
        assert "[+] NTP v4 client | Stratum 0" in text
        assert "MAC: key 1, 16-byte digest" in text

    def test_nts_extension_fields(self):
        text = render(corpus("ntp.pcap", 10))
        assert "Extension fields: Unique Identifier (32 bytes)" in text
        assert "NTS Cookie (64 bytes)" in text

    def test_reference_id_from_stratum_two(self):
        text = render(corpus("ntp.pcap", 14))
        assert "NTP v4 symmetric active | Stratum 9 (secondary server)" in text
        assert "Reference ID: 10.9.191.1" in text
        assert "Transmit: 2026-10-31T09:15:35" in text

    def test_kiss_code(self):
        rate = int.from_bytes(b"RATE", "big")
        text = render(udp_frame(123, ntp_message(stratum=0, reference_id=rate)))
        assert "Kiss code: RATE" in text

    def test_hostile_reference_id_never_reaches_the_terminal_raw(self):
        """C1: a stratum-1 Reference ID is ASCII the sender chose; ESC
        must not reach the terminal whichever accessor carries it."""
        hostile = int.from_bytes(b"\x1b[2J", "big")
        for stratum in (0, 1):
            frame = udp_frame(
                123, ntp_message(stratum=stratum, reference_id=hostile)
            )
            assert "\x1b" not in render(frame)


class TestNDJSONFallbackWarning:
    def test_unknown_type_warns_once_on_stderr(self, capsys):
        class Novel:
            def __str__(self) -> str:
                return "novel"

        assert _json_default(Novel()) == "novel"
        assert _json_default(Novel()) == "novel"
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.count("no JSON encoding for") == 1
        assert "Novel" in captured.err

    @pytest.mark.parametrize("value", [b"\x00", frozenset({1})])
    def test_known_types_do_not_warn(self, value, capsys):
        _json_default(value)
        assert capsys.readouterr().err == ""
