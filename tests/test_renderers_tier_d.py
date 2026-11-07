"""Tier D screen renderers: the tunnels and IPsec headers VXLAN, ESP and
AH (AHv6 too), and the UDP applications TFTP, RADIUS and STUN.

Real corpus frames carry the happy paths (``vxlan.pcap``, ``esp.pcap``,
``ah.pcap``, ``tftp.pcap``, ``radius.pcap`` and ``stun.pcap``; see
fixtures/MANIFEST.md). Crafted frames cover what no capture holds on
purpose: sender-chosen text carrying terminal escapes, newlines and
bidi overrides (C1), attribute lists that only fail when a renderer
asks for them (C2), the TFTP replies a stateless walk reaches only from
port 69, AH in an IPv6 chain, and FINGERPRINTs that are wrong or out of
place.
"""

from __future__ import annotations

import io
import struct

import pytest
from netprotocols import (
    AH,
    ESP,
    RADIUS,
    STUN,
    TFTP,
    UDP,
    VXLAN,
    AHv6,
    Ethernet,
    IPv6,
    Packet,
    Protocol,
    RADIUSAttribute,
    STUNAttribute,
)

from conftest import FIXTURES, read_pcap
from rootwire.decoder import decode_frame
from rootwire.frame import DecodedFrame
from rootwire.output import _LIST_LIMIT, _TEXT_LIMIT, OutputToScreen
from test_renderers_tier_a import udp_frame

#: The six classes this module renders; none may fall back to the
#: "(no renderer)" line anywhere in their captures.
_TIER_D = (VXLAN, ESP, AH, TFTP, RADIUS, STUN)

#: An ESC-led sequence that clears the screen, and the right-to-left
#: override that reorders what follows it: both must reach the
#: terminal escaped. Written as escapes, never as the characters.
_ESC = "\x1b[2J"
_BIDI = "\u202e"

_TFTP_PORT = 69
_RADIUS_PORT = 1812
_STUN_PORT = 3478
_IPPROTO_AH = 51
_IPPROTO_UDP = 17


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


def patched(name: str, index: int, old: bytes, new: bytes) -> bytes:
    """Frame *index* of *name* with *old* replaced by *new*, the same
    length, so every length field stays true."""
    assert len(old) == len(new)
    frame = corpus(name, index)
    assert frame.count(old) == 1
    return frame.replace(old, new)


def walks_to(data: bytes, cls: type[Protocol]) -> bytes:
    """*data*, after checking that its walk reaches a *cls* layer:
    construction is laxer than decoding, so a crafted frame proves
    nothing until the walk is seen to decode it."""
    assert any(type(layer) is cls for layer in decode(data).layers)
    return data


def tftp_frame(opcode: int, body: bytes) -> bytes:
    """A TFTP message to port 69, which a stateless walk dispatches
    whatever the opcode (see the TFTP module docstring)."""
    return walks_to(udp_frame(_TFTP_PORT, TFTP(opcode=opcode, body=body)), TFTP)


def radius_frame(code: int, attributes: bytes) -> bytes:
    """A RADIUS packet to port 1812 carrying the raw *attributes*."""
    packet = RADIUS(
        code=code,
        identifier=42,
        length=20 + len(attributes),
        authenticator=bytes(range(16)),
        attributes=attributes,
    )
    return walks_to(udp_frame(_RADIUS_PORT, packet), RADIUS)


def stun_frame(*attributes: STUNAttribute, raw: bytes = b"") -> bytes:
    """A STUN Binding Success Response to port 3478 carrying
    *attributes*, then the raw bytes *raw*."""
    body = b"".join(map(bytes, attributes)) + raw
    message = STUN(
        message_type=0x0101,
        magic_cookie=STUN.MAGIC_COOKIE,
        transaction_id=bytes(range(12)),
        attributes=body,
    )
    return walks_to(udp_frame(_STUN_PORT, message), STUN)


def assert_escaped(text: str) -> None:
    """*text* holds no raw ESC or bidi override, and no forged line."""
    assert "\x1b" not in text
    assert _BIDI not in text
    assert "\\x1b[2J" in text
    assert "\n[!]" not in text


# --- corpus-wide -----------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "vxlan.pcap",
        "esp.pcap",
        "ah.pcap",
        "ipip.pcap",
        "tftp.pcap",
        "radius.pcap",
        "stun.pcap",
        "stun_rfc3489.pcap",
    ],
)
def test_corpus_frames_render_without_fallback_or_fault(name: str) -> None:
    """Every frame of each capture renders through a registered
    renderer, with no guard tripping and no checksum flagged -- the
    inner layers of a tunnel included."""
    for index, raw in enumerate(read_pcap(FIXTURES / name)):
        text = render(raw)
        assert "(no renderer)" not in text, (name, index)
        assert "malformed:" not in text, (name, index)
        assert "mismatch" not in text, (name, index)
        assert "[!]" not in text, (name, index)
        if name == "stun.pcap":
            # Every frame here is RFC 8489 STUN: none may regress to a
            # best-effort miss, which the checks above would let pass.
            assert "[+] STUN " in text, (name, index)


# --- VXLAN -----------------------------------------------------------------


def test_vxlan_vni_and_inner_frame() -> None:
    """VXLAN shows its VNI and the I flag; the inner Ethernet frame
    renders as layers of its own."""
    text = render(corpus("vxlan.pcap", 2))
    assert "[+] VXLAN VNI 1193046 | Flags 0x08 (I)\n" in text
    assert "[+] ICMPv4 10.9.13.1 -> 10.9.13.2" in text
    assert "Reserved bits" not in text


def test_vxlan_reserved_bits_are_noted() -> None:
    """Reserved bits that are set, which RFC 7348 sends as zero, are
    noted, not flagged: receivers ignore them."""
    frame = patched(
        "vxlan.pcap",
        2,
        bytes.fromhex("0800000012345600"),
        bytes.fromhex("0c00000112345602"),
    )
    text = render(frame)
    assert "[+] VXLAN VNI 1193046 | Flags 0x0c (I)" in text
    assert (
        "[~] Reserved bits set: flags 0x04, 0x000001, 0x02 "
        "(zero on transmit, RFC 7348 §5)"
    ) in text


# --- ESP and AH ------------------------------------------------------------


def test_esp_spi_sequence_and_protected_size() -> None:
    """ESP shows what it sends in the clear and the protected size."""
    text = render(corpus("esp.pcap", 3))
    assert "[+] ESP SPI 0x10000002 | Seq 1\n" in text
    assert "Protected payload: 72 bytes (IV, data, padding" in text


def test_ah_transport_mode() -> None:
    """AH in transport mode names what it protects, which renders on."""
    text = render(corpus("ah.pcap", 0))
    assert "[+] AH SPI 0x20000001 | Seq 1 | Next: TCP\n" in text
    assert "ICV: 16 bytes (not verified) | Header: 28 bytes" in text
    assert "[+] TCP 40001 -> 80" in text


def test_ah_tunnel_mode_and_esp_inside() -> None:
    """AH carrying a whole IPv4 packet is tunnel mode; AH carrying ESP
    hands the walk to ESP."""
    tunnel = render(corpus("ah.pcap", 3))
    assert "Next: IPv4 encapsulation (tunnel mode)" in tunnel
    assert "[+] IPv4 192.0.2.1 -> 192.0.2.2" in tunnel
    nested = render(corpus("ah.pcap", 5))
    assert "Next: ESP\n" in nested
    assert "[+] ESP SPI 0x10000003 | Seq 1" in nested


def test_ahv6_dispatches_to_the_ah_renderer() -> None:
    """AHv6 subclasses AH, so it renders through the same method; the
    UDP checksum behind it still verifies against the IPv6 header."""
    udp = UDP(src_port=40000, dst_port=9, length=8, checksum=0)
    ah = AHv6(
        next_header=_IPPROTO_UDP,
        payload_len=4,
        reserved=0,
        spi=0x30000001,
        sequence_number=9,
        icv=bytes(12),
    )
    ip = IPv6(
        version=6,
        traffic_class=0,
        flow_label=0,
        payload_length=len(bytes(ah)) + 8,
        next_header=_IPPROTO_AH,
        hop_limit=64,
        src="2001:db8::1",
        dst="2001:db8::2",
    )
    eth = Ethernet(
        dst="02:00:00:00:00:02", src="02:00:00:00:00:01", ethertype=0x86DD
    )
    frame = bytes(Packet(eth, ip, ah, udp).with_checksums())
    text = render(walks_to(frame, AHv6))
    assert "[+] AH SPI 0x30000001 | Seq 9 | Next: UDP\n" in text
    assert "ICV: 12 bytes (not verified) | Header: 24 bytes" in text
    assert "[+] UDP 40000 -> 9" in text
    assert "mismatch" not in text


# --- TFTP ------------------------------------------------------------------


def test_tftp_requests() -> None:
    """RRQ and WRQ show the filename and mode; options get a line."""
    assert "[+] TFTP RRQ boot.bin (octet)\n" in render(corpus("tftp.pcap", 0))
    assert "[+] TFTP WRQ upload.bin (octet)\n" in render(
        corpus("tftp.pcap", 14)
    )
    text = render(corpus("tftp.pcap", 26))
    assert "Options: tsize=0, blksize=1024, timeout=6" in text


def test_tftp_data_ack_and_oack() -> None:
    """DATA shows its block and size, ACK its block, OACK its options."""
    data = render(tftp_frame(3, b"\x00\x07" + b"x" * 512))
    assert "[+] TFTP DATA block 7 (512 bytes)\n" in data
    assert "[+] TFTP ACK block 7\n" in render(tftp_frame(4, b"\x00\x07"))
    oack = render(tftp_frame(6, b"blksize\x001428\x00tsize\x004096\x00"))
    assert "[+] TFTP OACK\n" in oack
    assert "Options: blksize=1428, tsize=4096" in oack


def test_tftp_error() -> None:
    """ERROR shows the code, its name and the message."""
    text = render(tftp_frame(5, b"\x00\x01no such file\x00"))
    assert "[+] TFTP ERROR 1 (File not found): no such file\n" in text


def test_tftp_filename_is_sanitized_and_one_line() -> None:
    """C1: a filename carrying ESC and a newline cannot repaint the
    terminal or start a forged line."""
    frame = patched("tftp.pcap", 0, b"boot.bin", (_ESC + "\n[!]").encode())
    text = render(frame)
    assert_escaped(text)
    assert "[+] TFTP RRQ \\x1b[2J\\n[!] (octet)" in text


def test_tftp_error_message_is_sanitized_and_one_line() -> None:
    """C1: an ERROR's message is the sender's; ESC and a newline stay
    escaped, and a bidi override (not ASCII) reads as its bytes."""
    message = (_ESC + "\n[!] x" + _BIDI).encode()
    text = render(tftp_frame(5, b"\x00\x02" + message + b"\x00"))
    assert_escaped(text)
    assert "(Access violation): \\x1b[2J\\n[!] x\\xe2\\x80\\xae\n" in text


def test_tftp_mode_and_options_are_sanitized() -> None:
    """C1: the mode and an option's name and value are the client's."""
    body = f"f\x00oct{_ESC}\x00bl\nk\x00{_ESC}\x00".encode()
    text = render(tftp_frame(1, body))
    assert_escaped(text)
    assert "[+] TFTP RRQ f (oct\\x1b[2J)" in text
    assert "Options: bl\\nk=\\x1b[2J" in text


def test_tftp_long_filename_and_option_are_cut() -> None:
    """A filename and an option value are cut at the text limit."""
    long = b"f" * (_TEXT_LIMIT + 9)
    text = render(
        tftp_frame(1, long + b"\x00octet\x00blksize\x00" + long + b"\x00")
    )
    assert f"RRQ {'f' * _TEXT_LIMIT}... (+9 more chars) (octet)" in text
    assert f"blksize={'f' * _TEXT_LIMIT}... (+9 more chars)" in text


def test_tftp_options_are_capped() -> None:
    """A request with more options than the list limit is capped."""
    options = b"".join(b"o%d\x001\x00" % n for n in range(_LIST_LIMIT + 3))
    text = render(tftp_frame(1, b"f\x00octet\x00" + options))
    assert "(+3 more)" in text


# --- RADIUS ----------------------------------------------------------------


def test_radius_access_request() -> None:
    """An Access-Request: the header, the Authenticator, the User-Name
    on its own line, and the password by size only."""
    text = render(corpus("radius.pcap", 0))
    assert "[+] RADIUS Access-Request (ID 185) | Length 80\n" in text
    assert "Authenticator: 04030a2a7ae4755f03f6bdd3d857bd3f\n" in text
    assert "User-Name: np193-user\n" in text
    assert (
        "Attributes: Message-Authenticator (16 bytes), User-Password "
        "(16 bytes), NAS-IP-Address 10.9.193.2, NAS-Port 7\n"
    ) in text


def test_radius_reply_and_accounting_text_attributes() -> None:
    """Reply-Message and Acct-Session-Id are text, shown as such."""
    accept = render(corpus("radius.pcap", 1))
    assert "Reply-Message: np193 test user\n" in accept
    assert "Framed-IP-Address 10.9.193.50" in accept
    accounting = render(corpus("radius.pcap", 6))
    assert "Acct-Session-Id: np193-0001\n" in accounting
    assert "Acct-Status-Type (4 bytes)" in accounting


def test_radius_without_attributes_has_no_attribute_line() -> None:
    """An Accounting-Response with no attributes ends at its header."""
    text = render(corpus("radius.pcap", 7))
    assert "[+] RADIUS Accounting-Response (ID 33) | Length 20" in text
    assert "Attributes:" not in text


def test_radius_user_name_is_sanitized_and_one_line() -> None:
    """C1: the User-Name is the user's; ESC, a newline and a bidi
    override all reach the terminal escaped."""
    name = (_ESC + "\n[!] " + _BIDI + "admin").encode()
    text = render(radius_frame(1, bytes(RADIUSAttribute(1, name))))
    assert_escaped(text)
    assert "User-Name: \\x1b[2J\\n[!] \\u202eadmin\n" in text


def test_radius_reply_message_bad_utf8_and_length() -> None:
    """A Reply-Message that is not UTF-8 shows its bytes; one longer
    than the text limit is cut."""
    bad = render(radius_frame(2, bytes(RADIUSAttribute(18, b"ok\xff"))))
    assert "Reply-Message: ok\\xff\n" in bad
    long = bytes(RADIUSAttribute(18, b"r" * (_TEXT_LIMIT + 5)))
    text = render(radius_frame(2, long))
    assert f"Reply-Message: {'r' * _TEXT_LIMIT}... (+5 more chars)" in text


def test_radius_malformed_attributes_are_contained() -> None:
    """C2: an attribute Length below 2 raises when the attributes are
    parsed; the guard reports it and the header stays printed."""
    text = render(radius_frame(1, b"\x01\x01\x00"))
    assert "[+] RADIUS Access-Request (ID 42) | Length 23" in text
    assert "[!] RADIUS attributes malformed: " in text
    assert "User-Name" not in text


def test_radius_text_attributes_are_capped() -> None:
    """Repeated text attributes get a line each up to the list limit,
    then a count: one packet could otherwise print thousands of lines."""
    attributes = bytes(RADIUSAttribute(18, b"m")) * (_LIST_LIMIT + 4)
    text = render(radius_frame(2, attributes))
    assert text.count("Reply-Message: m\n") == _LIST_LIMIT
    assert "(+4 more text attributes)" in text


def test_radius_attributes_are_capped() -> None:
    """More non-text attributes than the list limit are capped."""
    attributes = bytes(RADIUSAttribute(5, struct.pack("!I", 1))) * (
        _LIST_LIMIT + 2
    )
    assert "(+2 more)" in render(radius_frame(4, attributes))


# --- STUN ------------------------------------------------------------------


def test_stun_success_response() -> None:
    """A Binding Success Response: the verified FINGERPRINT, the mapped
    addresses, SOFTWARE and every attribute by name."""
    text = render(corpus("stun.pcap", 1))
    assert (
        "[+] STUN Binding Success Response | Transaction "
        "d6f0c4b3d2008e560d5787f8 | Fingerprint: 0xd28d393d\n"
    ) in text
    assert "XOR-Mapped: 10.9.194.1:36125 | Mapped: 10.9.194.1:36125\n" in text
    assert "Software: Coturn-4.6.1 'Gorst'\n" in text
    assert (
        "Attributes: XOR-MAPPED-ADDRESS, MAPPED-ADDRESS, RESPONSE-ORIGIN"
        in text
    )


def test_stun_request_without_fingerprint() -> None:
    """A request with no FINGERPRINT says so, without a flag."""
    text = render(corpus("stun.pcap", 0))
    assert "[+] STUN Binding Request | Transaction " in text
    assert "| Fingerprint: none\n" in text


def test_stun_error_and_unknown_attributes() -> None:
    """An Error Response shows its code and reason, and the types it
    did not understand."""
    text = render(corpus("stun.pcap", 5))
    assert "Error: 420 Unknown Attribute\n" in text
    assert "Unknown attributes: 0x7ff0\n" in text


def test_stun_message_integrity_is_not_verified() -> None:
    """MESSAGE-INTEGRITY needs the credential's key: shown as present."""
    text = render(corpus("stun.pcap", 10))
    assert "Message-Integrity: present (HMAC-SHA1, not verified)" in text


def test_stun_two_messages_in_one_segment() -> None:
    """STUN over TCP: a segment of two messages renders both."""
    text = render(corpus("stun.pcap", 6))
    assert text.count("[+] STUN Binding Request") == 2


def test_stun_wrong_fingerprint_is_flagged() -> None:
    """A FINGERPRINT that does not match the message is flagged with
    the value it should have. The frame is built right (the library
    fills in the FINGERPRINT too), then its last byte corrupted."""
    frame = bytearray(stun_frame(STUNAttribute(STUN.FINGERPRINT, bytes(4))))
    frame[-1] ^= 0xFF
    text = render(bytes(frame))
    assert "Fingerprint: 0x3e68cd45 [!] mismatch (expected 0x3e68cdba)" in text


def test_stun_misplaced_fingerprint_is_flagged() -> None:
    """A FINGERPRINT before another attribute is not one RFC 8489
    defines; it is flagged, not shown as clean."""
    text = render(
        stun_frame(
            STUNAttribute(STUN.FINGERPRINT, b"\x00" * 4),
            STUNAttribute(STUN.SOFTWARE, b"late"),
        )
    )
    assert "Fingerprint: [!] misplaced (not the last attribute" in text


def test_stun_short_last_fingerprint_is_invalid_not_misplaced() -> None:
    """A last FINGERPRINT whose value is not 4 bytes is flagged as
    invalid, not misdiagnosed as out of place."""
    text = render(stun_frame(STUNAttribute(STUN.FINGERPRINT, b"\x00" * 3)))
    assert "Fingerprint: [!] invalid (3 bytes, not 4, RFC 8489 §14.7)" in text
    assert "misplaced" not in text


def test_stun_software_and_reason_are_sanitized() -> None:
    """C1: SOFTWARE and the error's reason phrase are the sender's."""
    text_value = (_ESC + "\n[!] " + _BIDI + "x").encode()
    error = STUNAttribute(STUN.ERROR_CODE, b"\x00\x00\x04\x01" + text_value)
    software = STUNAttribute(STUN.SOFTWARE, text_value)
    text = render(stun_frame(error, software))
    assert_escaped(text)
    assert "Error: 401 \\x1b[2J\\n[!] \\u202ex\n" in text
    assert "Software: \\x1b[2J\\n[!] \\u202ex\n" in text


def test_stun_long_software_is_cut_and_bad_code_shown() -> None:
    """A long SOFTWARE is cut; an ERROR-CODE whose Class is out of
    range keeps its reason and shows the code as invalid."""
    software = STUNAttribute(STUN.SOFTWARE, b"s" * (_TEXT_LIMIT + 4))
    error = STUNAttribute(STUN.ERROR_CODE, b"\x00\x00\x07\x00nope")
    text = render(stun_frame(software, error))
    assert f"Software: {'s' * _TEXT_LIMIT}... (+4 more chars)" in text
    assert "Error: invalid code nope\n" in text


def test_stun_ipv6_mapped_address() -> None:
    """An IPv6 address is bracketed before its port."""
    value = b"\x00\x02" + struct.pack("!H", 3478) + bytes(15) + b"\x01"
    text = render(stun_frame(STUNAttribute(STUN.MAPPED_ADDRESS, value)))
    assert "Mapped: [::1]:3478\n" in text


def test_stun_malformed_attributes_are_contained() -> None:
    """C2: an attribute whose Length runs past the message raises when
    the list is parsed; the guard reports it after what reads cleanly."""
    software = STUNAttribute(STUN.SOFTWARE, b"okay")
    text = render(stun_frame(software, raw=b"\x80\x22\x00\x20abcd"))
    assert "Software: okay\n" in text
    assert "[!] STUN attributes malformed: " in text
