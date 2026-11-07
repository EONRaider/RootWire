"""Tier B screen renderers: the routing and redundancy protocols VRRP,
HSRP, RIP, OSPF, PIM and BGP.

Real corpus frames carry the happy paths: every capture behind these
renderers is vendored (see fixtures/MANIFEST.md). Crafted frames cover
what no capture holds on purpose: clear-text passwords and operator
messages carrying terminal escapes (C1), bodies that only fail when a
renderer asks for them (C2), and lists long enough to need a cap.
"""

from __future__ import annotations

import io
import ipaddress
import struct

import pytest
from netprotocols import (
    BGP,
    HSRP,
    OSPF,
    PIM,
    RIP,
    VRRP,
    Ethernet,
    IPv6,
    Packet,
    PIMAssert,
    PIMEncodedGroup,
    PIMEncodedSource,
    PIMEncodedUnicast,
    PIMGroupSet,
    PIMJoinPrune,
    Protocol,
    RIPEntry,
    VRRPv6,
)

from conftest import FIXTURES, _eth, _ipv4, read_pcap
from rootwire.decoder import decode_frame
from rootwire.frame import DecodedFrame
from rootwire.output import _LIST_LIMIT, OutputToScreen
from test_renderers_tier_a import tcp_payload_frame, udp_frame

#: An ESC-led sequence that clears the screen, and the right-to-left
#: override that reorders what follows it: both must reach the
#: terminal escaped. Written as escapes, never as the characters.
_ESC = "\x1b[2J"
_BIDI = "\u202e"

#: ``0.0.0.0``, built rather than written (Bandit B104).
_ZERO = str(ipaddress.IPv4Address(0))

_IPPROTO_OSPF = 89
_IPPROTO_PIM = 103
_IPPROTO_VRRP = 112

#: The six classes this module renders; none may fall back to the
#: "(no renderer)" line anywhere in the corpus.
_TIER_B = (VRRP, HSRP, RIP, OSPF, PIM, BGP)


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


def ip_frame(protocol: int, upper: Protocol) -> bytes:
    """Ethernet/IPv4 carrying *upper* as IP protocol *protocol*, every
    checksum the library's own."""
    ip = _ipv4(protocol=protocol, total_length=20 + len(bytes(upper)))
    return bytes(Packet(_eth(0x0800), ip, upper).with_checksums())


def assert_escaped(text: str) -> None:
    """*text* holds no raw ESC or bidi override, only their escapes."""
    assert "\x1b" not in text
    assert _BIDI not in text
    assert "\\x1b[2J" in text


# --- corpus-wide -----------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "vrrp.pcap",
        "vrrp_rfc9568.pcap",
        "hsrp.pcap",
        "rip.pcap",
        "ospf.pcap",
        "pim.pcap",
        "bgp.pcap",
        "bgp_session.pcap",
    ],
)
def test_corpus_frames_render_without_fallback_or_fault(name: str) -> None:
    """Every frame of each capture renders through a registered
    renderer, with no guard tripping and no checksum flagged."""
    for index, raw in enumerate(read_pcap(FIXTURES / name)):
        text = render(raw)
        for cls in _TIER_B:
            assert f"{cls.__name__} (no renderer)" not in text, (name, index)
        assert "malformed:" not in text, (name, index)
        assert "mismatch" not in text, (name, index)
        assert "bad LS checksum" not in text, (name, index)


# --- VRRP ------------------------------------------------------------------


def test_vrrpv2_password_addresses_and_interval() -> None:
    """VRRPv2 with Auth Type 1 (PASS): the password is shown; the
    checksum verifies over the message alone."""
    text = render(corpus("vrrp.pcap", 0))
    assert "[+] VRRPv2 Advertisement | VRID 51 | Priority 200\n" in text
    assert "Addresses: 10.9.20.51, 10.9.20.52 | Interval: 1s" in text
    assert "Auth: Simple Text Password (np-vrrp)" in text


def test_vrrp_priority_zero_is_a_resignation() -> None:
    """Priority 0 is the master giving up (RFC 3768 §5.3.4)."""
    assert "Priority 0 (master resigning)" in render(corpus("vrrp.pcap", 2))


def test_vrrpv3_has_no_auth_line() -> None:
    """VRRPv3 dropped authentication (RFC 5798): no Auth line."""
    text = render(corpus("vrrp.pcap", 9))
    assert "[+] VRRPv3 Advertisement | VRID 53" in text
    assert "Auth:" not in text


def test_vrrp_corrupted_checksum_is_flagged() -> None:
    """A wrong VRRP checksum is reported with the expected value."""
    frame = bytearray(corpus("vrrp.pcap", 0))
    frame[14 + 20 + 6] ^= 0xFF
    assert "[!] mismatch (expected 0x5af6)" in render(bytes(frame))


def test_vrrpv6_dispatches_to_the_vrrp_renderer() -> None:
    """VRRPv6 subclasses VRRP, so it renders through the same method,
    its checksum verified behind the IPv6 pseudo-header."""
    vrrp = VRRPv6(
        version=3,
        type=1,
        vrid=7,
        priority=100,
        count_ip_addrs=1,
        adver_word=100,
        checksum=0,
        addresses=("fe80::1",),
    )
    ip = IPv6(
        version=6,
        traffic_class=0,
        flow_label=0,
        payload_length=len(bytes(vrrp)),
        next_header=_IPPROTO_VRRP,
        hop_limit=255,
        src="fe80::2",
        dst="ff02::12",
    )
    eth = Ethernet(
        dst="33:33:00:00:00:12", src="02:00:00:00:00:02", ethertype=0x86DD
    )
    text = render(bytes(Packet(eth, ip, vrrp).with_checksums()))
    assert "[+] VRRPv3 Advertisement | VRID 7 | Priority 100" in text
    assert "Addresses: fe80::1" in text
    assert "mismatch" not in text


def test_vrrp_password_is_sanitized() -> None:
    """C1: a PASS password is the sender's bytes, shown escaped."""
    frame = bytearray(corpus("vrrp.pcap", 0))
    auth = 14 + 20 + 8 + 2 * 4
    frame[auth : auth + 8] = (_ESC + _BIDI).encode()[:8].ljust(8, b"\x00")
    text = render(bytes(frame))
    assert "\x1b" not in text
    assert "Auth: Simple Text Password (\\x1b[2J" in text


# --- HSRP ------------------------------------------------------------------


def test_hsrp_hello_with_default_auth() -> None:
    """An HSRP Hello: group, state, priority, virtual IP and MAC,
    timers, and RFC 2281's default password flagged as such."""
    text = render(corpus("hsrp.pcap", 0))
    assert "[+] HSRP Hello | Group 1 | State Speak | Priority 120" in text
    assert "Virtual IP: 10.9.195.254 (MAC 00:00:0c:07:ac:01)" in text
    assert "Hellotime: 3s | Holdtime: 10s" in text
    assert "Auth: cisco (default)" in text


def test_hsrp_configured_password_and_coup() -> None:
    """A configured password is not flagged default; a Coup names its
    op code."""
    assert "Auth: spark\n" in render(corpus("hsrp.pcap", 10))
    assert "[+] HSRP Coup | Group 1" in render(corpus("hsrp.pcap", 8))


def test_hsrp_auth_with_escape_shows_no_raw_escape() -> None:
    """C1: Authentication Data with an ESC never reaches the terminal
    raw. The library already renders unprintable data as hex, so this
    also holds with the sanitizer removed; the renderer sanitizes it
    anyway, as it does every wire-chosen string."""
    hsrp = HSRP(
        version=0,
        opcode=0,
        state=16,
        hellotime=3,
        holdtime=10,
        priority=100,
        group=9,
        reserved=0,
        auth_data=_ESC.encode().ljust(8, b"\x00"),
        virtual_ip="10.1.1.1",
    )
    text = render(udp_frame(1985, hsrp))
    assert "\x1b" not in text
    assert "Auth: 0x1b5b324a00000000\n" in text


# --- RIP -------------------------------------------------------------------


def test_rip_whole_table_request() -> None:
    """RFC 2453 §3.9.1's one-entry, AFI 0, metric 16 request."""
    text = render(corpus("rip.pcap", 0))
    assert "[+] RIPv1 Request" in text
    assert "Request: the whole routing table" in text


def test_ripv1_routes_have_no_mask() -> None:
    """RIPv1 carries no mask, so the routes show bare addresses."""
    text = render(corpus("rip.pcap", 2))
    assert "Routes (3): 192.0.2.0 metric 1, 10.0.0.0 metric 1" in text


def test_ripv2_routes_and_poisoned_reverse() -> None:
    """RIPv2 routes show their prefix length; metric 16 is shown as
    unreachable (poisoned reverse)."""
    assert "10.20.3.128/25 metric 1" in render(corpus("rip.pcap", 6))
    text = render(corpus("rip.pcap", 8))
    assert "Routes (7):" in text
    assert text.count("unreachable") == 3


def test_rip_authentication_entries() -> None:
    """A plain-text password, and RFC 4822 keyed digests by Key ID with
    the trailer's length."""
    assert "Auth: Plain-text password (nprip-pw)" in render(
        corpus("rip.pcap", 10)
    )
    md5 = render(corpus("rip.pcap", 14))
    assert "(key 1, seq " in md5
    assert "| Trailer: 20 bytes" in md5
    assert "| Trailer: 36 bytes" in render(corpus("rip.pcap", 18))


def test_rip_route_next_hop_odd_mask_and_remainder() -> None:
    """A next hop is shown when set, a non-contiguous mask as itself,
    a foreign address family by name, and a partial entry counted."""
    entries = [
        RIPEntry(2, 0, "10.1.0.0", "255.255.0.0", "10.9.9.9", 2),
        RIPEntry(2, 0, "10.2.0.0", "255.0.255.0", _ZERO, 3),
        RIPEntry(7, 0, "10.3.0.0", _ZERO, _ZERO, 4),
    ]
    body = b"".join(map(bytes, entries)) + b"\x00\x02\x00"
    text = render(udp_frame(520, RIP(command=2, version=2, body=body)))
    assert "10.1.0.0/16 via 10.9.9.9 metric 2" in text
    assert "10.2.0.0 mask 255.0.255.0 metric 3" in text
    assert "10.3.0.0 (unknown (7)) metric 4" in text
    assert "Unparsed: 3 bytes" in text


def test_rip_host_mask_is_not_read_as_a_prefix() -> None:
    """ipaddress inverts a mask such as 0.255.255.255 as a host mask;
    the wire mask is shown as itself, not as the /8 it would become."""
    entry = RIPEntry(2, 0, "10.0.0.0", "0.255.255.255", _ZERO, 1)
    text = render(udp_frame(520, RIP(command=2, version=2, body=bytes(entry))))
    assert "10.0.0.0 mask 0.255.255.255 metric 1" in text
    assert "/8" not in text


def test_rip_response_shaped_like_a_table_request_is_a_route() -> None:
    """Only a Request with one AFI 0, metric 16 entry asks for the whole
    table; a Response with that entry still shows it."""
    entry = RIPEntry(0, 0, _ZERO, _ZERO, _ZERO, 16)
    text = render(udp_frame(520, RIP(command=2, version=2, body=bytes(entry))))
    assert "whole routing table" not in text
    assert "Routes (1):" in text
    assert "unreachable" in text


def test_rip_password_newline_stays_on_one_line() -> None:
    """C1: a newline in a password cannot start a forged line."""
    secret = b"pw\n[!] forged".ljust(16, b"\x00")
    body = b"\xff\xff\x00\x02" + secret
    text = render(udp_frame(520, RIP(command=1, version=2, body=body)))
    assert "(pw\\n[!] forged)" in text
    assert "\n[!] forged" not in text


def test_rip_password_is_sanitized() -> None:
    """C1: a RIP plain-text password is shown escaped."""
    secret = (_ESC + _BIDI + "pw").encode().ljust(16, b"\x00")
    body = b"\xff\xff\x00\x02" + secret
    text = render(udp_frame(520, RIP(command=1, version=2, body=body)))
    assert_escaped(text)
    # The field is ASCII: the override's UTF-8 bytes show one by one.
    assert "(\\x1b[2J\\xe2\\x80\\xaepw)" in text


def test_rip_routes_are_capped() -> None:
    """A Response can carry 25 entries; the line names at most 16."""
    entry = RIPEntry(2, 0, "10.0.0.0", "255.0.0.0", _ZERO, 1)
    body = bytes(entry) * 25
    text = render(udp_frame(520, RIP(command=2, version=2, body=body)))
    assert "Routes (25):" in text
    assert f"(+{25 - _LIST_LIMIT} more)" in text


# --- OSPF ------------------------------------------------------------------


def test_ospf_hello() -> None:
    """A Hello: router and area (0 named backbone), timers, options,
    an elected DR and the neighbor list."""
    text = render(corpus("ospf.pcap", 1))
    assert "[+] OSPFv2 Hello | Router " in text
    assert "Area 0.0.0.0 (backbone)" in text
    assert "Mask: 255.255.255.0 | Hello: 2s | Dead: 8s" in text
    assert "DR: 10.9.83.1 | BDR: " in text
    assert "Neighbors: 10.0.0.2" in text


def test_ospf_hello_before_election_shows_none() -> None:
    """An unelected DR/BDR (0.0.0.0) shows as none."""
    assert "DR: none | BDR: none | Neighbors: none" in render(
        corpus("ospf.pcap", 0)
    )


def test_ospf_database_description_and_requests() -> None:
    """A DD's MTU, I/M/MS flags and sequence; an LSR's requests."""
    assert "MTU: 1500 | Flags: I M MS | Seq: 0x7af063f2" in render(
        corpus("ospf.pcap", 2)
    )
    assert (
        "Requests (2): Router-LSA 10.0.0.1 (adv 10.0.0.1), "
        "AS-external-LSA 192.0.2.1 (adv 10.0.0.1)"
    ) in render(corpus("ospf.pcap", 6))


def test_ospf_update_and_acknowledgment() -> None:
    """An LSU's LSAs and an LSAck's headers, by type, ID, advertising
    router and sequence number."""
    assert (
        "LSAs (2): Router-LSA 10.0.0.1 (adv 10.0.0.1, seq 0x80000002)"
    ) in render(corpus("ospf.pcap", 9))
    assert (
        "Acknowledged (1): Router-LSA 10.0.0.2 (adv 10.0.0.2, seq 0x80000002)"
    ) in render(corpus("ospf.pcap", 12))


def test_ospf_bad_ls_checksum_is_flagged() -> None:
    """An LSA whose Fletcher checksum fails is marked. The packet
    checksum then fails too, and is flagged separately."""
    frame = bytearray(corpus("ospf.pcap", 9))
    frame[-1] ^= 0x01
    text = render(bytes(frame))
    assert "[!] bad LS checksum" in text
    assert "Checksum: 0xb8c1 [!] mismatch" in text


def test_ospf_simple_password() -> None:
    """AuType 1: the clear-text password is shown."""
    text = render(corpus("ospf.pcap", 18))
    assert "Auth: Simple Password (NPospf1) | Checksum: 0xf2c3\n" in text


def test_ospf_cryptographic_auth_replaces_the_checksum() -> None:
    """AuType 2: key and sequence shown; the checksum is not used, so
    it is neither verified nor flagged (RFC 2328 §D.4.3)."""
    text = render(corpus("ospf.pcap", 36))
    assert "Auth: Cryptographic (key 1, seq " in text
    assert "16-byte trailer) | Checksum: not used" in text


def test_ospf_password_is_sanitized() -> None:
    """C1: an AuType 1 password is shown escaped. The packet checksum
    leaves out the Authentication field, so it still verifies."""
    frame = bytearray(corpus("ospf.pcap", 18))
    start = 14 + 20 + 16
    frame[start : start + 8] = (_ESC + "pw").encode().ljust(8, b"\x00")
    text = render(bytes(frame))
    assert_escaped(text)
    assert "mismatch" not in text


def test_ospf_corrupted_packet_checksum_is_flagged() -> None:
    """A wrong OSPF packet checksum is reported."""
    frame = bytearray(corpus("ospf.pcap", 0))
    frame[14 + 20 + 12] ^= 0xFF
    assert "[!] mismatch (expected 0xf2c4)" in render(bytes(frame))


# --- PIM -------------------------------------------------------------------


def test_pim_hello_options_and_addresses() -> None:
    """A Hello's Holdtime, DR priority, Generation ID, LAN Prune Delay
    and secondary addresses; its checksum verifies."""
    text = render(corpus("pim.pcap", 0))
    assert "[+] PIMv2 Hello | Checksum: 0x071f\n" in text
    assert "Holdtime: 105s | DR priority: 1 | Generation ID: 0x75553e5a" in text
    assert "LAN prune delay: 500ms (override 2500ms)" in text
    assert "Secondary addresses: 10.184.13.1" in text


def test_pim_join_prune_flags() -> None:
    """(*,G) joins carry WC and RPT; (S,G,rpt) prunes carry RPT."""
    assert "join 10.184.12.1/32 (WC RPT); prune none" in render(
        corpus("pim.pcap", 2)
    )
    assert "prune 10.184.1.2/32 (RPT)" in render(corpus("pim.pcap", 11))


def test_pim_register_inner_header_and_null_register() -> None:
    """A data Register shows the encapsulated flow from its inner IP
    header alone; a Null-Register says so."""
    assert (
        "Encapsulated: 10.184.1.2 -> 239.184.0.1 (UDP), 47 bytes"
    ) in render(corpus("pim.pcap", 3))
    assert "Encapsulated: Null-Register" in render(corpus("pim.pcap", 7))
    assert "Group: 239.184.0.1/32 | Source: 10.184.1.2" in render(
        corpus("pim.pcap", 6)
    )


def test_pim_register_with_malformed_inner_header() -> None:
    """A Register whose inner header does not decode says so instead
    of raising or walking further."""
    pim = PIM(type=1, body=b"\x00\x00\x00\x00" + b"\x45\x00\x00")
    text = render(ip_frame(_IPPROTO_PIM, pim))
    assert "Encapsulated: 3 bytes, inner IP header malformed" in text


def test_pim_assert() -> None:
    """An Assert's group, source, preference and metric."""
    message = PIMAssert(
        group=PIMEncodedGroup(1, 0, 0, 32, "239.1.1.1"),
        source=PIMEncodedUnicast(1, 0, "10.1.1.1"),
        rpt=True,
        metric_preference=110,
        metric=20,
    )
    text = render(ip_frame(_IPPROTO_PIM, PIM(type=5, body=bytes(message))))
    assert (
        "Group: 239.1.1.1/32 | Source: 10.1.1.1 | Preference: 110 | "
        "Metric: 20 | RPT"
    ) in text
    assert "mismatch" not in text


def test_pim_raw_type_and_malformed_body() -> None:
    """A Bootstrap stays raw and shows its length; a Join/Prune cut
    short trips the guard instead of escaping update()."""
    raw = render(ip_frame(_IPPROTO_PIM, PIM(type=4, body=b"\x00" * 10)))
    assert "Body: 10 bytes, not decoded" in raw
    short = render(ip_frame(_IPPROTO_PIM, PIM(type=3, body=b"\x01")))
    assert "[!] Join/Prune malformed:" in short


def test_pim_join_prune_groups_are_capped() -> None:
    """A Join/Prune names at most 16 groups, then counts the rest."""
    groups = tuple(
        PIMGroupSet(
            group=PIMEncodedGroup(1, 0, 0, 32, f"239.0.0.{n}"),
            joined=(PIMEncodedSource(1, 0, 4, 32, "10.0.0.1"),),
        )
        for n in range(_LIST_LIMIT + 3)
    )
    message = PIMJoinPrune(
        upstream_neighbor=PIMEncodedUnicast(1, 0, "10.0.0.254"),
        holdtime=210,
        groups=groups,
    )
    text = render(ip_frame(_IPPROTO_PIM, PIM(type=3, body=bytes(message))))
    assert text.count("Group 239.0.0.") == _LIST_LIMIT
    assert "(+3 more groups)" in text


# --- BGP -------------------------------------------------------------------


def bgp_frame(*messages: BGP) -> bytes:
    """Ethernet/IPv4/TCP to port 179 carrying *messages*."""
    return tcp_payload_frame(179, b"".join(map(bytes, messages)))


def bgp(type_: int, body: bytes) -> BGP:
    """A BGP message of *type_* with *body*, its Length filled in."""
    return BGP(
        marker=b"\xff" * 16, length=19 + len(body), type=type_, body=body
    )


def test_bgp_open_and_keepalive() -> None:
    """An OPEN's version, AS, hold time, ID and parameters; a
    KEEPALIVE is its header line alone."""
    text = render(corpus("bgp.pcap", 0))
    assert "[+] BGP OPEN (53 bytes)" in text
    assert "Version: 4 | AS: 65001 | Hold time: 9s | ID: 10.185.0.1" in text
    assert "Optional parameters: Capabilities (22 bytes)" in text
    assert "[+] BGP KEEPALIVE (19 bytes)\n" in render(corpus("bgp.pcap", 2))


def test_bgp_update_and_end_of_rib() -> None:
    """An UPDATE's attributes and NLRI, every message of a segment in
    its own section; an empty UPDATE is End-of-RIB."""
    text = render(corpus("bgp.pcap", 4))
    assert (
        "Attributes: ORIGIN IGP, AS_PATH (empty), NEXT_HOP 10.185.0.1" in text
    )
    assert "NLRI (1): 198.51.100.0/25" in text
    assert text.count("[+] BGP UPDATE") > 1
    assert "End-of-RIB (IPv4 unicast)" in text


def test_bgp_withdrawals_and_long_nlri_are_capped() -> None:
    """Withdrawn routes are listed; a 90-prefix NLRI is capped."""
    withdrawn = bytes([24, 10, 1, 1, 16, 10, 2])
    update = bgp(2, struct.pack("!H", len(withdrawn)) + withdrawn + b"\x00\x00")
    assert "Withdrawn (2): 10.1.1.0/24, 10.2.0.0/16" in render(
        bgp_frame(update)
    )
    nlri = bytes([24, 10, 9, 0]) * (_LIST_LIMIT + 5)
    attrs = b"\x40\x01\x01\x00"
    update = bgp(2, b"\x00\x00" + struct.pack("!H", len(attrs)) + attrs + nlri)
    text = render(bgp_frame(update))
    assert f"NLRI ({_LIST_LIMIT + 5}):" in text
    assert "(+5 more)" in text


def test_bgp_notification_with_and_without_communication() -> None:
    """A Cease with a shutdown communication shows the text; any other
    NOTIFICATION shows its data's size."""
    text = render(corpus("bgp.pcap", 17))
    assert "Error: Cease / Administrative Shutdown" in text
    assert "Shutdown communication: NETProtocols fixture shutdown" in text
    hold = render(bgp_frame(bgp(3, b"\x04\x00\xab\xcd")))
    assert "Error: Hold Timer Expired / Unspecific\n" in hold
    assert "Data: 2 bytes" in hold


def test_bgp_shutdown_communication_is_sanitized() -> None:
    """C1: the shutdown communication is the peer's UTF-8 text."""
    message = (_ESC + _BIDI + "bye").encode()
    body = b"\x06\x02" + bytes([len(message)]) + message
    text = render(bgp_frame(bgp(3, body)))
    assert_escaped(text)
    assert "Shutdown communication: \\x1b[2J\\u202ebye" in text


def test_bgp_shutdown_communication_newline_stays_on_one_line() -> None:
    """C1: a newline in the shutdown communication cannot forge a
    frame header or diagnostic line."""
    message = b"bye\n[>] Frame #9 forged"
    body = b"\x06\x02" + bytes([len(message)]) + message
    text = render(bgp_frame(bgp(3, body)))
    assert "Shutdown communication: bye\\n[>] Frame #9 forged" in text
    assert "\n[>] Frame #9" not in text


def test_bgp_long_raw_attribute_is_truncated() -> None:
    """A raw attribute value shows its first 32 bytes in hex and its
    full length: one attribute can run to 65,535 bytes."""
    value = bytes(range(200))
    attribute = b"\x90\x08" + len(value).to_bytes(2, "big") + value
    update = bgp(2, b"\x00\x00" + len(attribute).to_bytes(2, "big") + attribute)
    text = render(bgp_frame(update))
    assert f"COMMUNITIES {value[:32].hex()}... (200 bytes)" in text
    assert value[32:].hex() not in text


def test_bgp_malformed_update_is_contained() -> None:
    """C2: an UPDATE whose Path Attributes length overruns decodes (the
    body is not validated on decode) and fails only in the renderer,
    inside its guard; the next message still renders."""
    broken = bgp(2, b"\x00\x00\x00\xff\x40")
    text = render(bgp_frame(broken, bgp(4, b"")))
    assert "[!] UPDATE malformed:" in text
    assert "[+] BGP KEEPALIVE" in text


def test_bgp_malformed_open_parameters_are_contained() -> None:
    """C2: an OPEN whose Optional Parameters Length disagrees with the
    message keeps its fixed fields and flags the parameters."""
    body = b"\x04\xfd\xe9\x00\x5a\x0a\x00\x00\x01\x09" + b"\x02\x00"
    text = render(bgp_frame(bgp(1, body)))
    assert "Version: 4 | AS: 65001 | Hold time: 90s | ID: 10.0.0.1" in text
    assert "[!] Optional parameters malformed:" in text
