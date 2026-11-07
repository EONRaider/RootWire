"""Tier C screen renderers: the layer-2 protocols LLDP, CDP, STP, MPLS,
LLC and SNAP.

Real corpus frames carry the happy paths (``lldp.pcap``, ``llc.pcap``
and ``mpls.pcap``; see fixtures/MANIFEST.md). Crafted and patched
frames cover what no capture holds on purpose: neighbor-chosen text
carrying terminal escapes and newlines (C1), an LLDPDU out of 802.1AB's
order, a Rapid Spanning Tree BPDU, and text too long for one line.
"""

from __future__ import annotations

import io

import pytest
from netprotocols import (
    CDP,
    LLC,
    LLDP,
    LLDPTLV,
    MPLS,
    SNAP,
    STP,
    Ethernet,
    Packet,
)

from conftest import FIXTURES, read_pcap
from rootwire.decoder import decode_frame
from rootwire.frame import DecodedFrame
from rootwire.output import _TEXT_LIMIT, OutputToScreen

#: The six classes this module renders; none may fall back to the
#: "(no renderer)" line anywhere in their captures.
_TIER_C = (LLDP, CDP, STP, MPLS, LLC, SNAP)

#: An ESC-led sequence that clears the screen, written as an escape.
_ESC = b"\x1b[2J"


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


def lldp_frame(*tlvs: LLDPTLV) -> bytes:
    """Ethernet carrying an LLDPDU of *tlvs*, End appended."""
    eth = Ethernet(
        dst="01:80:c2:00:00:0e", src="02:00:00:00:00:01", ethertype=0x88CC
    )
    return bytes(Packet(eth, LLDP(tlvs=(*tlvs, LLDPTLV(0)))))


def mandatory_tlvs() -> tuple[LLDPTLV, ...]:
    """Chassis ID (MAC), Port ID (interface name) and a 120 s TTL."""
    return (
        LLDPTLV(1, b"\x04" + bytes.fromhex("020000000001")),
        LLDPTLV(2, b"\x05eth0"),
        LLDPTLV(3, (120).to_bytes(2, "big")),
    )


def assert_escaped(text: str) -> None:
    """*text* holds no raw ESC, only its escape."""
    assert "\x1b" not in text
    assert "\\x1b[2J" in text


# --- corpus-wide -----------------------------------------------------------


@pytest.mark.parametrize("name", ["lldp.pcap", "llc.pcap", "mpls.pcap"])
def test_corpus_frames_render_without_fallback_or_fault(name: str) -> None:
    """Every frame of each capture renders through a registered
    renderer, with no guard tripping and no checksum flagged."""
    for index, raw in enumerate(read_pcap(FIXTURES / name)):
        text = render(raw)
        for cls in _TIER_C:
            assert f"{cls.__name__} (no renderer)" not in text, (name, index)
        assert "malformed:" not in text, (name, index)
        assert "mismatch" not in text, (name, index)


# --- LLDP ------------------------------------------------------------------


def test_lldp_identity_and_text_tlvs() -> None:
    """Chassis ID as a MAC, Port ID as an interface name, the TTL, the
    text TLVs and every other TLV by name or OUI."""
    text = render(corpus("lldp.pcap", 0))
    assert (
        "[+] LLDP Chassis MAC address 02:4e:50:86:00:0a | "
        "Port Interface name nplldp-va | TTL 120s\n"
    ) in text
    assert "System Name: nplldp-a" in text
    assert "System Description: NETProtocols LLDP fixture, agent A" in text
    assert "Management Address (12 bytes)" in text
    assert "OUI 0a-4e-50 subtype 1 (304 bytes)" in text


def test_lldp_locally_assigned_chassis_and_mac_port() -> None:
    """A locally assigned Chassis ID is text; a MAC Port ID a MAC."""
    text = render(corpus("lldp.pcap", 1))
    assert "Chassis Locally assigned nplldp-chassis-b" in text
    assert "Port MAC address 02:4e:50:86:00:0b | TTL 180s" in text


def test_lldp_shutdown() -> None:
    """A TTL of 0 is a shutdown LLDPDU."""
    assert "TTL 0s (shutdown)" in render(corpus("lldp.pcap", 2))


def test_lldp_out_of_order_is_flagged() -> None:
    """An LLDPDU not opening with Chassis ID, Port ID and TTL is
    flagged, its missing identifiers shown as n/a."""
    chassis, port, ttl = mandatory_tlvs()
    text = render(lldp_frame(port, chassis, ttl))
    assert "Chassis n/a | Port n/a | TTL 120s" in text
    assert "[!] Does not open with Chassis ID, Port ID and Time to Live" in text


def test_lldp_system_name_is_sanitized_and_one_line() -> None:
    """C1: a System Name carrying ESC and a newline cannot repaint the
    terminal or start a forged line."""
    frame = patched("lldp.pcap", 0, b"nplldp-a", _ESC + b"\n[!]")
    text = render(frame)
    assert_escaped(text)
    assert "System Name: \\x1b[2J\\n[!]" in text
    assert "\n[!]\n" not in text


def test_lldp_long_description_is_cut() -> None:
    """A System Description is cut at the text limit, the rest counted."""
    description = LLDPTLV(6, b"x" * (_TEXT_LIMIT + 72))
    text = render(lldp_frame(*mandatory_tlvs(), description))
    assert (
        f"System Description: {'x' * _TEXT_LIMIT}... (+72 more chars)" in text
    )


# --- CDP -------------------------------------------------------------------


def test_cdp_identity_capabilities_and_addresses() -> None:
    """CDP over LLC/SNAP: version, TTL and a verified checksum, the
    neighbor's identity, capabilities and addresses."""
    text = render(corpus("llc.pcap", 5))
    assert "[+] SNAP OUI 00-00-0c | PID 0x2000" in text
    assert "[+] CDPv1 | TTL 4s | Checksum: 0xfdf3\n" in text
    assert "Device ID: npllc-cdp | Port ID: npllc-ab | Platform: npllc" in text
    assert "Software: NETProtocols LLC fixture" in text
    assert "Capabilities: Switch, Host | Addresses: 10.9.30.1" in text


def test_cdp_non_ascii_byte_is_escaped() -> None:
    """The odd-length PDU ends in the byte 0xA9, shown as an escape;
    its checksum, over an odd number of bytes, still verifies."""
    text = render(corpus("llc.pcap", 7))
    assert "Platform: npll\\xa9" in text
    assert "mismatch" not in text


def test_cdp_corrupted_checksum_is_flagged() -> None:
    """A wrong CDP checksum is reported with the expected value."""
    frame = bytearray(corpus("llc.pcap", 5))
    start = bytes(frame).find(b"npllc-cdp") - 4 - 4
    frame[start + 2] ^= 0xFF
    assert "[!] mismatch (expected 0xfdf3)" in render(bytes(frame))


def test_cdp_text_is_sanitized_and_one_line() -> None:
    """C1: a Device ID with ESC and a Software Version with a newline
    stay escaped and on their own lines."""
    frame = patched("llc.pcap", 5, b"npllc-cdp", _ESC + b"evil\n")
    frame = frame.replace(b"NETProtocols LLC", b"NETProtocols\n[!]")
    text = render(frame)
    assert_escaped(text)
    assert "Device ID: \\x1b[2Jevil\\n | Port ID" in text
    assert "Software: NETProtocols\\n[!]" in text


# --- STP -------------------------------------------------------------------


def test_stp_configuration_bpdu() -> None:
    """A Configuration BPDU: root and bridge IDs, cost, port, flags
    and timers."""
    text = render(corpus("llc.pcap", 0))
    assert "[+] LLC DSAP 0x42 (Bridge Spanning Tree)" in text
    assert "[+] STP Configuration (Spanning Tree)" in text
    assert "Root: 32768/0/02:00:00:00:b0:00 | Cost: 0 | Bridge: " in text
    assert "Port: 128.1" in text
    assert "Max age: 20s | Hello: 1s | Forward delay: 2s" in text


def test_stp_topology_change_flags_and_tcn() -> None:
    """TC and TCA flags; a TCN BPDU has no fields beyond its type."""
    assert "Flags: TC, TCA" in render(corpus("llc.pcap", 4))
    tcn = render(corpus("llc.pcap", 3))
    assert "[+] STP Topology Change Notification" in tcn
    assert "Root:" not in tcn


def test_rstp_role_and_handshake_flags() -> None:
    """An RST BPDU: its port role and proposal/learning/forwarding."""
    stp = STP(
        protocol_id=0,
        version=2,
        bpdu_type=2,
        flags=0x3E,
        root_priority=4096,
        root_mac="02:00:00:00:00:0a",
        root_path_cost=4,
        bridge_priority=32768,
        bridge_mac="02:00:00:00:00:0b",
        port_id=0x8002,
        message_age=256,
        max_age=20 * 256,
        hello_time=2 * 256,
        forward_delay=15 * 256,
        version_1_length=0,
    )
    llc = LLC(dsap=0x42, ssap=0x42, control=0x03)
    eth = Ethernet(
        dst="01:80:c2:00:00:00",
        src="02:00:00:00:00:0b",
        ethertype=len(bytes(llc)) + len(bytes(stp)),
    )
    text = render(bytes(Packet(eth, llc, stp)))
    assert "(Rapid Spanning Tree)" in text
    assert "Flags: Role Designated, Proposal, Learning, Forwarding" in text
    assert "Port: 128.2" in text
    assert "Message age: 1s" in text


# --- MPLS ------------------------------------------------------------------


def test_mpls_label_stack_and_special_labels() -> None:
    """Every label with TC and TTL, the bottom marked, special-purpose
    labels named, and the payload the stack implies."""
    stack = render(corpus("mpls.pcap", 2))
    assert (
        "[+] MPLS (3 labels): 16001 (TC 5, TTL 64), 16002 (TC 3, TTL 63), "
        "16003 (TC 0, TTL 64) [S]"
    ) in stack
    assert "Payload: IPv4" in stack
    assert "7 Entropy Label Indicator (ELI)" in render(corpus("mpls.pcap", 3))
    assert "Payload: IPv6" in render(corpus("mpls.pcap", 5))


def test_mpls_pseudowire_names_no_payload() -> None:
    """Behind a pseudowire control word the stack implies no payload."""
    text = render(corpus("mpls.pcap", 7))
    assert "[+] MPLS (2 labels)" in text
    assert "Payload:" not in text


# --- LLC and SNAP ----------------------------------------------------------


def test_snap_ethertype_pids() -> None:
    """RFC 1042 and 802.1H SNAP name their PID as an EtherType."""
    assert "[+] SNAP OUI 00-00-00 | PID 0x0806 (ARP)" in render(
        corpus("llc.pcap", 8)
    )
    assert "[+] SNAP OUI 00-00-f8 | PID 0x0806 (ARP)" in render(
        corpus("llc.pcap", 10)
    )


def test_llc_control_and_raw_ipx() -> None:
    """LLC's control format and role; Novell raw 802.3 named as such."""
    assert "Control: 0x03 (U-format command)" in render(corpus("llc.pcap", 5))
    assert "[+] Novell raw 802.3 (IPX, no LLC header)" in render(
        corpus("llc.pcap", 12)
    )
