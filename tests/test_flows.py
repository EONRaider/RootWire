"""Conversation statistics: the end-of-run summary's per-flow tally.

A conversation is the innermost IP datagram's TCP, UDP or SCTP flow,
both directions together (``netprotocols.flow.flow_key``). Real captures
carry the cases: plain TCP (``http/http.pcap``), IPv6 (``tcp_https``),
tunnels whose inner conversation is what counts (``ah``, ``vxlan``), and
frames with no conversation at all (ARP, ICMP).
"""

from __future__ import annotations

import io
import struct

import pytest
from netprotocols import ESP

from conftest import FIXTURES, read_pcap
from rootwire import output
from rootwire.decoder import decode_frame, decode_options
from rootwire.output import StatsCollector, _frame_flow_key


def decode(data: bytes):
    """Decode *data* as frame 1."""
    return decode_frame(data, number=1, timestamp=0, interface=None)


def summary(*names: str) -> str:
    """The report for every frame of the captures *names*, in order."""
    stats = StatsCollector()
    for name in names:
        for data in read_pcap(FIXTURES / name):
            stats.update(decode(data))
    stream = io.StringIO()
    stats.report(stream)
    return stream.getvalue()


def test_both_directions_are_one_conversation() -> None:
    """Every frame of a TCP connection, client to server and back, is
    counted under one conversation."""
    text = summary("http/http.pcap")
    assert "[=] 7 conversations:\n" in text
    assert (
        "[=]   TCP 10.9.8.1:80 <-> 10.9.8.2:47278: 24 frames, 2,338 bytes\n"
        in text
    )


def test_conversations_are_listed_largest_first() -> None:
    """The list runs from the most bytes to the fewest."""
    lines = [
        line
        for line in summary("http/http.pcap").splitlines()
        if " <-> " in line
    ]
    sizes = [
        int(line.rsplit(", ", 1)[1].split()[0].replace(",", ""))
        for line in lines
    ]
    assert sizes == sorted(sizes, reverse=True)


def test_ipv6_endpoints_are_bracketed() -> None:
    """An IPv6 endpoint is bracketed before its port."""
    text = summary("tcp_https.pcap")
    assert "TCP [2606:4700::6810:b22]:443 <-> [2804:" in text


def test_ah_tunnel_mode_counts_the_inner_conversation() -> None:
    """Behind AH in tunnel mode the inner datagram's flow counts, not
    the tunnel endpoints'."""
    text = summary("ah.pcap")
    assert "TCP 192.0.2.1:40003 <-> 192.0.2.2:80: 1 frame, 106 bytes" in text
    assert "10.9.11.1:40003" not in text


def test_vxlan_counts_inner_flows_only() -> None:
    """VXLAN's underlay UDP is never a conversation: a frame with an
    inner UDP flow counts under it, one with an inner ICMP echo or ARP
    under nothing."""
    text = summary("vxlan.pcap")
    assert "[=] 1 conversation:\n" in text
    assert "UDP 10.9.13.1:40000 <-> 10.9.13.2:9999: 1 frame, 115 bytes" in text
    assert ":4789" not in text


@pytest.mark.parametrize(
    ("name", "index"), [("vxlan.pcap", 0), ("vxlan.pcap", 2)]
)
def test_tunnelled_arp_and_icmp_have_no_conversation(
    name: str, index: int
) -> None:
    """Frame 0 carries an inner ARP, frame 2 an inner ICMP echo."""
    assert _frame_flow_key(decode(read_pcap(FIXTURES / name)[index])) is None


def test_no_conversation_no_lines() -> None:
    """A capture with no transport flows prints no conversation lines."""
    text = summary("arp_exchange.pcap")
    assert "conversation" not in text


def test_list_is_cut_at_the_shown_limit(monkeypatch) -> None:
    """Past the shown limit only the largest are listed, and the
    heading says so."""
    monkeypatch.setattr(output, "_FLOW_SHOWN", 2)
    text = summary("http/http.pcap")
    assert "[=] 7 conversations, the 2 largest by bytes:\n" in text
    assert text.count(" <-> ") == 2


def test_tracked_conversations_are_capped(monkeypatch) -> None:
    """Past the tracking limit a new conversation is counted, not kept,
    and the conversations already tracked keep counting."""
    monkeypatch.setattr(output, "_FLOW_LIMIT", 2)
    text = summary("http/http.pcap")
    assert "[=] 2 conversations:\n" in text
    # 98 frames, 22 of them in the two tracked connections: every one of
    # the other 76 is counted, not each rejected conversation once.
    assert "[=]   (+76 frames of conversations past the 2 tracked)" in text
    # The first two connections are tracked whole: 12 and 10 frames.
    assert "47212: 12 frames" in text
    assert "47216: 10 frames" in text


def test_vxlan_with_a_truncated_inner_frame_has_no_conversation() -> None:
    """VXLAN whose inner Ethernet header is cut short ends the walk at
    VXLAN; its outer UDP is still an underlay, not a conversation."""
    data = read_pcap(FIXTURES / "vxlan.pcap")[6]
    start = data.index(bytes.fromhex("0800000012345600")) + 8
    frame = decode(data[: start + 6])
    assert type(frame.layers[-1]).__name__ == "VXLAN"
    assert _frame_flow_key(frame) is None


def test_esp_over_ip_has_no_conversation() -> None:
    """ESP straight over IP encrypts the transport, so none of the
    frames in ``esp.pcap`` belongs to a conversation."""
    frames = read_pcap(FIXTURES / "esp.pcap")
    assert frames
    assert all(_frame_flow_key(decode(data)) is None for data in frames)


def test_udp_encapsulated_esp_counts_under_its_udp_flow() -> None:
    """NAT-T ESP (RFC 3948), decoded with ``udp.port=4500:ESP``, still
    has a cleartext UDP header in front of it: the frame counts under
    that UDP flow, as the README's capture statistics section says."""
    esp = struct.pack("!II", 0x1000, 1) + b"\xaa" * 16
    udp = struct.pack("!HHHH", 40000, 4500, 8 + len(esp), 0) + esp
    ip = (
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(udp),
            0,
            0,
            64,
            17,
            0,
            bytes([10, 0, 0, 1]),
            bytes([10, 0, 0, 2]),
        )
        + udp
    )
    data = b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip
    frame = decode_frame(
        data,
        number=1,
        timestamp=0,
        interface=None,
        options=decode_options({"udp.port": {4500: ESP}}),
    )
    assert isinstance(frame.layers[-1], ESP)
    key = _frame_flow_key(frame)
    assert key is not None
    assert key.protocol == 17
    assert {key.port_a, key.port_b} == {40000, 4500}
