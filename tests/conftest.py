"""Recorded and synthesized frames for socketless decoder tests.

Frames are built with netprotocols' own encode path from real header
values, which keeps the fixtures readable while remaining byte-exact.
"""

import struct
from pathlib import Path

import pytest
from netprotocols import (
    ARP,
    GRE,
    IGMP,
    TCP,
    UDP,
    Ethernet,
    ICMPv4,
    ICMPv6,
    IPv4,
    IPv6,
    Packet,
)


def _eth(ethertype: int) -> Ethernet:
    return Ethernet(
        dst="ff:ff:ff:ff:ff:ff", src="00:07:0d:af:f4:54", ethertype=ethertype
    )


def _ipv4(protocol: int, total_length: int, options: bytes = b"") -> IPv4:
    return IPv4(
        version=4,
        ihl=5 + len(options) // 4,
        dscp=0,
        ecn=0,
        total_length=total_length,
        identification=0xEC6C,
        flags=2,
        fragment_offset=0,
        ttl=64,
        protocol=protocol,
        checksum=0x2B51,
        src="192.168.1.96",
        dst="192.168.1.254",
        options=options,
    )


def ipv4_udp(total_length: int, payload: bytes = b"\xaa\xbb") -> bytes:
    """Ethernet / IPv4 / UDP with a caller-chosen IPv4 ``total_length``,
    for exercising length diagnostics. The ports are unassigned so the
    decoder leaves the payload as raw frame bytes."""
    udp = UDP(
        src_port=40000, dst_port=40001, length=8 + len(payload), checksum=0
    )
    ip = _ipv4(protocol=17, total_length=total_length)
    return bytes(Packet(_eth(0x0800), ip, udp)) + payload


@pytest.fixture
def arp_frame() -> bytes:
    return bytes(
        Packet(
            _eth(0x0806),
            ARP(
                htype=1,
                ptype=0x0800,
                hlen=6,
                plen=4,
                oper=1,
                sha="00:07:0d:af:f4:54",
                spa="192.168.1.96",
                tha="00:00:00:00:00:00",
                tpa="192.168.1.254",
            ),
        )
    )


@pytest.fixture
def tcp_frame_with_options() -> bytes:
    """Ethernet / IPv4 / TCP with a 12-byte options block and payload."""
    payload = b"GET / HTTP/1.1\r\n"
    tcp = TCP(
        src_port=51888,
        dst_port=80,
        seq=0xD676F671,
        ack=0x0C7A1457,
        data_offset=8,
        reserved=0,
        flags=0x018,
        window=8540,
        checksum=0x2008,
        urgent_pointer=0,
        options=b"\x01\x01\x08\x0a\x00\x08\xca\x61\x00\x01\x69\x2e",
    )
    ip = _ipv4(protocol=6, total_length=20 + 32 + len(payload))
    return bytes(Packet(_eth(0x0800), ip, tcp)) + payload


@pytest.fixture
def udp_frame() -> bytes:
    payload = b"\xaa\xbb"
    udp = UDP(
        src_port=2398, dst_port=53, length=8 + len(payload), checksum=0x3649
    )
    ip = _ipv4(protocol=17, total_length=20 + 8 + len(payload))
    return bytes(Packet(_eth(0x0800), ip, udp)) + payload


@pytest.fixture
def icmpv4_frame() -> bytes:
    icmp = ICMPv4(type=8, code=0, checksum=0x83F7, rest=b"\x00\x01\x00\x01")
    ip = _ipv4(protocol=1, total_length=20 + 8)
    return bytes(Packet(_eth(0x0800), ip, icmp))


@pytest.fixture
def icmpv6_frame() -> bytes:
    icmp = ICMPv6(type=128, code=0, checksum=0x3F69, rest=b"\x76\x20\x01\x00")
    ip = IPv6(
        version=6,
        traffic_class=0,
        flow_label=0,
        payload_length=8,
        next_header=58,
        hop_limit=255,
        src="fe80::1",
        dst="ff02::1",
    )
    return bytes(Packet(_eth(0x86DD), ip, icmp))


@pytest.fixture
def gre_frame() -> bytes:
    """A GRE tunnel (checksum + key present) encapsulating a bare inner
    IPv4 header. No real capture carries GRE (see fixtures/MANIFEST.md),
    so this is hand-built the same way the other synthetic fixtures
    above are."""
    inner = _ipv4(protocol=1, total_length=20)
    gre = GRE(
        flags=0x8000 | 0x2000,  # checksum + key present
        protocol_type=0x0800,
        fields=b"\x00\x00\x00\x00" + b"\x00\x00\x00\x2a",
    )
    outer = _ipv4(protocol=47, total_length=20 + gre.header_len + 20)
    return bytes(Packet(_eth(0x0800), outer, gre)) + bytes(inner)


@pytest.fixture
def igmp_report_frame() -> bytes:
    """An IGMPv2 Membership Report for the mDNS group 224.0.0.251. No
    real capture carries IGMP; hand-built like the other synthetic
    fixtures above."""
    igmp = IGMP(
        type=0x16, max_resp_code=0, checksum=0, body=b"\xe0\x00\x00\xfb"
    )
    ip = _ipv4(protocol=2, total_length=20 + igmp.header_len)
    return bytes(Packet(_eth(0x0800), ip, igmp))


@pytest.fixture
def igmpv3_report_frame() -> bytes:
    """An IGMPv3 Membership Report with one MODE_IS_EXCLUDE group
    record for 224.0.0.1. No real capture carries IGMP; hand-built like
    the other synthetic fixtures above."""
    record = (
        bytes([2, 0])  # record_type=MODE_IS_EXCLUDE, aux_data_len=0 words
        + b"\x00\x00"  # num_sources = 0
        + b"\xe0\x00\x00\x01"  # multicast address 224.0.0.1
    )
    body = b"\x00\x00\x00\x01" + record  # reserved + num_records=1
    igmp = IGMP(type=0x22, max_resp_code=0, checksum=0, body=body)
    ip = _ipv4(protocol=2, total_length=20 + igmp.header_len)
    return bytes(Packet(_eth(0x0800), ip, igmp))


@pytest.fixture
def unknown_ethertype_frame() -> bytes:
    """An LLDP frame: the library does not decode past Ethernet."""
    return bytes(_eth(0x88CC)) + b"\x02\x07\x04\x00\x07\x0d\xaf\xf4\x54"


@pytest.fixture
def truncated_frame(tcp_frame_with_options) -> bytes:
    """A capture cut short in the middle of the TCP header."""
    return tcp_frame_with_options[:40]


FIXTURES = Path(__file__).parent / "fixtures"


def read_pcap(path: Path) -> list[bytes]:
    """Minimal classic-pcap reader for the fixture corpus (test-only;
    independent of the future application pcap module)."""
    data = path.read_bytes()
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    else:
        raise ValueError(f"{path.name}: not a pcap")
    frames = []
    cursor = 24
    while cursor + 16 <= len(data):
        (incl_len,) = struct.unpack_from(f"{endian}I", data, cursor + 8)
        cursor += 16
        frames.append(data[cursor : cursor + incl_len])
        cursor += incl_len
    return frames


def corpus_frames() -> list[tuple[str, int, bytes]]:
    """Every corpus frame as (pcap_name, index, frame_bytes)."""
    return [
        (pcap.name, index, frame)
        for pcap in sorted(FIXTURES.glob("*.pcap"))
        for index, frame in enumerate(read_pcap(pcap))
    ]
