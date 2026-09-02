"""VLAN-tagged frames decode end-to-end: the tag is a first-class layer
and the IP payload behind it is reached (single tag and QinQ)."""

import struct

from rootwire.decoder import decode_frame

ETH = struct.Struct("!6s6sH")
TAG = struct.Struct("!HH")

DST = b"\xaa" * 6
SRC = b"\xbb" * 6


def tagged(inner_ethertype: int, payload: bytes, tci: int = 0x002A) -> bytes:
    return ETH.pack(DST, SRC, 0x8100) + TAG.pack(tci, inner_ethertype) + payload


def ipv4(payload: bytes, proto: int = 6) -> bytes:
    return (
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(payload),
            0x1234,
            0,
            64,
            proto,
            0,
            b"\xc0\xa8\x01\x01",
            b"\xc0\xa8\x01\x02",
        )
        + payload
    )


def test_single_tagged_frame_decodes_to_tcp() -> None:
    tcp = struct.pack("!HHIIHHHH", 12345, 80, 1, 0, 0x5002, 65535, 0, 0)
    frame = decode_frame(
        tagged(0x0800, ipv4(tcp) + b"GET / HTTP/1.1"),
        number=1,
        timestamp=0.0,
        interface="test",
    )
    names = [type(layer).__name__ for layer in frame.layers]
    assert names == ["Ethernet", "VLAN", "IPv4", "TCP"]
    assert frame.error is None


def test_qinq_frame_decodes_one_layer_per_tag() -> None:
    udp = struct.pack("!HHHH", 5353, 5353, 18, 0) + b"0123456789"
    outer = ETH.pack(DST, SRC, 0x88A8) + TAG.pack(0, 0x8100)
    inner = TAG.pack(0x002A, 0x0800) + ipv4(udp, proto=17)
    frame = decode_frame(
        outer + inner, number=1, timestamp=0.0, interface="test"
    )
    names = [type(layer).__name__ for layer in frame.layers]
    assert names == ["Ethernet", "VLAN", "VLAN", "IPv4", "UDP"]


def test_tagged_frame_truncation_still_detected() -> None:
    udp = struct.pack("!HHHH", 5353, 5353, 18, 0) + b"0123456789"
    full = tagged(0x0800, ipv4(udp))
    frame = decode_frame(full[:-5], number=1, timestamp=0.0, interface="test")
    assert frame.truncated is True
