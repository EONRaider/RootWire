"""Generate the length-prefixed frame batch both benchmarks replay.

Run inside the project environment: uv run python benchmarks/generate_frames.py
"""

import random
import struct
from pathlib import Path

from netprotocols import ARP, TCP, UDP, Ethernet, ICMPv4, IPv4, Packet

random.seed(1701)
OUT = Path(__file__).parent / "frames.bin"


def eth(ethertype: int) -> Ethernet:
    return Ethernet(
        dst="ff:ff:ff:ff:ff:ff", src="00:07:0d:af:f4:54", ethertype=ethertype
    )


def ipv4(protocol: int, total_length: int) -> IPv4:
    return IPv4(
        version=4,
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=total_length,
        identification=random.randrange(65536),
        flags=2,
        fragment_offset=0,
        ttl=64,
        protocol=protocol,
        checksum=0x2B51,
        src="192.168.1.96",
        dst="192.168.1.254",
    )


def build() -> list[bytes]:
    payload = bytes(random.randrange(256) for _ in range(200))
    tcp = TCP(
        src_port=51888,
        dst_port=443,
        seq=1,
        ack=2,
        data_offset=8,
        reserved=0,
        flags=0x018,
        window=64240,
        checksum=0,
        urgent_pointer=0,
        options=b"\x01\x01\x08\x0a\x00\x08\xca\x61\x00\x01\x69\x2e",
    )
    udp = UDP(src_port=2398, dst_port=53, length=8 + 60, checksum=0)
    icmp = ICMPv4(type=8, code=0, checksum=0, rest=b"\x00\x01\x00\x01")
    arp = ARP(
        htype=1,
        ptype=0x0800,
        hlen=6,
        plen=4,
        oper=1,
        sha="00:07:0d:af:f4:54",
        spa="192.168.1.96",
        tha="00:00:00:00:00:00",
        tpa="192.168.1.254",
    )
    return [
        bytes(Packet(eth(0x0800), ipv4(6, 20 + 32 + 200), tcp)) + payload,
        bytes(Packet(eth(0x0800), ipv4(17, 20 + 8 + 60), udp)) + payload[:60],
        bytes(Packet(eth(0x0800), ipv4(1, 20 + 8), icmp)),
        bytes(Packet(eth(0x0806), arp)),
    ]


def main() -> None:
    frames = build() * 2_500  # 10,000 frames per pass
    with OUT.open("wb") as f:
        for frame in frames:
            f.write(struct.pack("!H", len(frame)))
            f.write(frame)
    print(f"wrote {len(frames)} frames to {OUT}")


if __name__ == "__main__":
    main()
