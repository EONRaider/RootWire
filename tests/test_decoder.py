from netprotocols import ARP, TCP, UDP, Ethernet, ICMPv4, ICMPv6, IPv4, IPv6

from packet_sniffer.decoder import decode_frame


def decode(data: bytes):
    return decode_frame(data, number=1, timestamp=0.0, interface="eth0")


class TestDecodeFrame:
    def test_arp_frame(self, arp_frame):
        frame = decode(arp_frame)
        assert [type(layer) for layer in frame.layers] == [Ethernet, ARP]
        assert frame.payload == b""
        assert frame.error is None
        assert not frame.truncated

    def test_tcp_frame_with_options_payload_offset(
        self, tcp_frame_with_options
    ):
        """The payload must start after the 32-byte TCP header — the
        exact slice the old header_len=32-vs-IHL confusion got wrong."""
        frame = decode(tcp_frame_with_options)
        assert [type(layer) for layer in frame.layers] == [
            Ethernet,
            IPv4,
            TCP,
        ]
        tcp = frame.layer(TCP)
        assert tcp is not None and tcp.header_len == 32
        assert frame.payload == b"GET / HTTP/1.1\r\n"

    def test_udp_frame(self, udp_frame):
        frame = decode(udp_frame)
        assert [type(layer) for layer in frame.layers] == [Ethernet, IPv4, UDP]
        assert frame.payload == b"\xaa\xbb"

    def test_icmpv4_frame(self, icmpv4_frame):
        frame = decode(icmpv4_frame)
        assert [type(layer) for layer in frame.layers] == [
            Ethernet,
            IPv4,
            ICMPv4,
        ]

    def test_icmpv6_frame(self, icmpv6_frame):
        frame = decode(icmpv6_frame)
        assert [type(layer) for layer in frame.layers] == [
            Ethernet,
            IPv6,
            ICMPv6,
        ]
        ip = frame.layer(IPv6)
        assert ip is not None and ip.src == "fe80::1"

    def test_unknown_ethertype_stops_chain(self, unknown_ethertype_frame):
        frame = decode(unknown_ethertype_frame)
        assert [type(layer) for layer in frame.layers] == [Ethernet]
        assert frame.payload == unknown_ethertype_frame[14:]
        assert frame.error is None

    def test_truncated_frame_is_diagnosed_not_fatal(self, truncated_frame):
        frame = decode(truncated_frame)
        assert [type(layer) for layer in frame.layers] == [Ethernet, IPv4]
        assert frame.error is not None
        assert "TCP" in frame.error
        assert frame.truncated

    def test_metadata_carried_through(self, arp_frame):
        frame = decode_frame(
            arp_frame, number=42, timestamp=1755772800.5, interface=None
        )
        assert frame.number == 42
        assert frame.timestamp == 1755772800.5
        assert frame.interface is None
        assert frame.length == len(arp_frame)

    def test_frames_do_not_alias_the_capture_buffer(self, udp_frame):
        """Mutating the source buffer after decoding must not change
        the frame — the regression the old yield-self decoder had."""
        buffer = bytearray(udp_frame)
        frame = decode_frame(
            bytes(buffer), number=1, timestamp=0.0, interface=None
        )
        payload_before = frame.payload
        udp_before = frame.layer(UDP)
        buffer[:] = bytes(len(buffer))
        assert frame.payload == payload_before
        assert frame.layer(UDP) == udp_before
