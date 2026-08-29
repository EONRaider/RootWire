import io

from packet_sniffer.decoder import decode_frame
from packet_sniffer.output import OutputToScreen


def render(data: bytes, *, display_payload: bool = False) -> str:
    stream = io.StringIO()
    output = OutputToScreen(display_payload=display_payload, stream=stream)
    output.update(decode_frame(data, number=1, timestamp=0.0, interface="eth0"))
    return stream.getvalue()


class TestOutputToScreen:
    def test_arp_request_rendering(self, arp_frame):
        text = render(arp_frame)
        assert "Frame #1" in text
        assert "Ethernet 00:07:0d:af:f4:54 -> ff:ff:ff:ff:ff:ff" in text
        assert "ARP who has 192.168.1.254? tell 192.168.1.96" in text

    def test_tcp_rendering_includes_ip_and_flags(self, tcp_frame_with_options):
        text = render(tcp_frame_with_options)
        assert "IPv4 192.168.1.96 -> 192.168.1.254" in text
        assert "TCP 51888 -> 80" in text
        assert "PSH ACK" in text
        assert "Options: 12 bytes" in text

    def test_icmpv6_rendering_shows_enclosing_ip_route(self, icmpv6_frame):
        """The old renderer crashed on IPv6 (flabel_txt_str) and ICMP
        lines need addresses from the IP layer, not the ICMP layer."""
        text = render(icmpv6_frame)
        assert "IPv6 fe80::1 -> ff02::1" in text
        assert "ICMPv6 fe80::1 -> ff02::1" in text
        assert "Echo Request" in text

    def test_payload_rendering_is_opt_in(self, tcp_frame_with_options):
        assert "GET / HTTP" not in render(tcp_frame_with_options)
        assert "GET / HTTP" in render(
            tcp_frame_with_options, display_payload=True
        )

    def test_unknown_and_truncated_diagnostics(
        self, unknown_ethertype_frame, truncated_frame
    ):
        assert "EtherType: 0x88cc" in render(unknown_ethertype_frame)
        truncated_text = render(truncated_frame)
        assert "Malformed header: TCP" in truncated_text
        assert "Truncated" in truncated_text


class TestExtensionHeaderRendering:
    def test_mld_frame_renders_hop_by_hop(self, request):
        from conftest import FIXTURES, read_pcap

        frame = read_pcap(FIXTURES / "ipv6_mld.pcap")[0]
        text = render(frame)
        assert "IPv6 Hop-by-Hop Options" in text
        assert "Next Header: IPv6-ICMP" in text
        assert "ICMPv6" in text

    def test_fragment_positions_are_labeled(self):
        from conftest import FIXTURES, read_pcap

        texts = [
            render(frame)
            for frame in read_pcap(FIXTURES / "ipv6_fragments.pcap")
        ]
        assert any("first fragment" in text for text in texts)
        assert any("fragment at offset" in text for text in texts)
