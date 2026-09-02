import io

from netprotocols import UDP, Packet

from conftest import _eth, _ipv4
from rootwire.decoder import decode_frame
from rootwire.output import OutputToScreen


def render(data: bytes, *, display_payload: bool = False) -> str:
    stream = io.StringIO()
    output = OutputToScreen(display_payload=display_payload, stream=stream)
    output.update(decode_frame(data, number=1, timestamp=0.0, interface="eth0"))
    return stream.getvalue()


def _frame_with_payload(payload: bytes) -> bytes:
    """Ethernet / IPv4 / UDP carrying an arbitrary, attacker-shaped
    payload — the bytes a hostile peer controls end to end. The ports are
    unassigned so the decoder leaves the payload as raw frame bytes rather
    than handing it to an upper-layer parser."""
    udp = UDP(
        src_port=40000, dst_port=40001, length=8 + len(payload), checksum=0
    )
    ip = _ipv4(protocol=17, total_length=20 + 8 + len(payload))
    return bytes(Packet(_eth(0x0800), ip, udp)) + payload


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

    def test_payload_ansi_escapes_are_neutralized(self):
        """An attacker-controlled payload must not smuggle ANSI escape
        sequences into the analyst's terminal via -d."""
        frame = _frame_with_payload(b"\x1b[2J\x1b[31mowned\x1b[0m")
        text = render(frame, display_payload=True)
        assert "\x1b" not in text  # no raw ESC reaches the terminal
        assert "\\x1b[2J" in text  # rendered as a visible escape instead
        assert "owned" in text  # printable content still shown

    def test_payload_carriage_return_is_escaped(self):
        """CR can rewrite the current line; it must not pass through."""
        frame = _frame_with_payload(b"real\rspoofed")
        text = render(frame, display_payload=True)
        assert "\r" not in text
        assert "\\x0d" in text

    def test_payload_c1_and_bidi_controls_are_escaped(self):
        """C1 (U+0080 to U+009F) and bidi overrides are non-printable."""
        frame = _frame_with_payload("\x85\u202eevil".encode())
        text = render(frame, display_payload=True)
        assert "\x85" not in text and "\u202e" not in text
        assert "\\x85" in text and "\\u202e" in text

    def test_payload_newlines_survive_sanitization(self):
        """Newlines are the intended line structure and are preserved."""
        frame = _frame_with_payload(b"line-one\nline-two")
        text = render(frame, display_payload=True)
        assert "line-one" in text and "line-two" in text

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
