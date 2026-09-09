import io

from netprotocols import DNS, IGMP, TCP, UDP, Packet

from conftest import _eth, _ipv4, ipv4_udp
from rootwire.decoder import decode_frame
from rootwire.output import OutputToScreen


def render(data: bytes, *, display_payload: bool = False) -> str:
    stream = io.StringIO()
    output = OutputToScreen(display_payload=display_payload, stream=stream)
    output.update(decode_frame(data, number=1, timestamp=0, interface="eth0"))
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
        assert "Options: No-Operation, No-Operation, Timestamps" in text

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

    def test_malformed_ip_length_is_diagnosed(self):
        text = render(ipv4_udp(total_length=4))
        assert "Malformed: IPv4 total_length (4)" in text
        assert "smaller than its header (20 bytes)" in text

    def test_dhcp_rendering(self, dhcp_frame):
        text = render(dhcp_frame)
        assert "DHCP ACK" in text
        assert "Client: 00:07:0d:af:f4:54" in text
        assert "XID: 0x3903f326" in text
        assert "Your Addr: 192.168.1.96" in text
        assert "Server Addr: 192.168.1.254" in text
        assert "Options: 3 parsed" in text

    def test_gre_rendering(self, gre_frame):
        text = render(gre_frame)
        assert "GRE (protocol: IPv4)" in text
        assert "Key: 0x0000002a" in text

    def test_igmp_v2_report_rendering(self, igmp_report_frame):
        text = render(igmp_report_frame)
        assert "IGMP IGMPv2 Membership Report" in text
        assert "Group: 224.0.0.251" in text

    def test_igmpv3_report_rendering(self, igmpv3_report_frame):
        text = render(igmpv3_report_frame)
        assert "IGMP IGMPv3 Membership Report" in text
        assert "Record: MODE_IS_EXCLUDE 224.0.0.1" in text

    def test_igmpv3_malformed_body_is_diagnosed(self):
        """A v3 report declaring one group record (reserved + count),
        but with no record bytes following, must render a [!]
        diagnostic instead of raising out of the renderer."""
        igmp = IGMP(
            type=0x22, max_resp_code=0, checksum=0, body=b"\x00\x00\x00\x01"
        )
        ip = _ipv4(protocol=2, total_length=20 + igmp.header_len)
        frame = bytes(Packet(_eth(0x0800), ip, igmp))
        text = render(frame)
        assert "[!] Body malformed:" in text


class TestDNSRendering:
    def test_dns_response_renders_questions_and_answers(self, request):
        from conftest import FIXTURES, read_pcap

        pcap = FIXTURES / "udp_dns.pcap"
        texts = [render(frame) for frame in read_pcap(pcap)]
        assert any("DNS response" in text for text in texts)
        assert any("Q: " in text for text in texts)
        assert any("A: " in text for text in texts)

    def test_dns_question_name_ansi_escapes_are_neutralized(self):
        """A DNS name is fully attacker-controlled (it comes straight
        off the wire from whatever server answered) -- a malicious
        label must not smuggle ANSI escapes into the terminal, the
        same guarantee -d's payload display already has."""
        evil = b"\x1b[31mowned\x1b[0m"
        qname = bytes([len(evil)]) + evil + b"\x00"
        sections = qname + b"\x00\x01" + b"\x00\x01"  # QTYPE=A, QCLASS=IN
        dns = DNS(
            transaction_id=1,
            flags=0x8180,
            qdcount=1,
            ancount=0,
            nscount=0,
            arcount=0,
            sections=sections,
        )
        udp = UDP(
            src_port=53, dst_port=1234, length=8 + dns.header_len, checksum=0
        )
        ip = _ipv4(protocol=17, total_length=20 + 8 + dns.header_len)
        frame = bytes(Packet(_eth(0x0800), ip, udp, dns))
        text = render(frame)
        assert "\x1b" not in text
        assert "\\x1b[31mowned\\x1b[0m" in text


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


class TestNDPRendering:
    def test_neighbor_solicitation_shows_target_and_link_layer_option(self):
        from conftest import FIXTURES, read_pcap

        frame = read_pcap(FIXTURES / "ipv6_ndp_mld.pcap")[0]
        text = render(frame)
        assert "Neighbor Solicitation" in text
        assert "Target: 2804:14d:bac3:8ada:df3:1895:3c4e:7470" in text
        assert "Option: Source Link-Layer Address (84:01:12:be:7e:d9)" in text

    def test_neighbor_advertisement_shows_target_link_layer_option(self):
        from conftest import FIXTURES, read_pcap

        frame = read_pcap(FIXTURES / "ipv6_ndp_mld.pcap")[5]
        text = render(frame)
        assert "Neighbor Advertisement" in text
        assert "Target: fe80::f6d7:8b9a:993e:5efa" in text
        assert "Option: Target Link-Layer Address (a8:3b:76:da:a6:9d)" in text

    def test_echo_frames_show_no_ndp_fields(self, icmpv6_frame):
        """Only NDP message types carry a target/options -- an ordinary
        echo must not print either line."""
        text = render(icmpv6_frame)
        assert "Target:" not in text
        assert "Option:" not in text


class TestOptionRendering:
    def test_ipv4_router_alert_option_decoded(self):
        udp = UDP(src_port=1234, dst_port=53, length=8, checksum=0)
        ip = _ipv4(
            protocol=17, total_length=24 + 8, options=b"\x94\x04\x00\x00"
        )
        text = render(bytes(Packet(_eth(0x0800), ip, udp)))
        assert "Options: Router Alert (0)" in text

    def test_ipv4_malformed_options_diagnosed(self):
        """Kind 7 (Record Route) declares a length of 10 but only 4
        option bytes are actually present -- parsed_options must raise,
        and the renderer must turn that into a diagnostic, not a
        traceback."""
        udp = UDP(src_port=1234, dst_port=53, length=8, checksum=0)
        ip = _ipv4(
            protocol=17, total_length=24 + 8, options=b"\x07\x0a\x00\x00"
        )
        text = render(bytes(Packet(_eth(0x0800), ip, udp)))
        assert "[!] Options malformed" in text

    def test_tcp_sack_option_decoded(self):
        """NOP, NOP, SACK (one block: 100-200) -- exercises the
        tuple-of-tuples value formatting, distinct from Timestamps'
        plain pair (already covered by test_tcp_rendering_includes_
        ip_and_flags)."""
        options = b"\x01\x01\x05\x0a\x00\x00\x00\x64\x00\x00\x00\xc8"
        tcp = TCP(
            src_port=1234,
            dst_port=80,
            seq=0,
            ack=0,
            data_offset=5 + len(options) // 4,
            reserved=0,
            flags=0x010,
            window=1024,
            checksum=0,
            urgent_pointer=0,
            options=options,
        )
        ip = _ipv4(protocol=6, total_length=20 + tcp.header_len)
        text = render(bytes(Packet(_eth(0x0800), ip, tcp)))
        assert "Options: No-Operation, No-Operation, SACK ((100, 200),)" in text


class TestChecksumVerification:
    def test_valid_udp_checksum_shows_no_mismatch(self):
        payload = b"hello"
        udp = UDP(
            src_port=1234, dst_port=53, length=8 + len(payload), checksum=0
        )
        ip = _ipv4(protocol=17, total_length=20 + 8 + len(payload))
        packet = Packet(_eth(0x0800), ip, udp).with_checksums(payload)
        assert "mismatch" not in render(bytes(packet) + payload)

    def test_corrupted_udp_checksum_is_flagged(self):
        payload = b"hello"
        udp = UDP(
            src_port=1234, dst_port=53, length=8 + len(payload), checksum=0
        )
        ip = _ipv4(protocol=17, total_length=20 + 8 + len(payload))
        packet = Packet(_eth(0x0800), ip, udp).with_checksums(payload)
        frame = bytearray(bytes(packet) + payload)
        frame[40] ^= 0xFF  # UDP checksum's high byte (14 eth + 20 ip + 6)
        text = render(bytes(frame))
        assert "UDP" in text
        assert "[!] mismatch" in text

    def test_corrupted_ipv4_header_checksum_is_flagged(self, udp_frame):
        frame = bytearray(udp_frame)
        frame[24] ^= 0xFF  # IPv4 checksum's high byte (14 eth + 10)
        text = render(bytes(frame))
        assert "IPv4" in text
        assert "[!] mismatch" in text

    def test_fragment_checksums_are_not_verified(self):
        """A fragment's ICMP checksum covers the *reassembled* message,
        which RootWire never builds -- verifying it against a lone
        fragment's bytes would always disagree, so it must not even be
        attempted (the real corpus's checksums are independently known
        good; a "mismatch" here would be this feature lying)."""
        from conftest import FIXTURES, read_pcap

        for pcap_name in ("ipv4_fragments.pcap", "ipv6_fragments.pcap"):
            for frame in read_pcap(FIXTURES / pcap_name):
                assert "mismatch" not in render(frame)
