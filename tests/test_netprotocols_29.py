"""The safety floor for NETProtocols 2.9: what the upgrade from 2.2.1
changed underneath RootWire, pinned frame by frame.

- Port-dispatched application decoders (TLS on 443, BGP on 179, ...)
  are best-effort: a bare ACK or continuation segment they cannot decode
  is a *miss*, never a malformed frame (R1).
- A dense BGP/STUN/TLS segment that outnumbers the layer ceiling is a
  miss too; any other overflow stays an error (R7).
- Checksums are verified against the *nearest* enclosing IP header, the
  route's final destination behind an IPv6 Routing header, and never
  over the frame's trailer (padding, FCS) (R3, R5).
- NDJSON survives nested ``bytes`` (LLDP/CDP TLVs) (C3).
- Library diagnostics are sanitized before they reach a terminal, and
  lazily parsed sections are contained by one guard (C1, C2).
"""

from __future__ import annotations

import io
import json

import netprotocols
import pytest
from netprotocols import (
    BGP,
    CDP,
    DHCP,
    DNS,
    HSRP,
    IGMP,
    LLDP,
    NTP,
    RADIUS,
    RIP,
    STUN,
    TCP,
    TFTP,
    TLS,
    UDP,
    VLAN,
    VXLAN,
    DNSOverTCP,
    Ethernet,
    ICMPv4,
    IPv4,
    IPv6,
    IPv6HopByHopOptions,
    IPv6Routing,
    Packet,
    Protocol,
    TruncatedHeaderError,
    compute,
)

from conftest import FIXTURES, _eth, _ipv4, corpus_frames, read_pcap
from rootwire.decoder import _BEST_EFFORT_L7, _MAX_LAYERS, decode_frame
from rootwire.frame import DecodedFrame
from rootwire.output import (
    OutputToNDJSON,
    OutputToScreen,
    StatsCollector,
    _json_default,
)

_V6_SRC = "2001:db8::1"
_V6_DST = "2001:db8::2"
_V6_FINAL = "2001:db8::99"


def decode(data: bytes) -> DecodedFrame:
    return decode_frame(data, number=1, timestamp=0, interface="eth0")


def render(data: bytes | DecodedFrame, *, display_payload: bool = False) -> str:
    """Render *data* (raw bytes, or an already decoded frame) to text."""
    frame = data if isinstance(data, DecodedFrame) else decode(data)
    stream = io.StringIO()
    OutputToScreen(display_payload=display_payload, stream=stream).update(frame)
    return stream.getvalue()


def malformed_count(*frames: bytes) -> str:
    """The StatsCollector report for *frames*, decoded in order."""
    stats = StatsCollector()
    for data in frames:
        stats.update(decode(data))
    stream = io.StringIO()
    stats.report(stream)
    return stream.getvalue()


def _tcp(dst_port: int, *, flags: int = 0x010) -> TCP:
    return TCP(
        src_port=50000,
        dst_port=dst_port,
        seq=1,
        ack=1,
        data_offset=5,
        reserved=0,
        flags=flags,
        window=512,
        checksum=0,
        urgent_pointer=0,
    )


def _udp(dst_port: int, payload_len: int) -> UDP:
    return UDP(
        src_port=50000, dst_port=dst_port, length=8 + payload_len, checksum=0
    )


def _ipv6(next_header: int, payload_length: int) -> IPv6:
    return IPv6(
        version=6,
        traffic_class=0,
        flow_label=0,
        payload_length=payload_length,
        next_header=next_header,
        hop_limit=64,
        src=_V6_SRC,
        dst=_V6_DST,
    )


def _with_checksums(*layers: Protocol, payload: bytes = b"") -> bytes:
    """Wire bytes with every checksum filled in by the library itself:
    the oracle these tests verify RootWire's rendering against."""
    return bytes(Packet(*layers).with_checksums(payload)) + payload


def tcp_segment(dst_port: int, payload: bytes = b"", *, v6: bool = False):
    """An Ethernet/IP/TCP bare ACK (or data segment) to *dst_port* with
    every checksum filled in by the library."""
    tcp = _tcp(dst_port)
    if v6:
        ip: Protocol = _ipv6(6, 20 + len(payload))
        return _with_checksums(_eth(0x86DD), ip, tcp, payload=payload)
    ip = _ipv4(protocol=6, total_length=20 + 20 + len(payload))
    return _with_checksums(_eth(0x0800), ip, tcp, payload=payload)


def udp_datagram(dst_port: int, payload: bytes = b"", *, v6: bool = False):
    """An Ethernet/IP/UDP datagram to *dst_port* with every checksum
    filled in by the library."""
    udp = _udp(dst_port, len(payload))
    if v6:
        ip: Protocol = _ipv6(17, 8 + len(payload))
        return _with_checksums(_eth(0x86DD), ip, udp, payload=payload)
    ip = _ipv4(protocol=17, total_length=20 + 8 + len(payload))
    return _with_checksums(_eth(0x0800), ip, udp, payload=payload)


_TCP_L7_PORTS = sorted(
    port
    for port, cls in netprotocols.DEFAULT.table("tcp.port").items()
    if cls in _BEST_EFFORT_L7
)
_UDP_L7_PORTS = sorted(
    port
    for port, cls in netprotocols.DEFAULT.table("udp.port").items()
    if cls in _BEST_EFFORT_L7
)


class TestBestEffortSet:
    def test_derived_from_the_registry_covers_every_new_port_decoder(self):
        """Derived at import from the default registry, not hardcoded;
        at 2.9.0 that is exactly the nine port-heuristic decoders added
        since 2.2.1. A superset check, so a future release registering
        another one keeps this green and is covered automatically."""
        assert {
            BGP,
            HSRP,
            NTP,
            RADIUS,
            RIP,
            STUN,
            TFTP,
            TLS,
            VXLAN,
        } <= _BEST_EFFORT_L7

    def test_pre_2_3_port_decoders_stay_authoritative(self):
        """DNS, DNS-over-TCP and DHCP malformations predate the upgrade
        and have always been real signal; they must not be silenced."""
        assert not {DNS, DNSOverTCP, DHCP} & _BEST_EFFORT_L7

    def test_only_port_dispatched_classes(self):
        """EtherType/IP-protocol decoders (LLDP, CDP, OSPF, ...) are
        authoritative dispatch, not a port guess: never best-effort."""
        assert not {LLDP, CDP, IPv4, IPv6, TCP, UDP} & _BEST_EFFORT_L7

    def test_tables_actually_dispatch_on_those_ports(self):
        """The well-known ports these tests flood really are dispatched."""
        assert {443, 179, 3478} <= set(_TCP_L7_PORTS)
        assert {123, 1812, 1813, 1985, 69, 520, 4789, 3478} <= set(
            _UDP_L7_PORTS
        )


class TestBareSegmentFlood:
    """R1: at 2.2.1 none of these ports had a decoder, so the walk ended
    cleanly at TCP/UDP. At 2.9.0 the library hands the empty payload to
    TLS/BGP/STUN/NTP/... unconditionally, which raises."""

    @pytest.mark.parametrize("v6", [False, True], ids=["ipv4", "ipv6"])
    @pytest.mark.parametrize("port", _TCP_L7_PORTS)
    def test_bare_ack_is_a_miss_not_malformed(self, port, v6):
        """An empty TCP segment to a best-effort port ends at TCP, clean."""
        frame = decode(tcp_segment(port, v6=v6))
        assert type(frame.layers[-1]) is TCP
        assert frame.error is None
        assert frame.l7_miss is not None
        assert frame.payload == b""
        text = render(frame)
        assert "[!]" not in text
        assert "[~]" not in text  # nothing undecoded to explain

    @pytest.mark.parametrize("v6", [False, True], ids=["ipv4", "ipv6"])
    @pytest.mark.parametrize("port", _UDP_L7_PORTS)
    def test_empty_datagram_is_a_miss_not_malformed(self, port, v6):
        """An empty UDP datagram to a best-effort port ends at UDP, clean."""
        frame = decode(udp_datagram(port, v6=v6))
        assert type(frame.layers[-1]) is UDP
        assert frame.error is None
        assert frame.l7_miss is not None
        assert "[!]" not in render(frame)

    def test_flood_counts_nothing_as_malformed(self):
        """Thousands of bare segments across every port: zero malformed."""
        frames = [tcp_segment(p) for p in _TCP_L7_PORTS] * 50 + [
            udp_datagram(p, v6=True) for p in _UDP_L7_PORTS
        ] * 50
        report = malformed_count(*frames)
        assert f"{len(frames)} frames" in report
        assert "malformed" not in report

    def test_continuation_segment_keeps_its_payload(self):
        """A segment that continues a TLS record begun earlier: bytes
        the port suggests are TLS, but are not a record header."""
        middle = bytes(range(200, 256)) * 3
        frame = decode(tcp_segment(443, middle))
        assert frame.error is None
        assert frame.l7_miss is not None
        assert frame.payload == middle
        text = render(frame, display_payload=True)
        assert "[!]" not in text
        assert "[~] Payload left undecoded" in text

    def test_truncated_dns_is_still_an_error(self):
        """The excluded classes keep their diagnosis: three bytes on UDP
        53 cannot be a 12-byte DNS header, and that is real signal."""
        frame = decode(udp_datagram(53, b"\x12\x34\x01"))
        assert frame.error is not None and "DNS" in frame.error
        assert frame.l7_miss is None
        assert "malformed: 1" in malformed_count(udp_datagram(53, b"\x00"))

    def test_truncated_dns_over_tcp_is_still_an_error(self):
        """One byte on TCP 53 cannot be a DNS-over-TCP length prefix plus
        message; that stays a real error."""
        frame = decode(tcp_segment(53, b"\x00"))
        assert frame.error is not None
        assert frame.l7_miss is None

    def test_stop_inside_a_tunnel_is_classified_by_its_class(self):
        """A bare inner datagram to NTP inside VXLAN: the miss is NTP's,
        three tunnel layers deep, and still not malformed."""
        inner = _with_checksums(
            _eth(0x0800), _ipv4(protocol=17, total_length=28), _udp(123, 0)
        )
        vxlan = VXLAN(flags=0x08, reserved1=0, vni=42, reserved2=0)
        outer = _with_checksums(
            _eth(0x0800),
            _ipv4(protocol=17, total_length=20 + 8 + 8 + len(inner)),
            _udp(4789, 8 + len(inner)),
            vxlan,
            payload=inner,
        )
        frame = decode(outer)
        assert [type(layer) for layer in frame.layers][-3:] == [
            Ethernet,
            IPv4,
            UDP,
        ]
        assert frame.error is None and frame.l7_miss is not None


def _keepalives(count: int) -> bytes:
    keepalive = BGP(marker=b"\xff" * 16, length=19, type=BGP.KEEPALIVE)
    return bytes(keepalive) * count


class TestLayerCeiling:
    """R7: the ceiling matches the library's default, and a dense
    self-chaining segment past it is a miss, not malformed."""

    def test_ceiling_is_at_least_the_library_default(self):
        """RootWire never caps below the library's own default depth."""
        assert _MAX_LAYERS >= netprotocols.MAX_DEPTH

    def test_dense_bgp_segment_is_benign(self):
        """76 KEEPALIVEs fill a 1448-byte segment (the library's own
        worked example): Ethernet, IPv4, TCP and 29 BGP layers fit; the
        other 47 messages stay payload."""
        segment = tcp_segment(179, _keepalives(76))
        frame = decode(segment)
        assert len(frame.layers) == _MAX_LAYERS
        assert all(isinstance(layer, BGP) for layer in frame.layers[3:])
        assert frame.error is None
        assert frame.l7_miss is not None
        assert f"after {_MAX_LAYERS} headers" in frame.l7_miss
        assert frame.payload == _keepalives(76 - (_MAX_LAYERS - 3))
        assert "malformed" not in malformed_count(segment)
        assert "[!]" not in render(frame)

    def test_bgp_segment_that_fits_decodes_whole(self):
        """29 messages exactly fill the room the ceiling leaves -- the
        boundary is not an overflow."""
        frame = decode(tcp_segment(179, _keepalives(_MAX_LAYERS - 3)))
        assert len(frame.layers) == _MAX_LAYERS
        assert frame.error is None and frame.l7_miss is None
        assert frame.payload == b""

    def test_deep_non_l7_chain_reaching_an_l7_port_is_an_error(self):
        """Hop-by-hop headers fill the budget so the overflow lands just
        as TLS would come next: the depth is the outer chain's fault,
        not record density, so it stays malformed. The last decoded
        layer (TCP) is not the next class (TLS) -- that is the test."""
        hbh_count = _MAX_LAYERS - 3  # Ethernet, IPv6, ..., TCP
        hbh = b"\x00\x00\x01\x04\x00\x00\x00\x00"
        chain = hbh * (hbh_count - 1) + b"\x06" + hbh[1:]
        tcp = bytes(_tcp(443))
        ip = _ipv6(0, len(chain) + len(tcp))
        frame = decode(bytes(_eth(0x86DD)) + bytes(ip) + chain + tcp)
        assert type(frame.layers[-1]) is TCP
        assert isinstance(frame.layers[-2], IPv6HopByHopOptions)
        assert frame.error is not None
        assert "TLS next" in frame.error
        assert frame.l7_miss is None

    def test_vxlan_nesting_bomb_stays_an_error(self):
        """VXLAN in VXLAN in ...: each level is 4 layers, the 33rd would
        be another Ethernet. Ethernet is not best-effort, so the overflow
        is an error even though VXLAN itself is."""
        data = b""
        for _ in range(9):
            udp_len = 8 + 8 + len(data)
            data = (
                bytes(_eth(0x0800))
                + bytes(_ipv4(protocol=17, total_length=20 + udp_len))
                + bytes(_udp(4789, 8 + len(data)))
                + bytes(VXLAN(flags=0x08, reserved1=0, vni=1, reserved2=0))
                + data
            )
        frame = decode(data)
        assert len(frame.layers) == _MAX_LAYERS
        assert isinstance(frame.layers[-1], VXLAN)
        assert frame.error is not None and "Ethernet next" in frame.error
        assert frame.l7_miss is None


class TestLyingLength:
    """R2: a lying length is diagnosed once on screen, counted once in
    stats, and stops the walk at the header that told the lie."""

    def test_lying_udp_length_stops_at_udp(self):
        """UDP Length 1-7 is shorter than the UDP header itself."""
        udp = UDP(src_port=40000, dst_port=40001, length=3, checksum=0)
        data = bytes(
            Packet(_eth(0x0800), _ipv4(protocol=17, total_length=30), udp)
        ) + bytes(2)
        frame = decode(data)
        assert type(frame.layers[-1]) is UDP
        assert frame.error is not None and "UDP length 3" in frame.error
        assert frame.l7_miss is None
        assert "malformed: 1" in malformed_count(data)

    def test_lying_ipv4_length_counts_once(self):
        """A lying IPv4 length is one malformed frame, not two."""
        from conftest import ipv4_udp

        report = malformed_count(ipv4_udp(total_length=4))
        assert "malformed: 1," in report

    def test_tso_zero_length_still_exempt(self):
        """total_length 0 (TSO) is not a lie and stops nothing."""
        from conftest import ipv4_udp

        frame = decode(ipv4_udp(total_length=0))
        assert frame.error is None and not frame.malformed_length
        assert type(frame.layers[-1]) is UDP


class TestChecksumContext:
    """R3/R5/C4 (checksum half): verify the way the library fills."""

    def test_padded_bare_ack_verifies(self):
        """A 54-byte bare ACK padded to the 60-byte Ethernet minimum.
        Before the trailer was split out, the 6 pad bytes were summed as
        TCP payload -- a false mismatch on ordinary traffic."""
        padding = b"\xde\xad\xbe\xef\x00\x01"
        frame = decode(tcp_segment(8080) + padding)
        assert frame.trailer == padding
        assert frame.payload == b""
        assert "mismatch" not in render(frame)

    def test_padded_icmpv4_echo_verifies(self):
        """An echo request padded to 60 bytes with non-zero fill verifies:
        the sum ends at the IPv4 header's declared end."""
        icmp = ICMPv4(type=8, code=0, checksum=0, rest=b"\x00\x01\x00\x01")
        ip = _ipv4(protocol=1, total_length=28)
        data = _with_checksums(_eth(0x0800), ip, icmp) + b"\xff" * 18
        frame = decode(data)
        assert len(frame.trailer) == 18
        assert "mismatch" not in render(frame)

    def test_padded_igmp_report_verifies(self):
        """An IGMPv2 report padded to 60 bytes with non-zero fill verifies."""
        igmp = IGMP(
            type=0x16, max_resp_code=0, checksum=0, body=b"\xe0\0\0\xfb"
        )
        ip = _ipv4(protocol=2, total_length=28)
        data = _with_checksums(_eth(0x0800), ip, igmp) + b"\xab" * 18
        text = render(data)
        assert "IGMP" in text and "mismatch" not in text

    def test_bad_igmp_checksum_is_flagged(self):
        """A wrong IGMP checksum is flagged with the expected value."""
        igmp = IGMP(
            type=0x16, max_resp_code=0, checksum=0x1234, body=b"\xe0\0\0\xfb"
        )
        ip = _ipv4(protocol=2, total_length=28)
        data = bytes(Packet(_eth(0x0800), ip, igmp))
        assert "Checksum: 0x1234 [!] mismatch" in render(data)

    @pytest.mark.parametrize("transport", ["udp", "tcp"])
    def test_checksum_behind_routing_header_uses_final_destination(
        self, transport
    ):
        """RFC 8200 §8.1: behind a Routing header with segments left, the
        pseudo-header carries the final destination, not IPv6.dst."""
        payload = b"routed"
        upper: Protocol = (
            _udp(40001, len(payload)) if transport == "udp" else _tcp(40001)
        )
        proto = 17 if transport == "udp" else 6
        address = IPv6(
            version=6,
            traffic_class=0,
            flow_label=0,
            payload_length=0,
            next_header=0,
            hop_limit=0,
            src="::",
            dst=_V6_FINAL,
        )
        final = bytes(address)[24:40]
        routing = IPv6Routing(
            next_header=proto,
            hdr_ext_len=2,
            routing_type=0,
            segments_left=1,
            data=b"\x00" * 4 + final,
        )
        # Guard against a vacuous pass: if the library could not read a
        # final destination out of this RH0 data, both the oracle and
        # RootWire would silently fall back to IPv6.dst and agree.
        assert routing.final_destination(_V6_DST) == _V6_FINAL
        ip = _ipv6(43, routing.header_len + upper.header_len + len(payload))
        data = _with_checksums(
            _eth(0x86DD), ip, routing, upper, payload=payload
        )
        frame = decode(data)
        assert isinstance(frame.layers[2], IPv6Routing)
        assert "mismatch" not in render(frame)

    def test_corpus_has_no_checksum_mismatch(self):
        """Upstream's corpus guarantees every non-fragment checksum
        verifies (MANIFEST.md), so any mismatch here is RootWire's bug.
        At 2.2.1-era rendering this caught two: inner UDP in VXLAN and
        TCP behind AH tunnel mode, both verified against the outer IP."""
        offenders = []
        for name, index, data in corpus_frames():
            for line in render(data).splitlines():
                if "mismatch" in line:
                    offenders.append(f"{name}#{index}: {line.strip()}")
        assert not offenders, "\n".join(offenders)


def _vxlan_around(inner: bytes, *, udp_checksum: int | None = None) -> bytes:
    """Outer Ethernet/IPv4/UDP 4789/VXLAN carrying *inner* (a whole
    Ethernet frame, padding included) as the UDP payload. The outer UDP
    checksum is the library's own computation over every byte the UDP
    Length covers, unless *udp_checksum* overrides it."""
    vxlan = VXLAN(flags=0x08, reserved1=0, vni=7, reserved2=0)
    body = bytes(vxlan) + inner
    udp = _udp(4789, len(body))
    ip = _ipv4(protocol=17, total_length=20 + 8 + len(body))
    ip = Packet(_eth(0x0800), ip).with_checksums().layers[1]
    assert isinstance(ip, IPv4)
    checksum = compute(udp, ip=ip, payload=body)
    udp = UDP(
        src_port=udp.src_port,
        dst_port=udp.dst_port,
        length=udp.length,
        checksum=checksum if udp_checksum is None else udp_checksum,
    )
    return bytes(_eth(0x0800)) + bytes(ip) + bytes(udp) + body


class TestPerLayerContext:
    """Each layer is judged by the headers that enclose *it*, not by
    frame-wide facts (first IP, frame trailer, any fragment anywhere)."""

    def test_outer_udp_checksum_covers_inner_frame_padding(self):
        """The inner Ethernet frame is padded to 60 bytes. Its padding is
        the frame's trailer (past the inner IPv4's declared end) but lies
        inside the outer UDP datagram, so the outer checksum covers it."""
        icmp = ICMPv4(type=8, code=0, checksum=0, rest=b"\x00\x01\x00\x01")
        inner = _with_checksums(
            _eth(0x0800), _ipv4(protocol=1, total_length=28), icmp
        )
        inner += b"\x5a" * (60 - len(inner))
        frame = decode(_vxlan_around(inner))
        assert len(frame.trailer) == 18  # the inner frame's padding
        assert "mismatch" not in render(frame)

    def test_bad_outer_udp_checksum_still_flagged(self):
        """Covering the inner padding must not hide a genuinely wrong outer
        UDP checksum."""
        icmp = ICMPv4(type=8, code=0, checksum=0, rest=b"\x00\x01\x00\x01")
        inner = _with_checksums(
            _eth(0x0800), _ipv4(protocol=1, total_length=28), icmp
        )
        text = render(_vxlan_around(inner, udp_checksum=0x1234))
        assert "Checksum: 0x1234 [!] mismatch" in text

    def test_inner_fragment_suppresses_only_inner_checksums(self):
        """An inner IPv4 first fragment (MF set) in a whole outer
        datagram: the inner UDP checksum spans the reassembled datagram
        and is not checked; the outer UDP checksum still is."""
        inner_ip = IPv4(
            version=4,
            ihl=5,
            dscp=0,
            ecn=0,
            total_length=20 + 8 + 4,
            identification=1,
            flags=0b001,  # More Fragments
            fragment_offset=0,
            ttl=64,
            protocol=17,
            checksum=0,
            src="10.0.0.1",
            dst="10.0.0.2",
        )
        inner_udp = UDP(src_port=1, dst_port=40001, length=1000, checksum=0xBAD)
        inner = (
            _with_checksums(_eth(0x0800), inner_ip) + bytes(inner_udp) + b"frag"
        )
        text = render(_vxlan_around(inner, udp_checksum=0x1234))
        assert "Checksum: 0x1234 [!] mismatch" in text  # outer UDP
        assert "Checksum: 0x0bad [!]" not in text  # inner UDP: skipped

    def test_truncation_anchored_at_ip_behind_a_vlan_tag(self):
        """A VLAN-tagged datagram short by two bytes. With the old fixed
        14-byte IP offset, the 4-byte tag hid the shortfall."""
        payload = b"\xaa" * 8
        ip = _ipv4(protocol=17, total_length=20 + 8 + len(payload))
        data = bytes(
            Packet(
                _eth(0x8100),
                VLAN(pcp=0, dei=0, vid=30, ethertype=0x0800),
                ip,
                _udp(40001, len(payload)),
            )
        )
        data += payload
        assert not decode(data).truncated
        assert decode(data[:-2]).truncated

    def test_lying_inner_ipv4_length_is_flagged(self):
        """A valid outer IPv4 around an inner one whose total_length (4)
        is shorter than its header: flagged, and the screen names the
        inner header's values."""
        inner_ip = _ipv4(protocol=17, total_length=4)
        inner = bytes(_eth(0x0800)) + bytes(inner_ip) + b"\x00" * 8
        frame = decode(_vxlan_around(inner))
        assert frame.malformed_length
        text = render(frame)
        assert "Malformed: IPv4 total_length (4)" in text
        assert text.count("[!] Malformed") == 1

    def test_positional_construction_still_binds_raw(self):
        """l7_miss and trailer were added after raw, so code that built a
        DecodedFrame positionally keeps its captured bytes in raw."""
        frame = DecodedFrame(
            1, 0, None, 3, (), b"", False, False, None, b"\x01\x02\x03"
        )
        assert frame.raw == b"\x01\x02\x03"
        assert frame.l7_miss is None and frame.trailer == b""


class TestNDJSONNested:
    """C3: nested bytes anywhere in a layer serialize."""

    @staticmethod
    def emit(data: bytes) -> dict[str, object]:
        """Serialize one frame and return its parsed JSON record."""
        stream = io.StringIO()
        OutputToNDJSON(stream).update(decode(data))
        record = json.loads(stream.getvalue())
        assert isinstance(record, dict)
        return record

    def test_lldp_tlv_values_are_hex(self):
        """Every LLDP TLV value, two levels into the layer, is hex."""
        for data in read_pcap(FIXTURES / "lldp.pcap"):
            record = self.emit(data)
            layers = record["layers"]
            assert isinstance(layers, list)
            lldp = layers[1]
            assert lldp["type"] == "LLDP"
            assert lldp["tlvs"]
            for tlv in lldp["tlvs"]:
                bytes.fromhex(tlv["value"])  # hex, not a crash

    def test_cdp_via_snap_serializes(self):
        """CDP, reached through LLC/SNAP, serializes with hex TLV values."""
        cdp_seen = 0
        for data in read_pcap(FIXTURES / "llc.pcap"):
            record = self.emit(data)
            layers = record["layers"]
            assert isinstance(layers, list)
            for layer in layers:
                if layer["type"] == "CDP":
                    cdp_seen += 1
                    for tlv in layer["tlvs"]:
                        bytes.fromhex(tlv["value"])
        assert cdp_seen >= 3

    def test_private_decode_context_is_not_emitted(self):
        """BGP's underscored decode context (``_followed``) is not emitted."""
        record = self.emit(tcp_segment(179, _keepalives(2)))
        layers = record["layers"]
        assert isinstance(layers, list)
        assert layers[-1]["type"] == "BGP"
        assert not any(key.startswith("_") for key in layers[-1])

    def test_layer_type_field_does_not_clobber_the_discriminator(self):
        """ICMPv4's own ``type`` field (8, Echo Request) used to replace
        the layer's class name under the same key."""
        icmp = ICMPv4(type=8, code=0, checksum=0, rest=b"\x00\x01\x00\x01")
        data = _with_checksums(
            _eth(0x0800), _ipv4(protocol=1, total_length=28), icmp
        )
        layers = self.emit(data)["layers"]
        assert isinstance(layers, list)
        assert [layer["type"] for layer in layers] == [
            "Ethernet",
            "IPv4",
            "ICMPv4",
        ]
        assert layers[2]["type_"] == 8

    def test_new_frame_fields(self):
        """l7_miss and trailer_len reach NDJSON for a padded bare ACK on 443."""
        record = self.emit(tcp_segment(443) + b"\x00" * 6)
        assert record["l7_miss"] is not None
        assert record["error"] is None
        assert record["trailer_len"] == 6
        assert record["payload_len"] == 0

    def test_default_hook_value_types(self):
        """Each value type the hook knows maps to its JSON form, and an
        unknown one falls back to ``str``."""
        import enum
        import ipaddress

        class Colour(enum.Enum):
            RED = "red"

        assert _json_default(b"\x01\xff") == "01ff"
        assert _json_default(bytearray(b"\x02")) == "02"
        assert _json_default(memoryview(b"\x03")) == "03"
        assert _json_default(Colour.RED) == "red"
        assert _json_default(ipaddress.ip_address("10.0.0.1")) == "10.0.0.1"
        assert _json_default(frozenset({2, 1})) == [1, 2]
        assert _json_default(object()).startswith("<object object")


class TestSanitizedDiagnostics:
    """C1: library messages can quote wire bytes; they reach the
    terminal escaped, like every other attacker-shaped string."""

    @staticmethod
    def frame(**fields: object) -> DecodedFrame:
        defaults: dict[str, object] = {
            "number": 1,
            "timestamp": 0,
            "interface": "eth0",
            "length": 0,
            "layers": (),
            "payload": b"x",
        }
        return DecodedFrame(**{**defaults, **fields})  # type: ignore[arg-type]

    def test_error_line_is_sanitized(self):
        """ESC and CR in a decode error reach the terminal escaped."""
        text = render(self.frame(error="bad \x1b[2Jlabel\r"))
        assert "\x1b" not in text and "\r" not in text
        assert "\\x1b[2Jlabel\\x0d" in text

    def test_l7_miss_line_is_sanitized(self):
        """C1 and bidi controls in an l7_miss note are escaped."""
        text = render(self.frame(l7_miss="odd \x9b31m\u202e"))
        assert "\x9b" not in text and "\u202e" not in text
        assert "\\x9b31m\\u202e" in text


class TestGuard:
    """C2: one helper contains every lazily parsed section. Exercised
    through the public rendering path: a DNS header that promises one
    question and carries none parses fine at decode time and only fails
    when the renderer reads ``questions``."""

    @staticmethod
    def dns_frame() -> bytes:
        dns = bytes.fromhex("123401000001000000000000")  # QDCOUNT=1, no body
        return udp_datagram(53, dns)

    def test_protocol_error_is_contained(self):
        """A ProtocolError from a lazy section becomes a [!] line, after
        whatever the renderer printed before it."""
        text = render(self.dns_frame())
        assert "DNS query (id 0x1234)" in text  # printed before the fault
        assert "[!] Records malformed: DNS name runs past the message" in text
        assert text.rstrip().endswith(
            "Records malformed: DNS name runs past the message"
        )

    def test_guard_message_is_sanitized(self, monkeypatch):
        """The guard's [!] line escapes control characters in the message."""

        def hostile(_: DNS) -> object:
            raise TruncatedHeaderError("short \x1b]0;pwned\x07")

        monkeypatch.setattr(DNS, "questions", property(hostile))
        text = render(self.dns_frame())
        assert "\x1b" not in text and "\x07" not in text
        assert "[!] Records malformed: short \\x1b]0;pwned\\x07" in text

    def test_other_exceptions_propagate(self, monkeypatch):
        """Only ProtocolError is contained: anything else is a RootWire
        or library bug and must surface, not be rendered away."""

        def broken(_: DNS) -> object:
            raise ZeroDivisionError

        monkeypatch.setattr(DNS, "questions", property(broken))
        with pytest.raises(ZeroDivisionError):
            render(self.dns_frame())
