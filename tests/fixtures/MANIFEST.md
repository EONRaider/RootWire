# Real-capture fixture corpus

Captured 2026-08-29 with `scripts/capture_fixtures.sh` and
`scripts/capture_fixtures_supplement.sh` (tcpdump on `lo` and the
default interface) and validated by `scripts/check_fixtures.py`:
**every frame's checksums verify internally** (IPv4 header, TCP/UDP
pseudo-header, ICMPv4/v6; fragment slices carry no verifiable
upper-layer checksum — it spans the reassembled datagram). Frames used
as checksum ground truth were captured **inbound only** — outbound
frames routinely leave checksums to NIC offload. 65 frames across 12
scenarios. Addresses are as-captured from the capture host's network.

| File | Frames | Contents |
|---|---|---|
| `arp_exchange.pcap` | 4 | ARP requests ×3 + reply ×1 (fresh exchange after neighbor flush) |
| `icmpv4_echo_lo.pcap` | 6 | Loopback echo request/reply pairs (types 8 and 0) |
| `icmpv4_external.pcap` | 2 | Inbound echo replies from 1.1.1.1 |
| `icmpv4_ttl_exceeded.pcap` | 3 | Time Exceeded (type 11) errors from intermediate hops |
| `icmpv6_echo_lo.pcap` | 6 | Loopback ICMPv6 echo pairs (types 128/129) |
| `ipv4_fragments.pcap` | 5 | Fragmented 2028-byte echo replies: first fragments (offset 0, MF) + non-first fragments |
| `ipv6_fragments.pcap` | 5 | Fragmented 2048-byte ICMPv6 echo replies: first fragments (offset 0) + non-first fragments behind fragment headers (next_header 44) |
| `ipv6_mld.pcap` | 4 | MLD reports behind hop-by-hop extension headers (next_header 0) — provoked by multicast group join/leave |
| `ipv6_ndp_mld.pcap` | 10 | NDP Neighbor Solicitation/Advertisement (135/136) + echo 128/129 |
| `tcp_http.pcap` | 4 | Inbound HTTP-port segments over IPv6: ACK, PSH-ACK ×2, FIN-ACK — all carrying options |
| `tcp_https.pcap` | 12 | Inbound HTTPS segments over IPv4 (7) and IPv6 (5): ACK/PSH-ACK with options |
| `udp_dns.pcap` | 4 | DNS responses (src port 53) over IPv4 (1) and IPv6 (3), with payloads |

Consumed by `tests/test_corpus.py` (corpus-wide invariants +
representative field asserts), mirrored into Packet-Sniffer's test
suite, and later reused as fuzz seeds and pcap-replay goldens.

## Capture notes

- The MLD scenario needed a second pass: the original filter used BPF
  `icmp6`, which matches only `next_header == 58` *directly* — it
  structurally cannot see ICMPv6 behind a hop-by-hop header. The
  supplement captures `ip6 proto 0` instead.
- No inbound SYN-ACK was caught (handshake timing vs. capture start);
  options-bearing segments are otherwise abundant.
- Unknown-EtherType frames are exercised by deliberately synthetic
  fixtures in the unit tests (their point is being unknown), not by the
  corpus.

## Provenance note

This corpus exposed a real defect on arrival: non-first IPv4 fragments
were chained into garbage upper-layer decodes ("ICMPv4 type 192" from
mid-payload bytes) because `IPv4.next_protocol()` ignored
`fragment_offset`. Fixed alongside the corpus's introduction; see
`tests/test_corpus.py::TestFragmentHandling`.
