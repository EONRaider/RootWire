# Vendoring note (RootWire)

Every capture in this directory is vendored byte-for-byte from the
[NETProtocols](https://github.com/EONRaider/NETProtocols) repository's
`tests/fixtures/` at the **2.9.0 release** (commit `93ddd64`), the
library version RootWire pins as its floor. The upstream manifest
follows unchanged below; where it names `tests/test_*.py` or
`scripts/`, it means NETProtocols' files, not RootWire's.

RootWire's own differences from the upstream layout:

- **Every capture is Ethernet** (link type 1), the only one
  `rootwire -r` accepts (`pcap.py` rejects any other per Interface
  Description Block), so nothing upstream had to be left out on that
  ground.
- **The three session captures are flattened into this directory and
  join the corpus**: `bgp/bgp_session.pcap` → `bgp_session.pcap`,
  `tls/tls_session.pcap` → `tls_session.pcap` and
  `stun/stun_rfc3489.pcap` → `stun_rfc3489.pcap`. Upstream keeps them
  out of its corpus because a *strict* walk raises on their bare ACKs,
  split records and RFC 3489 messages. RootWire walks lax and records a
  stop inside a port-dispatched decoder as a best-effort miss
  (`DecodedFrame.l7_miss`), not an error, so these 206 frames are
  exactly the real-traffic regression set for that rule:
  `tests/test_corpus.py` requires every one of them to decode with no
  error.
- **Left out**: `mpls/mpls_snaplen.pcap`, whose frames are cut at a
  20-byte snap length and genuinely end in errors (the corpus requires
  none), and `http/` (raw request/response streams plus `http.pcap`),
  which belongs with the HTTP renderer: HTTP is not in NETProtocols'
  default registry, so RootWire only decodes it once `--decode-as`
  exists.

In all: **617 frames across 42 captures**, every one decoded, rendered
and serialized to NDJSON by the test suite, with no checksum mismatch
on screen.

---

# Real-capture fixture corpus

Captured 2026-08-29 with `scripts/capture_fixtures.sh` and
`scripts/capture_fixtures_supplement.sh` (tcpdump on `lo` and the
default interface) and validated by `scripts/check_fixtures.py`:
**every frame's checksums verify internally** (IPv4 header, TCP/UDP
pseudo-header, ICMPv4/v6, GRE where its Checksum field is present,
VRRP, PIM, SCTP's CRC32c, CDP, the OSPF packet checksum and every OSPF
LSA's Fletcher checksum; fragment slices carry no verifiable
upper-layer checksum — it spans the reassembled datagram), as does
every IPsec ICV, every RIPv2 keyed digest, every OSPF MD5 digest,
every RADIUS authenticator the corpus holds (a reply's against its
request's), every STUN MESSAGE-INTEGRITY and every NTP MAC, with the
test keys published below, and every STUN FINGERPRINT; every TCP
segment on port 443 that carries data holds whole TLS records. Frames
used as checksum ground truth were captured **inbound only** — outbound
frames routinely leave checksums to NIC offload. 411 frames across 39
scenarios. Addresses are as-captured from the capture host's network.

Twenty-six scenarios (`vlan_icmp.pcap`, `dhcp.pcap`, `gre.pcap`,
`gre_csum.pcap`, `gre6.pcap`, `dns_tcp.pcap`, `ipip.pcap`,
`vxlan.pcap`, `esp.pcap`, `ah.pcap`, `sctp.pcap`, `vrrp.pcap`,
`vrrp_rfc9568.pcap`, `rip.pcap`, `ospf.pcap`, `pim.pcap`, `bgp.pcap`,
`mpls.pcap`, `lldp.pcap`, `llc.pcap`, `tftp.pcap`, `radius.pcap`,
`stun.pcap`, `ntp.pcap`, `hsrp.pcap`, `tls.pcap`) are
captured
separately by
their own `scripts/capture_fixtures_*.sh` over
purpose-built topologies — real kernel vlan devices, a DHCP
server/client, kernel GRE tunnels over IPv4 and IPv6, a DNS server
queried over TCP, kernel IP-in-IP encapsulation, a kernel VXLAN
tunnel, a userspace SCTP
association, IPsec ESP and AH built by a script and sent through raw
sockets, two keepalived VRRP routers, two BIRD routers speaking RIP,
two FRR OSPF routers, two FRR PIM-SM routers, BGP sessions between
three BIRD speakers, MPLS label stacks built by a script around
kernel-built IPv4 datagrams and sent through a raw socket, two lldpd
LLDP agents, two STP bridges with lldpd speaking CDP, a tftpd-hpa
server with tftp-hpa and curl clients, a FreeRADIUS server answering
radclient, coturn answering STUN clients, a chronyd NTP server
queried by ntpdig and chronyd clients, HSRP messages crafted by
Yersinia and sent between two netns, and an nginx HTTPS server
answering Chromium, curl, gnutls-cli and openssl s_client — see their
rows and the notes below.

| File | Frames | Contents |
|---|---|---|
| `arp_exchange.pcap` | 4 | ARP requests ×3 + reply ×1 (fresh exchange after neighbor flush) |
| `icmpv4_echo_lo.pcap` | 6 | Loopback echo request/reply pairs (types 8 and 0) |
| `icmpv4_external.pcap` | 2 | Inbound echo replies from 1.1.1.1 |
| `icmpv4_ttl_exceeded.pcap` | 3 | Time Exceeded (type 11) errors from intermediate hops |
| `icmpv6_echo_lo.pcap` | 6 | Loopback ICMPv6 echo pairs (types 128/129) |
| `igmp.pcap` | 4 | IGMPv3 Membership Reports (type 0x22) provoked by joining an IPv4 multicast group |
| `ipv4_fragments.pcap` | 5 | Fragmented 2028-byte echo replies: first fragments (offset 0, MF) + non-first fragments |
| `ipv6_fragments.pcap` | 5 | Fragmented 2048-byte ICMPv6 echo replies: first fragments (offset 0) + non-first fragments behind fragment headers (next_header 44) |
| `ipv6_mld.pcap` | 4 | MLD reports behind hop-by-hop extension headers (next_header 0) — provoked by multicast group join/leave |
| `ipv6_ndp_mld.pcap` | 10 | NDP Neighbor Solicitation/Advertisement (135/136) + echo 128/129 |
| `tcp_http.pcap` | 4 | Inbound HTTP-port segments over IPv6: ACK, PSH-ACK ×2, FIN-ACK — all carrying options; the two PSH-ACK payloads together are one chunked response, which `tests/test_http.py` decodes as `HTTP` |
| `tcp_https.pcap` | 12 | Inbound HTTPS segments over IPv4 (7) and IPv6 (5): ACK/PSH-ACK with options. Each IPv4 segment is one whole TLS application_data record, `Ethernet→IPv4→TCP→TLS`; the IPv6 segments are bare ACKs from port 443, on which a strict walk raises `TruncatedHeaderError` at the empty payload, as on BGP's port 179 (`tests/test_corpus.py` names them in `BARE_SEGMENTS` and walks them lax) |
| `udp_dns.pcap` | 4 | DNS responses (src port 53) over IPv4 (1) and IPv6 (3), with payloads |
| `vlan_icmp.pcap` | 12 | 802.1Q single-tag (VID 100) and 802.1ad QinQ (S-VID 200 / C-VID 30) frames carrying ARP + ICMPv4 echo — **direct capture** of real kernel-tagged traffic (see VLAN note) |
| `dhcp.pcap` | 4 | DHCP DORA exchange (DISCOVER / OFFER / REQUEST / ACK) over IPv4/UDP — **direct capture** via dnsmasq + dhclient over a veth pair (see DHCP note) |
| `gre.pcap` | 8 | IPv4-in-GRE ICMPv4 echo over a plain and a keyed (RFC 2890) kernel GRE tunnel — `Ethernet→IPv4→GRE→IPv4→ICMPv4`; **direct capture** (see GRE note) |
| `gre_csum.pcap` | 4 | IPv4-in-GRE ICMPv4 echo over a checksummed (RFC 2784 §2.5, C bit set) kernel GRE tunnel — `Ethernet→IPv4→GRE→IPv4→ICMPv4`; **direct capture** (see GRE note) |
| `gre6.pcap` | 4 | IPv4-in-GRE ICMPv4 echo over a kernel ip6gre tunnel (GRE over IPv6, RFC 7676, flags all clear) — `Ethernet→IPv6→GRE→IPv4→ICMPv4`; **direct capture** (see GRE note) |
| `dns_tcp.pcap` | 4 | DNS over TCP (RFC 1035 §4.2.2): A and TXT queries + responses from `dig +tcp` against `dnsmasq` — `Ethernet→IPv4→TCP→DNSOverTCP→DNS`; **direct capture** (see DNS-over-TCP note) |
| `ipip.pcap` | 4 | IP-in-IP ICMP echo requests: IPv4 in IPv4 (protocol 4, RFC 2003) ×2 and IPv6 in IPv4 (protocol 41, 6in4, RFC 4213) ×2 — `Ethernet→IPv4→IPv4→ICMPv4` and `Ethernet→IPv4→IPv6→ICMPv6`; **direct capture** (see IP-in-IP note) |
| `vxlan.pcap` | 11 | VXLAN (RFC 7348) over a kernel tunnel on UDP 4789, two segments: VNI 1193046 (`0x123456`) with the outer UDP checksum computed — ARP request/reply, two echo request/reply pairs, one UDP datagram — then VNI 100 with a zero (`noudpcsum`) outer checksum — ARP request/reply, one echo pair — `Ethernet→IPv4→UDP→VXLAN→Ethernet→ARP` / `→IPv4→ICMPv4` / `→IPv4→UDP`; **direct capture** (see VXLAN note) |
| `esp.pcap` | 6 | IPsec ESP (RFC 4303), NULL encryption + HMAC-SHA-256-128, two SAs: transport mode carrying ICMPv4 echo ×2 and UDP ×1 (SPI `0x10000001`, sequence 1-3), tunnel mode carrying inner IPv4 with ICMPv4 echo ×2 and UDP ×1 (SPI `0x10000002`, sequence 1-3) — `Ethernet→IPv4→ESP`, where the walk ends by design; **direct capture** of script-built ESP (see IPsec note) |
| `ah.pcap` | 6 | IPsec AH (RFC 4302), HMAC-SHA-256-128, three SAs: transport mode protecting a TCP SYN (MSS option), an ICMPv4 echo and a UDP datagram (SPI `0x20000001`, sequence 1-3); tunnel mode protecting inner IPv4 with an ICMPv4 echo and a TCP SYN (SPI `0x20000002`, sequence 1-2); and an AH-over-ESP bundle, AH (SPI `0x20000003`) protecting NULL-encrypted ESP (SPI `0x10000003`) carrying an ICMPv4 echo — `Ethernet→IPv4→AH→` then TCP, ICMPv4, UDP, IPv4 (→ ICMPv4 or TCP) or ESP; **direct capture** of script-built datagrams (see IPsec note) |
| `rip.pcap` | 21 | RIP between two BIRD 2.14 routers on UDP 520, five scenarios of 4 frames each (each router's first Request, for the whole table, and its first Response, carrying its routes): RIPv1 broadcast (3 classful routes per Response), RIPv2 multicast with no authentication (4 routes, plus one periodic update of 7 entries, 3 of them poisoned reverse at metric 16), a plain-text password, keyed MD5 and HMAC-SHA-256 (RFC 4822, with a 20- and a 36-byte authentication trailer) — `Ethernet→IPv4→UDP→RIP`; **direct capture**, both directions (see RIP note) |
| `tftp.pcap` | 33 | Six TFTP (RFC 1350) transfers between tftpd-hpa 5.2 and two clients, each a request to UDP 69 followed by the transfer between two ephemeral ports: an RRQ in octet mode for a 1300-byte file (DATA blocks of 512, 512 and 276 bytes, each ACKed); an RRQ for a 1024-byte file, ending in an empty DATA block 3; a WRQ of 600 bytes (ACK of block 0, then DATA of 512 and 88); an RRQ for a missing file (ERROR code 1, `File not found`) and one for a file the server cannot open (ERROR code 0, `Permission denied`), each followed by the tftp-hpa client's ACK of block 1; and curl's RRQ with RFC 2347 options `tsize` 0, `blksize` 1024 and `timeout` 6, answered by an OACK (`tsize` 1300) and ACKed with block 0, then DATA of 1024 and 276 bytes — `Ethernet→IPv4→UDP→TFTP` for the 6 requests, `Ethernet→IPv4→UDP` for the other 27, which no port names; **direct capture**, both directions (see TFTP note) |
| `ospf.pcap` | 54 | OSPFv2 (RFC 2328) between two FRR 8.4 routers on one broadcast network in area 0, three adjacencies in turn: AuType 0 (no authentication), AuType 1 (simple password) and AuType 2 (keyed MD5), 18 frames each — 6 Hellos (one with an empty neighbor list, DR/BDR election), 5 Database Descriptions (the I/M/MS exchange, LSA headers), 2 Link State Requests, 3 Link State Updates (router, network and AS-external LSAs, 6 per adjacency) and 2 Link State Acknowledgments — `Ethernet→IPv4→OSPF`; **direct capture**, both directions (see OSPF note) |
| `bgp.pcap` | 19 | BGP-4 (RFC 4271) over TCP 179 between BIRD 2.14 speakers, an eBGP (AS 65001-65002) and an iBGP (AS 65001) session: an OPEN each way on each, a KEEPALIVE each way on each, 23 UPDATEs (announcements with ORIGIN, AS_PATH, NEXT_HOP, MULTI_EXIT_DISC and, over iBGP, LOCAL_PREF; End-of-RIB markers; a five-prefix withdrawal to each peer), one segment carrying 7 messages and others 2-6, and a Cease / Administrative Shutdown NOTIFICATION to each peer — `Ethernet→IPv4→TCP→BGP` (→ `BGP` …); **direct capture**, both directions, only the segments that hold whole messages, and of those carrying nothing but a KEEPALIVE only the first per direction per session (see BGP note) |
| `mpls.pcap` | 8 | MPLS label stacks (RFC 3032) over Ethernet: one label (`0x12345`) carrying an ICMPv4 echo; two labels (16001, 16002) carrying UDP; three labels (16001-16003, traffic classes 5/3/0) carrying an echo; an Entropy Label Indicator (7) and an entropy label (RFC 6790) carrying an echo; an IPv4 Explicit NULL bottom label (0) carrying a UDP datagram of 2 bytes of payload, zero padded to 60 bytes; an IPv6 Explicit NULL bottom label (2) carrying an IPv6 UDP datagram; EtherType `0x8848` to a multicast MAC carrying an echo; and an Ethernet pseudowire, a control word (RFC 4448 §4.6) and a whole Ethernet frame — `Ethernet→MPLS→IPv4→ICMPv4` / `→IPv4→UDP` / `→IPv6→UDP`, and `Ethernet→MPLS`, where the walk stops at the control word; **script-built label stacks around kernel-built IPv4 datagrams**, the IPv6 datagram script-built (see MPLS note) |
| `sctp.pcap` | 16 | One SCTP association (RFC 9260) from usrsctp over raw IPv4: INIT / INIT ACK / COOKIE ECHO / COOKIE ACK, DATA + SACK each way, HEARTBEAT + HEARTBEAT ACK from each end, SHUTDOWN / SHUTDOWN ACK / SHUTDOWN COMPLETE; then one script-built packet carrying an unknown chunk type (63) — `Ethernet→IPv4→SCTP`; **direct capture**, both directions (see SCTP note) |
| `vrrp.pcap` | 18 | VRRP adverts from two keepalived 2.2.8 routers, A (`10.9.20.1`, priority 200) and B (`10.9.20.2`, priority 100), four virtual routers: VRID 51, VRRPv2 with `auth_type PASS` (Auth Type 1, password `np-vrrp`) and two addresses — A ×2, A's priority-0 resignation, B taking over ×2, B's resignation; VRID 52, VRRPv2 without authentication (8 zero bytes of Authentication Data), one address — A ×2 and its resignation; VRID 53, VRRPv3 with one address (the minimal 12-byte message) — the same failover as VRID 51; VRID 54, VRRPv3 unicast from A to B, three addresses, Max Adver Int 50 cs — A ×2 and its resignation — `Ethernet→IPv4→VRRP`; **direct capture**, both directions, of a selection from the raw capture (see VRRP note) |
| `vrrp_rfc9568.pcap` | 9 | VRRPv3 adverts from two keepalived 2.2.8 routers with `v3_checksum_as_v2`, A (`10.9.203.1`, priority 200) and B (`10.9.203.2`, priority 100), every checksum the message's alone, without the IPv4 pseudo-header (RFC 9568 §5.2.8), two virtual routers: VRID 61, one address (the minimal 12-byte message), multicast — A ×2, A's priority-0 resignation, B taking over ×2, B's resignation; VRID 62, unicast from A to B, three addresses, Max Adver Int 50 cs — A ×2 and its resignation — `Ethernet→IPv4→VRRP`; **direct capture**, both directions, of a selection from the raw capture (see VRRP note) |
| `lldp.pcap` | 6 | LLDP (IEEE 802.1AB) LLDPDUs from two lldpd 1.0.18 agents to `01:80:c2:00:00:0e`, a veth pair apart: A's first (Chassis ID: MAC address `02:4e:50:86:00:0a`, subtype 4; Port ID: interface name `nplldp-va`, subtype 5; TTL 120; System Name, System Description, System Capabilities, Management Address `10.9.86.1`, Port Description, two IEEE 802.3 organizationally specific TLVs and a 304-byte custom one, OUI `0a-4e-50`), B's first (Chassis ID: locally assigned `nplldp-chassis-b`, subtype 7; Port ID: MAC address `02:4e:50:86:00:0b`, subtype 3; TTL 180; the same optional TLVs but the custom one), A's shutdown LLDPDU (TTL 0) for its old Port ID when its Port ID changes to a locally assigned `np-port-a` (subtype 7), A's first LLDPDU with the new one, and A's and B's shutdown LLDPDUs on exit — `Ethernet→LLDP`; **direct capture**, both directions, a selection of the first LLDPDU of each kind (see LLDP note) |
| `pim.pcap` | 13 | PIM-SM (RFC 7761) between two FRR 8.4 routers (zebra + pimd) on the link between them: Hello ×3 (R1's with Holdtime, LAN Prune Delay, DR Priority, Generation ID and Address List; R2's without an Address List; R2's Holdtime-0 goodbye), Register ×2 (a data Register carrying the source's UDP datagram, a Null-Register), Register-Stop ×1, and Join/Prune ×7 — (*,G) and (S,G) joins, (S,G) and (*,G) prunes, and one message joining (*,G) while pruning (S,G,rpt) — `Ethernet→IPv4→PIM`; **direct capture**, a selection of one frame of each kind, R1's outbound Hello and Registers among them (see PIM note) |
| `llc.pcap` | 14 | Frames whose type/length field is not an EtherType: in all but the last it is an IEEE 802.3 Length, and in all but the raw IPX one an 802.2 LLC header follows it. Five 802.1D BPDUs from two Linux bridges (Configuration BPDUs from each, the root's with Topology Change and with Topology Change + Acknowledgment, and a 21-byte Topology Change Notification) — `Ethernet→LLC→STP` (DSAP 0x42; no RST BPDU, which `tests/test_stp.py` builds by hand); CDPv1 and CDPv2 from lldpd 1.0.18, and a CDPv1 frame whose odd-length PDU ends in the byte 0xA9 — `Ethernet→LLC→SNAP→CDP` (OUI 00-00-0C, PID 0x2000); and six script-built frames: RFC 1042 ARP padded to 60 bytes and RFC 1042 ICMPv4 echo — `Ethernet→LLC→SNAP→ARP` / `→IPv4→ICMPv4`; IEEE 802.1H (OUI 00-00-F8) ARP; RFC 1042 ARP behind an 802.1Q tag (VID 30) — `Ethernet→VLAN→LLC→SNAP→ARP`; Novell raw 802.3 IPX — `Ethernet→LLC`; and a type/length value of 1501 — `Ethernet`; **direct capture**, both directions, a selection of one frame of each kind (see LLC note) |
| `radius.pcap` | 12 | RADIUS (RFC 2865, RFC 2866) between radclient and a FreeRADIUS 3.2.5 server, six requests each followed by its reply: an Access-Request with a PAP password (User-Name, User-Password, NAS-IP-Address, NAS-Port, Message-Authenticator) and its Access-Accept (Framed-IP-Address, Reply-Message, Message-Authenticator); the same with a wrong password and its Access-Reject; an Access-Request with a CHAP-Password and its Access-Accept; an Accounting-Request Start (Acct-Status-Type, Acct-Session-Id, Framed-IP-Address, ...) and Stop (session time, octet and packet counters, Acct-Terminate-Cause), each answered by an attribute-less Accounting-Response; and a Status-Server (RFC 5997) answered by an Access-Accept — `Ethernet→IPv4→UDP→RADIUS`, on UDP 1812 and 1813; **direct capture**, both directions (see RADIUS note) |
| `stun.pcap` | 12 | STUN (RFC 8489, RFC 5389) between clients and coturn 4.6.1 in STUN-only mode on port 3478, every response carrying SOFTWARE and FINGERPRINT: a Binding Request and its Success Response (XOR-MAPPED-ADDRESS, MAPPED-ADDRESS, RESPONSE-ORIGIN) from `turnutils_stunclient`; its RFC 5780 request (CHANGE-REQUEST, RESPONSE-PORT) and the error 420 it draws; a request with an unknown comprehension-required attribute (0x7FF0) and the error 420 naming it in UNKNOWN-ATTRIBUTES; two requests in one TCP segment and the two responses in one segment back (`Ethernet→IPv4→TCP→STUN→STUN`); and, from a server requiring the long-term credential mechanism, an unauthenticated request, the error 401 with REALM and NONCE, the authenticated request (USERNAME, REALM, NONCE, MESSAGE-INTEGRITY) and its Success Response with MESSAGE-INTEGRITY — `Ethernet→IPv4→UDP→STUN` otherwise; **direct capture**, both directions, data segments only over TCP (see STUN note) |
| `ntp.pcap` | 17 | NTP on UDP 123 from a chronyd 4.5 server at `local stratum 8` (Reference ID 127.127.1.1), eight scenarios: an ntpdig (ntpsec) NTPv4 client request and the server's answer (modes 3 and 4, the bare 48-byte header); the same with a symmetric-key MAC, MD5 (Key ID 1, 20 bytes) and SHA-1 (Key ID 2, 24 bytes), each way; a chronyd client speaking NTPv3 (RFC 1305) and the NTPv3 answer; a chronyd client sending chrony's experimental extension field 0xF323 (RFC 7822 framing, 28 bytes) and the answer carrying one back; an NTS (RFC 8915) request (Unique Identifier, NTS Cookie, NTS Authenticator) and answer (Unique Identifier, NTS Authenticator); a chronyd symmetric active peer (mode 1) and the server's symmetric passive answers (mode 2), once unsynchronized (stratum 0) and once synchronized to the server (stratum 9, Reference ID 10.9.191.1); and one broadcast (mode 5) to 10.9.191.255 — `Ethernet→IPv4→UDP→NTP`; **direct capture**, both directions, a selection (see NTP note) |
| `hsrp.pcap` | 12 | HSRPv1 (RFC 2281) messages crafted by Yersinia 0.8.2, every one to 224.0.0.2 (TTL 1) from and to UDP 1985 with Hellotime 3 and Holdtime 10, staging an election and a failover in two standby groups: group 1 (virtual IP 10.9.195.254, the default authentication data `cisco`) — R1 (10.9.195.11, priority 120) and R2 (10.9.195.12, priority 100) Hellos in Speak, R1 in Standby then Active, R2 in Standby, R1's Resign from Active, R2 in Speak then Active, then R3 (10.9.195.13, priority 200) preempting with a Coup and its Active Hello; group 2 (virtual IP 10.9.195.253, the configured password `spark`) — R4 (10.9.195.21, priority 110) Active and R5 (10.9.195.22, priority 90) Standby — 10 Hellos, 1 Coup, 1 Resign in all — `Ethernet→IPv4→UDP→HSRP`; **direct capture of script-built frames**, every byte Yersinia's (see HSRP note) |
| `tls.pcap` | 15 | TLS (RFC 9846, RFC 5246) on TCP 443 between an nginx 1.24 server (OpenSSL 3.0, a self-signed ECDSA P-256 certificate for `tls.np196.test`) and five clients, each segment a whole number of records: from curl (OpenSSL 3.0, a 512-byte ClientHello with SNI), gnutls-cli (GnuTLS 3.8, record version TLS 1.2, SNI) and `openssl s_client -noservername` (no server_name), the ClientHello and the server's TLS 1.3 flight (ServerHello, ChangeCipherSpec and four encrypted records in one segment); from headless Chromium 153 (BoringSSL), whose ClientHello spans two segments and is not in the corpus, the server's flight and the client's ChangeCipherSpec and Finished; and every data segment of curl capped at TLS 1.2 — ClientHello; ServerHello, Certificate, ServerKeyExchange, ServerHelloDone; ClientKeyExchange, ChangeCipherSpec and the encrypted Finished; ChangeCipherSpec and Finished back; application data each way; the client's close_notify Alert — `Ethernet→IPv4→TCP→TLS` (→ `TLS` …, up to 6 records a segment); **direct capture**, both directions, a selection of the session in `tls/` (see TLS note) |

Consumed by `tests/test_corpus.py` (corpus-wide invariants +
representative field asserts), mirrored into RootWire's test
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
  corpus. The one exception is `llc.pcap`'s script-built frame whose
  type/length value, 1501, IEEE 802.3 leaves undefined.
- `vlan_icmp.pcap` was produced by `scripts/capture_fixtures_vlan.sh`.
  A VLAN tag never reaches a host on an access port, so the script
  builds real 802.1Q / 802.1ad vlan devices over a veth pair, lets the
  kernel `8021q` driver tag the frames, and captures on the parent
  device with tcpdump. veth's VLAN and checksum offload is turned off
  (`ethtool -K`) first, so the tags land **in-band** in the saved bytes
  (EtherType `0x8100` / `0x88a8` at offset 12, not stripped into
  ancillary data) and the inner IPv4/ICMP checksums are computed to
  their real values — `check_fixtures` verifies those inner checksums
  like any other frame. On a kernel without the `8021q` driver the
  script falls back to splicing tag shims over a real untagged capture,
  which is byte-identical; the committed fixture is a direct capture.
- `dhcp.pcap` was produced by `scripts/capture_fixtures_dhcp.sh`: a real
  DHCP DORA exchange between `dnsmasq` (DHCP only) and `dhclient` over a
  veth pair, captured on the server side. The four messages decode
  `Ethernet→IPv4→UDP→DHCP`; `check_fixtures` verifies the UDP checksum,
  which covers the DHCP payload. Offload is disabled first so the
  server's checksums are computed rather than left to "offload".
- `gre.pcap` was produced by `scripts/capture_fixtures_gre.sh`: ICMPv4
  echo across a kernel GRE tunnel built over a veth pair, captured on
  the underlay so each frame is `Ethernet→IPv4 (proto 47)→GRE→IPv4→
  ICMPv4`. Half the frames ride a plain tunnel (GRE flags all clear) and
  half a keyed tunnel (the RFC 2890 key field). `check_fixtures` peels
  the GRE header and verifies the inner IPv4/ICMP checksums.
- `gre_csum.pcap` was produced by the same script, over a checksummed
  (`csum`) tunnel in its own netns pair, `npgrecsa` and `npgrecsb`,
  joined by the veth pair `npgvcsa`/`npgvcsb` with tx/rx checksum
  offload off: underlay 10.9.197.1 <-> 10.9.197.2 (10.9.197.0/25),
  overlay 10.9.197.129 <-> 10.9.197.130 (10.9.197.128/25), captured on
  `npgvcsa`. Its four frames are two echo requests from .129 to .130,
  each followed by its reply, ICMP sequence numbers 1 and 2 under one
  identifier, every GRE flags word `0x8000` (the C bit alone, version
  0) with Protocol Type `0x0800`. `check_fixtures` verifies each
  frame's GRE Checksum (RFC 2784 §2.5: the GRE header with the field
  zeroed and its payload, up to the outer IPv4 Total Length), then
  peels the GRE header and verifies the inner IPv4/ICMP checksums.
- `gre6.pcap` was produced by the same script, over an `ip6gre`
  tunnel with `encaplimit none`, so no Tunnel Encapsulation Limit
  option sits between the IPv6 header and GRE: next header 47. Netns
  `npgre6a` and `npgre6b`, joined by the veth pair `npgv6a`/`npgv6b`
  with tx/rx checksum offload off; underlay fd09:326:1::1 <->
  fd09:326:1::2 (the ULA fd09:326:1::/64), overlay 10.9.197.193 <->
  10.9.197.194 (10.9.197.192/30), IPv6 off on the tunnel device;
  captured on `npgv6a`. Its four frames are two echo requests from .193
  to .194, each followed by its reply, ICMP sequence numbers 1 and 2
  under one identifier, every GRE flags word `0x0000` with Protocol
  Type `0x0800`, each IPv6 Payload Length ending its frame.
  `check_fixtures` peels each frame's GRE header, up to the IPv6
  Payload Length, and verifies the inner IPv4/ICMP checksums; with the
  C bit clear there is no GRE Checksum to verify. The capture script
  asserts the frames listed here with the standard library, among them
  that each frame's inner IPv4 header and ICMPv4 checksums verify, and
  the corpus tests walk them `Ethernet→IPv6→GRE→IPv4→ICMPv4` and
  round-trip every layer.
- `dns_tcp.pcap` was produced by `scripts/capture_fixtures_dns_tcp.sh`:
  a real DNS exchange over TCP — `dig +tcp` querying an A and a TXT
  record against `dnsmasq` answering from its own records — over a veth
  pair, captured on the server side with offload disabled so the TCP
  checksums are computed for real (`check_fixtures` verifies them; the
  TCP checksum covers the length-prefixed DNS message). Only the
  data-bearing segments are kept: each committed frame decodes
  `Ethernet→IPv4→TCP→DNSOverTCP→DNS` cleanly, whereas the connection's
  bare handshake/teardown segments carry no DNS message — walking one
  sends an empty payload into the length shim, the documented
  malformed-frame path of port-based dispatch.
- `ipip.pcap` was produced by `scripts/capture_fixtures_ipip.sh`: ICMP
  echo requests sent through raw IP sockets opened for protocol 4 and
  41 over a veth pair, so the kernel builds the outer IPv4 header (and
  its checksum) exactly as a tunnel endpoint would, captured on the
  receiving side with offload disabled. The inner packets are built by
  the script with real checksums; `check_fixtures` peels the outer
  header and verifies them. The capture host's kernel had no IPv6, so
  only the IPv4-outer combinations are here; IPv4 in IPv6 and IPv6 in
  IPv6 (RFC 2473) are covered by constructed frames in
  `tests/test_ipip.py`, and the script captures them too on a kernel
  with IPv6.
- `esp.pcap` was produced by `scripts/capture_fixtures_ipsec.sh`. The
  capture host's kernel has no xfrm ESP transform (`ip xfrm state add
  … proto esp` fails with "Requested type not found"), so it cannot do
  the IPsec processing itself; `scripts/ipsec_fixture_packets.py`
  (stdlib only) builds each ESP packet instead — SPI, sequence number,
  the NULL-encrypted (RFC 2410) payload, the RFC 4303 §2.4 default
  padding (`01 02 …`) to a 4-byte boundary, Pad Length, Next Header,
  and an HMAC-SHA-256-128 ICV (RFC 4868) over all of it — and sends it
  through a raw socket opened for protocol 50 over a veth pair, captured
  on the receiving side with offload disabled. **What the kernel built:
  the outer IPv4 header** (identification, DF, TTL 64, checksum) and the
  Ethernet header. **What the script built: every byte from the SPI
  on**, which the script confirms after the capture by comparing each
  captured datagram past its IPv4 header with what it sent, byte for
  byte. In transport mode the payload is an ICMPv4 echo or UDP datagram
  whose checksum covers the outer header's pseudo-header; in tunnel mode
  it is a whole inner IPv4 packet (`192.0.2.1 → 192.0.2.2`, RFC 5737)
  between the hosts behind the two gateways. `check_fixtures` verifies
  each ICV with the keys below, then the padding, then the inner
  packet's checksums; a frame on an SPI not listed below fails. The
  kernel has no IPv6, so IPv6-outer ESP is covered by constructed
  frames in `tests/test_esp.py`.
- `ah.pcap` was produced by the same script. AH's ICV covers the outer
  IPv4 header (RFC 4302 §3.3.3: every field but TOS, flags, fragment
  offset, TTL and the header checksum, which are zeroed for the
  computation), so unlike ESP the script has to build that header
  itself, with an explicit identification (`0xa101`-`0xa106`), DSCP AF11
  (a mutable field set non-zero on purpose), DF and TTL 64, and send the
  whole datagram with `IP_HDRINCL` (a raw `IPPROTO_RAW` socket).
  **What the script built: every byte of the IPv4 datagram** — header,
  AH with its ICV, and payload. **What the kernel did:** prepended the
  Ethernet header, and it owns three header fields even under
  `IP_HDRINCL`: probed on the capture host, it replaced a deliberately
  wrong total length (0, 999) and a zero header checksum with the
  correct values, and filled in a zero source address (a zero
  identification with DF set it left as 0). The script sends correct
  values for all three, and its post-capture comparison found every
  captured datagram byte-identical to the one it built — so whatever
  the kernel recomputed, it recomputed to the bytes the ICV covers.
  Transport mode protects a TCP SYN, an ICMPv4 echo and a UDP datagram,
  tunnel mode an inner IPv4 packet (`192.0.2.1 → 192.0.2.2`) carrying an
  ICMPv4 echo or a TCP SYN, and the last frame is an AH-over-ESP
  transport-adjacency bundle (RFC 4301 §4.5). `check_fixtures` verifies
  each AH ICV with the keys below, then what it protects: the transport
  checksums against the outer header's pseudo-header, the inner IPv4
  packet, or the bundled ESP packet's own ICV, padding and payload. A
  frame on an SPI not listed below fails, as does AH behind IPv4 header
  options or an IPv6 header, whose ICV `check_fixtures` does not
  compute. IPv6-outer AH, with the 4 bytes of ICV padding
  HMAC-SHA-256-128 needs there, is covered by constructed frames in
  `tests/test_ah.py`.

- `vxlan.pcap` was produced by `scripts/capture_fixtures_vxlan.sh`: a
  kernel VXLAN device (`dstport 4789`) in each of two netns over a veth
  underlay, the overlay addressed and exercised with a fresh ARP
  exchange, `ping`, and one UDP datagram between fixed ports (40000 →
  9999), captured on the underlay with offload disabled on both the
  veth and the vxlan devices. Both directions are kept: every frame was
  built by the kernel, and every checksum computed in software. The
  first segment ran with `udpcsum`, so the outer UDP checksum is real
  and `check_fixtures` verifies it over the whole encapsulated frame;
  the second with `noudpcsum`, so it is zero ("not used", RFC 768), as
  RFC 7348 §5 says it SHOULD be sent. `check_fixtures`
  peels the VXLAN header on destination port 4789 and verifies the
  inner frame's checksums too. The outer source ports are the kernel's
  hash of each inner flow; none is a registered port. This file's echo
  and UDP frames are the deepest chains outside `bgp.pcap`, at 7 layers.

- `mpls.pcap` was produced by `scripts/capture_fixtures_mpls.sh`. The
  capture host's kernel has `CONFIG_MPLS_ROUTING` off (no
  `/proc/sys/net/mpls`), so it can neither push nor forward a label,
  and no daemon here sends MPLS; the frames are built by
  `scripts/mpls_fixture_packets.py` and sent through an `AF_PACKET`
  socket over a veth pair between two netns, offload disabled, then
  captured on the far end. The capture is in two steps. First the
  kernel sends two ICMP echo requests (`ping`) and two UDP datagrams
  (40000 → 9999, to a listener) from A to B, captured inbound on B and
  kept out of the corpus. Then the script wraps those datagrams and
  sends the eight frames, and reads the capture back to confirm every
  byte arrived as built. **What the script built: every outer
  Ethernet header, every label stack entry, the 8 zero bytes padding
  the Explicit NULL frame to 60 bytes, the pseudowire control word
  (`00 00 00 01`: first nibble 0, sequence number 1), and the whole
  IPv6 datagram under IPv6 Explicit NULL** (header, UDP header,
  payload and UDP checksum: the host runs with IPv6 disabled). **What
  the kernel built: every IPv4 datagram, its header and ICMP or UDP
  checksum included, and, in the pseudowire frame, the whole Ethernet
  frame after the control word**, which is the kernel's first captured
  frame verbatim. The entropy label carries TTL 0, as RFC 6790 §4.2
  requires; the multicast frame goes to `01:00:5e:00:00:01` under
  EtherType `0x8848`, the case RFC 5332 §4 keeps it for. MPLS carries
  no checksum. `check_fixtures` walks each stack to its bottom entry
  and verifies the labelled packet's checksums, IPv4 and IPv6 alike,
  choosing the family by the Explicit NULL label or the first nibble,
  as the library does but in its own code, and reads the pseudowire's
  payload as the Ethernet frame it is (an RFC 4448 pseudowire's payload
  type is signalled, not encoded, and this one is Ethernet). A second
  tcpdump captured the same eight frames with a 20-byte snap length as
  `mpls/mpls_snaplen.pcap`, outside the corpus globs and the counts
  above, as `bgp/bgp_session.pcap` is: its records are real truncation,
  cut at byte 20, 2 bytes past each stack's first entry, so the six
  stacks of two or three entries end after their first
  (`TruncatedHeaderError` from `MPLS` at frame offset 18) and the two
  one-entry stacks hand a 2-byte IPv4 header to `IPv4`. The capture
  script checks that each record is the first 20 bytes of the
  matching corpus frame; `tests/test_mpls.py` walks them.

- `bgp.pcap` was produced by `scripts/capture_fixtures_bgp.sh`: three
  BIRD 2.14 instances in their own netns on one Linux bridge — A (AS
  65001) with an eBGP session to B (AS 65002) and an iBGP session to C
  (AS 65001) — captured on the bridge, so both sessions and both
  directions are in one file. Offload (checksum, TSO, GSO, GRO) was
  disabled on every veth end first, so the kernel computed every TCP
  checksum and no segment exceeds the 1460-byte MSS; `check_fixtures`
  verifies them all. **What BIRD built: every BGP message** (the TCP
  payload); **what the kernel built: the Ethernet, IPv4 and TCP
  headers.** A originates five prefixes of different lengths (/24 to
  /32), each with its own MED, B two with a MED and 600 /24s without
  one, C one; then A withdraws its five and shuts both sessions down
  with an RFC 9003 shutdown communication. Both speakers advertised
  4-byte AS numbers (RFC 6793), so every AS_PATH carries 4-byte ones.
  The script writes every frame to `bgp/bgp_session.pcap` (see below)
  and keeps here only the frames whose payload is a whole number of
  complete messages — of those carrying nothing but a KEEPALIVE, only
  the first in each direction of each session — since a bare ACK or a
  segment that starts or ends inside a message does not walk cleanly.
  It checks what each direction's reassembled stream announced and
  withdrew, prefix by prefix, before writing either file. The busiest
  segment carries 7 UPDATEs, a 10-layer chain and the corpus's deepest.
  The kernel had no IPv6, so BGP over IPv6 is covered by constructed
  frames in `tests/test_bgp.py`.

- `vrrp.pcap` was produced by `scripts/capture_fixtures_vrrp.sh`:
  keepalived 2.2.8 in two netns over a veth pair, run through four
  segments (one VRID each, see the row above), captured on B's side.
  The script asks ethtool to turn offload off first but, like the
  other capture scripts, does not check that it did; what is
  guaranteed is that `check_fixtures` verifies every IPv4 header
  checksum and VRRP checksum in the file. **What keepalived built:
  the whole IPv4 datagram but its header checksum** — it sends
  through a raw socket with `IP_HDRINCL` (TOS `0xc0`, TTL 255, its
  own identification counter), and `strace`, run once while
  developing the script, showed it handing the kernel a zero header
  checksum for the kernel to fill — plus every byte of the VRRP
  message, checksum included.
  **What the kernel built:** the IPv4 header checksum and the Ethernet
  header. A master advertises once per interval for as long as it
  runs, so the script drives each segment by watching the capture,
  then keeps a fixed selection: each router's first two adverts with a
  nonzero priority in each segment, and its priority-0 advert; the gaps
  this leaves in the identification counters are adverts it dropped.
  It asserts the kept frames' composition exactly. Every VRRPv3
  frame here carries its checksum behind the IPv4 pseudo-header, with
  the real destination, so for VRID 54 the unicast peer's address
  rather than `224.0.0.18`. `check_fixtures` verifies every VRRP
  checksum: the message alone for VRRPv2 (RFC 3768 §5.3.8), and for
  VRRPv3 over IPv4 either form, behind the IPv4 pseudo-header or over
  the message alone. The pseudo-header form is keepalived's default;
  RFC 5798 §5.2.8 cites only RFC 2460's pseudo-header, which is
  IPv6's. keepalived's `v3_checksum_as_v2` option, and RFC 9568,
  which obsoletes RFC 5798, leave the IPv4 pseudo-header out: see
  `vrrp_rfc9568.pcap` below.
  It also requires each message's length, from its version and count,
  to be the IP payload's exactly.
  veth does not pad a short frame, so none of these frames carries
  Ethernet padding (they are 46-58 bytes); `tests/test_vrrp.py` pads
  them to 60 bytes, and appends a 4-byte trailer, to show the walk
  leaves both undecoded. The kernel has no IPv6, so VRRPv3 over IPv6
  is covered by constructed frames in `tests/test_vrrp.py`, with
  checksums computed there and checked by `check_fixtures` too.

- `vrrp_rfc9568.pcap` was produced by
  `scripts/capture_fixtures_vrrp_rfc9568.sh`: keepalived 2.2.8 in two
  netns (`npvr9-a`, `npvr9-b`) over a veth pair on `10.9.203.0/24`,
  every `vrrp_instance` configured with `vrrp_version 3` and
  `v3_checksum_as_v2`, run through two segments (one VRID each, see
  the row above) and captured on B's side with tcpdump 4.99.4. The
  script, keepalived's raw-socket sending, the offload caveat and the
  selection rule are `vrrp.pcap`'s. Its own stdlib assertions require
  every kept advert's checksum to be the sum of the message alone and
  not the sum behind the IPv4 pseudo-header, and the composition to
  be exact. `check_fixtures` verifies both forms independently for
  VRRPv3 over IPv4 and counts each of these 9 frames as
  `vrrpv3-no-pseudo-header`; `verify()` accepts them, and
  `with_checksums()` rewrites each into the pseudo-header form.
  tcpdump 4.99.4 reports every one as `bad vrrp cksum`: it sums
  VRRPv3 over IPv4 behind the pseudo-header.

- `ospf.pcap` was produced by `scripts/capture_fixtures_ospf.sh`: FRR
  8.4's `zebra` and `ospfd` in each of two netns over a veth pair, with
  2 s hello and 8 s dead intervals; router A (router ID 10.0.0.1,
  priority 10) also redistributes a connected /32, 192.0.2.1, so it
  originates an AS-external LSA. For each AuType the daemons are started
  fresh, A first and alone until it has elected itself Designated
  Router, off the capture; then the capture starts and B comes up, so
  the whole adjacency (2-Way, the Database Description exchange, the
  requests, the flooding and its acknowledgments) is captured within
  seconds of B's first Hello, and the capture stops once both routers
  are Full with all four LSAs in both databases, before any daemon is
  stopped. The three
  captures are concatenated, AuType 0, 1, 2 in that order. **What
  ospfd built: every OSPF byte** — header, messages, the packet
  checksum, every LSA and its LS checksum, and the MD5 digest. **What
  the kernel built:** the IPv4 header (TOS `0xc0`, TTL 1, to
  224.0.0.5 or the neighbor) and the Ethernet header. Both directions
  were captured on B's side of the veth pair with offload disabled; all
  of those checksums are computed in software (OSPF's in userspace).
  `check_fixtures` verifies the IPv4 header checksums, the OSPF packet
  checksum of every AuType 0 and 1 packet (the internet checksum of the
  packet but its Authentication field, RFC 2328 §D.4.1), the published
  password of every AuType 1 packet, the keyed-MD5 digest (RFC 2328
  §D.4.3) of every AuType 2 packet, whose packet checksum must be zero,
  with the published key, and every LSA's Fletcher checksum (RFC 2328
  §12.1.7) in its own verification form. ospfd sent no Link-Local
  Signaling (RFC 5613): no Hello or Database Description sets the L bit,
  and every IP payload is exactly Packet Length (plus the 16-byte digest
  under MD5), which the script asserts. Bytes after a packet (LLS,
  Ethernet padding, an FCS) and OSPFv3 over IPv6 (the kernel had no
  IPv6) are covered by constructed frames in `tests/test_ospf.py`. How
  B's two router LSAs are packed into updates varied between runs (one
  update, or one each); this capture has them together.

### OSPF test secrets

Published for the same reason as the IPsec keys below. Also hard-coded,
independently, in `scripts/check_fixtures.py` and `tests/test_ospf.py`.

| AuType | Secret |
|---|---|
| 1, simple password | `NPospf1` (NUL-padded to the 8-byte field) |
| 2, keyed MD5, Key ID 1 | `NETProtocols-md5` |

### IPsec test keys

Published so anyone can verify the captures: these keys protect
nothing. Every SA uses HMAC-SHA-256-128 (RFC 4868: HMAC-SHA-256 with a
256-bit key, the output truncated to its first 16 bytes) for integrity;
every ESP SA uses NULL encryption (RFC 2410). Sequence numbers are
32-bit (no ESN). The keys are also hard-coded, independently, in
`scripts/check_fixtures.py`, `tests/test_esp.py` and `tests/test_ah.py`.

| SPI | Protocol | Mode | Integrity key (hex) |
|---|---|---|---|
| `0x10000001` | ESP | transport | `e41126360fbc54a0e11a8747218b24d0cc4638f579c3985017b4d0ab1a30398b` |
| `0x10000002` | ESP | tunnel | `4bc3ce948208049b2f5016e06616867773924d2ccb4dab8b3aff93e6d26f3834` |
| `0x10000003` | ESP | transport, inside the AH bundle | `107c873bdbb0c7a11be8aa1d9064e51f63b26098412295c3bd6785958abd44d4` |
| `0x20000001` | AH | transport | `8eaa03a41a3b08f31a67f3a4b7fd78a2bf3d963a97b0af5a104301ef8fbff685` |
| `0x20000002` | AH | tunnel | `d2142153fb758a3f698e45720e2af765b2ada021d70ac1bcbde1f5bc38514fd1` |
| `0x20000003` | AH | transport, over the bundled ESP | `008a9a220d8c1bf5edec1838a724b588364c08314bf93206985e776c385e1c7a` |

- `sctp.pcap` was produced by `scripts/capture_fixtures_sctp.sh`: the
  capture host's kernel has no SCTP, so the association is between
  usrsctp's example `client` and `echo_server` (Ubuntu's
  `libusrsctp-examples`, usrsctp 0.9.5.0) in two netns over a veth
  pair, running without UDP encapsulation. usrsctp then sends through
  a raw IPv4 socket with `IP_HDRINCL`, so for frames 1-15 **usrsctp
  built the IPv4 header and the whole SCTP packet**, CRC32c included,
  and the kernel filled in the IPv4 total length and header checksum
  (and the identification on the INIT and INIT ACK, where usrsctp left
  it zero). The client sent one line, idled 45 s so each end sent a
  HEARTBEAT, and closed. Frame 16, the unknown chunk (type 63, under a
  verification tag no association uses), was **built by the script**,
  CRC32c included, and sent through a raw protocol-132 socket without
  `IP_HDRINCL`, so **the kernel built its IPv4 header**. The server
  discards it without reply: the type's high bits say so (RFC 9260
  §3.2), and usrsctp's examples set its `sctp_blackhole` sysctl, so
  they never answer an out-of-the-blue packet with an ABORT; ABORT is
  covered by constructed chunks in `tests/test_sctp.py`. Both
  directions were captured on the server's side of the veth pair,
  which is sound here: offload was disabled and every checksum in the
  file is computed in software (the CRC32c in userspace), and
  `check_fixtures` verifies all of them. veth does not pad frames to
  Ethernet's 60-byte minimum, so the short packets here carry no
  trailer; `tests/test_sctp.py` pads them by hand to cover a real NIC's.
  The kernel had no IPv6, so SCTP over IPv6 is covered by constructed
  frames in `tests/test_sctp.py`.

- `lldp.pcap` was produced by `scripts/capture_fixtures_lldp.sh`: lldpd
  1.0.18 in each of two netns over a veth pair whose ends have fixed,
  locally administered MAC addresses, run without `-c`, `-e`, `-f` or
  `-s`, so only LLDP is spoken, each on its own veth end (`-I`) with its
  own control socket (`-u`), its IPv4 address as management address
  (`-m`) and a configuration file of `lldpcli` commands (`-O`), which
  lldpd runs before it sends anything: a system name and description,
  the Port ID subtype (`portidsubtype ifname` for A, `macaddress` for
  B), and for A a custom TLV (`custom-tlv oui 0a,4e,50 subtype 1` with
  300 bytes of content, `00 01 … ff 00 … 2b`), for B a locally assigned
  Chassis ID (`system chassisid`) and `tx-hold 6`. A's Port ID is then
  changed at run time with `lldpcli configure lldp portidsubtype local
  np-port-a`, and both agents are stopped with SIGTERM. **What lldpd
  built: every byte of every frame**, the Ethernet header included —
  `_lldp_send()` writes it and the frame goes out through a raw
  `PF_PACKET` socket — so there is no kernel-built header and no
  checksum: LLDP has none. **What the configuration chose:** the system
  names and descriptions, the Port ID subtypes, A's custom TLV, B's
  Chassis ID and its TTL (tx-interval 30 s × tx-hold 6); the rest is
  lldpd's default — Chassis ID from A's MAC address, TTL 120 (30 s × 4),
  the System Capabilities, the two IEEE 802.3 TLVs (link aggregation,
  MAC/PHY), and the interface number in the Management Address TLV (42
  for A and 41 for B in this capture, 8 and 7 in an earlier run), which
  lldpd takes from the system and the script does not pin. lldpd sends a
  shutdown LLDPDU (TTL 0, the three mandatory TLVs and End of LLDPDU
  only) when it stops, and before it sends with a changed chassis or
  port ID, for the old one. Both directions were captured on B's side of
  the pair (`ether proto 0x88cc`); lldpd repeats an unchanged LLDPDU
  every 30 s, so the script keeps the first LLDPDU of each kind (sender,
  Port ID subtype, shutdown or not) and asserts the six exactly:
  destination, sender, Chassis ID, Port ID, TTL, the TLV type sequence,
  A's custom TLV, and that nothing follows End of LLDPDU. Every TLV is
  under 512 bytes, as the 9-bit Length requires, and the custom one, at
  304, is the only one past 255. veth does not pad, so the shutdown
  frames are 41 and 48 bytes; `tests/test_lldp.py` pads every frame to
  60 bytes, and appends a 4-byte trailer, to show the walk leaves both
  undecoded, and builds the TLV types, lengths and malformed LLDPDUs no
  capture holds. LLDP has no checksum, so `check_fixtures` checks each
  LLDPDU's structure instead: the TLVs walk to an empty End of LLDPDU
  TLV followed only by zero bytes, the first three are a Chassis ID and
  a Port ID (each a subtype and a 1-255 byte ID) and a 2-byte Time To
  Live, none of which recurs, and a shutdown LLDPDU carries nothing
  else.

- `pim.pcap` was produced by `scripts/capture_fixtures_pim.sh`: four
  netns in a line over three veth pairs — a multicast source, two FRR
  8.4 routers (zebra + pimd, R1 `10.184.12.1` with a secondary
  `10.184.13.1` on the captured link, R2 `10.184.12.2`) and a receiver
  that joins two groups from a socket with `IP_ADD_MEMBERSHIP` (IGMPv3,
  `ip igmp` on R2's receiver-facing interface). Static RPs are on
  opposite routers — R2 for `239.184.0.1`, R1 for `239.184.0.2` — so
  both a (*,G) tree and a Register exchange cross the R1–R2 link, where
  tcpdump captured `ip proto 103` on R1's side. So R1's own Hello and
  both Registers (frames 1, 4 and 8) are outbound frames, despite the
  inbound-only rule above, and the other ten are R2's, inbound. That
  is harmless here, as for SCTP: pimd computes every PIM checksum
  itself, in userspace, before the kernel sees the packet, the kernel
  computes IPv4 header checksums in software, the script asks ethtool
  to turn veth offloads off, and `check_fixtures` verifies all of
  them. `ip pim
  register-suppress-time 15` brings R1's Null-Register probe inside the
  capture. The receiver then leaves (R2 prunes), and R2's pimd is
  stopped (its goodbye Hello). Hello and Join/Prune timers make the raw
  capture's frame count vary, so the script keeps the first frame of
  each of the 13 kinds it names and fails unless it saw all of them;
  the committed file is that selection. **pimd built every PIM
  message**, checksum included, **and the outer IPv4 headers**: FRR
  8.4's `pim_msg_send()` fills in the identification, TOS, TTL, total
  length and addresses and sends with `IP_HDRINCL` (`IPPROTO_RAW` for
  Registers), so **the kernel filled in only the IPv4 header checksum
  and total length**, as it always does for such a socket.
  FRR sums a Register's checksum over its first 8 bytes
  only, as RFC 7761 §4.9.3 specifies; `check_fixtures` accepts that or
  the whole-message form the RFC asks receivers to accept too. The data
  Register's encapsulated packet is the source's datagram as R1
  received it (IPv4 header and UDP checksum built by the source's
  kernel), and `check_fixtures` verifies it too. The Null-Register's
  dummy IPv4 header carries a zero header checksum, which RFC 7761
  §4.9.3 says a receiver must not check, so `check_fixtures` counts it
  as `pim-null-register-unchecked` (an IPv6 Null-Register's dummy PIM
  header, which no capture here holds, is checked by its own checksum;
  `tests/test_pim.py` builds two). veth does not pad frames, and the
  shortest here (the Register-Stop, a 38-byte datagram) would get 8
  bytes of zero padding from a real NIC; `tests/test_pim.py` appends
  padding and a 4-byte trailer by hand. The kernel had no IPv6, so PIM
  over IPv6 is covered by constructed frames in `tests/test_pim.py`,
  their pseudo-header checksums computed there independently. No
  capture holds an Assert, Bootstrap, Candidate-RP-Advertisement or
  Graft: `tests/test_pim.py` builds an Assert and Graft messages, and
  decodes the other types with their body kept raw.

- `rip.pcap` was produced by `scripts/capture_fixtures_rip.sh`: two
  BIRD 2.14 daemons, one per netns over a veth pair, each exporting
  three static blackhole routes (and, over RIPv2, its connected
  10.9.52.0/24) with a 5-second update timer, run once per scenario
  with tcpdump on 10.9.52.1's side of the pair and offload disabled on
  both ends. **BIRD built every RIP byte**, the authentication entries
  and trailers included; **the kernel built the UDP header** (its
  checksum computed in software, and verified by `check_fixtures`),
  **the IPv4 header and the Ethernet header**. Updates follow at times
  a capture cannot pin down, so the script captures each scenario whole
  and keeps a fixed selection, asserting it exactly: per scenario, each
  router's first Request and first Response, and in the RIPv2 scenario
  10.9.52.1's first Response whose whole-second pcap timestamp is 6 or
  more past the scenario's first captured frame's, hence more than 5 s
  after it (not necessarily the first Response more than 5 s after),
  past its 5-second update timer: a whole-table update, carrying the
  peer's routes back poisoned. BIRD sends a RIPv1 router only classful
  networks, so the v1 routes are a class A, B and C network and the
  connected /24 is not advertised. In the RFC 4822 scenarios BIRD fills
  in Auth Data Len as 20 for keyed MD5, counting the trailer's 4-byte
  header with the 16-byte digest, and as 32 for HMAC-SHA-256, the digest
  alone, as the RFC says; `tests/test_rip.py` pins both. The sequence
  numbers of the Responses come from BIRD's clock, so a re-capture
  differs in them, the digests, the IPv4 identification and the
  timestamps. Everything here is IPv4: RIP has no IPv6 form (RIPng,
  RFC 2080, is a separate protocol on UDP 521, not decoded), and veth
  does not pad, so no frame carries Ethernet padding or an FCS;
  `tests/test_rip.py` appends a 4-byte trailer to every frame and cuts
  one inside an entry to cover both.

- `tftp.pcap` was produced by `scripts/capture_fixtures_tftp.sh`:
  in.tftpd from tftpd-hpa 5.2 (`--secure --create`, as user `nobody`,
  on a scratch directory) in one netns and the tftp-hpa 5.2 client and
  curl 8.5.0 in another, over a veth pair with offload disabled on both
  ends, tcpdump on the server's side filtering on the two hosts rather
  than on port 69, so the whole transfer is kept: **the clients and the
  server built every TFTP byte; the kernel built the UDP header** (its
  checksum computed in software, and verified by `check_fixtures`),
  **the IPv4 header and the Ethernet header**. A transfer is lockstep,
  so the capture is kept whole, and the script asserts its composition
  exactly, frame by frame: direction, whether port 69 is one of the
  ports, opcode, block number, data length, error code and option names;
  it also checks that each file arrived intact. Only the requests go to
  port 69 (RFC 1350 §4), so a default walk decodes a `TFTP` layer for
  those 6 alone and stops at UDP for the other 27; `tests/test_tftp.py`
  decodes them by naming the server's port with `decode_as`. Two
  behaviours are the programs' own and kept as sent: tftpd-hpa reports a
  file it cannot open as ERROR code 0 with `strerror`'s text, not as
  code 2, and the tftp-hpa client answers either ERROR with an ACK of
  block 1, as BSD tftp's `recvfile` does. The file contents are fixed
  text the script writes; the ports, the IPv4 identification and the
  timestamps differ in a re-capture. veth does not pad, so no frame
  carries Ethernet padding (every ACK here, 4 bytes in an untagged
  frame over IPv4 with no options, would get 14 bytes of it on a wire)
  or an FCS; `tests/test_tftp.py` appends both.

- `radius.pcap` was produced by `scripts/capture_fixtures_radius.sh`:
  FreeRADIUS 3.2.5 (`freeradius -X`, in the foreground, on a copy of
  the packaged configuration with the EAP module and the inner-tunnel
  site left out and a minimal site of the script's own: `chap`,
  `files` and `pap` to authorize, `detail` for accounting) in one netns
  and radclient 3.2.5 in another, over a veth pair with offload
  disabled on both ends and tcpdump on the server's side. **radclient
  and FreeRADIUS built every RADIUS byte**, the authenticators, the
  hidden User-Password, the CHAP-Password and the
  Message-Authenticators included; **the kernel built the UDP header**
  (its checksum computed in software, and verified by
  `check_fixtures`), **the IPv4 header and the Ethernet header**. Each
  request is sent once (`radclient -r 1`) and answered before the next
  is sent, so the capture is exactly the twelve frames in request,
  reply order, which the script asserts, frame by frame, with the
  attribute types each one carries and the Identifier pairing.
  radclient 3.2.5 adds a Message-Authenticator to every Access-Request
  and Status-Server, and FreeRADIUS 3.2.5 to every Access-Accept and
  Access-Reject (both BlastRADIUS hardening), so every authentication
  frame here carries one; `tests/test_radius.py` builds an
  Access-Request without one. FreeRADIUS answers the wrong password
  after its 1-second reject delay, and its Access-Reject carries the
  user entry's Reply-Message, which `attr_filter.access_reject` lets
  through. The Identifiers, the Request Authenticators of the
  Access-Requests and the Status-Server (random), every authenticator
  and Message-Authenticator computed from them, the IPv4
  identifications and the timestamps differ in a re-capture. veth
  does not pad and no packet is short enough to need Ethernet padding,
  so no frame carries padding or an FCS; `tests/test_radius.py`
  appends a 4-byte trailer to every frame. Everything here is IPv4.

- `llc.pcap` was produced by `scripts/capture_fixtures_llc.sh`: three
  netns, A and B each holding a Linux bridge with STP on (802.1D, 1 s
  hello time, 2 s forward delay; A at priority 0x1000, so the root),
  a veth pair between A's port and B's, and a second from B's other
  port to netns X, with tcpdump on B's port facing A capturing both
  directions (`not ether proto 0x88cc`, so no LLDP). Bringing the A-B
  link up gives each bridge's first Configuration BPDU, then A's, as
  root, and A's with the Topology Change flag once its port forwards;
  bringing B's second port up makes B, not the root, send a Topology
  Change Notification, which A acknowledges. lldpd 1.0.18 then runs in
  A on A's port, with its own control socket, pidfile and interface
  list, `-cc` (CDPv1 forced), then `-ccc` (CDPv2 forced), then `-cc`
  again with the platform name `npll` and the byte 0xA9, in its own
  UTS namespace with hostname `npllc-cdp`, `-k`, `-S` and `-P`, so the
  frames carry no detail of the capture host. Last,
  `scripts/llc_fixture_frames.py` (stdlib only) sends six frames from A
  through an `AF_PACKET` socket. **The kernel's bridge code built every
  BPDU** (Ethernet header, LLC header and BPDU), **lldpd built every
  CDP frame** in userspace, its checksum included, and **the script
  built every byte of the other six**, their zero padding to 60 bytes
  and the IPv4 header and ICMP checksums included; `AF_PACKET` sends a
  frame as it is given. The bridges and veths have fixed MAC addresses,
  so the BPDUs' bridge and port IDs are the same on every run. BPDUs
  repeat every second and CDP frames too, so the script keeps the first
  frame of each of the 14 kinds it names and fails unless it saw all of
  them, in order. `check_fixtures` holds each 802.3 Length against its
  frame (only the zero padding of a PDU shorter than 46 bytes may
  follow), checks the LLC and SNAP framing and the BPDU and raw IPX
  lengths, walks the CDP TLVs to the Length's end and verifies the CDP
  checksum over exactly that PDU (91 bytes in all three, odd: where RFC
  1071 pads a final byte into the high byte of a word, CDP's checksum
  adds it as the low byte when it is below 0x80 and as 0xFF00 plus its
  value less 1 when not, the form of lldpd's `frame_checksum()` in
  src/daemon/frame.c and Wireshark's packet-cdp.c, and lldpd's three
  frames verify that way; the third, ending in 0xA9, pins that a final
  byte from 0x80 is not padded as RFC 1071 pads it, nor added as its
  plain value or as 0xFF00 plus it without the `- 1`, but it cannot
  tell lldpd's form from adding the byte less 0x100, which differs
  only where the sum under `v - 0x100` folds to 0, which is 0xFFFF
  under lldpd's form, giving a checksum of 0xFFFF under `v - 0x100`
  and 0 under lldpd's: `test_cdp_odd_byte_is_lldpds_form` in
  `tests/test_llc.py` separates the two on `b"\x00\x7f\x81"`), and
  verifies the IPv4 and ICMP checksums inside RFC 1042 framing. veth
  does not pad, so the BPDUs and CDP frames carry no padding (the TCN is a
  21-byte frame); `tests/test_llc.py` appends padding and a 4-byte
  FCS by hand, and `tests/test_cdp.py` does for the CDP frames. The
  BPDUs decode to `STP` (all 802.1D, Protocol Version 0: the kernel's
  bridge speaks no RSTP, and mstpd, which would, has no installable
  package here, so RST BPDUs are covered only by frames
  `tests/test_stp.py` builds), and `check_fixtures` also holds each
  BPDU to its type's length (35 octets for a Configuration BPDU, 4 for
  a TCN, 36 for an RST BPDU, which must also have a Protocol Version of
  2 or more) and, as checks on what the sender transmitted rather than
  what a receiver requires, its type's unused flag bits and an RST
  BPDU's Version 1 Length to 0. The CDP frames decode through to
  `CDP`, whose checksum `tests/test_checksum.py` recomputes for all
  three; the three carry the same six TLVs (Device ID, one IPv4
  address, Port ID, Capabilities, Software version, Platform), and the
  forms they do not, such as an IPv6 address, are built in the tests
  (the kernel boots with IPv6 disabled).

- `stun.pcap` was produced by `scripts/capture_fixtures_stun.sh`:
  coturn 4.6.1's `turnserver` in STUN-only mode (`--stun-only`, no TLS
  or DTLS, `--fingerprint`) on 10.9.194.2 in one netns, clients on
  10.9.194.1 in another, a veth pair between them with offload disabled
  on both ends, tcpdump on the client's side, one capture per scenario.
  **coturn built every response (frames 1, 3, 5, 7 with two, 9 and
  11). `turnutils_stunclient` built the binding and RFC 5780 requests
  (frames 0 and 2), neither with a FINGERPRINT; the script built the
  other five** (the unknown-attribute request, frame 4; the two TCP
  requests, both in frame 6; and the secure scenario's two, the
  unauthenticated request in frame 8 and the authenticated one in
  frame 10), in a stdlib Python client, adding a FINGERPRINT to each
  but the second TCP request, which is a bare header; **the kernel
  built the UDP and TCP headers** (their checksums computed in software
  and verified by `check_fixtures`), **the IPv4 header and the Ethernet
  header.** The
  script keeps every UDP frame, every TCP segment with data (a bare
  ACK on port 3478 hands `STUN` an empty payload, as one on 179 hands
  `BGP`), and of the `-f` run only the RFC 5780 request and its answer,
  and asserts the selection exactly: direction, transport, message
  types, attribute types in order, matching transaction IDs, error
  codes and every FINGERPRINT. coturn pads its error reason phrases
  with NUL bytes it counts in the attribute's length. The transaction
  IDs, the NONCE, the ports and so every XOR-MAPPED-ADDRESS, the
  FINGERPRINTs and MESSAGE-INTEGRITYs differ in a re-capture. The
  kernel had no IPv6, so XOR-MAPPED-ADDRESS over IPv6, whose XOR also
  takes in the transaction ID, is covered by RFC 5769's test vectors
  in `tests/test_stun.py`. The same script captures the RFC 3489
  exchange in `stun/stun_rfc3489.pcap` (see below).

### STUN test credential

Published so anyone can verify the captures: it protects nothing. The
secure scenario's server ran with `--secure-stun --lt-cred-mech`, realm
`np194.test` and one user, `npstun`, password `np194-pass`. The
long-term key is MD5(`npstun:np194.test:np194-pass`) (RFC 8489
§9.2.2, RFC 5389 §15.4), and `check_fixtures` verifies every
MESSAGE-INTEGRITY with it: HMAC-SHA1 over the message before the
attribute, the header's Length counting up to the attribute's end. A
message carrying another USERNAME, or a MESSAGE-INTEGRITY-SHA256,
which it does not compute, fails. The credential is also hard-coded,
independently, in `scripts/check_fixtures.py` and `tests/test_stun.py`.

- `ntp.pcap` was produced by `scripts/capture_fixtures_ntp.sh`: a
  chronyd 4.5 server (`local stratum 8`, `allow all`, a keyfile and a
  throwaway NTS certificate, all in a scratch directory) in one netns
  over a veth pair, and clients in the other: ntpdig from ntpsec, plain
  and with each published key, then chronyd with `-Q`, which only
  measures, as an NTPv3 client (`version 3`), with `extfield F323`
  and with `nts`, then chronyd as a symmetric active peer, then the
  server restarted with `broadcast`. Every chronyd runs with `-x`, so
  none touches the system clock. tcpdump captures `udp port 123` on the
  server's side of the pair, offload disabled on both ends, one scratch
  file per scenario, and the script keeps a fixed selection and asserts
  it exactly (sender, version, mode, stratum and length after the
  header): per client scenario the first request and the server's
  answer to it, found by its Origin Timestamp, which is the request's
  Transmit Timestamp (RFC 5905 §8); the peer's first packet at stratum
  0 and its first at stratum 9, each with the answer; and the first
  broadcast. The NTS-KE handshake that precedes the NTS exchange runs
  over TCP 4460 and is left out by the filter. **chronyd and ntpdig
  built every NTP byte**, MACs, extension fields and NTS cookies
  included; **the kernel built the UDP header** (its checksum computed
  in software, and verified by `check_fixtures`), **the IPv4 header and
  the Ethernet header**. `check_fixtures` also walks every NTPv4
  message's extension fields (RFC 7822 §3's Length rules) and verifies
  each MAC with the published keys: the digest of the key followed by
  the message before the MAC, which ntpdig's requests and chronyd's
  answers both compute that way. ntpdig puts the current time in its
  Transmit Timestamp, so `tests/test_ntp.py` holds its conversion
  against the pcap timestamps; chrony's client puts random bits there,
  which its server echoes. A re-capture differs in every timestamp, the
  random Transmit Timestamps, the NTS keys, cookies and ciphertext, the
  digests, the IPv4 identification and the client's source ports.
  Everything here is IPv4 (the container's kernel had IPv6 disabled).
  No frame carries Ethernet padding, and none could: the 48-byte NTP
  header behind IPv4's 20 bytes and UDP's 8 already fills Ethernet's
  46-byte minimum payload. No frame carries an FCS either, since
  tcpdump on a veth device captures none. `tests/test_ntp.py` builds
  the trailers, a crypto-NAK, a Kiss-o'-Death and the control messages
  the decoder rejects (an ntpq mode 6 request and response, and mode 7
  requests of 48 and 192 bytes), none of which these daemons send.

### NTP test keys

Published so anyone can verify the captures: these keys protect
nothing. `check_fixtures` and `tests/test_ntp.py` both hard-code them,
independently, and verify every MAC in `ntp.pcap` with them.

| Key ID | Algorithm | Key (ASCII) |
|---|---|---|
| 1 | MD5 | `np191-md5-key` |
| 2 | SHA-1 | `np191-sha1-key` |

### RIP test keys

Published so anyone can verify the captures: these passwords protect
nothing. `check_fixtures` verifies every keyed-MD5 digest (MD5 over the
message up to and including the trailer's header, then the key
zero-padded to 16 bytes, RFC 4822 §2.4) and every HMAC-SHA-256 digest
(over the same bytes followed by the Apad `0x878FE1F3` repeated over
the digest's length, §2.5), keyed by Key ID; the keys are also
hard-coded, independently, in `scripts/check_fixtures.py` and
`tests/test_rip.py`.

| Scenario | Authentication | Key ID | Password |
|---|---|---|---|
| plaintext | plain-text password (type 2) | — | `nprip-pw` |
| md5 | keyed MD5 (type 3) | 1 | `nprip-md5-key` |
| sha256 | HMAC-SHA-256 (type 3) | 2 | `nprip-sha256-key` |

### RADIUS test secrets

Published so anyone can verify the captures: these values protect
nothing. `check_fixtures` verifies, with the shared secret, the Request
Authenticator of every Accounting-Request (Code 4), Disconnect-Request
(Code 40) and CoA-Request (Code 43): MD5 over the packet with a zero
Authenticator, then the secret (RFC 2866 §3; RFC 5176 §2.3 computes a
Disconnect-Request's and a CoA-Request's as an Accounting-Request's),
counted and failed as `radius-accounting-authenticator`,
`radius-disconnect-authenticator` and `radius-coa-authenticator`
respectively. It verifies the Message-Authenticator of every
Access-Request (Code 1) and Status-Server (Code 12), HMAC-MD5 under the
secret over the packet with the attribute's value zeroed (RFC 3579
§3.2), and of every Disconnect-Request and CoA-Request that carries
one, the same over the packet with its Authenticator zeroed too (RFC
5176 §3.4: the Message-Authenticator is computed first and the Request
Authenticator then covers it), all as `radius-message-authenticator`;
a request's Request Authenticator and Message-Authenticator fail on
their own. A reply's Response Authenticator and
Message-Authenticator are computed over its request's Authenticator, in
another frame, so `check_fixtures` pairs each reply with a request of
the same pcap: one from the reply's destination address and port to
its source address and port with the same Identifier and a Code the
reply's Code answers, the most recent such request no earlier reply has
answered, which handles a reused Identifier. Access-Accept,
Access-Reject and Access-Challenge answer an Access-Request (RFC 2865
§3), Accounting-Response an Accounting-Request (RFC 2866 §3),
Disconnect-ACK/NAK a Disconnect-Request and CoA-ACK/NAK a CoA-Request
(RFC 5176 §2.3). A Status-Server is answered by Access-Accept,
Accounting-Response or Access-Reject: RFC 5997 §2 says a server answers
it with Access-Accept on an authentication port or Accounting-Response
on an accounting port, that it MAY answer with Access-Reject and that
Access-Challenge is NOT RECOMMENDED, so Access-Challenge is not paired
with one. It then verifies the reply's Response Authenticator (MD5 over
the reply with the request's Authenticator in its place, then the
secret, RFC 2865 §3, `radius-response-authenticator`) and its
Message-Authenticator when it carries one (HMAC-MD5 under the secret
over the reply with the request's Authenticator in place and the
attribute's value zeroed, RFC 3579 §3.2,
`radius-reply-message-authenticator`), for Access-Accept, Access-Reject,
Access-Challenge, Accounting-Response and the Disconnect and CoA ACKs
and NAKs (RFC 5176 §2.3, on UDP 3799). A UDP datagram is read as RADIUS
when the server's port is 1812, 1813 or 3799, the source port of a reply
and the destination port of anything else, and neither port is STUN's
3478, NTP's 123 or HSRP's 1985, the ports the checker reads as those
protocols, so a STUN or NTP reply sent to a client's ephemeral 1812,
1813 or 3799 is read as STUN or NTP. A reply that no earlier request of
its pcap matches is counted `radius-reply-unpaired` and not checked, as
an unreadable payload is counted and not failed, and fails as
`unchecked-radius-reply-unpaired` inside a payload an IPsec ICV vouched
for; one whose exchange has unanswered requests, but none of a Code it
answers, is counted `radius-reply-code-mismatch` and not checked, and
fails as `unchecked-radius-reply-code-mismatch` inside such a payload.
`radius.pcap`'s six replies all pair and verify. `tests/test_radius.py`
also pairs each reply with its request and verifies those, and unhides
each User-Password (RFC 2865 §5.2) and checks the CHAP-Password (§5.3).
The values are also hard-coded, independently, in
`scripts/check_fixtures.py` and `tests/test_radius.py`.

| What | Value |
|---|---|
| shared secret (client `10.9.193.2`) | `np193-radius-secret` |
| user | `np193-user` |
| its password (PAP and CHAP) | `np193-pass` |
| the wrong password (PAP, rejected) | `np193-wrong` |

- `hsrp.pcap` was produced by `scripts/capture_fixtures_hsrp.sh`.
  RFC 2281's HSRP is Cisco's and no open-source router speaks it, so
  there is no daemon to run between two netns as the other scenarios
  do. Yersinia 0.8.2's HSRP attack 0 sends one raw HSRPv1 message per
  invocation, every field set from its command line, and the script
  runs it twelve times, one invocation per frame, in one netns, out a
  veth pair whose other end, in a second netns, tcpdump captures on,
  offload disabled on both ends. **What Yersinia built: every byte of
  every frame**, the Ethernet, IPv4 and UDP headers and their
  checksums included (it writes raw frames, so the kernel builds
  nothing); `check_fixtures` verifies every IPv4 header checksum and
  UDP checksum in the file. The source MAC addresses are pinned on the
  command line, since Yersinia randomizes them otherwise, so a
  re-capture is byte for byte the same but for the pcap record
  timestamps. Yersinia sets the TTL to 1, as RFC 2281 §5.1 says, the
  IPv4 identification to 0 and the ToS to 0x10 (DSCP 4) rather than
  the CS6 a Cisco router uses. The script asserts the twelve frames
  one by one, by sender, Op Code, State, priority, timers, group,
  virtual IP, authentication data, addresses, ports, Version and the
  Reserved and TTL bytes, parsing the pcap with the standard library,
  and then runs `check_fixtures` over it. HSRP has no checksum of its
  own, so `check_fixtures` checks each message's fields instead (see
  `_check_hsrp`): exactly 20 bytes, from and to port 1985, Version 0,
  a known Op Code and State and, in a Hello, a Holdtime above the
  Hellotime, which RFC 2281 requires, and, as this corpus's
  conventions rather than the RFC's, a zero Reserved byte and
  clear-text Authentication Data. No router's state machine sent these
  frames: they are a scripted sequence of Hello, Coup and Resign
  messages, not a faithful run of RFC 2281's state machine (frame 7
  has R2 go from Standby to Speak after R1's Resign, where §5.7's
  table takes a Standby router straight to Active), and every sender
  uses its own MAC address, Active or not, where §6.1 has an Active
  router send from the group's virtual MAC address
  (`00:00:0c:07:ac:01` for group 1), and keeps the 3 s / 10 s timers
  throughout. `tests/test_hsrp.py` therefore builds, as
  constructed frames, an exchange modelling behaviour reported for
  Cisco routers (TTL 2, the virtual MAC as the Active router's source,
  timers moving to 5 s / 15 s on becoming Active, a Coup from Listen
  preempting the Active router and its Resign), and what neither
  holds: the Initial and Learn states, HSRPv2, an Op Code 3 Advertise,
  the MD5 Authentication TLV and other trailers. Nothing in the frames
  is sensitive: the addresses are in 10.9.195.0/24, the MAC addresses
  locally administered, and the passwords `cisco` (§5.1's default) and
  `spark` protect nothing. Everything here is IPv4 and untagged, and
  no frame carries Ethernet padding or an FCS: a 20-byte HSRP message
  behind UDP's 8 bytes and IPv4's 20 already fills Ethernet's 46-byte
  minimum payload, and tcpdump on a veth device captures no FCS.
- `tls.pcap` was produced by `scripts/capture_fixtures_tls.sh`. nginx
  1.24 (nginx-light, OpenSSL 3.0.13) serves HTTPS on 10.9.196.2:443 in
  one netns, with session tickets off and a self-signed ECDSA P-256
  certificate for `tls.np196.test` that the script generates in a
  scratch directory and deletes on exit; no key is committed. Five
  clients in a second netns, a veth pair away with offload disabled on
  both ends, reach it by that name, never by address (RFC 6066 §3
  forbids an IP literal in server_name), through an `/etc/hosts` that
  `ip netns exec` bind-mounts from `/etc/netns/np-tls-client/`: headless
  Chromium 153 (Chrome for Testing, BoringSSL), curl 8.5 (OpenSSL
  3.0.13), gnutls-cli 3.8.3, `openssl s_client -noservername` and curl
  with `--tls-max 1.2`. Each runs in its own tcpdump capture on the
  client's end of the pair. **What the clients and nginx built: every
  TLS byte; what the kernel built: the TCP and IPv4 headers and their
  checksums**, which `check_fixtures` verifies, and the Ethernet
  header, from MAC addresses the script pins. The script reassembles
  every connection with `scripts/extract_http_streams.py`'s `extract()`
  and asserts what it keeps: the number of connections per client
  (Chromium opens two, abandoning the first after the server's flight),
  that both sides of each are whole records, each ClientHello's record
  version, session ID and server_name, Chromium's GREASE, its
  X25519MLKEM768 key share beside X25519's, its two segments and its
  two extension orders, each ServerHello, the TLS 1.2 record sequence,
  and the content types of every corpus frame, in order. What it
  observed: Chromium's ClientHello is a 1738-byte record (19
  extensions, a 1263-byte key_share, GREASE first and last, and three
  types `TLSExtension.type_name` shows as `unknown (n)`: 4832, 17613
  and 51764, which IANA's ExtensionType registry (read 2026-11-01)
  leaves unassigned and BoringSSL's `include/openssl/tls1.h` (main,
  commit 5ed1348b) defines, each as "not an IANA defined extension
  number", as `server_padding`, `application_settings` (ALPS,
  draft-vvv-tls-alps, which Wireshark's `packet-tls-utils.h` names too)
  and `trust_anchors`), carried in a 1448-byte and a 290-byte segment,
  its extensions in a different order on each connection; curl's is 517 bytes (12 extensions, padded by
  OpenSSL to a 512-byte fragment), gnutls-cli's 392 (13), s_client's
  293 (9, no server_name) and the TLS 1.2 curl's 225 (7, no session ID
  and no TLS 1.3 suite); every one but gnutls-cli's says TLS 1.0 in its
  record header. No ECH extension was sent. TLS carries no checksum of
  its own beyond TCP's, so `check_fixtures` checks the records instead
  (see `_check_tls`): each segment on port 443 that carries data must
  be whole records with a length of at most 2^14 + 2048, no empty
  Handshake, Alert or ChangeCipherSpec record, every ChangeCipherSpec
  the single byte 1, every ClientHello whole and its fields tiling it,
  and every server_name one printable-ASCII host name, neither an IP
  address nor ending in a dot. A segment that begins or ends inside a
  record is counted `tls-unchecked`, and fails its file (`tls-split`)
  unless the file is a session capture, named `*_session.pcap`; the
  corpus has none.
  Randoms, key shares, session IDs and GREASE values are fresh in
  every run, so a re-capture differs in those bytes and in the
  timestamps, but not in what the script asserts. Nothing is
  sensitive: the addresses are in 10.9.196.0/24, the MAC addresses
  locally administered, the key gone, and the only application data is
  `GET /` and nginx's fixed answer, encrypted.

## HTTP captures (`tests/fixtures/http/`)

Outside the corpus on purpose: the corpus globs are non-recursive, and
none of the counts above include these. HTTP is not port-dispatched —
a TCP segment is not an HTTP message — so these frames would add
nothing to the per-frame invariants; what they are for is the byte
streams.

`http.pcap` (98 frames, every TCP checksum verified by
`check_fixtures`) was produced by `scripts/capture_fixtures_http.sh`:
Python's `http.server` (`protocol_version = "HTTP/1.1"`) on one end of
a veth pair, curl and a raw socket client on the other, offload
disabled, every segment kept. `scripts/extract_http_streams.py`
(stdlib only, no netprotocols import) wrote each connection's byte
streams, `NN.request` and `NN.response`, in the order the connections
opened; `tests/test_http.py` reassembles them again through
`decode_frame` and checks they match before decoding them.

| Connection | Client | Requests | Responses |
|---|---|---|---|
| 01 | curl | `GET /hello` | 200, Content-Length |
| 02 | curl | `HEAD /hello` | 200, Content-Length 42 and no body |
| 03 | curl | `GET /hello`, `If-None-Match` | 304 |
| 04 | curl | `POST /echo` | 201, the body echoed |
| 05 | curl | `GET /chunked` | 200, chunked, one trailer field |
| 06 | curl | `GET /missing` | 404, `Connection: close` |
| 07 | socket | `GET /hello`, `HEAD /hello`, `GET /chunked` with `Connection: close`, pipelined in one write | the three responses, in order |

curl cannot pipeline (libcurl's `CURLMOPT_PIPELINING` has no effect for
HTTP/1.1 since 7.62.0), hence the socket client for 07. The streams
also seed `tests/fuzz/fuzz_http_decode.py`.

## BGP session capture (`tests/fixtures/bgp/`)

Outside the corpus on purpose, like the HTTP captures above: none of
the counts above include it. `bgp_session.pcap` (94 frames, every TCP
checksum verified by `check_fixtures`) is every frame of the session
`bgp.pcap` was cut from, the handshakes, bare ACKs, FINs and
KEEPALIVE-only segments included. Its point is the segments a
per-segment walk cannot decode whole: frame 31 holds two complete
UPDATEs and the first 332 bytes of a 1063-byte third, which frame 33
finishes; frames 34-35 and 86-87 each split one UPDATE (2090 and 2430
bytes) between them. `tests/test_bgp.py` walks those strictly and in
lax mode, and reassembles each direction's stream to check it is
nothing but whole messages.

## STUN RFC 3489 capture (`tests/fixtures/stun/`)

Outside the corpus on purpose: `netprotocols.STUN` rejects every frame
in it, at the magic cookie, so a strict walk of it raises, which the
corpus's invariants do not allow. `stun_rfc3489.pcap` (4 frames, every
UDP checksum verified by `check_fixtures`, which counts them as
`stun-rfc3489`) is the `stun` client's (stun-client 0.97) exchange with
the same coturn server, captured by `scripts/capture_fixtures_stun.sh`:
RFC 3489 messages, with a 16-byte transaction ID where RFC 5389 put the
cookie. The script keeps two of its exchanges: a Binding Request with
CHANGE-REQUEST 0 and the Success Response, which carries
MAPPED-ADDRESS, SOURCE-ADDRESS, CHANGED-ADDRESS and SERVER (the name
RFC 3489 gave 0x8022), and a request asking for another address and
port and the error 420 coturn answers with. `tests/test_stun.py` walks
them to the rejection, strict and lax.

## TLS session capture (`tests/fixtures/tls/`)

Outside the corpus on purpose, like the BGP session above: none of the
counts above include it. `tls_session.pcap` (108 frames, every TCP
checksum verified by `check_fixtures`) is every frame of the six
connections `tls.pcap` was cut from, the handshakes, bare ACKs and
FINs included, in capture order: Chromium's two (frames 0-35, the
first connection's last frames interleaved with the second's), curl's
(36-53), gnutls-cli's (54-71), s_client's (72-91) and the TLS 1.2
curl's (92-107). Its point is what a per-segment walk cannot decode:
frames 3 and 15 each hold a Chromium ClientHello's record header and
its first 1443 bytes, which frames 4 and 16 finish, so a strict walk
raises `TruncatedHeaderError` at the first and `InvalidFieldError` at
the second, and `check_fixtures` counts all four `tls-unchecked`, which
it allows only in a file named `*_session.pcap`, as this one is; the
SNI of those ClientHellos is read by reassembling the client's stream
and decoding that. `tests/test_tls.py` walks the split segments strict
and lax, reassembles every connection with
`scripts/extract_http_streams.py` and reads each client's SNI.

## Provenance note

This corpus exposed a real defect on arrival: non-first IPv4 fragments
were chained into garbage upper-layer decodes ("ICMPv4 type 192" from
mid-payload bytes) because `IPv4.next_protocol()` ignored
`fragment_offset`. Fixed alongside the corpus's introduction; see
`tests/test_corpus.py::TestFragmentHandling`.
