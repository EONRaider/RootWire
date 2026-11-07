# RootWire

[![CodeFactor](https://www.codefactor.io/repository/github/eonraider/rootwire/badge)](https://www.codefactor.io/repository/github/eonraider/rootwire)
[![CI](https://github.com/EONRaider/RootWire/actions/workflows/ci.yml/badge.svg)](https://github.com/EONRaider/RootWire/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/rootwire)](https://pypi.org/project/rootwire/)
![Python Version](https://img.shields.io/badge/python-3.12%2B-blue?logo=python)
![OS](https://img.shields.io/badge/OS-GNU%2FLinux-red?logo=linux)
[![License](https://img.shields.io/github/license/EONRaider/RootWire)](https://github.com/EONRaider/RootWire/blob/master/LICENSE)

A network traffic monitor for GNU/Linux — *formerly known as
Packet-Sniffer*. Frames are captured from one or more network
interfaces with a raw socket, timestamped by the kernel itself, decoded
layer by layer with the
[NETProtocols](https://github.com/EONRaider/NETProtocols) library, and
rendered live, written to nanosecond-precision pcap, or streamed as
JSON:

```
[>] Frame #4 at 15:42:07 (wlan0, 74 bytes)
    [+] Ethernet 3c:7c:3f:1a:be:22 -> 9c:1e:95:aa:01:5f
        EtherType: IPv4
    [+] IPv4 192.168.1.96 -> 142.250.79.78
        TTL: 64 | Flags: Don't fragment (DF) | Total Length: 60 | ID: 39754
        Protocol: TCP | Checksum: 0x2b51
    [+] TCP 51888 -> 443
        Flags: 0x002 (SYN) | Seq: 3598801521 | Ack: 0
        Window: 64240 | Checksum: 0x2008
        Options: Maximum Segment Size (1460), SACK Permitted, Timestamps (3644437524, 0), No-Operation, Window Scale (7)
```

Every protocol NETProtocols decodes on its own has a renderer of its
own, from Ethernet to BGP, STUN and VXLAN (see the
[table below](#what-it-decodes)), and HTTP joins them when you ask for
it with `--decode-as`. Checksums are verified against a recomputation
and flagged inline when they disagree. Malformed, truncated or hostile
frames are diagnosed, never fatal: the capture survives whatever the
network delivers.

## What it decodes

| Layer | Protocol | What the screen shows |
|---|---|---|
| Link | Ethernet, 802.1Q VLAN (nested QinQ too) | addresses, EtherType; each tag's VID, PCP and DEI |
| Link | IEEE 802.2 LLC, SNAP | DSAP/SSAP by name, control format; OUI and PID (as an EtherType where the OUI makes it one); Novell raw 802.3 |
| Link | LLDP, CDP | the neighbor's chassis/device ID, port, TTL, system name and description, platform, software, capabilities and addresses |
| Link | STP, RSTP | root and bridge IDs, path cost, port, flags (an RST BPDU's role and proposal/agreement handshake) and timers |
| Link | MPLS | the label stack, top first: label (special-purpose ones by name), traffic class, TTL, bottom of stack |
| Network | ARP | the who-has / is-at summary, sender and target |
| Network | IPv4 | TTL, flags, length, ID, **decoded options**, fragments |
| Network | IPv6 and its extension headers | Hop-by-Hop, Destination Options, Routing, Fragment (an MLD report renders its whole chain) |
| Network | ICMPv4, ICMPv6 | the enclosing addresses, type and code, and **Neighbor Discovery** targets and link-layer options |
| Network | IGMP | message type, group, every v3 group record |
| Tunnels | GRE, IP-in-IP | encapsulated protocol and optional fields; the inner packet renders as its own layers |
| Tunnels | VXLAN | VNI and flags (set reserved bits noted); the inner Ethernet frame renders in full |
| Tunnels | IPsec ESP, AH (IPv4 and IPv6) | SPI and sequence number; the protected size (ESP), or what AH protects, tunnel mode named, and the ICV's size |
| Transport | TCP, UDP | ports, flags, sequence numbers, window, **decoded TCP options** |
| Transport | SCTP | verification tag and the chunk types in wire order with their flags |
| Routing | OSPFv2 | Hello timers and DR/BDR election, Database Description, LSA requests, updates and acknowledgments, authentication |
| Routing | RIP v1/v2 | routes with metrics and next hops, whole-table requests, authentication entries |
| Routing | BGP | OPEN, UPDATE (withdrawals, path attributes, NLRI), NOTIFICATION, one section per message |
| Routing | PIM v2 | Hello options, Register, Register-Stop, Join/Prune groups and sources, Assert |
| Redundancy | VRRP v2/v3, HSRP | virtual router or group, priority (resignation and address owner named), virtual addresses, timers, clear-text authentication |
| Application | DNS (UDP and TCP), DHCP | every question and answer with decoded RDATA; DHCP message type, client MAC, addresses, options |
| Application | TLS | one line per record; a ClientHello's version, **SNI**, cipher-suite count and extensions — or, for a ClientHello split across segments (never reassembled), the SNI alone, when its first segment holds it |
| Application | NTP | mode, stratum, Reference ID or kiss code, timestamps, extension fields, MAC |
| Application | TFTP | the request's filename, mode and options; DATA/ACK blocks; ERROR code and message; OACK options |
| Application | RADIUS | code, identifier, Authenticator, User-Name and the other text attributes, addresses and numbers (passwords by size only) |
| Application | STUN | method and class, mapped addresses, ERROR-CODE, SOFTWARE, unknown attributes, MESSAGE-INTEGRITY's presence |
| Application | HTTP/1.x (with `--decode-as`) | start line, Host, User-Agent and the other triage fields, body framing and size, and the framing anomalies request smuggling rests on |

**Checksums verified:** IPv4, ICMPv4, ICMPv6, IGMP, GRE (when present),
TCP, UDP, SCTP (CRC32c), VRRP, PIM, OSPF and every OSPF LSA's LS
checksum, CDP, and the STUN FINGERPRINT. A mismatch shows inline as
`Checksum: 0x0000 [!] mismatch (expected 0x1a2b)` — a real signal for
corrupted or spoofed traffic. Inside a tunnel the inner IP header is
used, behind an IPv6 Routing header the route's final destination, and
Ethernet padding never reaches the sum; a non-reassembled fragment is
not checked, since its checksum covers a datagram RootWire never
rebuilds. Authenticators that need a key (AH's ICV, RADIUS's
Authenticator, STUN's MESSAGE-INTEGRITY, an OSPF digest) are shown,
never verified.

## Installation

```
pipx install rootwire        # or: uv tool install rootwire
```

Or run from a clone with [uv](https://docs.astral.sh/uv/):

```
git clone https://github.com/EONRaider/RootWire.git
cd RootWire
uv sync
```

## Usage

<!-- usage:start -->
```
usage: rootwire [-h] [-i INTERFACE] [-r FILE] [-w FILE]
                [--filter NAME_OR_EXPR] [--decode-as TABLE=KEY:CLASS] [--json]
                [-d] [--version]

Monitor network traffic: capture Ethernet frames from an interface (or replay
them from a pcap file), decode their protocol stack and render each frame.

options:
  -h, --help            show this help message and exit
  -i, --interface INTERFACE
                        interface to capture frames from; repeat to capture on
                        several interfaces concurrently (default: all
                        interfaces)
  -r, --read FILE       replay frames from a pcap or pcapng file instead of
                        live capture (no privileges required); mutually
                        exclusive with -i
  -w, --write FILE      also write every captured frame to a classic pcap file
  --filter NAME_OR_EXPR
                        attach a kernel-side capture filter so only matching
                        frames reach userspace: a canned name (arp, ip6, tcp,
                        udp) or a filter expression (protocols
                        tcp/udp/sctp/icmp/arp/ip/ip6; host/port, each
                        optionally prefixed with src/dst; and/or/not;
                        parentheses -- e.g. 'tcp and port 80'); mutually
                        exclusive with -r
  --decode-as TABLE=KEY:CLASS
                        decode what a dispatch table maps KEY to as CLASS, or
                        as nothing with CLASS 'none'; repeatable -- e.g.
                        'udp.port=40000:TFTP' to follow a TFTP transfer past
                        its request, 'tcp.port=8080:HTTP' (HTTP is never
                        decoded otherwise), 'udp.port=1812:none'; tables:
                        ethertype, llc.dsap, llc.snap, ip.proto, ip.proto.v6,
                        udp.port, tcp.port
  --json                emit one NDJSON object per frame on stdout instead of
                        the human-readable rendering
  -d, --data            also display each frame's raw payload (ignored with
                        --json)
  --version             show program's version number and exit
```
<!-- usage:end -->

Some favorite combinations:

```
sudo rootwire -i eth0 -w session.pcap             # capture and keep the evidence
sudo rootwire -i eth0 --filter tcp                # drop non-TCP in the kernel
sudo rootwire -i eth0 --filter "tcp and port 80"  # kernel-side filter expression
sudo rootwire -i eth0 -i wlan0                    # merge two interfaces into one stream
rootwire -r session.pcap                          # inspect it later, no root
rootwire -r session.pcap --json | jq .            # machine-readable analysis
```

Live capture needs a raw socket, which on Linux means root
(`sudo rootwire -i eth0`) or granting the interpreter the
`CAP_NET_RAW` capability. Replaying files with `-r` never needs
privileges. From a clone, run it as `sudo .venv/bin/python -m rootwire`.

### Following traffic with `--decode-as`

NETProtocols picks the decoder for what follows a header from that
header's own type field, or, for applications, from a well-known port.
`--decode-as TABLE=KEY:CLASS` changes that choice for one capture:
decode what *TABLE* maps *KEY* to as *CLASS*, any NETProtocols decoder
in any letter case, or as nothing with `none`. *KEY* takes any base
Python's `int(x, 0)` reads (`8080`, `0x88b5`), and the flag can be
repeated.

```
rootwire -r web.pcap --decode-as tcp.port=8080:HTTP   # HTTP is never decoded unasked
rootwire -r tftp.pcap --decode-as udp.port=43394:TFTP # follow a transfer by its server TID
rootwire -r lab.pcap --decode-as udp.port=1812:none   # leave RADIUS's port undecoded
```

The tables are `ethertype`, `llc.dsap`, `llc.snap`, `ip.proto`,
`ip.proto.v6`, `udp.port` and `tcp.port`. TFTP is the classic case for
it: only the request goes to port 69, and the server answers from a
port of its own choosing, its transfer ID, which the first reply's
source port reveals.

A port is only a hint, so a class `--decode-as` maps to a port gets the
same treatment as the library's own port-dispatched decoders: a segment
that does not hold a whole message of it (a bare ACK, a response body
sent after its head) is not reported as malformed, and when undecoded
bytes remain, screen output notes them with `[~]` (a bare ACK has none,
so it gets no note). Two exceptions keep their faults reported as
`[!] Malformed`: DNS, DNS-over-TCP and DHCP, whose malformations are
signal wherever they appear, and any class a header's own type field
also reaches (EtherType, LLC, IP protocol — `udp.port=4000:IPv4`, say),
so that a mapping cannot hide that header's faults elsewhere. A frame
whose very first header fails is always malformed. A bad value —
malformed, an unknown table or decoder, a key outside its field's
range, the same table and key twice — is a usage error (exit 2).

## Reading the output

| Marker | Meaning |
|---|---|
| `[>]` | a frame: its number, capture time, interface and size |
| `[+]` | a decoded layer, its detail lines indented below it |
| `[!]` | a fault: a malformed or truncated header, a checksum mismatch, an out-of-place field (an LLDPDU not opening with its mandatory TLVs, a misplaced STUN FINGERPRINT), an HTTP framing anomaly that request smuggling rests on |
| `[~]` | information, not a fault: payload a port-dispatched decoder could not read whole, reserved bits set, bytes after a pipelined HTTP message |
| `[=]` | the end-of-run summary (on stderr) |

Everything a sender chose — names, passwords, free text, HTTP fields,
library diagnostics quoting wire bytes — is escaped before it reaches
the terminal (control and format characters, ESC and bidi overrides
among them, show as `\xNN` or `\uXXXX`), kept on one line and cut at
128 characters; a one-line list (chunks, options, attributes, header
fields) stops at 16 items with `(+N more)`, while DNS shows every
question and answer on its own line. `-d` adds each
frame's undecoded payload, sanitized the same way.

## Machine-readable output

`--json` prints one NDJSON object per frame on stdout and nothing else
— the banner, the summary and any warning go to stderr — so it pipes
straight into `jq`:

```
{"number": 4, "timestamp": 1792765147036685000, "interface": "tests/fixtures/http/http.pcap", "length": 142, "truncated": false, "malformed_length": false, "error": null, "l7_miss": null, "payload_len": 0, "trailer_len": 0, "sni_peek": null, "layers": [{"type": "Ethernet", ...}, {"type": "IPv4", ...}, {"type": "TCP", ...}, {"type": "HTTP", ...}]}
```

| Field | Meaning |
|---|---|
| `number` | position in the capture, from 1 |
| `timestamp` | capture time, nanoseconds since the Unix epoch (the kernel's clock live, the file's on replay) |
| `interface` | the capturing interface, the replayed file's path, or `null` for all interfaces |
| `length` | bytes captured |
| `truncated` | the IP datagram declares more bytes than were captured |
| `malformed_length` | an IPv4 Total Length smaller than its own header |
| `error` | why the walk stopped on a malformed header, else `null` |
| `l7_miss` | why a port-dispatched decoder could not read the payload (not an error), else `null` |
| `payload_len`, `trailer_len` | bytes left undecoded, and bytes past the declared end (padding, an FCS) |
| `sni_peek` | the SNI of a ClientHello too large for one segment, else `null` |
| `layers` | every decoded header, outermost first |

Each layer record holds that header's fields as NETProtocols defines
them, with `"type"` its class name; a wire field itself called `type`
(ICMP, IGMP, BGP, ...) appears as `"type_"`, and bytes appear as
lowercase hex at any depth. For example, every frame that stopped on a
malformed header, and why:

```
rootwire -r session.pcap --json | jq -c 'select(.error) | {number, error}'
```

## Capture statistics

When the capture ends — Ctrl-C, `SIGTERM`, or the end of a `-r` file,
all three the same clean shutdown — a summary goes to stderr: frames,
bytes and rate, a tally by innermost protocol, malformed and truncated
counts, and the ten largest conversations by bytes:

```
[=] 98 frames, 9,263 bytes in 0.0s (4,724 frames/s)
[=] TCP: 98
[=] 7 conversations:
[=]   TCP 10.9.8.1:80 <-> 10.9.8.2:47278: 24 frames, 2,338 bytes
[=]   TCP 10.9.8.1:80 <-> 10.9.8.2:47254: 18 frames, 1,521 bytes
...
```

A conversation is a TCP, UDP or SCTP flow, both directions together.
It is the *innermost* IP datagram's, so tunnelled traffic (IP-in-IP,
GRE, AH tunnel mode, VXLAN) counts under the conversation inside the
tunnel, and a VXLAN underlay never counts as one. ESP encrypts what it
carries, so the decode stops at ESP and no inner conversation is
visible: ESP straight over IP counts under none, and UDP-encapsulated
ESP (NAT-T, with `--decode-as udp.port=4500:ESP`) under its UDP flow. At most 65,536
conversations are tracked — a spoofed flood mints one per frame — and
frames of any past that are counted as untracked.

## How it works

`capture.py`'s `capture_async()` yields raw frames — merged from one
`AF_PACKET` socket per interface, each timestamped by the kernel
itself at arrival (`SO_TIMESTAMPNS`, not a userspace clock read) — as
`(bytes, timestamp, interface)` triples; replaying from a file with
`-r` adapts `pcap.py`'s frames into that same shape. `decoder.py` walks
each frame's protocol chain into an immutable `DecodedFrame`, against
the dispatch tables `decode_as.py` built once from `--decode-as`.
Outputs — the screen renderer, the NDJSON stream, the pcap writer, the
statistics collector — consume every frame through one small `Output`
interface. The full tour, including why memory stays flat during long
captures and how to write a renderer, is in
[ARCHITECTURE.md](https://github.com/EONRaider/RootWire/blob/master/ARCHITECTURE.md).

Everything except the raw socket runs on any OS, so the test suite —
which includes a 617-frame corpus of real captured traffic replayed
through the whole pipeline — needs neither root nor Linux:

```
uv run pytest
```

## Contributing

Bug reports and pull requests are welcome.
[CONTRIBUTING.md](https://github.com/EONRaider/RootWire/blob/master/CONTRIBUTING.md)
covers the development setup, the checks a pull request must pass, and
what a good one looks like here; security reports go through
[SECURITY.md](https://github.com/EONRaider/RootWire/blob/master/SECURITY.md).

## Legal Disclaimer

The use of code contained in this repository, either in part or in its
totality, for engaging targets without prior mutual consent is
illegal. **It is the end user's responsibility to obey all applicable
local, state and federal laws.**

Developers assume **no liability** and are not responsible for misuses
or damages caused by any code contained in this repository in any
event that, accidentally or otherwise, it comes to be utilized by a
threat agent or unauthorized entity as a means to compromise the
security, privacy, confidentiality, integrity, and/or availability of
systems and their associated resources. In this context the term
"compromise" is henceforth understood as the leverage of exploitation
of known or unknown vulnerabilities present in said systems, including,
but not limited to, the implementation of security controls, human- or
electronically-enabled.

The use of this code is **only** endorsed by the developers in those
circumstances directly related to **educational environments** or
**authorized penetration testing engagements** whose declared purpose
is that of finding and mitigating vulnerabilities in systems, limiting
their exposure to compromises and exploits employed by malicious
agents as defined in their respective threat models.

## License

[AGPL-3.0](https://github.com/EONRaider/RootWire/blob/master/LICENSE)
