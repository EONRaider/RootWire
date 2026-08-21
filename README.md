# Packet Sniffer

[![CI](https://github.com/EONRaider/Packet-Sniffer/actions/workflows/ci.yml/badge.svg)](https://github.com/EONRaider/Packet-Sniffer/actions/workflows/ci.yml)
![Python Version](https://img.shields.io/badge/python-3.12%2B-blue?logo=python)
![OS](https://img.shields.io/badge/OS-GNU%2FLinux-red?logo=linux)
[![License](https://img.shields.io/github/license/EONRaider/Packet-Sniffer)](LICENSE)

A network traffic monitor for GNU/Linux. Frames are captured from a
network interface with a raw socket, decoded layer by layer with the
[NETProtocols](https://github.com/EONRaider/NETProtocols) library, and
rendered on screen as they arrive:

```
[>] Frame #4 at 15:42:07 (wlan0, 74 bytes)
    [+] Ethernet 3c:7c:3f:1a:be:22 -> 9c:1e:95:aa:01:5f
        EtherType: IPv4
    [+] IPv4 192.168.1.96 -> 142.250.79.78
        TTL: 64 | Flags: Don't fragment (DF) | Total Length: 60 | ID: 39754
        Protocol: TCP | Checksum: 0x2b51
    [+] TCP 51888 -> 443
        Flags: 0x002 (SYN) | Seq: 3598801521 | Ack: 0
        Window: 64240 | Checksum: 0x2008 | Options: 20 bytes
```

Decoding is options-aware (IPv4 IHL and TCP data offset are honored),
malformed or truncated frames are diagnosed instead of crashing the
capture, and unknown protocols end the decode chain gracefully — the
capture survives whatever the network delivers.

## Installation

```
pipx install "git+https://github.com/EONRaider/Packet-Sniffer.git"
```

(Or `uv tool install` with the same URL. The application is not
published to PyPI under this name — that debut is reserved for its
upcoming rename.)

Or run from a clone with [uv](https://docs.astral.sh/uv/):

```
git clone https://github.com/EONRaider/Packet-Sniffer.git
cd Packet-Sniffer
uv sync
```

## Usage

```
packet-sniffer [-h] [-i INTERFACE] [-d] [--version]

options:
  -i, --interface   interface to capture frames from (default: all interfaces)
  -d, --data        also display each frame's raw payload
```

Capturing requires a raw socket, which on Linux means either root:

```
sudo packet-sniffer -i eth0
```

...or granting the interpreter the `CAP_NET_RAW` capability. From a
clone, run it as `sudo .venv/bin/python -m packet_sniffer`.

## How it works

`capture.py` yields raw frames from an `AF_PACKET` socket;
`decoder.py` walks each frame's protocol chain (Ethernet → ARP /
IPv4 / IPv6 → ICMP / TCP / UDP) into an immutable `DecodedFrame`;
renderers in `output.py` dispatch on the decoded layer types. The full
tour — including why memory stays flat during long captures and how to
add a renderer — is in [ARCHITECTURE.md](ARCHITECTURE.md).

Everything except the raw socket runs on any OS, so the test suite
(decode and rendering over recorded frames) needs neither root nor
Linux:

```
uv run pytest
```

## Roadmap

- BPF filtering (kernel-side capture filters)
- pcap/pcapng file output and replay-from-pcap input
- JSON/NDJSON output for piping into other tools
- Kernel timestamps (`SO_TIMESTAMPNS`)
- A new name — watch this space

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

[AGPL-3.0](LICENSE)
