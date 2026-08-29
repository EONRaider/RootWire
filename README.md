# RootWire

[![CI](https://github.com/EONRaider/RootWire/actions/workflows/ci.yml/badge.svg)](https://github.com/EONRaider/RootWire/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/rootwire)](https://pypi.org/project/rootwire/)
![Python Version](https://img.shields.io/badge/python-3.12%2B-blue?logo=python)
![OS](https://img.shields.io/badge/OS-GNU%2FLinux-red?logo=linux)
[![License](https://img.shields.io/github/license/EONRaider/RootWire)](LICENSE)

A network traffic monitor for GNU/Linux — *formerly known as
Packet-Sniffer*. Frames are captured from a network interface with a
raw socket, decoded layer by layer with the
[NETProtocols](https://github.com/EONRaider/NETProtocols) library, and
rendered live, written to pcap, or streamed as JSON:

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

The decoder covers Ethernet, ARP, IPv4 (options and fragments), IPv6
**including extension headers** (an MLD report renders its full
Hop-by-Hop chain), ICMPv4/v6, TCP (options-aware payload offsets) and
UDP. Malformed or truncated frames are diagnosed instead of crashing
the capture, unknown protocols end the chain gracefully, and a
16-layer cap keeps crafted extension-header stacks from amplifying —
the capture survives whatever the network delivers.

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

```
rootwire [-h] [-i INTERFACE] [-r FILE] [-w FILE] [--json] [-d] [--version]

options:
  -i, --interface   interface to capture frames from (default: all interfaces)
  -r, --read FILE   replay frames from a classic pcap file instead of live
                    capture (no privileges required)
  -w, --write FILE  also write every captured frame to a classic pcap file
  --json            one NDJSON object per frame on stdout (banner and
                    statistics stay on stderr): pipe straight into jq
  -d, --data        also display each frame's raw payload (ignored with --json)
```

Capture statistics — frames, bytes, frames/s, malformed/truncated
counts, per-protocol tallies — are reported on stderr when the capture
ends. Some favorite combinations:

```
sudo rootwire -i eth0 -w session.pcap   # capture and keep the evidence
rootwire -r session.pcap                # inspect it later, no root
rootwire -r session.pcap --json | jq .  # machine-readable analysis
```

Live capture needs a raw socket, which on Linux means root
(`sudo rootwire -i eth0`) or granting the interpreter the
`CAP_NET_RAW` capability. Replaying files with `-r` never needs
privileges. From a clone, run it as `sudo .venv/bin/python -m rootwire`.

## How it works

`capture.py` yields raw frames from an `AF_PACKET` socket (or
`pcap.py` replays them from a file — the two sources are
interchangeable); `decoder.py` walks each frame's protocol chain into
an immutable `DecodedFrame`; outputs — the screen renderer, the NDJSON
stream, the pcap writer, the statistics collector — consume every
frame through one small `Output` interface. The full tour, including
why memory stays flat during long captures and how to add an output,
is in [ARCHITECTURE.md](ARCHITECTURE.md).

Everything except the raw socket runs on any OS, so the test suite —
which includes a 65-frame corpus of real captured traffic replayed
through the whole pipeline — needs neither root nor Linux:

```
uv run pytest
```

## Roadmap

- BPF filtering (kernel-side capture filters)
- Kernel timestamps (`SO_TIMESTAMPNS`) and SIGTERM-clean service use
- Checksum verification rendering (the library already computes them)

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
