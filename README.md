# Python 3 Network Packet Sniffer

![Python Version](https://img.shields.io/badge/python-3.8+-blue?style=for-the-badge&logo=python)
![OS](https://img.shields.io/badge/OS-GNU%2FLinux-red?style=for-the-badge&logo=linux)
[![CodeFactor Grade](https://img.shields.io/codefactor/grade/github/EONRaider/Packet-Sniffer?label=CodeFactor&logo=codefactor&style=for-the-badge)](https://www.codefactor.io/repository/github/eonraider/packet-sniffer)
[![License](https://img.shields.io/github/license/EONRaider/Packet-Sniffer?style=for-the-badge)](https://github.com/EONRaider/Packet-Sniffer/blob/master/LICENSE)

[![Reddit](https://img.shields.io/badge/Reddit-EONRaider-FF4500?style=flat-square&logo=reddit)](https://www.reddit.com/user/eonraider)
[![Discord](https://img.shields.io/badge/Discord-EONRaider-7289DA?style=flat-square&logo=discord)](https://discord.gg/KVjWBptv)
[![Twitter](https://img.shields.io/badge/Twitter-eon__raider-38A1F3?style=flat-square&logo=twitter)](https://twitter.com/intent/follow?screen_name=eon_raider)

A Network Packet Sniffer developed in Python 3. Packets are disassembled
as they arrive at a given network interface controller and their information
is displayed on the screen.

This application depends exclusively on the [NETProtocols](https://github.com/EONRaider/NETProtocols) 
library (also developed and maintained by [EONRaider](https://github.com/EONRaider)) 
from version 2.0.0 and above and can be run by any Python 3.8+ interpreter.

## Demo
![sniffer_demo](https://user-images.githubusercontent.com/15611424/178045423-067df4ec-1853-400e-9b5a-10154cb6fcc1.gif)

## Running the Application
### I. Development Mode
Simply clone this repository with `git clone`, install the dependencies and execute the 
`sniffer.py` file.
```
user@host:~$ git clone https://github.com/EONRaider/Packet-Sniffer.git
user@host:~$ cd Packet-Sniffer
user@host:~/packet-sniffer$ pip install -r requirements.txt <--or--> poetry install
user@host:~/packet-sniffer$ sudo python3 packet_sniffer/sniffer.py
```

*The `sudo` command is required due to the use of `socket.SOCK_RAW`,
which needs administrative privileges to run on GNU/Linux. Notice
that the existence of dependencies may require the execution of the interpreter contained in
the virtual environment in which the dependencies have been installed (if you use one),
instead of just using the system interpreter.*

### II. (Optional) Build the binary
Use the `build.py` file to compile your own binary with the `PyInstaller` package. You just need to install all dependencies and build. 
Dependency management works with both [Poetry](https://python-poetry.org/) (recommended) and [Virtualenv](https://virtualenv.pypa.io/en/latest/). 
```
<-- Install dependencies as shown above in Step I -->
user@host:~/packet-sniffer$ python3 build.py
```

## Usage
```
sniffer.py [-h] [-i INTERFACE] [-d] [--dhcp-audit] [--pcap FILE]
           [--dhcp-window SECONDS] [--json] [--dhcp-verbose] [--audit-quiet]

Network packet sniffer with optional DHCP auditing

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Interface from which packets will be captured (monitors
                        all available interfaces by default).
  -d, --data            Output packet data during capture.
  --dhcp-audit          Record DHCP/BOOTP during live capture and print a report
                        when the capture stops (Ctrl+C).
  --pcap FILE           Replay a capture file and run the DHCP audit (no root).
  --dhcp-window SECONDS Limit H1/H2 analysis to this many seconds after the first
                        DHCP packet (omit to use the full trace).
  --json                Emit JSON instead of plain text for DHCP reports.
  --dhcp-verbose        Print each DHCP datagram as it is parsed.
  --audit-quiet         Hide normal packet output while auditing DHCP live.
```

### DHCP audit examples
```
# Offline lab capture (does not require sudo)
python3 packet_sniffer/sniffer.py --pcap captura.pcapng

# Live capture with DHCP heuristics at the end (requires sudo)
sudo python3 packet_sniffer/sniffer.py --dhcp-audit --audit-quiet

# Machine-readable export
python3 packet_sniffer/sniffer.py --pcap captura.pcap --json > report.json
```

## Legal Disclaimer
The use of code contained in this repository, either in part or in its totality,
for engaging targets without prior mutual consent is illegal. **It is
the end user's responsibility to obey all applicable local, state and
federal laws.**

Developers assume **no liability** and are not
responsible for misuses or damages caused by any code contained
in this repository in any event that, accidentally or otherwise, it comes to
be utilized by a threat agent or unauthorized entity as a means to compromise
the security, privacy, confidentiality, integrity, and/or availability of
systems and their associated resources. In this context the term "compromise" is
henceforth understood as the leverage of exploitation of known or unknown vulnerabilities
present in said systems, including, but not limited to, the implementation of
security controls, human- or electronically-enabled.

The use of this code is **only** endorsed by the developers in those
circumstances directly related to **educational environments** or
**authorized penetration testing engagements** whose declared purpose is that
of finding and mitigating vulnerabilities in systems, limiting their exposure
to compromises and exploits employed by malicious agents as defined in their
respective threat models.
