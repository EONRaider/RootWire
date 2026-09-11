# Security Policy

RootWire runs privileged (root or `CAP_NET_RAW`) and decodes whatever
bytes arrive on the wire or sit in a capture file someone hands it — a
sniffer's input is adversarial by definition. It also compiles a
user-supplied `--filter` expression straight into kernel-loaded
bytecode, a different but related trust boundary: the expression is
local input, not network traffic, but a wrong compile still produces a
security tool that lies about what it captured. This document covers
reporting a vulnerability in either path.

## Reporting a vulnerability

GitHub's private vulnerability reporting isn't enabled for this
repository, so please don't open a public issue for a suspected
vulnerability. Email the maintainer directly instead:
[livewire_voodoo@protonmail.com](mailto:livewire_voodoo@protonmail.com)
(the address in `pyproject.toml`'s `authors` field).

Beyond what you'd put in an ordinary bug report, include:

- A minimal reproducer if you have one — a crafted frame, a pcap/pcapng
  file, or a `--filter` expression — rather than just a description of
  the bug class.
- The impact as you see it: a crash, a wrong filter that silently
  mis-captures traffic, unbounded memory growth, or something that
  reaches further than the frame it came from.
- Whether it needs live capture (privileged) or reproduces through `-r`
  replay of a file (unprivileged) — reaching it the first way is more
  severe.

This is a solo-maintained project with no dedicated security team and no
contractual SLA. Based on current maintenance activity, expect an
initial response within a few days; how fast a fix follows depends on
severity and how deep into the capture/decode/compile path it reaches. A
shipped fix gets written up under `CHANGELOG.md`'s `Security` heading,
the same as the two terminal-injection fixes already there (#53, #75) —
that's existing project practice, not something new this policy
introduces.

## Scope

In scope: the code standing between untrusted input and the rest of the
pipeline.

- **[`capture.py`](src/rootwire/capture.py)** — raw `AF_PACKET` socket
  handling: buffer sizing (a frame larger than `BUFFER_SIZE` truncates)
  and kernel-timestamp parsing from `recvmsg` ancillary data. Runs
  privileged.
- **[`bpf_compiler.py`](src/rootwire/bpf_compiler.py)** and
  **[`bpf.py`](src/rootwire/bpf.py)** — `bpf_compiler.py` compiles a
  `--filter` expression to cBPF; `bpf.py` loads the result into the
  kernel via `SO_ATTACH_FILTER`. A compiler bug matters in two ways: a
  wrong-but-valid filter makes RootWire silently misrepresent what it
  captured, and malformed bytecode is what would reach the kernel's own
  BPF verifier in an interesting way.
- **[`decoder.py`](src/rootwire/decoder.py)** — walks a captured frame's
  protocol chain. Malformed and truncated frames must be diagnosed,
  never crash the capture or read past a buffer.
- **[`pcap.py`](src/rootwire/pcap.py)** — parses pcap/pcapng files for
  `-r` replay, including the pre-decode link-type check that stops a
  wrong link type from silently decoding into nonsense. A crafted
  capture file is the same untrusted-input problem as live traffic,
  delivered from disk instead of a socket — and needs no privilege to
  reach.
- **[`output.py`](src/rootwire/output.py)** — renders decoded fields,
  including raw payload bytes, to the terminal and to NDJSON. Every
  value it renders came off the wire; two prior fixes addressed terminal
  control-character injection here (see `CHANGELOG.md`'s `Security`
  entries for #53 and #75), which is why it counts as in scope alongside
  the modules doing the actual parsing.

Out of scope: the protocol decoding itself — Ethernet, IPv4/IPv6,
TCP/UDP, DNS, and everything else `decoder.py` and `pcap.py` call into —
lives in [NETProtocols](https://github.com/EONRaider/NETProtocols), a
separate project with its own issue tracker. A bug in how a specific
protocol's bytes get decoded, rather than in how RootWire drives,
bounds, or renders that decoding, belongs there instead.

## Supported versions

One supported line: whatever `pyproject.toml` currently declares as
`version` (`6.0.0` as of this writing) — there's no maintained branch
for older majors. `pipx upgrade rootwire` / `uv tool upgrade rootwire`
gets you current; check that against the latest tag before reporting
something that might already be fixed.
