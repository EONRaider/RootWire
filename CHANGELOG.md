# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Diagnose IPv4 frames whose `total_length` is smaller than the header
  itself — a length field that cannot be correct. The frame is flagged
  `[!] Malformed` on screen, carries a `malformed_length` field in NDJSON
  output, and counts toward the statistics `malformed` tally; upper layers
  are still decoded and shown. A `total_length` of 0 is exempt, being the
  large-send offload (TSO) sentinel found in locally captured frames
  rather than corruption (#56).

### Security
- Payload display (`-d`) now neutralizes terminal control characters.
  Packet payloads are attacker-controlled, and the previous rendering
  passed ESC and other control bytes straight to the terminal, allowing a
  crafted frame to inject ANSI escape sequences. Non-printable characters
  (C0/C1 controls, `DEL`, and Unicode format characters such as the
  bidirectional overrides) are now shown as visible `\xNN`/`\uXXXX`
  escapes; printable text and newlines are unchanged (#53).

### Fixed
- Refuse `-r FILE -w FILE` when both refer to the same file. The writer
  truncated its target before the lazy replay reader had read a byte, so
  replaying and writing the same path destroyed the capture; it is now
  rejected up front, before anything is opened (#52).
- A `-w` target that cannot be opened (bad directory, permission denied)
  now reports a clear write-specific error instead of a raw traceback,
  and no longer risks being misreported as a capture-privilege problem
  (#54).
- The end-of-run statistics summary is no longer printed while an
  unexpected exception is propagating, where it made a crash look like a
  clean run (#54).

## [5.0.0] - 2026-08-29

**Packet-Sniffer is now RootWire.** Same engine, new name — and its
first release on PyPI: `pip install rootwire`.

### Changed
- Distribution, module, and console script renamed: install
  `rootwire`, import `rootwire`, run `rootwire` (or
  `python -m rootwire`). The `packet-sniffer` command and the
  `packet_sniffer` module are gone — this is the breaking change
  behind the major version.
- The GitHub repository is now
  [EONRaider/RootWire](https://github.com/EONRaider/RootWire); links
  to the old name redirect.
- Releases publish to PyPI automatically on tags via trusted
  publishing.

*Why 5.0.0 and not 1.0.0*: the version continues the
Packet-Sniffer lineage (this repository already carries tags up to
`v4.1.0`, and a `v1.0.0` from 2021), and the rename itself is a
breaking change.

## [4.1.0] - 2026-08-29

### Added
- **pcap output and replay**: `-w FILE` writes every captured frame
  byte-exactly to a classic pcap file (opens in Wireshark/tcpdump);
  `-r FILE` replays a pcap through the whole decode/render pipeline —
  no privileges required. The reader handles both byte orders and
  nanosecond-precision files, and rejects non-Ethernet linktypes.
- **NDJSON output**: `--json` emits one JSON object per frame on
  stdout with nothing else mixed in (banner, statistics, and the abort
  notice live on stderr), so output pipes cleanly into `jq` and
  friends. `-d` is ignored in JSON mode.
- **Capture statistics** on exit and at replay end-of-file: frames,
  bytes, duration, frames/s, malformed and truncated counts, and
  per-protocol tallies bucketed by innermost decoded layer.
- **IPv6 extension-header rendering** (netprotocols 1.1): MLD traffic
  now renders as Ethernet / IPv6 / Hop-by-Hop Options / ICMPv6, and
  fragments are labeled first/at-offset.

### Changed
- The decode chain is capped at 16 layers per frame (diagnosed on the
  frame, capture continues): a crafted frame of back-to-back 8-byte
  extension headers could otherwise decode thousands of layer objects.
- Dependency floor raised to `netprotocols>=1.1,<2`.

## [4.0.0] - 2026-08-21

Complete rebuild on netprotocols 1.0. The CLI gains proper entry
points (`packet-sniffer` console script and `python -m packet_sniffer`);
internals are rewritten around an immutable `DecodedFrame`.

*A note on the version number*: this repository shipped tags `3.1.0`
and `3.1.2` in 2022 (an era whose entries never made it into this
changelog), so the rebuild releases as 4.0.0 rather than reusing the
3.x line.

### Changed
- Decoding is a pure function (`decoder.decode_frame`) producing a
  frozen, self-contained `DecodedFrame`; the mutable, reused `Decoder`
  object (whose yielded frames changed under any observer that kept
  them) is gone.
- Renderers dispatch on decoded layer types via `singledispatchmethod`
  and receive the whole frame (ICMP lines show the enclosing IP
  route); the string-magic `_display_{name}_data` dispatch is gone.
- Capture buffer grows from 9,000 to 65,550 bytes, so maximum-size
  loopback frames are no longer silently truncated; each frame is one
  freshly allocated immutable `bytes` object.
- Packaging moved to PEP 621 (`hatchling` + `uv`), src layout, Python
  3.12+; the raw-socket import is confined to `capture.py`, so tests
  run on any OS without root.
- The privilege check now reacts to the actual `PermissionError`
  (mentioning `CAP_NET_RAW` as the sudo alternative) instead of
  requiring UID 0 up front.

### Fixed
- IPv6 frames crashed the renderer (`flabel_txt_str` — an attribute
  that never existed in the released library versions).
- Payload offsets were wrong for TCP segments with options and IPv4
  headers with options (the library previously hardcoded
  `TCP.header_len = 32` and the decoder ignored IHL).
- Malformed or truncated frames killed the capture loop; they are now
  diagnosed on screen and counted, and the capture continues.
- The `pyproject.toml` version had never been bumped for 2.1.0 (it
  still read 2.0.1).

### Removed
- PyInstaller and `build.py` (the build targeted a module with no
  entry code and produced a do-nothing binary), and `requirements.txt`.
  Install with `pipx`/`uv tool install`, or run via `uv sync` +
  `python -m packet_sniffer`.

## [2.1.0] - 2022-07-08
- The application was restructured for ease of use. The new layout dispenses with 
the need of passing the PYTHONPATH environment variable to `sudo` during execution.
- Updates were made to the documentation and requirements files.

## [2.0.1] - 2022-07-05
- Updated the README.md file to include the dependency on NETProtocols.
- Added support for ICMPv4 and ICMPv6.
- Removed the distribution of a pre-packaged binary file.

## [2.0.0] - 2022-02-22
- All manipulation of protocol logic was removed from the application. The 
"protocols" directory was removed and replace with the importing of the 
"netprotocols" library, available at PyPI.

## [1.1.1] - 2021-12-16
- Moved 'arp.py' file from 'src/protocols/layer3' to 'src/protocols/layer2' in
compliance with the OSI model.
