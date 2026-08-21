# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
