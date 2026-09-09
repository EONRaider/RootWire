"""pcap/pcapng file writing and replay.

The writer emits the classic (not pcapng) format: a 24-byte global
header — magic ``0xA1B23C4D``, version 2.4, thiszone 0, sigfigs 0,
snaplen matching the capture buffer, linktype 1 (Ethernet) — followed
by 16-byte per-record headers. Timestamps are written with nanosecond
precision, little-endian: this is a long-established classic-pcap
variant every tool that matters (Wireshark, tcpdump, tshark) already
reads, and it is what makes the kernel-timestamp precision RootWire
captures (``SO_TIMESTAMPNS``) survive to disk losslessly instead of
being rounded to microseconds on write.

The reader accepts classic pcap *and* pcapng, auto-detected from the
file's magic bytes, by delegating to
:func:`netprotocols.read_captures` — timestamp normalization to
nanoseconds (including foreign/older microsecond-precision classic
captures, and pcapng's per-interface timestamp resolution) happens
there. Before decoding, this module checks the capture's declared link
type against Ethernet where it can be determined up front (always for
classic pcap; the first Interface Description Block for pcapng) and
rejects anything else: :class:`~netprotocols.Ethernet` accepts any
14+ bytes structurally, so nothing else stops a wrong link type from
silently decoding into nonsense. Reading otherwise deliberately has the
same shape as :func:`rootwire.capture.capture_async` — so replaying a
file is a drop-in frame source for the whole pipeline, no root
required.

``orig_len`` is written equal to ``incl_len``: a frame delivered by
``recv()`` carries no record of a kernel-side truncation, so the
captured length is the only honest value.
"""

from __future__ import annotations

import struct
import time
from collections.abc import Iterator
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, Self

from netprotocols import MalformedCaptureError
from netprotocols import read_captures as _read_captures

__all__ = ["PcapWriter", "read_captures"]

#: Matches capture.BUFFER_SIZE without importing that module — capture
#: is the one Linux-only module (PF_PACKET), and replaying a file must
#: work anywhere.
_SNAPLEN = 65_550

_MAGIC_MICROSECONDS = 0xA1B2C3D4
_MAGIC_NANOSECONDS = 0xA1B23C4D
_LINKTYPE_ETHERNET = 1
_GLOBAL_HEADER = struct.Struct("<IHHiIII")
_RECORD_HEADER = struct.Struct("<IIII")

#: Classic-pcap magic numbers, either byte order, either timestamp
#: resolution — matches what netprotocols.read_pcap itself recognizes.
_PCAP_MAGICS = (
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
)
_PCAP_MAGICS_LE = (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")

#: pcapng Section Header Block's type field — a byte-order-independent
#: palindrome, so it is recognizable before any endianness is known.
_SHB_TYPE = b"\x0a\x0d\x0d\x0a"
_SHB_BOM = 0x1A2B3C4D
_IDB_TYPE = 1


def _pcapng_first_linktype(data: bytes) -> int | None:
    """The ``LinkType`` field of the first Interface Description Block
    in a pcapng buffer, or ``None`` if none is found before the buffer
    ends (an interface-free capture, or a truncated one — either way,
    not this function's job to diagnose; :func:`read_captures` does).

    Only the first section is examined: enough for the up-front
    linktype gate this exists for, and a capture legitimately mixing
    link types across sections is not a case a single-shot replay tool
    needs to get right.
    """
    if len(data) < 12 or data[:4] != _SHB_TYPE:
        return None
    endian = "<" if data[8:12] == struct.pack("<I", _SHB_BOM) else ">"
    cursor = 0
    while cursor + 8 <= len(data):
        block_type, block_len = struct.unpack_from(f"{endian}II", data, cursor)
        if block_len < 12 or cursor + block_len > len(data):
            return None
        if block_type == _IDB_TYPE and block_len >= 16:
            (link_type,) = struct.unpack_from(f"{endian}H", data, cursor + 8)
            return int(link_type)
        cursor += block_len
    return None


def _declared_linktype(data: bytes) -> int | None:
    """The capture's declared link type, when determinable up front
    without fully parsing the file — always for classic pcap (the
    global header's fixed ``network`` field); best-effort for pcapng
    (see :func:`_pcapng_first_linktype`). ``None`` for anything else,
    including a file that is not a recognized capture at all —
    :func:`netprotocols.read_captures` is what actually validates the
    format and raises accordingly."""
    if len(data) >= _GLOBAL_HEADER.size and data[:4] in _PCAP_MAGICS:
        endian = "<" if data[:4] in _PCAP_MAGICS_LE else ">"
        return int(struct.unpack_from(f"{endian}I", data, 20)[0])
    return _pcapng_first_linktype(data)


class PcapWriter:
    """Write frames to a nanosecond-precision classic pcap file; usable
    as a context manager.

    >>> with PcapWriter("capture.pcap") as writer:
    ...     writer.write(frame_bytes, timestamp)
    """

    def __init__(self, path: str | Path) -> None:
        self._file: BinaryIO = open(path, "wb")  # noqa: SIM115
        self._file.write(
            _GLOBAL_HEADER.pack(
                _MAGIC_NANOSECONDS,
                2,  # version major
                4,  # version minor
                0,  # thiszone
                0,  # sigfigs
                _SNAPLEN,
                _LINKTYPE_ETHERNET,
            )
        )

    def write(self, data: bytes, timestamp: int | None = None) -> None:
        """Append one frame with the given capture timestamp — integer
        nanoseconds since the Unix epoch — defaulting to now if
        omitted."""
        if timestamp is None:
            timestamp = time.time_ns()
        ts_sec, ts_nsec = divmod(timestamp, 1_000_000_000)
        self._file.write(
            _RECORD_HEADER.pack(ts_sec, ts_nsec, len(data), len(data))
        )
        self._file.write(data)

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def read_captures(path: str | Path) -> Iterator[tuple[bytes, int]]:
    """Yield ``(frame, timestamp)`` pairs from a classic pcap or pcapng
    file, auto-detected from its magic bytes.

    ``timestamp`` is always integer nanoseconds since the Unix epoch,
    however the source file recorded it — see
    :func:`netprotocols.read_captures` for exactly how each format's
    on-disk precision is normalized. A pcapng Simple Packet Block, which
    carries no timestamp, reports ``0`` (the library's own contract).

    :raises ValueError: the capture's declared link type is not
        Ethernet, or the file is not a recognized pcap/pcapng capture,
        or it is corrupt/truncated.
    """
    data = Path(path).read_bytes()
    linktype = _declared_linktype(data)
    if linktype is not None and linktype != _LINKTYPE_ETHERNET:
        raise ValueError(
            f"{path}: linktype {linktype} is not Ethernet (1); this file "
            f"cannot be replayed through an Ethernet decoder"
        )
    try:
        for captured in _read_captures(data):
            yield captured.data, captured.timestamp
    except MalformedCaptureError as error:
        raise ValueError(f"{path}: {error}") from error
