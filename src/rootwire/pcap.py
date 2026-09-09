"""Classic pcap file writing and replay, dependency-free.

The writer emits the classic (not pcapng) format: a 24-byte global
header — magic ``0xA1B23C4D``, version 2.4, thiszone 0, sigfigs 0,
snaplen matching the capture buffer, linktype 1 (Ethernet) — followed
by 16-byte per-record headers. Timestamps are written with nanosecond
precision, little-endian: this is a long-established classic-pcap
variant every tool that matters (Wireshark, tcpdump, tshark) already
reads, and it is what makes the kernel-timestamp precision RootWire
captures (``SO_TIMESTAMPNS``) survive to disk losslessly instead of
being rounded to microseconds on write.

The reader accepts both byte orders and both timestamp precisions
(including foreign/older microsecond-precision captures), validates
that the file carries Ethernet frames before handing them to an
Ethernet decoder, and deliberately has the same shape as
:func:`rootwire.capture.capture` — so replaying a file is a drop-in
frame source for the whole pipeline, no root required.

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

__all__ = ["PcapWriter", "read_pcap"]

#: Matches capture.BUFFER_SIZE without importing that module — capture
#: is the one Linux-only module (PF_PACKET), and replaying a file must
#: work anywhere.
_SNAPLEN = 65_550

_MAGIC_MICROSECONDS = 0xA1B2C3D4
_MAGIC_NANOSECONDS = 0xA1B23C4D
_LINKTYPE_ETHERNET = 1
_GLOBAL_HEADER = struct.Struct("<IHHiIII")
_RECORD_HEADER = struct.Struct("<IIII")


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


def read_pcap(path: str | Path) -> Iterator[tuple[bytes, int]]:
    """Yield ``(frame, timestamp)`` pairs from a classic pcap file.

    ``timestamp`` is always integer nanoseconds since the Unix epoch,
    regardless of the file's on-disk precision: a microsecond-precision
    file's fractional field is scaled by 1000, which is exact (no
    precision is invented, none is lost). Accepts both byte orders;
    rejects files whose linktype is not Ethernet (nothing else can be
    fed to an Ethernet decoder) and files that end mid-record.

    :raises ValueError: If the file is not classic pcap, carries a
        non-Ethernet linktype, or is truncated.
    """
    data = Path(path).read_bytes()
    if len(data) < _GLOBAL_HEADER.size:
        raise ValueError(f"{path}: too short to be a pcap file")
    magic_le = struct.unpack_from("<I", data)[0]
    magic_be = struct.unpack_from(">I", data)[0]
    if magic_le in (_MAGIC_MICROSECONDS, _MAGIC_NANOSECONDS):
        endian, magic = "<", magic_le
    elif magic_be in (_MAGIC_MICROSECONDS, _MAGIC_NANOSECONDS):
        endian, magic = ">", magic_be
    else:
        raise ValueError(f"{path}: not a classic pcap file")
    frac_to_ns = 1 if magic == _MAGIC_NANOSECONDS else 1000
    (network,) = struct.unpack_from(f"{endian}I", data, 20)
    if network != _LINKTYPE_ETHERNET:
        raise ValueError(
            f"{path}: linktype {network} is not Ethernet (1); this file "
            f"cannot be replayed through an Ethernet decoder"
        )
    record = struct.Struct(f"{endian}IIII")
    cursor = _GLOBAL_HEADER.size
    while cursor < len(data):
        if cursor + record.size > len(data):
            raise ValueError(f"{path}: truncated record header")
        ts_sec, ts_frac, incl_len, _ = record.unpack_from(data, cursor)
        cursor += record.size
        if cursor + incl_len > len(data):
            raise ValueError(f"{path}: truncated frame data")
        yield (
            bytes(data[cursor : cursor + incl_len]),
            ts_sec * 1_000_000_000 + ts_frac * frac_to_ns,
        )
        cursor += incl_len
