"""The immutable result of decoding one captured frame."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeVar

from netprotocols import Protocol

__all__ = ["DecodedFrame"]

_P = TypeVar("_P", bound=Protocol)


@dataclass(frozen=True, slots=True)
class DecodedFrame:
    """Everything known about one captured frame.

    Instances are immutable and self-contained: they hold no references
    to capture buffers or sockets, so retaining one is always safe and
    releasing one frees all its memory.

    :param number: Position of this frame in the capture, counted
        from 1.
    :param timestamp: Capture time in seconds since the Unix epoch.
    :param interface: Interface the frame was captured on, or ``None``
        when listening on all interfaces.
    :param length: Number of bytes captured for this frame.
    :param layers: The successfully decoded protocol headers, outermost
        first.
    :param payload: The bytes following the last decoded header.
    :param truncated: True when the enclosed IP datagram declares more
        bytes than were captured (the payload is incomplete).
    :param error: Diagnostic message when the decode chain aborted on a
        malformed header, else ``None``. The layers decoded before the
        failure are preserved.
    """

    number: int
    timestamp: float
    interface: str | None
    length: int
    layers: tuple[Protocol, ...]
    payload: bytes
    truncated: bool = False
    error: str | None = None

    def layer(self, protocol: type[_P]) -> _P | None:
        """The first decoded layer of the given class, or ``None``.

        >>> frame.layer(IPv4).ttl
        """
        for candidate in self.layers:
            if isinstance(candidate, protocol):
                return candidate
        return None
