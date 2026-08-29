"""Turn raw frame bytes into a :class:`DecodedFrame`.

The decoder is a pure function: frame metadata (number, timestamp,
interface) is passed in explicitly, nothing is shared between calls,
and a malformed frame produces a diagnosable result instead of an
exception — a capture session must survive whatever the network
delivers.
"""

from __future__ import annotations

from netprotocols import Ethernet, IPv4, IPv6, Protocol, ProtocolError

from packet_sniffer.frame import DecodedFrame

__all__ = ["decode_frame"]

_ETHERNET_HEADER_LEN = 14

#: Upper bound on decoded layers per frame. Real stacks stay in single
#: digits; a crafted 65,535-byte frame of back-to-back 8-byte
#: extension headers would otherwise decode ~8,100 layer objects per
#: frame -- a sniffer's input is adversarial by definition.
_MAX_LAYERS = 16


def _declared_length(layers: tuple[Protocol, ...]) -> int | None:
    """Total frame length implied by the IP layer, if one was decoded."""
    for layer in layers:
        if isinstance(layer, IPv4):
            return _ETHERNET_HEADER_LEN + layer.total_length
        if isinstance(layer, IPv6):
            return (
                _ETHERNET_HEADER_LEN + layer.header_len + layer.payload_length
            )
    return None


def decode_frame(
    data: bytes,
    *,
    number: int,
    timestamp: float,
    interface: str | None,
) -> DecodedFrame:
    """Decode one captured frame.

    Walks the protocol chain from Ethernet inward, each decoded header
    telling the walker how many bytes it consumed (``header_len``) and
    which class decodes what follows (``next_protocol()``). The walk
    ends at the first protocol the library does not implement — the
    remainder becomes the frame's payload — or at the first malformed
    header, recorded on ``DecodedFrame.error``.
    """
    view = memoryview(data)
    layers: list[Protocol] = []
    cursor = 0
    error: str | None = None
    protocol: type[Protocol] | None = Ethernet
    while protocol is not None:
        if len(layers) >= _MAX_LAYERS:
            error = f"decode chain exceeded {_MAX_LAYERS} layers"
            break
        try:
            header = protocol.decode(view[cursor:])
        except ProtocolError as e:
            error = f"{protocol.__name__}: {e}"
            break
        layers.append(header)
        cursor += header.header_len
        protocol = header.next_protocol()

    decoded_layers = tuple(layers)
    declared = _declared_length(decoded_layers)
    return DecodedFrame(
        number=number,
        timestamp=timestamp,
        interface=interface,
        length=len(data),
        layers=decoded_layers,
        payload=bytes(view[cursor:]),
        truncated=declared is not None and declared > len(data),
        error=error,
        raw=data,
    )
