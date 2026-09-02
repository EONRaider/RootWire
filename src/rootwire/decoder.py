"""Turn raw frame bytes into a :class:`DecodedFrame`.

The decoder is a pure function: frame metadata (number, timestamp,
interface) is passed in explicitly, nothing is shared between calls,
and a malformed frame produces a diagnosable result instead of an
exception — a capture session must survive whatever the network
delivers.
"""

from __future__ import annotations

from netprotocols import Ethernet, IPv4, IPv6, Protocol, ProtocolError

from rootwire.frame import DecodedFrame

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


def _ip_length_malformed(layers: tuple[Protocol, ...]) -> bool:
    """Whether a decoded IPv4 header declares an impossible length.

    ``total_length`` counts the whole datagram — header plus data — so a
    value below the header's own size cannot be correct. The walk advances
    on ``header_len`` (from ``ihl``), not on ``total_length``, so this does
    not corrupt decoding; it is purely a diagnosis of a lying length field.

    A ``total_length`` of 0 is exempt: it is the sentinel large-send
    offload (TSO) leaves in locally captured outbound frames, where the
    real length is filled in by hardware after capture. Flagging it would
    cry wolf on ordinary local traffic.
    """
    for layer in layers:
        if isinstance(layer, IPv4):
            return 0 < layer.total_length < layer.header_len
    return False


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
        malformed_length=_ip_length_malformed(decoded_layers),
        error=error,
        raw=data,
    )
