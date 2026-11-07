"""Turn raw frame bytes into a :class:`DecodedFrame`.

The decoder is a pure function: frame metadata (number, timestamp,
interface) is passed in explicitly, nothing is shared between calls,
and a malformed frame produces a diagnosable result instead of an
exception — a capture session must survive whatever the network
delivers.

Best-effort application decoders
--------------------------------

NETProtocols dispatches some application protocols on a well-known
TCP/UDP port alone: TLS on 443, BGP on 179, STUN on 3478, NTP on 123
and so on. A port is a hint, not a promise. A bare ACK, a segment that
continues a record begun in an earlier segment, or an unrelated
service squatting on the port all reach that decoder anyway, and the
library's walk calls it unconditionally. When it then raises, the frame
is not malformed: the transport layer was fine and the payload simply
was not (a whole) message of the protocol the port suggested.

:data:`_BEST_EFFORT_L7` is the set of such port-dispatched classes, and
a walk that stops in one of them is recorded as a *miss*
(:attr:`DecodedFrame.l7_miss`), not an error: no ``[!]``, not counted
as malformed, the undecoded bytes left as payload. DNS, DNS over TCP
and DHCP are deliberately excluded: they were port-dispatched before
NETProtocols 2.3 already, and their malformations have always been
real signal in RootWire's output.
"""

from __future__ import annotations

from netprotocols import (
    DHCP,
    DNS,
    DNSOverTCP,
    IPv4,
    IPv6,
    MaxDepthExceededError,
    Protocol,
    ProtocolError,
)
from netprotocols import decode_frame as _decode_chain
from netprotocols.registry import DEFAULT

from rootwire.frame import DecodedFrame

__all__ = ["decode_frame"]

#: Upper bound on decoded layers per frame. Real stacks stay in single
#: digits; a crafted 65,535-byte frame of back-to-back 8-byte
#: extension headers would otherwise decode ~8,100 layer objects per
#: frame -- a sniffer's input is adversarial by definition. Equal to
#: the library's own default (``netprotocols.MAX_DEPTH``): BGP, STUN
#: over TCP and TLS decode one layer per message or record, and a
#: valid dense segment routinely holds dozens of them, so the old
#: ceiling of 16 turned ordinary BGP/TLS traffic into "malformed"
#: frames. A segment denser still overflows this ceiling too; that
#: case is a miss, not an error (see :func:`_classify_stop`).
_MAX_LAYERS = 32


def _port_dispatched_l7() -> frozenset[type[Protocol]]:
    """The application classes NETProtocols dispatches on port alone,
    minus the three that predate NETProtocols 2.3 (see the module
    docstring).

    Derived from the default registry rather than hardcoded, so a
    future release that registers another port-heuristic decoder is
    covered without a RootWire change. A key the registry *withholds*
    (``netprotocols.registry.WITHHELD``) is not a class and is skipped.
    """
    dispatched = (
        *DEFAULT.table("tcp.port").values(),
        *DEFAULT.table("udp.port").values(),
    )
    classes = {cls for cls in dispatched if isinstance(cls, type)}
    return frozenset(classes - {DNS, DNSOverTCP, DHCP})


#: Port-dispatched application classes whose decode failures are
#: best-effort misses rather than malformed frames.
_BEST_EFFORT_L7 = _port_dispatched_l7()


def _classify_stop(
    error: ProtocolError | None, layers: tuple[Protocol, ...]
) -> tuple[str | None, str | None]:
    """Split a lax walk's ``stopped_by`` into ``(error, l7_miss)``.

    At most one of the two is set:

    - A :class:`~netprotocols.MaxDepthExceededError` is a miss only
      when the layer that would come next is the same best-effort class
      as the last one decoded — a dense BGP/STUN/TLS segment whose
      messages outnumber the layer ceiling. Its ``protocol`` is the
      *next* class, so comparing it with the last decoded layer is what
      tells self-chaining density apart from a deep chain of *other*
      headers that merely happens to reach an application port, or a
      tunnel-nesting bomb (next: Ethernet); those stay errors.
    - Any other error raised while decoding a best-effort class is a
      miss: the port suggested a protocol the payload does not hold.
    - Everything else is a genuine error.
    """
    if error is None:
        return None, None
    if isinstance(error, MaxDepthExceededError):
        self_chaining = (
            error.protocol in _BEST_EFFORT_L7
            and bool(layers)
            and type(layers[-1]) is error.protocol
        )
        return (None, str(error)) if self_chaining else (str(error), None)
    if error.protocol in _BEST_EFFORT_L7:
        return None, str(error)
    return str(error), None


def _declared_length(layers: tuple[Protocol, ...]) -> int | None:
    """Total frame length implied by the outermost IP header, if one was
    decoded: that header's offset in the frame plus the datagram length
    it declares.

    The offset is the sum of every preceding header's ``header_len``,
    not a fixed 14 bytes: a VLAN tag, a QinQ pair, an MPLS label stack
    or LLC/SNAP all sit between Ethernet and IP, and with a fixed offset
    a capture short by up to that many bytes read as complete. The
    *outermost* IP header is the right anchor because it is the one
    whose datagram the capture must hold whole; an inner tunnelled
    datagram ends inside it.
    """
    offset = 0
    for layer in layers:
        if isinstance(layer, IPv4):
            return offset + layer.total_length
        if isinstance(layer, IPv6):
            return offset + layer.header_len + layer.payload_length
        offset += layer.header_len
    return None


def _ip_length_malformed(layers: tuple[Protocol, ...]) -> bool:
    """Whether a decoded IPv4 header declares an impossible length.

    ``total_length`` counts the whole datagram — header plus data — so a
    value below the header's own size cannot be correct. Since
    NETProtocols 2.3 the walk itself also rejects it (the declared
    length bounds every later layer, and one shorter than its own header
    bounds nothing sensible), so the walk stops right after the IPv4
    header and ``DecodedFrame.error`` carries the library's message; this
    flag remains the structured, protocol-specific diagnosis of it. The
    two always coincide: the walk rejects exactly this condition
    (``0 < total_length < ihl * 4``) on *any* IPv4 header it meets,
    outer or tunnelled, and stops there, so the offending header is the
    last IPv4 header decoded — which is why every one is checked here,
    not just the first.

    A ``total_length`` of 0 is exempt: it is the sentinel large-send
    offload (TSO) leaves in locally captured outbound frames, where the
    real length is filled in by hardware after capture. Flagging it would
    cry wolf on ordinary local traffic, and the library exempts it too.
    """
    return any(
        isinstance(layer, IPv4) and 0 < layer.total_length < layer.header_len
        for layer in layers
    )


def decode_frame(
    data: bytes,
    *,
    number: int,
    timestamp: int,
    interface: str | None,
) -> DecodedFrame:
    """Decode one captured frame.

    Delegates the chain walk to :func:`netprotocols.decode_frame`
    (``lax=True``, at most :data:`_MAX_LAYERS` layers): it walks
    Ethernet inward, bounded in depth, and reports a structured
    :class:`~netprotocols.ProtocolError` on early stop instead of
    raising. The walk ends at the first protocol the library does not
    implement — the remainder becomes the frame's payload — or at the
    first header that fails to decode. That failure is recorded on
    ``DecodedFrame.error``, unless it happened in a port-dispatched
    application decoder, where it is a best-effort miss recorded on
    ``DecodedFrame.l7_miss`` instead (see the module docstring).

    Bytes past the end the frame's own length fields declare (Ethernet
    padding, a captured FCS) are kept apart as ``DecodedFrame.trailer``
    rather than folded into the payload: they belong to no layer.
    """
    packet = _decode_chain(data, lax=True, max_depth=_MAX_LAYERS)
    decoded_layers = packet.layers
    error, l7_miss = _classify_stop(packet.stopped_by, decoded_layers)
    trailer = packet.trailer
    payload_end = len(data) - len(trailer)

    declared = _declared_length(decoded_layers)
    return DecodedFrame(
        number=number,
        timestamp=timestamp,
        interface=interface,
        length=len(data),
        layers=decoded_layers,
        payload=data[packet.consumed : payload_end],
        truncated=declared is not None and declared > len(data),
        malformed_length=_ip_length_malformed(decoded_layers),
        error=error,
        l7_miss=l7_miss,
        trailer=trailer,
        raw=data,
    )
