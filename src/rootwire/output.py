"""Renderers and other consumers of decoded frames.

``OutputToScreen`` dispatches on the *type* of each decoded layer via
``singledispatchmethod`` and always receives the whole
:class:`DecodedFrame`, so renderers can reach for context beyond their
own layer (the ICMP lines show the enclosing IP addresses, for
example). Unknown layers and malformed frames render diagnostics
instead of raising: display helpers must never kill a capture.
"""

from __future__ import annotations

import dataclasses
import enum
import ipaddress
import json
import sys
import time
from abc import ABC, abstractmethod
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from functools import singledispatchmethod
from typing import IO, Any, cast

from netprotocols import (
    AH,
    ARP,
    BGP,
    CDP,
    DHCP,
    DNS,
    ESP,
    GRE,
    HSRP,
    HTTP,
    IGMP,
    LLC,
    LLDP,
    LLDPTLV,
    MPLS,
    NTP,
    OSPF,
    OSPFLSA,
    PIM,
    RADIUS,
    RIP,
    SCTP,
    SNAP,
    STP,
    STUN,
    TCP,
    TFTP,
    TLS,
    UDP,
    VLAN,
    VRRP,
    VXLAN,
    BGPPathAttribute,
    CDPAddress,
    DNSOverTCP,
    Ethernet,
    EtherType,
    HTTPAnomaly,
    HTTPAnomalyKind,
    ICMPv4,
    ICMPv6,
    IPv4,
    IPv4Option,
    IPv6,
    IPv6DestinationOptions,
    IPv6Fragment,
    IPv6HopByHopOptions,
    IPv6Routing,
    LLDPChassisID,
    LLDPPortID,
    MPLSLabel,
    OSPFLSAHeader,
    PIMAssert,
    PIMEncodedSource,
    PIMHello,
    PIMJoinPrune,
    PIMRegister,
    PIMRegisterStop,
    Protocol,
    ProtocolError,
    RADIUSAttribute,
    RIPAuthentication,
    RIPEntry,
    STUNAddress,
    TCPOption,
    compute,
    verify,
    verify_lsa,
)
from netprotocols.flow import FlowKey, flow_key

from rootwire.frame import DecodedFrame
from rootwire.pcap import PcapWriter

__all__ = [
    "Output",
    "OutputToNDJSON",
    "OutputToPcap",
    "OutputToScreen",
    "StatsCollector",
]

_I = " " * 4  # base indentation for layer sections
_II = " " * 8  # indentation for field detail lines

#: Most items a list-style line (SCTP chunks, TLS extensions) names
#: before summarizing the rest as "(+N more)": a crafted packet can carry
#: hundreds of 4-byte SCTP chunks, and one line of them is unreadable.
_LIST_LIMIT = 16


def _capped(items: list[str]) -> str:
    """*items* joined with ", ", cut at :data:`_LIST_LIMIT` with a
    ``(+N more)`` suffix, or ``"none"`` when empty."""
    if not items:
        return "none"
    shown = ", ".join(items[:_LIST_LIMIT])
    extra = len(items) - _LIST_LIMIT
    return f"{shown} (+{extra} more)" if extra > 0 else shown


def _sanitize_for_terminal(text: str) -> str:
    r"""Return *text* with terminal-unsafe characters neutralized.

    Payload bytes are attacker-controlled, so escape sequences must never
    reach the terminal verbatim: a crafted packet could otherwise move the
    cursor, rewrite the window title, or recolour and erase prior output
    when displayed with ``-d``. Printable characters and newlines — the
    intended line structure — pass through unchanged; everything else
    (C0 controls and ``DEL``, the C1 range ``U+0080`` to ``U+009F``, and
    Unicode format characters such as the bidirectional overrides) is
    rendered as a visible ``\xNN`` or ``\uXXXX`` escape.

    :class:`str.isprintable` already reports every one of those categories
    as non-printable, so a single membership test covers the whole set.
    """
    out: list[str] = []
    for char in text:
        if char == "\n" or char.isprintable():
            out.append(char)
        else:
            code = ord(char)
            out.append(f"\\x{code:02x}" if code <= 0xFF else f"\\u{code:04x}")
    return "".join(out)


def _format_option(option: IPv4Option | TCPOption) -> str:
    """A compact ``"Name (value)"`` / ``"Name (N bytes)"`` / ``"Name"``
    rendering of one TLV option: decoded where the library understands
    the kind (``option.value``), falling back to a raw byte count for
    kinds it only keeps raw, and bare for a kind with no data at all
    (EOL, NOP, SACK-Permitted)."""
    value = option.value
    if value is None:
        return (
            f"{option.kind_name} ({len(option.data)} bytes)"
            if option.data
            else option.kind_name
        )
    if isinstance(value, tuple):
        # Timestamps' (tsval, tsecr) pair and SACK's block tuple both
        # already stringify with their own parens -- no extra wrapping.
        return f"{option.kind_name} {value}"
    return f"{option.kind_name} ({value})"


def _offset_of(frame: DecodedFrame, layer: Protocol) -> tuple[int, int]:
    """``(index, offset)`` of *layer* in *frame*: its position in
    ``frame.layers`` and the frame offset its header starts at, the sum
    of every preceding header's ``header_len``."""
    offset = 0
    for index, candidate in enumerate(frame.layers):
        if candidate is layer:
            return index, offset
        offset += candidate.header_len
    raise ValueError("layer is not in frame.layers")  # pragma: no cover


def _declared_end(frame: DecodedFrame, layer: Protocol) -> int:
    """Where the bytes that belong to *layer* end, by the length fields
    of the headers that enclose it, *layer* itself included.

    That is the tightest of: each enclosing IPv4 header's Total Length,
    IPv6 header's Payload Length, UDP header's Length and Ethernet/VLAN
    IEEE 802.3 Length (a type/length value of 1500 or less), each
    measured from that header's own offset, and the end of the capture.
    It is the bound NETProtocols' walk handed *layer*'s decoder, plus
    *layer*'s own length when it has one (a UDP checksum covers exactly
    ``length`` bytes). A zero, or a value shorter than its own header,
    bounds nothing, as in the walk.

    Computed per layer on purpose. ``frame.trailer`` is the bytes past
    the *tightest* end anywhere in the frame, which in a tunnel is the
    inner datagram's: an inner Ethernet frame's padding inside VXLAN is
    trailer, yet it is part of the outer UDP datagram and its checksum.
    """
    index, _ = _offset_of(frame, layer)
    end = len(frame.raw)
    offset = 0
    for candidate in frame.layers[: index + 1]:
        extent = _length_extent(candidate)
        if extent is not None:
            end = min(end, offset + extent)
        offset += candidate.header_len
    return end


def _length_extent(layer: Protocol) -> int | None:
    """How many bytes, from its own start, *layer*'s length field says
    belong to it, or ``None`` if it has no such field or the value
    bounds nothing: 0 (TSO's IPv4 sentinel, IPv6 jumbograms, UDP over
    IPv6 jumbograms) or less than the header itself."""
    if isinstance(layer, IPv4):
        valid = layer.total_length >= layer.header_len
        return layer.total_length if valid else None
    if isinstance(layer, IPv6):
        bounded = layer.payload_length > 0
        return layer.header_len + layer.payload_length if bounded else None
    if isinstance(layer, UDP):
        return layer.length if layer.length >= layer.header_len else None
    if isinstance(layer, Ethernet | VLAN) and 0 < layer.ethertype <= 1500:
        # An IEEE 802.3 Length rather than an EtherType.
        return layer.header_len + layer.ethertype
    return None


def _trailing_bytes(frame: DecodedFrame, layer: Protocol) -> bytes:
    """The bytes that followed *layer* on the wire, up to its declared
    end (see :func:`_declared_end`), whether or not anything after it was
    itself decoded into a further layer — reconstructed from the frame's
    own raw capture rather than re-serializing subsequent layers, so it
    is exact regardless of chain depth.

    Ending at the declared end keeps Ethernet padding and a captured FCS
    out of a checksum that never covered them: a TCP or ICMPv6 checksum
    sums the segment's length as ``header_len + len(payload)``, so six
    bytes of padding behind a 54-byte bare ACK would otherwise read as a
    mismatch on perfectly good traffic.
    """
    index, offset = _offset_of(frame, layer)
    start = offset + frame.layers[index].header_len
    return frame.raw[start : max(start, _declared_end(frame, layer))]


def _enclosing_ip(
    frame: DecodedFrame, layer: Protocol
) -> tuple[IPv4 | IPv6 | None, IPv6Routing | None]:
    """The IP header enclosing *layer*, and the Routing header that
    redirects its pseudo-header, if any.

    The IP header is the *nearest* one before *layer* — the inner one
    in a tunnel (IP-in-IP, GRE, VXLAN, AH tunnel mode), not the
    outermost: an inner TCP/UDP checksum is computed over the inner
    datagram's pseudo-header, so verifying it against the outer IP's
    addresses flags a false mismatch on every tunnelled segment.

    The Routing header is the last :class:`~netprotocols.IPv6Routing`
    between that IP header and *layer* with ``segments_left`` above 0:
    behind one, the pseudo-header carries the route's final destination
    rather than the next hop in ``IPv6.dst`` (RFC 8200 §8.1), and a
    Routing header that has no segments left is already at its final
    destination. Both rules mirror NETProtocols'
    :meth:`~netprotocols.Packet.with_checksums`, so RootWire verifies a
    checksum exactly the way the library would fill it in.
    """
    index, _ = _offset_of(frame, layer)
    routing: IPv6Routing | None = None
    for candidate in reversed(frame.layers[:index]):
        if isinstance(candidate, (IPv4, IPv6)):
            return candidate, routing
        if (
            routing is None
            and isinstance(candidate, IPv6Routing)
            and candidate.segments_left > 0
        ):
            routing = candidate
    return None, None


def _is_fragmented(frame: DecodedFrame, layer: Protocol) -> bool:
    """Whether *layer* sits inside a non-reassembled IP fragment.

    A transport-layer checksum (ICMP/TCP/UDP/IGMP/GRE) covers the
    *reassembled* datagram; RootWire never reassembles fragments (each
    renders independently, labeled "first fragment" / "fragment at
    offset N"). Verifying one against a single fragment's bytes would
    disagree with the wire checksum every time — correctly, but for a
    reason that has nothing to do with the checksum being wrong, so
    callers use this to suppress that check rather than flag a false
    mismatch.

    Only the headers *enclosing* *layer* count: an IPv4 header with More
    Fragments set or a nonzero Fragment Offset, or an IPv6 Fragment
    header, anywhere before it. An inner tunnelled datagram's
    fragmentation therefore suppresses its own checksums but not the
    outer UDP's, and a fragmented inner IPv4 is caught even when the
    outer one is whole.
    """
    index, _ = _offset_of(frame, layer)
    for candidate in frame.layers[:index]:
        if isinstance(candidate, IPv6Fragment):
            return True
        if isinstance(candidate, IPv4) and (
            candidate.flags & 0b001 or candidate.fragment_offset > 0
        ):
            return True
    return False


def _checksum_note(
    layer: Protocol,
    *,
    ip: IPv4 | IPv6 | None = None,
    routing: IPv6Routing | None = None,
    payload: bytes = b"",
) -> str:
    """A trailing ``" [!] mismatch (expected 0xXXXX)"`` note for a
    checksum display line, or ``""`` when it verifies.

    *ip* and *routing* are the layer's enclosing headers (see
    :func:`_enclosing_ip`); *payload* is what follows it on the wire
    (see :func:`_trailing_bytes`). Given *ip*, NETProtocols ends an
    IGMP, ICMPv4 or GRE checksum at that datagram's declared end, so
    padding a layer decoded on its own never reaches the sum.

    Never raises: a checksum this helper cannot compute (most notably,
    a required enclosing IP layer this frame doesn't have) is treated
    as unverifiable, not as a mismatch — rendering must never flag a
    false positive over its own inability to check.
    """
    try:
        if verify(layer, ip=ip, routing=routing, payload=payload):
            return ""
        expected = compute(layer, ip=ip, routing=routing, payload=payload)
    except ProtocolError:
        return ""
    return f" [!] mismatch (expected {expected:#06x})"


def _transport_checksum_note(frame: DecodedFrame, layer: Protocol) -> str:
    """:func:`_checksum_note` for a layer whose checksum covers what
    follows it (TCP, UDP, SCTP), with its enclosing IP and Routing
    headers; ``""`` for a non-reassembled fragment (see
    :func:`_is_fragmented`).

    Also right for a message whose checksum covers only itself or adds
    a pseudo-header (VRRP, PIM, OSPF): NETProtocols ignores *payload*
    for those, and the enclosing IP and fragment rules are the same."""
    if _is_fragmented(frame, layer):
        return ""
    ip, routing = _enclosing_ip(frame, layer)
    return _checksum_note(
        layer, ip=ip, routing=routing, payload=_trailing_bytes(frame, layer)
    )


#: ``0.0.0.0``, built rather than written: routing protocols use it for
#: "none" (an unelected OSPF DR/BDR, a RIP next hop of "this sender",
#: RIPv1's absent mask), and the bare literal reads to Bandit as a
#: bind-all-interfaces address (B104).
_UNSET_ADDRESS = str(ipaddress.IPv4Address(0))

#: RIP's Request command, IP Address Family Identifier, and its metric
#: "infinity".
_RIP_REQUEST = 1
_RIP_AFI_IP = 2
_RIP_INFINITY = 16

#: The version nibble that starts an IPv6 header.
_IPV6_VERSION = 6


def _inline_text(text: str) -> str:
    """*text* sanitized for the terminal (see
    :func:`_sanitize_for_terminal`) and kept on one line: a newline is
    shown as ``\\n``. For wire text rendered inside a field line, where
    a sender-chosen newline could otherwise start a line that reads as
    RootWire's own (a forged ``[>] Frame`` header or ``[!]`` note)."""
    return _sanitize_for_terminal(text).replace("\n", "\\n")


def _secret_text(data: bytes) -> str:
    """A clear-text password field (VRRPv2 PASS, RIP type 2, OSPF
    AuType 1) for display: its NUL padding stripped, any byte outside
    ASCII shown as ``\\xNN``, and the result sanitized for the terminal
    on one line (see :func:`_inline_text`) -- ESC and newline are ASCII,
    and the sender chose every byte."""
    text = data.rstrip(b"\x00").decode("ascii", errors="backslashreplace")
    return _inline_text(text) if text else "(empty)"


def _or_none(address: str) -> str:
    """*address*, or ``"none"`` for ``0.0.0.0``."""
    return "none" if address == _UNSET_ADDRESS else address


def _lsa_header_text(header: OSPFLSAHeader) -> str:
    """One OSPF LSA header as ``"Router-LSA 10.0.0.1 (adv 10.0.0.1,
    seq 0x80000002)"``: the triple that identifies an LSA instance."""
    return (
        f"{header.ls_type_name} {header.link_state_id} "
        f"(adv {header.advertising_router}, "
        f"seq {header.ls_sequence_number_hex_str})"
    )


def _lsa_text(lsa: OSPFLSA) -> str:
    """One LSA of a Link State Update: its header (see
    :func:`_lsa_header_text`), flagged when its LS Checksum fails --
    the Fletcher checksum over the LSA, which a router discards it for
    (RFC 2328 §13)."""
    note = "" if verify_lsa(lsa) else " [!] bad LS checksum"
    return _lsa_header_text(lsa.header) + note


def _rip_route_text(entry: RIPEntry) -> str:
    """One RIP route as ``"10.20.2.0/24 via 10.20.1.2 metric 1"``.

    RIPv1 carries no mask (``0.0.0.0``), and a next hop of ``0.0.0.0``
    means "via the sender" (RFC 2453 §4.4), so each is shown only when
    set. A mask that is not contiguous has no prefix length and is
    shown as itself. Metric 16 is infinity: the route is withdrawn or
    poisoned.
    """
    destination = entry.address
    if entry.subnet_mask != _UNSET_ADDRESS:
        network: ipaddress.IPv4Network | None
        try:
            network = ipaddress.IPv4Network(
                f"{entry.address}/{entry.subnet_mask}", strict=False
            )
        except ValueError:
            network = None
        # ipaddress reads a mask such as 0.255.255.255 as a *host* mask
        # and inverts it; only a mask it reproduces is a prefix length.
        if network is not None and str(network.netmask) == entry.subnet_mask:
            destination = f"{entry.address}/{network.prefixlen}"
        else:
            destination = f"{entry.address} mask {entry.subnet_mask}"
    if entry.afi != _RIP_AFI_IP:
        destination = f"{destination} ({entry.afi_name})"
    via = f" via {entry.next_hop}" if entry.next_hop != _UNSET_ADDRESS else ""
    metric = (
        "unreachable"
        if entry.metric >= _RIP_INFINITY
        else f"metric {entry.metric}"
    )
    return f"{destination}{via} {metric}"


def _rip_auth_text(auth: RIPAuthentication) -> str:
    """A RIPv2 authentication entry: a plain-text password (type 2)
    shown sanitized; a keyed digest (type 3, RFC 4822) by its Key ID,
    sequence number and digest length; anything else by name."""
    if (password := auth.password) is not None:
        return f"{auth.auth_type_name} ({_secret_text(password)})"
    if auth.key_id is not None:
        # Auth Data Len counts the trailer's 4-byte header as well as
        # the digest, so the digest's size is left to the Trailer field.
        return (
            f"{auth.auth_type_name} (key {auth.key_id}, "
            f"seq {auth.sequence_number})"
        )
    return auth.auth_type_name


def _pim_source_text(source: PIMEncodedSource) -> str:
    """A Join/Prune source as ``"10.184.1.2/32"``, with its WC and RPT
    bits when set: ``(*,G)`` and ``(S,G,rpt)`` entries differ from an
    ``(S,G)`` one only there."""
    flags = " ".join(
        name
        for name, bit in (("WC", source.wildcard), ("RPT", source.rpt))
        if bit
    )
    text = f"{source.address}/{source.mask_len}"
    return f"{text} ({flags})" if flags else text


def _pim_register_inner(register: PIMRegister) -> str:
    """What a PIM Register encapsulates: ``"Null-Register"``, or the
    inner datagram's addresses and protocol and its length.

    Only the inner IP header is decoded, by itself. The library's
    :attr:`~netprotocols.PIMRegister.encapsulated` would run a second
    :func:`~netprotocols.decode_frame` walk over the inner datagram,
    outside the frame's single layer budget (see ARCHITECTURE.md); one
    header is all an analyst needs to see which flow is being
    registered.
    """
    if register.null_register:
        return "Null-Register"
    packet = register.packet
    try:
        if packet[:1] and packet[0] >> 4 == _IPV6_VERSION:
            inner6 = IPv6.decode(packet)
            return (
                f"{inner6.src} -> {inner6.dst} ({inner6.next_header_name}), "
                f"{len(packet)} bytes"
            )
        inner4 = IPv4.decode(packet)
    except ProtocolError:
        return f"{len(packet)} bytes, inner IP header malformed"
    return (
        f"{inner4.src} -> {inner4.dst} ({inner4.protocol_name}), "
        f"{len(packet)} bytes"
    )


def _lying_ipv4(frame: DecodedFrame) -> IPv4 | None:
    """The IPv4 header whose ``total_length`` is shorter than itself,
    the one ``frame.malformed_length`` reports: always the last IPv4
    header decoded, outer or tunnelled, since the walk stops there."""
    for layer in reversed(frame.layers):
        if (
            isinstance(layer, IPv4)
            and 0 < layer.total_length < layer.header_len
        ):
            return layer
    return None


class Output(ABC):
    """Interface for consumers of decoded frames (screen, file, ...)."""

    @abstractmethod
    def update(self, frame: DecodedFrame) -> None:
        """Process one decoded frame."""

    def close(self) -> None:  # noqa: B027 -- optional hook, not abstract
        """Release resources at end of capture; default: nothing.

        Deliberately not abstract: most outputs hold no resources, and
        forcing every renderer to write a no-op close would be noise.
        """


class OutputToScreen(Output):
    """Render decoded frames as indented text, one block per frame.

    :param display_payload: Also render the frame's raw payload,
        decoded as text with undecodable bytes ignored.
    :param stream: Destination stream; defaults to stdout.
    """

    def __init__(
        self, *, display_payload: bool, stream: IO[str] | None = None
    ) -> None:
        self._display_payload = display_payload
        self._stream = stream if stream is not None else sys.stdout

    def _print(self, text: str) -> None:
        print(text, file=self._stream)

    @contextmanager
    def _guard(self, what: str) -> Iterator[None]:
        """Contain a malformed on-demand section of a layer.

        Several layers parse part of themselves lazily, on first access
        of a property (DNS records, DHCP/TCP/IPv4 options, IGMP group
        records, NDP options, ...), so a structurally valid header can
        still raise from a renderer. Inside ``with self._guard("X"):``
        a :class:`~netprotocols.ProtocolError` ends the block, prints
        ``[!] X malformed: <reason>`` and rendering carries on with the
        next line or layer; whatever the block printed before the fault
        stays printed. Only ``ProtocolError`` is contained: anything
        else is a RootWire bug and should surface as one.
        """
        try:
            yield
        except ProtocolError as error:
            reason = _sanitize_for_terminal(str(error))
            self._print(f"{_II}[!] {what} malformed: {reason}")

    def update(self, frame: DecodedFrame) -> None:
        """Render one frame: a header line, every layer through its
        registered renderer, the frame-level diagnostics, and (with
        ``display_payload``) the sanitized undecoded payload."""
        local_time = time.strftime(
            "%H:%M:%S", time.localtime(frame.timestamp / 1_000_000_000)
        )
        interface = frame.interface or "all"
        self._print(
            f"[>] Frame #{frame.number} at {local_time} "
            f"({interface}, {frame.length} bytes)"
        )
        for layer in frame.layers:
            self._render(layer, frame)
        self._render_diagnostics(frame)
        if self._display_payload and frame.payload:
            text = _sanitize_for_terminal(frame.payload.decode(errors="ignore"))
            self._print(f"{_I}[+] Payload ({len(frame.payload)} bytes):")
            self._print(f"{_II}{text.replace(chr(10), chr(10) + _II)}")
        self._print("")

    def _render_diagnostics(self, frame: DecodedFrame) -> None:
        """The frame-level ``[!]``/``[~]`` lines that follow its layers:
        a decode error, a best-effort application miss, truncation, and
        a lying IPv4 length. Prints nothing for a healthy frame."""
        # A lying IPv4 total_length is reported once, by the specific
        # line below: the walk's own error for it is the same fault
        # (see DecodedFrame.malformed_length). Library messages can quote
        # wire bytes, so they are sanitized like any other wire text.
        if frame.error is not None and not frame.malformed_length:
            self._print(
                f"{_I}[!] Malformed header: "
                f"{_sanitize_for_terminal(frame.error)}"
            )
        if frame.l7_miss is not None and frame.payload:
            # Informational, not a [!]: see DecodedFrame.l7_miss. Shown
            # only when there are undecoded bytes to explain -- a bare
            # ACK on port 443 has nothing to say.
            self._print(
                f"{_I}[~] Payload left undecoded: "
                f"{_sanitize_for_terminal(frame.l7_miss)}"
            )
        if frame.sni_peek is not None:
            # The name a split ClientHello asks for, read from its first
            # segment (see DecodedFrame.sni_peek): what the [~] line
            # above leaves undecoded is, in this case, worth one line.
            self._print(
                f"{_I}[+] TLS ClientHello (continues in a later segment) "
                f"SNI: {_sanitize_for_terminal(frame.sni_peek)}"
            )
        if frame.truncated:
            self._print(
                f"{_I}[!] Truncated: the IP datagram declares more bytes "
                f"than were captured"
            )
        if frame.malformed_length and (ip := _lying_ipv4(frame)) is not None:
            self._print(
                f"{_I}[!] Malformed: IPv4 total_length ({ip.total_length}) "
                f"is smaller than its header ({ip.header_len} bytes); "
                f"upper layers not decoded"
            )

    @singledispatchmethod
    def _render(self, layer: Protocol, frame: DecodedFrame) -> None:
        self._print(f"{_I}[+] {type(layer).__name__} (no renderer)")

    @_render.register
    def _(self, layer: Ethernet, frame: DecodedFrame) -> None:
        self._print(f"{_I}[+] Ethernet {layer.src} -> {layer.dst}")
        self._print(f"{_II}EtherType: {layer.ethertype_name}")

    @_render.register
    def _(self, layer: ARP, frame: DecodedFrame) -> None:
        if layer.oper == 1:
            summary = f"who has {layer.tpa}? tell {layer.spa}"
        else:
            summary = f"{layer.spa} is at {layer.sha}"
        self._print(f"{_I}[+] ARP {summary}")
        self._print(
            f"{_II}Operation: {layer.oper} ({layer.oper_name}) | "
            f"Protocol Type: {layer.ptype_name} ({layer.ptype_hex_str})"
        )
        self._print(f"{_II}Sender: {layer.sha} / {layer.spa}")
        self._print(f"{_II}Target: {layer.tha} / {layer.tpa}")

    @_render.register
    def _(self, layer: IPv4, frame: DecodedFrame) -> None:
        self._print(f"{_I}[+] IPv4 {layer.src} -> {layer.dst}")
        self._print(
            f"{_II}TTL: {layer.ttl} | Flags: {layer.flags_name} | "
            f"Total Length: {layer.total_length} | ID: {layer.identification}"
        )
        self._print(
            f"{_II}Protocol: {layer.protocol_name} | "
            f"Checksum: {layer.checksum_hex_str}{_checksum_note(layer)}"
        )
        self._render_options_line(layer)

    @_render.register
    def _(self, layer: IPv6, frame: DecodedFrame) -> None:
        self._print(f"{_I}[+] IPv6 {layer.src} -> {layer.dst}")
        self._print(
            f"{_II}Hop Limit: {layer.hop_limit} | "
            f"Traffic Class: {layer.traffic_class_hex_str} | "
            f"Flow Label: {layer.flow_label_hex_str}"
        )
        self._print(
            f"{_II}Payload Length: {layer.payload_length} | "
            f"Next Header: {layer.next_header_name}"
        )

    @_render.register
    def _(self, layer: IPv6HopByHopOptions, frame: DecodedFrame) -> None:
        self._render_options_header(layer, "IPv6 Hop-by-Hop Options")

    @_render.register
    def _(self, layer: IPv6DestinationOptions, frame: DecodedFrame) -> None:
        self._render_options_header(layer, "IPv6 Destination Options")

    def _render_options_header(
        self,
        layer: IPv6DestinationOptions | IPv6HopByHopOptions,
        title: str,
    ) -> None:
        self._print(f"{_I}[+] {title}")
        self._print(
            f"{_II}Length: {layer.header_len} bytes | "
            f"Next Header: {layer.next_header_name}"
        )

    def _render_options_line(self, layer: IPv4 | TCP) -> None:
        """Print a decoded ``"Options: ..."`` summary, or a ``[!]``
        diagnostic if the options bytes are malformed. Prints nothing
        for a header carrying no options."""
        if not layer.options:
            return
        with self._guard("Options"):
            options = layer.parsed_options
            # Capped like every one-line list: 40 bytes of options can
            # be 40 one-byte No-Operations.
            formatted = [_format_option(option) for option in options]
            self._print(f"{_II}Options: {_capped(formatted)}")

    @_render.register
    def _(self, layer: IPv6Routing, frame: DecodedFrame) -> None:
        self._print(f"{_I}[+] IPv6 Routing (type {layer.routing_type})")
        self._print(
            f"{_II}Segments Left: {layer.segments_left} | "
            f"Length: {layer.header_len} bytes | "
            f"Next Header: {layer.next_header_name}"
        )

    @_render.register
    def _(self, layer: IPv6Fragment, frame: DecodedFrame) -> None:
        position = (
            "first fragment"
            if layer.fragment_offset == 0
            else f"fragment at offset {layer.fragment_offset * 8}"
        )
        self._print(f"{_I}[+] IPv6 Fragment ({position})")
        self._print(
            f"{_II}ID: {layer.identification} | "
            f"More Fragments: {'yes' if layer.m_flag else 'no'} | "
            f"Next Header: {layer.next_header_name}"
        )

    @_render.register
    def _(self, layer: GRE, frame: DecodedFrame) -> None:
        """GRE: the encapsulated protocol and which optional fields are
        present, with the checksum verified (over the datagram up to its
        IP header's declared end) when the Checksum-Present bit is set."""
        self._print(f"{_I}[+] GRE (protocol: {layer.protocol_name})")
        optional = []
        if layer.checksum_present:
            ip, _ = _enclosing_ip(frame, layer)
            note = (
                ""
                if _is_fragmented(frame, layer)
                else _checksum_note(
                    layer,
                    ip=ip,
                    payload=_trailing_bytes(frame, layer),
                )
            )
            optional.append(f"Checksum: {layer.checksum_hex_str}{note}")
        if layer.key_present:
            optional.append(f"Key: {layer.key:#010x}")
        if layer.sequence_present:
            optional.append(f"Sequence: {layer.sequence_number}")
        self._print(
            f"{_II}{' | '.join(optional) if optional else 'No optional fields'}"
        )

    @_render.register
    def _(self, layer: IGMP, frame: DecodedFrame) -> None:
        """IGMP: message type, Max Resp Code and verified checksum, then
        the group (v1/v2 report, leave, query) or every v3 group record,
        parsed lazily inside a guard."""
        self._print(f"{_I}[+] IGMP {layer.type_name}")
        ip, _ = _enclosing_ip(frame, layer)
        note = (
            "" if _is_fragmented(frame, layer) else _checksum_note(layer, ip=ip)
        )
        self._print(
            f"{_II}Max Resp Code: {layer.max_resp_code} | "
            f"Checksum: {layer.checksum_hex_str}{note}"
        )
        with self._guard("Body"):
            group_address = layer.group_address
            records = layer.group_records
            if group_address is not None:
                self._print(f"{_II}Group: {group_address}")
            for record in records or ():
                sources = ", ".join(record.source_addresses) or "none"
                self._print(
                    f"{_II}Record: {record.record_type_name} "
                    f"{record.multicast_address} (sources: {sources})"
                )

    @_render.register
    def _(self, layer: ICMPv4, frame: DecodedFrame) -> None:
        self._render_icmp(layer, frame, version=4)

    @_render.register
    def _(self, layer: ICMPv6, frame: DecodedFrame) -> None:
        self._render_icmp(layer, frame, version=6)

    def _render_icmp(
        self, layer: ICMPv4 | ICMPv6, frame: DecodedFrame, *, version: int
    ) -> None:
        """Shared ICMPv4/ICMPv6 rendering: the enclosing route, type/code
        and a checksum verified against the nearest IP header (plus any
        Routing header), then Neighbor Discovery detail for ICMPv6."""
        ip, routing = _enclosing_ip(frame, layer)
        route = f" {ip.src} -> {ip.dst}" if ip is not None else ""
        self._print(f"{_I}[+] ICMPv{version}{route}")
        # The ICMPv6 pseudo-header needs the enclosing IPv6 layer (and
        # the final destination behind a Routing header); ICMPv4 has no
        # pseudo-header, but given its IP the library ends the sum at
        # the datagram's declared end, keeping padding out. Skipped
        # entirely for a fragment: the checksum covers the reassembled
        # message, which this single fragment's bytes never match.
        note = (
            ""
            if _is_fragmented(frame, layer)
            else _checksum_note(
                layer,
                ip=ip,
                routing=routing,
                payload=_trailing_bytes(frame, layer),
            )
        )
        self._print(
            f"{_II}Type: {layer.type} ({layer.type_name}) | "
            f"Code: {layer.code} | Checksum: {layer.checksum_hex_str}{note}"
        )
        if isinstance(layer, ICMPv6):
            self._render_ndp(layer)

    def _render_ndp(self, layer: ICMPv6) -> None:
        """Neighbor Discovery detail for a Router/Neighbor
        Solicitation/Advertisement or Redirect (RFC 4861) -- a no-op
        for every other ICMPv6 message type, since
        ``ndp_target_address``/``ndp_options`` are both ``None`` there."""
        target = layer.ndp_target_address
        if target is not None:
            self._print(f"{_II}Target: {target}")
        with self._guard("NDP options"):
            for option in layer.ndp_options or ():
                detail = option.link_layer_address or (
                    option.data.hex() if option.data else ""
                )
                self._print(
                    f"{_II}Option: {option.type_name}"
                    + (f" ({detail})" if detail else "")
                )

    @_render.register
    def _(self, layer: TCP, frame: DecodedFrame) -> None:
        self._print(f"{_I}[+] TCP {layer.src_port} -> {layer.dst_port}")
        self._print(
            f"{_II}Flags: {layer.flags_hex_str} ({layer.flags_str}) | "
            f"Seq: {layer.seq} | Ack: {layer.ack}"
        )
        note = _transport_checksum_note(frame, layer)
        self._print(
            f"{_II}Window: {layer.window} | "
            f"Checksum: {layer.checksum_hex_str}{note}"
        )
        self._render_options_line(layer)

    @_render.register
    def _(self, layer: UDP, frame: DecodedFrame) -> None:
        self._print(f"{_I}[+] UDP {layer.src_port} -> {layer.dst_port}")
        note = _transport_checksum_note(frame, layer)
        self._print(
            f"{_II}Length: {layer.length} | "
            f"Checksum: {layer.checksum_hex_str}{note}"
        )

    @_render.register
    def _(self, layer: DNS, frame: DecodedFrame) -> None:
        """DNS: direction, transaction ID, flags/opcode/RCODE and every
        question and answer, names and RDATA sanitized; the records are
        parsed lazily, so they render inside a guard."""
        direction = "response" if layer.qr else "query"
        self._print(f"{_I}[+] DNS {direction} (id {layer.transaction_id:#06x})")
        self._print(
            f"{_II}Flags: {layer.flags_hex_str} | Opcode: {layer.opcode} | "
            f"RCODE: {layer.rcode}"
        )
        with self._guard("Records"):
            questions = layer.questions
            answers = layer.answers
            for question in questions:
                name = _inline_text(question.name)
                self._print(f"{_II}Q: {name} (type {question.qtype})")
            for answer in answers:
                name = _inline_text(answer.name)
                rdata = _inline_text(answer.rdata_text)
                self._print(
                    f"{_II}A: {name} {answer.rtype_name} {answer.ttl}s "
                    f"-> {rdata}"
                )

    @_render.register
    def _(self, layer: DNSOverTCP, frame: DecodedFrame) -> None:
        self._print(
            f"{_I}[+] DNS over TCP "
            f"(message length: {layer.message_length} bytes)"
        )

    @_render.register
    def _(self, layer: DHCP, frame: DecodedFrame) -> None:
        """DHCP: message type (falling back to BOOTP op), client MAC and
        XID, the four address fields, and a parsed-option count, the
        options guarded since they parse on demand."""
        try:
            message_type = layer.message_type_name
        except ProtocolError:
            # message_type_name and parsed_options both read the same
            # underlying option_map, so a malformed options section
            # raises identically from either -- falling back silently
            # here is safe: the [!] diagnostic below still fires.
            message_type = None
        self._print(f"{_I}[+] DHCP {message_type or layer.op_name}")
        self._print(
            f"{_II}Client: {layer.client_mac or 'n/a'} | XID: {layer.xid:#010x}"
        )
        self._print(
            f"{_II}Client Addr: {layer.ciaddr} | Your Addr: {layer.yiaddr} | "
            f"Server Addr: {layer.siaddr} | Gateway Addr: {layer.giaddr}"
        )
        with self._guard("Options"):
            if option_count := len(layer.parsed_options):
                self._print(f"{_II}Options: {option_count} parsed")

    @_render.register
    def _(self, layer: VLAN, frame: DecodedFrame) -> None:
        self._print(
            f"{_I}[+] 802.1Q VLAN (VID {layer.vid}, PCP {layer.pcp}, "
            f"DEI {layer.dei})"
        )
        self._print(f"{_II}EtherType: {layer.ethertype_name}")

    @_render.register
    def _(self, layer: TLS, frame: DecodedFrame) -> None:
        """TLS: one line per record (a segment often holds several),
        naming its content type, the handshake message for a Handshake
        record, the record-layer version and length. A ClientHello also
        gets its own version, SNI host name, cipher-suite count and
        extension list, parsed on demand. An encrypted TLS 1.2 Finished
        whose ciphertext happens to start with 1 reads as a ClientHello
        and raises (see :attr:`netprotocols.TLS.client_hello`), so a
        failure to parse one is an informational ``[~]`` line, not a
        ``[!]``: healthy traffic produces it. A ClientHello may carry no
        extensions block at all (TLS 1.2 and earlier)."""
        message = (
            f" ({layer.handshake_type_name})"
            if layer.handshake_type_name
            else ""
        )
        self._print(
            f"{_I}[+] TLS {layer.content_type_name}{message} | "
            f"{layer.legacy_version_name} | "
            f"{layer.length} byte{'' if layer.length == 1 else 's'}"
        )
        try:
            hello = layer.client_hello
        except ProtocolError as error:
            # Not a [!]: a healthy encrypted TLS 1.2 Finished is a
            # Handshake record whose first ciphertext byte is 1 about
            # one time in 256, and no field tells it from a ClientHello
            # cut short. Informational, like the [~] best-effort miss.
            reason = _sanitize_for_terminal(str(error))
            self._print(
                f"{_II}[~] Not parsed as a ClientHello (an encrypted "
                f"handshake message can begin like one): {reason}"
            )
            return
        if hello is None:
            return
        with self._guard("ClientHello"):
            # The library checks the name is ASCII, but ESC is ASCII:
            # the SNI is chosen by whoever sent the ClientHello.
            name = layer.server_name
            sni = _sanitize_for_terminal(name) if name is not None else "none"
            self._print(
                f"{_II}ClientHello: {hello.legacy_version_name} | "
                f"SNI: {sni} | "
                f"Cipher suites: {len(hello.cipher_suites) // 2}"
            )
            self._print(
                f"{_II}Extensions: "
                + _capped([ext.type_name for ext in hello.extensions or ()])
            )

    @_render.register
    def _(self, layer: SCTP, frame: DecodedFrame) -> None:
        """SCTP: ports, verification tag, the CRC32c checksum verified
        (RFC 9260 §6.8; skipped inside a fragment), and the chunk types
        in wire order with their flags. Chunks parse on demand, so they
        render inside a guard."""
        self._print(f"{_I}[+] SCTP {layer.src_port} -> {layer.dst_port}")
        note = _transport_checksum_note(frame, layer)
        self._print(
            f"{_II}Verification Tag: {layer.verification_tag_hex_str} | "
            f"Checksum: {layer.checksum_hex_str}{note}"
        )
        with self._guard("Chunks"):
            chunks = [
                f"{chunk.type_name} [{chunk.flags_str}]"
                if chunk.flags_str
                else chunk.type_name
                for chunk in layer.parsed_chunks
            ]
            self._print(f"{_II}Chunks: {_capped(chunks)}")

    @_render.register
    def _(self, layer: NTP, frame: DecodedFrame) -> None:
        """NTP: version, mode and stratum; leap indicator, poll interval,
        precision and root delay/dispersion; the Reference ID, or the
        kiss code a stratum-0 message carries instead (sanitized: both
        are bytes the sender chose); the transmit time; and any NTPv4
        extension fields, MAC and unparsed remainder."""
        self._print(
            f"{_I}[+] NTP v{layer.version} {layer.mode_name} | "
            f"Stratum {layer.stratum} ({layer.stratum_name})"
        )
        self._print(
            f"{_II}Leap: {layer.leap_name} | Poll: {layer.poll_seconds:g}s | "
            f"Precision: {layer.precision_seconds:g}s | "
            f"Root delay: {layer.root_delay_seconds:g}s | "
            f"Root dispersion: {layer.root_dispersion_seconds:g}s"
        )
        with self._guard("Body"):
            if (kiss := layer.kiss_code) is not None:
                self._print(f"{_II}Kiss code: {_sanitize_for_terminal(kiss)}")
            elif reference := layer.reference_id_str:
                self._print(
                    f"{_II}Reference ID: {_sanitize_for_terminal(reference)}"
                )
            transmit = layer.transmit_time
            self._print(
                f"{_II}Transmit: "
                + (transmit.isoformat() if transmit is not None else "none")
            )
            self._render_ntp_tail(layer)

    def _render_ntp_tail(self, layer: NTP) -> None:
        """The NTPv4 extension fields, MAC and unparsed remainder of an
        NTP message, each line only when present."""
        fields = [
            f"{field.type_name} ({len(field.value)} bytes)"
            for field in layer.extension_fields
        ]
        if fields:
            self._print(f"{_II}Extension fields: {_capped(fields)}")
        if (mac := layer.mac) is not None:
            detail = (
                "crypto-NAK"
                if mac.is_crypto_nak
                else f"key {mac.key_id}, {len(mac.digest)}-byte digest"
            )
            self._print(f"{_II}MAC: {detail}")
        if layer.remainder:
            self._print(f"{_II}Unparsed: {len(layer.remainder)} bytes")

    @_render.register
    def _(self, layer: VRRP, frame: DecodedFrame) -> None:
        """VRRP (v2 and v3, IPv4 and IPv6): the message type, virtual
        router ID and priority -- 0 is a master resigning, 255 the
        address owner -- the virtual addresses, the advertisement
        interval and the checksum, verified the way RFC 3768/9568 define
        it per version. VRRPv2 adds its authentication, a ``PASS``
        password shown sanitized: it is clear text the sender chose."""
        priority = _VRRP_PRIORITY_NOTES.get(layer.priority, "")
        self._print(
            f"{_I}[+] VRRPv{layer.version} {layer.type_name} | "
            f"VRID {layer.vrid} | Priority {layer.priority}{priority}"
        )
        note = _transport_checksum_note(frame, layer)
        self._print(
            f"{_II}Addresses: {_capped(list(layer.addresses))} | "
            f"Interval: {layer.advertisement_interval:g}s | "
            f"Checksum: {layer.checksum_hex_str}{note}"
        )
        if layer.auth_type_name is not None:
            detail = (
                f" ({_secret_text(layer.auth_data)})"
                if layer.auth_type == _VRRP_AUTH_PASSWORD
                else ""
            )
            self._print(f"{_II}Auth: {layer.auth_type_name}{detail}")

    @_render.register
    def _(self, layer: HSRP, frame: DecodedFrame) -> None:
        """HSRP: op code, standby group, the sender's state and
        priority; the virtual IP and the group's virtual MAC, the timers;
        and the Authentication Data -- a clear-text password, shown
        sanitized and flagged when it is RFC 2281's default ``cisco``."""
        self._print(
            f"{_I}[+] HSRP {layer.opcode_name} | Group {layer.group} | "
            f"State {layer.state_name} | Priority {layer.priority}"
        )
        self._print(
            f"{_II}Virtual IP: {layer.virtual_ip} "
            f"(MAC {layer.virtual_mac}) | Hellotime: {layer.hellotime}s | "
            f"Holdtime: {layer.holdtime}s"
        )
        # auth_data_str already shows unprintable bytes as hex; it is
        # sanitized anyway, as every wire-chosen string here is.
        auth = _sanitize_for_terminal(layer.auth_data_str) or "(empty)"
        default = " (default)" if layer.is_default_auth else ""
        self._print(f"{_II}Auth: {auth}{default}")

    @_render.register
    def _(self, layer: RIP, frame: DecodedFrame) -> None:
        """RIP (v1/v2): command and version; a RIPv2 authentication
        entry (see :func:`_rip_auth_text`) and RFC 4822 trailer; then
        either a request for the whole table (RFC 2453 §3.9.1) or the
        routes, capped, and any bytes short of a whole entry."""
        self._print(f"{_I}[+] RIPv{layer.version} {layer.command_name}")
        with self._guard("Entries"):
            if (auth := layer.authentication) is not None:
                trailer = layer.authentication_trailer
                extra = (
                    f" | Trailer: {len(trailer)} bytes"
                    if trailer is not None
                    else ""
                )
                self._print(f"{_II}Auth: {_rip_auth_text(auth)}{extra}")
            routes = layer.routes
            if layer.command == _RIP_REQUEST and _is_whole_table_request(
                routes
            ):
                self._print(f"{_II}Request: the whole routing table")
            else:
                self._print(
                    f"{_II}Routes ({len(routes)}): "
                    + _capped([_rip_route_text(route) for route in routes])
                )
            if layer.remainder:
                self._print(f"{_II}Unparsed: {len(layer.remainder)} bytes")

    @_render.register
    def _(self, layer: OSPF, frame: DecodedFrame) -> None:
        """OSPFv2: message type, router and area; the authentication
        (a simple password sanitized, a digest by key and sequence) and
        the packet checksum, which cryptographic authentication replaces
        (RFC 2328 §D.4.3); then the message body, one helper per type
        (see :data:`_OSPF_BODIES`)."""
        backbone = " (backbone)" if layer.area_id == _UNSET_ADDRESS else ""
        self._print(
            f"{_I}[+] OSPFv{layer.version} {layer.type_name} | "
            f"Router {layer.router_id} | Area {layer.area_id}{backbone}"
        )
        if layer.au_type in OSPF.CRYPTOGRAPHIC_AU_TYPES:
            auth = (
                f"{layer.au_type_name} (key {layer.key_id}, "
                f"seq {layer.crypto_sequence_number}, "
                f"{len(layer.auth_trailer)}-byte trailer)"
            )
            checksum = "not used (cryptographic authentication)"
        else:
            auth = layer.au_type_name
            if layer.au_type == _OSPF_AUTH_PASSWORD:
                auth += f" ({_secret_text(layer.authentication)})"
            note = _transport_checksum_note(frame, layer)
            checksum = f"{layer.checksum_hex_str}{note}"
        self._print(f"{_II}Auth: {auth} | Checksum: {checksum}")
        if (body := _OSPF_BODIES.get(layer.type)) is not None:
            with self._guard(layer.type_name):
                body(self, layer)

    def _render_ospf_hello(self, layer: OSPF) -> None:
        """An OSPF Hello: mask, timers, priority and options, the
        DR/BDR election (``none`` before one), and the neighbors heard."""
        hello = layer.hello
        if hello is None:  # pragma: no cover -- dispatched on the type
            return
        self._print(
            f"{_II}Mask: {hello.network_mask} | "
            f"Hello: {hello.hello_interval}s | "
            f"Dead: {hello.router_dead_interval}s | "
            f"Priority: {hello.router_priority} | "
            f"Options: {hello.options_str or 'none'}"
        )
        self._print(
            f"{_II}DR: {_or_none(hello.designated_router)} | "
            f"BDR: {_or_none(hello.backup_designated_router)} | "
            f"Neighbors: {_capped(list(hello.neighbors))}"
        )

    def _render_ospf_dd(self, layer: OSPF) -> None:
        """An OSPF Database Description: MTU, the I/M/MS flags, the DD
        sequence number and the LSA headers it summarizes."""
        dd = layer.database_description
        if dd is None:  # pragma: no cover -- dispatched on the type
            return
        self._print(
            f"{_II}MTU: {dd.interface_mtu} | "
            f"Flags: {dd.flags_str or 'none'} | "
            f"Seq: {dd.dd_sequence_number:#010x} | "
            f"Options: {dd.options_str or 'none'}"
        )
        self._print(
            f"{_II}LSA headers ({len(dd.lsa_headers)}): "
            + _capped([_lsa_header_text(h) for h in dd.lsa_headers])
        )

    def _render_ospf_lsr(self, layer: OSPF) -> None:
        """An OSPF Link State Request: the LSAs asked for."""
        requests = layer.ls_requests or ()
        self._print(
            f"{_II}Requests ({len(requests)}): "
            + _capped(
                [
                    f"{r.ls_type_name} {r.link_state_id} "
                    f"(adv {r.advertising_router})"
                    for r in requests
                ]
            )
        )

    def _render_ospf_lsu(self, layer: OSPF) -> None:
        """An OSPF Link State Update: each LSA's header, with its LS
        Checksum verified (see :func:`_lsa_text`)."""
        lsas = layer.lsas or ()
        self._print(
            f"{_II}LSAs ({len(lsas)}): "
            + _capped([_lsa_text(lsa) for lsa in lsas])
        )

    def _render_ospf_ack(self, layer: OSPF) -> None:
        """An OSPF Link State Acknowledgment: the LSA headers it
        acknowledges (headers only: there is no LSA body to verify)."""
        headers = layer.ls_acknowledgments or ()
        self._print(
            f"{_II}Acknowledged ({len(headers)}): "
            + _capped([_lsa_header_text(h) for h in headers])
        )

    @_render.register
    def _(self, layer: PIM, frame: DecodedFrame) -> None:
        """PIM (v2, IPv4 and IPv6): message type and checksum, verified
        per RFC 7761 §4.9 (a Register's covers only its first 8 bytes),
        then the message, parsed on demand inside a guard and rendered
        by type (see :data:`_PIM_BODIES`); the types kept raw (Bootstrap,
        Candidate-RP-Advertisement, ...) show their length."""
        note = _transport_checksum_note(frame, layer)
        self._print(
            f"{_I}[+] PIMv{layer.version} {layer.type_name} | "
            f"Checksum: {layer.checksum_hex_str}{note}"
        )
        with self._guard(layer.type_name):
            message = layer.message
            if message is None:
                self._print(f"{_II}Body: {len(layer.body)} bytes, not decoded")
                return
            _PIM_BODIES[type(message)](self, message)

    def _render_pim_hello(self, hello: PIMHello) -> None:
        """A PIM Hello: the options a neighbor and DR election use, each
        shown only when present, and the sender's secondary addresses."""
        parts = []
        if hello.holdtime is not None:
            parts.append(f"Holdtime: {hello.holdtime}s")
        if hello.dr_priority is not None:
            parts.append(f"DR priority: {hello.dr_priority}")
        if hello.generation_id is not None:
            parts.append(f"Generation ID: {hello.generation_id:#010x}")
        if (delay := hello.lan_prune_delay) is not None:
            parts.append(
                f"LAN prune delay: {delay.propagation_delay}ms "
                f"(override {delay.override_interval}ms"
                f"{', T' if delay.t else ''})"
            )
        self._print(f"{_II}{' | '.join(parts) or 'No options'}")
        if (addresses := hello.address_list) is not None:
            self._print(
                f"{_II}Secondary addresses: "
                + _capped([address.address for address in addresses])
            )

    def _render_pim_register(self, register: PIMRegister) -> None:
        """A PIM Register: the Border bit and what it encapsulates (see
        :func:`_pim_register_inner`)."""
        border = " | Border" if register.border else ""
        self._print(
            f"{_II}Encapsulated: {_pim_register_inner(register)}{border}"
        )

    def _render_pim_register_stop(self, stop: PIMRegisterStop) -> None:
        """A PIM Register-Stop: the group and source to stop for."""
        group = stop.group
        self._print(
            f"{_II}Group: {group.address}/{group.mask_len} | "
            f"Source: {stop.source.address}"
        )

    def _render_pim_join_prune(self, message: PIMJoinPrune) -> None:
        """A PIM Join/Prune (also Graft and Graft-Ack): the upstream
        neighbor and holdtime, then one line per group with the sources
        joined and pruned, groups and sources both capped."""
        self._print(
            f"{_II}Upstream: {message.upstream_neighbor.address} | "
            f"Holdtime: {message.holdtime}s | Groups: {len(message.groups)}"
        )
        for group_set in message.groups[:_LIST_LIMIT]:
            group = group_set.group
            joined = _capped([_pim_source_text(s) for s in group_set.joined])
            pruned = _capped([_pim_source_text(s) for s in group_set.pruned])
            self._print(
                f"{_II}Group {group.address}/{group.mask_len}: "
                f"join {joined}; prune {pruned}"
            )
        if (extra := len(message.groups) - _LIST_LIMIT) > 0:
            self._print(f"{_II}(+{extra} more groups)")

    def _render_pim_assert(self, message: PIMAssert) -> None:
        """A PIM Assert: the (S,G) contested and the metric that wins
        it -- preference first, then metric, lower being better."""
        group = message.group
        rpt = " | RPT" if message.rpt else ""
        self._print(
            f"{_II}Group: {group.address}/{group.mask_len} | "
            f"Source: {message.source.address} | "
            f"Preference: {message.metric_preference} | "
            f"Metric: {message.metric}{rpt}"
        )

    @_render.register
    def _(self, layer: BGP, frame: DecodedFrame) -> None:
        """BGP: one section per message (a segment often carries
        several), naming the type and length, then the body by type
        (see :data:`_BGP_BODIES`). Every body accessor parses on demand
        and raises on a field that overruns, so each part renders inside
        its own guard."""
        self._print(f"{_I}[+] BGP {layer.type_name} ({layer.length} bytes)")
        if (body := _BGP_BODIES.get(layer.type)) is not None:
            body(self, layer)

    def _render_bgp_open(self, layer: BGP) -> None:
        """A BGP OPEN: version, AS, hold time, BGP Identifier and the
        optional parameters by type and size (capabilities stay raw)."""
        self._print(
            f"{_II}Version: {layer.version} | AS: {layer.my_as} | "
            f"Hold time: {layer.hold_time}s | ID: {layer.bgp_identifier}"
        )
        with self._guard("Optional parameters"):
            parameters = layer.optional_parameters or ()
            self._print(
                f"{_II}Optional parameters: "
                + _capped(
                    [
                        f"{p.type_name} ({len(p.value)} bytes)"
                        for p in parameters
                    ]
                )
            )

    def _render_bgp_update(self, layer: BGP) -> None:
        """A BGP UPDATE: withdrawn routes, path attributes and NLRI,
        each capped (see :func:`_bgp_update_lines`) and guarded; one
        with none of the three is an End-of-RIB marker for IPv4 unicast
        (RFC 4724 §2)."""
        with self._guard("UPDATE"):
            lines = _bgp_update_lines(layer)
            for line in lines or ["End-of-RIB (IPv4 unicast)"]:
                self._print(f"{_II}{line}")

    def _render_bgp_notification(self, layer: BGP) -> None:
        """A BGP NOTIFICATION: the error code and subcode, then the
        operator's shutdown communication (RFC 9003), sanitized -- free
        UTF-8 text from the peer -- or else the raw data's size."""
        subcode = layer.error_subcode_name
        self._print(
            f"{_II}Error: {layer.error_code_name}"
            + (f" / {subcode}" if subcode else "")
        )
        if (message := layer.shutdown_communication) is not None:
            self._print(f"{_II}Shutdown communication: {_inline_text(message)}")
        elif layer.error_data:
            self._print(f"{_II}Data: {len(layer.error_data)} bytes")

    @_render.register
    def _(self, layer: LLDP, frame: DecodedFrame) -> None:
        """LLDP: the Chassis ID, Port ID and Time To Live an analyst maps
        a neighbor by (0 is a shutdown LLDPDU), flagged when the LLDPDU
        does not open with them as 802.1AB requires; the System Name,
        Port Description and System Description (duplicates included),
        sanitized, kept on one line and cut -- the neighbor chose every
        byte -- and every other TLV
        by name and size. No accessor here raises."""
        chassis, port, ttl = layer.chassis_id, layer.port_id, layer.ttl
        shutdown = " (shutdown)" if layer.is_shutdown else ""
        self._print(
            f"{_I}[+] LLDP Chassis {_lldp_id_text(chassis)} | "
            f"Port {_lldp_id_text(port)} | "
            f"TTL {'n/a' if ttl is None else f'{ttl}s'}{shutdown}"
        )
        if not layer.has_mandatory_tlvs:
            self._print(
                f"{_II}[!] Does not open with Chassis ID, Port ID and Time "
                f"to Live (802.1AB): receivers discard it"
            )
        for label, tlv_type in _LLDP_TEXT_TLVS:
            # Every one, not just the first: a duplicate is out of spec
            # (lldpd drops it, Wireshark flags it), so it is shown too.
            for tlv in layer.tlvs:
                if tlv.type == tlv_type:
                    self._print(f"{_II}{label}: {_wire_text(tlv.value)}")
        others = [
            _lldp_tlv_text(tlv)
            for tlv in layer.tlvs
            if tlv.type not in _LLDP_SHOWN_TLVS
        ]
        if others:
            self._print(f"{_II}Other TLVs: {_capped(others)}")

    @_render.register
    def _(self, layer: CDP, frame: DecodedFrame) -> None:
        """CDP: version, TTL and the checksum, verified over the whole
        PDU; the Device ID, Port ID and Platform, then the Software
        Version, each sanitized, kept on one line and cut (a neighbor's
        free text); the capabilities and addresses; and every other TLV
        by name. No accessor here raises."""
        note = _checksum_note(layer)
        self._print(
            f"{_I}[+] CDPv{layer.version} | TTL {layer.ttl}s | "
            f"Checksum: {layer.checksum_hex_str}{note}"
        )
        identity = [
            f"{label}: {_cut(_inline_text(text))}"
            for label, text in (
                ("Device ID", layer.device_id),
                ("Port ID", layer.port_id),
                ("Platform", layer.platform),
            )
            if text is not None
        ]
        if identity:
            self._print(f"{_II}{' | '.join(identity)}")
        if (software := layer.software_version) is not None:
            self._print(f"{_II}Software: {_cut(_inline_text(software))}")
        self._print(
            f"{_II}Capabilities: {_capped(list(layer.capability_names))} | "
            f"Addresses: {_cdp_addresses_text(layer.addresses)} | "
            f"Management: {_cdp_addresses_text(layer.management_addresses)}"
        )
        others = [
            f"{tlv.type_name} ({len(tlv.value)} bytes)"
            for tlv in layer.tlvs
            if tlv.type not in _CDP_SHOWN_TLVS
        ]
        if others:
            self._print(f"{_II}Other TLVs: {_capped(others)}")

    @_render.register
    def _(self, layer: STP, frame: DecodedFrame) -> None:
        """STP/RSTP: the BPDU type and protocol version; for a
        Configuration or RST BPDU the root and bridge identifiers, root
        path cost and port, the flags (an RST BPDU's port role and
        proposal/agreement handshake among them), and the four timers. A
        Topology Change Notification has none of those fields."""
        self._print(
            f"{_I}[+] STP {layer.bpdu_type_name} ({layer.version_name})"
        )
        if layer.root_id_str is None:
            return
        self._print(
            f"{_II}Root: {layer.root_id_str} | "
            f"Cost: {layer.root_path_cost} | "
            f"Bridge: {layer.bridge_id_str} | "
            f"Port: {layer.port_priority}.{layer.port_number}"
        )
        self._print(f"{_II}Flags: {_stp_flags_text(layer)}")
        self._print(
            f"{_II}Message age: {layer.message_age_seconds:g}s | "
            f"Max age: {layer.max_age_seconds:g}s | "
            f"Hello: {layer.hello_time_seconds:g}s | "
            f"Forward delay: {layer.forward_delay_seconds:g}s"
        )

    @_render.register
    def _(self, layer: MPLS, frame: DecodedFrame) -> None:
        """MPLS: the label stack, top first, each entry's label (named
        when it is a special-purpose one, such as the Entropy Label
        Indicator), traffic class and TTL, the bottom one marked; and
        the payload the stack's bottom implies, when it implies one."""
        labels = [_mpls_label_text(entry) for entry in layer.labels]
        self._print(
            f"{_I}[+] MPLS ({len(labels)} label"
            f"{'' if len(labels) == 1 else 's'}): {_capped(labels)}"
        )
        if (payload := layer.payload_ethertype) is not None:
            self._print(f"{_II}Payload: {payload.display_name}")

    @_render.register
    def _(self, layer: LLC, frame: DecodedFrame) -> None:
        """IEEE 802.2 LLC: DSAP and SSAP by name, their group and
        command/response bits, and the control field's format; or
        Novell's raw 802.3, whose IPX header begins where an LLC header
        would."""
        if layer.is_raw_ipx:
            self._print(f"{_I}[+] Novell raw 802.3 (IPX, no LLC header)")
            return
        group = " (group)" if layer.is_group else ""
        role = "response" if layer.is_response else "command"
        self._print(
            f"{_I}[+] LLC DSAP {layer.dsap:#04x} ({layer.dsap_name}){group}"
            f" -> SSAP {layer.ssap:#04x} ({layer.ssap_name})"
        )
        self._print(
            f"{_II}Control: {layer.control:#04x} "
            f"({layer.control_format}-format {role})"
        )

    @_render.register
    def _(self, layer: SNAP, frame: DecodedFrame) -> None:
        """SNAP: the OUI and the protocol ID, named as an EtherType when
        the OUI makes it one (RFC 1042's 00-00-00, 802.1H's 00-00-F8)."""
        pid = f"{layer.pid:#06x}"
        if layer.carries_ethertype:
            pid += f" ({_ethertype_name(layer.pid)})"
        self._print(f"{_I}[+] SNAP OUI {layer.oui_str} | PID {pid}")

    @_render.register
    def _(self, layer: VXLAN, frame: DecodedFrame) -> None:
        """VXLAN: the VNI and the flags, the I flag named; reserved bits
        that are set (RFC 7348 §5 sends them as zero and has receivers
        ignore them) are noted. The inner Ethernet frame renders as its
        own layers."""
        i_flag = " (I)" if layer.flags & VXLAN.I_FLAG else ""
        self._print(
            f"{_I}[+] VXLAN VNI {layer.vni} | Flags {layer.flags:#04x}{i_flag}"
        )
        reserved_flags = layer.flags & ~VXLAN.I_FLAG
        if reserved_flags or layer.reserved1 or layer.reserved2:
            self._print(
                f"{_II}[~] Reserved bits set: flags {reserved_flags:#04x}, "
                f"{layer.reserved1:#08x}, {layer.reserved2:#04x} "
                f"(zero on transmit, RFC 7348 §5)"
            )

    @_render.register
    def _(self, layer: ESP, frame: DecodedFrame) -> None:
        """ESP: the SPI and sequence number, which are all ESP sends in
        the clear, and the size of the protected rest. Its Next Header
        sits inside that rest, at an offset only the SA knows, so the
        walk (and this renderer) stop here."""
        self._print(
            f"{_I}[+] ESP SPI {layer.spi_hex_str} | Seq {layer.sequence_number}"
        )
        self._print(
            f"{_II}Protected payload: {len(layer.ciphertext)} bytes "
            f"(IV, data, padding, trailer and ICV; not decoded)"
        )

    @_render.register
    def _(self, layer: AH, frame: DecodedFrame) -> None:
        """AH, in an IPv4 chain or (:class:`~netprotocols.AHv6`, a
        subclass) an IPv6 one: the SPI, sequence number and what it
        protects, tunnel mode named when that is a whole IP packet, and
        the ICV's size -- never verified, which needs the SA's key."""
        tunnel = " (tunnel mode)" if layer.next_header in _IP_IN_IP else ""
        self._print(
            f"{_I}[+] AH SPI {layer.spi_hex_str} | "
            f"Seq {layer.sequence_number} | "
            f"Next: {layer.next_header_name}{tunnel}"
        )
        self._print(
            f"{_II}ICV: {len(layer.icv)} bytes (not verified) | "
            f"Header: {layer.header_len} bytes"
        )

    @_render.register
    def _(self, layer: TFTP, frame: DecodedFrame) -> None:
        """TFTP: the opcode and its fields -- a request's filename and
        mode, a DATA's or ACK's block (and a DATA's size), an ERROR's
        code, name and message -- and a request's or OACK's options.
        The client chose the filename, mode and options and the sender
        the message, so each is sanitized, kept on one line and cut. No
        accessor here raises."""
        summary = _tftp_summary(layer)
        self._print(f"{_I}[+] TFTP {layer.opcode_name}{summary}")
        if layer.options:
            options = [
                f"{_cut(_inline_text(name))}={_cut(_inline_text(value))}"
                for name, value in layer.options
            ]
            self._print(f"{_II}Options: {_capped(options)}")

    @_render.register
    def _(self, layer: RADIUS, frame: DecodedFrame) -> None:
        """RADIUS: code, identifier and length, the Authenticator, then
        the attributes, parsed once and guarded (a malformed Length
        raises): each text attribute (User-Name, Reply-Message, the
        station IDs, ...) on its own line, sanitized, on one line and
        cut, and every other attribute by name, with its value when it
        is an address or a number and its size otherwise. User-Password
        and CHAP-Password are hidden with the shared secret; only their
        size is shown."""
        self._print(
            f"{_I}[+] RADIUS {layer.code_name} (ID {layer.identifier}) | "
            f"Length {layer.length}"
        )
        self._print(f"{_II}Authenticator: {layer.authenticator.hex()}")
        with self._guard("RADIUS attributes"):
            attributes = layer.parsed_attributes
            texts = [
                attribute
                for attribute in attributes
                if attribute.type in _RADIUS_TEXT_ATTRIBUTES
            ]
            # One line each, capped like a list line: one 4096-byte
            # packet can hold some 2,000 empty Reply-Messages.
            for attribute in texts[:_LIST_LIMIT]:
                self._print(
                    f"{_II}{attribute.type_name}: "
                    f"{_radius_text(attribute.data)}"
                )
            if (extra := len(texts) - _LIST_LIMIT) > 0:
                self._print(f"{_II}(+{extra} more text attributes)")
            others = [
                _radius_attribute_text(attribute)
                for attribute in attributes
                if attribute.type not in _RADIUS_TEXT_ATTRIBUTES
            ]
            if others:
                self._print(f"{_II}Attributes: {_capped(others)}")

    @_render.register
    def _(self, layer: HTTP, frame: DecodedFrame) -> None:
        """HTTP/1.x, reached only through ``--decode-as`` (NETProtocols
        registers it on no port): the start line; the Host, User-Agent,
        Referer, Content-Type, Server and Location fields, then every
        field by name; the body's framing and size, never its bytes;
        and the anomalies the grammar resolved, those that let two
        parsers disagree on where a message ends (request smuggling)
        flagged ``[!]``. Every byte of the head is the sender's, read
        as latin-1, so each value is sanitized -- a lone 0x9B is a C1
        CSI -- kept on one line and cut. When bytes follow the message
        in the frame (a pipelined request, the start of the next
        response) a ``[~]`` line counts them: the walk does not chain
        HTTP messages. No accessor here raises."""
        self._print(f"{_I}[+] HTTP {_http_start_line(layer)}")
        for name in _HTTP_SHOWN_FIELDS:
            # Every occurrence up to the list limit, then a count: one
            # head can repeat a field thousands of times.
            values = layer.header_values(name)
            for value in values[:_LIST_LIMIT]:
                self._print(f"{_II}{name}: {_cut(_inline_text(value))}")
            if (extra := len(values) - _LIST_LIMIT) > 0:
                self._print(f"{_II}(+{extra} more {name})")
        names = [_cut(_inline_text(field.name)) for field in layer.fields]
        if names:
            self._print(f"{_II}Fields: {_capped(names)}")
        self._print(f"{_II}Body: {_http_body_text(layer)}")
        smuggling, other = _http_anomalies(layer.anomalies)
        if smuggling:
            self._print(f"{_II}[!] Framing anomalies: {_capped(smuggling)}")
        if other:
            self._print(f"{_II}[~] Anomalies: {_capped(other)}")
        if layer is frame.layers[-1] and frame.payload:
            self._print(
                f"{_II}[~] {len(frame.payload)} more bytes follow this "
                f"message (a pipelined message or a later one's start; "
                f"not decoded)"
            )

    @_render.register
    def _(self, layer: STUN, frame: DecodedFrame) -> None:
        """STUN: the method and class, the Transaction ID and the
        FINGERPRINT, verified (a misplaced one flagged); the mapped
        addresses, ERROR-CODE, SOFTWARE, UNKNOWN-ATTRIBUTES and whether
        MESSAGE-INTEGRITY is present (it needs the credential's key to
        verify); and every attribute by name. The sender chose the
        SOFTWARE and the error's reason phrase, so both are sanitized,
        kept on one line and cut. Those accessors never raise; the full
        attribute list parses on demand and is guarded."""
        self._print(
            f"{_I}[+] STUN {layer.message_type_name} | "
            f"Transaction {layer.transaction_id.hex()} | "
            f"Fingerprint: {_stun_fingerprint_text(layer)}"
        )
        for line in _stun_detail_lines(layer):
            self._print(f"{_II}{line}")
        with self._guard("STUN attributes"):
            names = [
                attribute.type_name for attribute in layer.parsed_attributes
            ]
            if names:
                self._print(f"{_II}Attributes: {_capped(names)}")


#: Annotations for the VRRP priorities with a meaning of their own
#: (RFC 3768 §5.3.4, RFC 5798 §5.2.4).
_VRRP_PRIORITY_NOTES = {0: " (master resigning)", 255: " (address owner)"}

#: VRRPv2's Simple Text Password Auth Type, and OSPF's simple password
#: AuType: both put the password in the clear.
_VRRP_AUTH_PASSWORD = 1
_OSPF_AUTH_PASSWORD = 1

#: OSPF message type -> the renderer for its body.
_OSPF_BODIES: dict[int, Callable[[OutputToScreen, OSPF], None]] = {
    1: OutputToScreen._render_ospf_hello,
    2: OutputToScreen._render_ospf_dd,
    3: OutputToScreen._render_ospf_lsr,
    4: OutputToScreen._render_ospf_lsu,
    5: OutputToScreen._render_ospf_ack,
}

#: Parsed PIM message class -> its renderer. Graft and Graft-Ack parse
#: as PIMJoinPrune, so every class :attr:`PIM.message` returns is here.
_PIM_BODIES: dict[type, Callable[[OutputToScreen, Any], None]] = {
    PIMHello: OutputToScreen._render_pim_hello,
    PIMRegister: OutputToScreen._render_pim_register,
    PIMRegisterStop: OutputToScreen._render_pim_register_stop,
    PIMJoinPrune: OutputToScreen._render_pim_join_prune,
    PIMAssert: OutputToScreen._render_pim_assert,
}

#: BGP message type -> the renderer for its body. KEEPALIVE has none and
#: a ROUTE-REFRESH body stays raw, so neither is listed.
_BGP_BODIES: dict[int, Callable[[OutputToScreen, BGP], None]] = {
    1: OutputToScreen._render_bgp_open,
    2: OutputToScreen._render_bgp_update,
    3: OutputToScreen._render_bgp_notification,
}


#: Most bytes of a raw BGP path attribute value shown in hex: one
#: attribute can be up to 65,535 bytes long (an AS_PATH, COMMUNITIES or
#: an attribute this library keeps raw), far past one readable line.
_BGP_VALUE_PREVIEW = 32


def _bgp_attribute_text(attribute: BGPPathAttribute) -> str:
    """One path attribute as ``"NAME value"``: the decoded value for the
    types the library decodes (ORIGIN, NEXT_HOP, MED, LOCAL_PREF), else
    the raw value in hex, its first :data:`_BGP_VALUE_PREVIEW` bytes
    only when it is longer, then how many bytes were left out and the
    full length, in :func:`_capped`'s ``(+N more)`` style."""
    if attribute.value is not None:
        return f"{attribute.type_name} {attribute.value_text}"
    data = attribute.data
    if not data:
        return f"{attribute.type_name} (empty)"
    if len(data) <= _BGP_VALUE_PREVIEW:
        return f"{attribute.type_name} {data.hex()}"
    preview = data[:_BGP_VALUE_PREVIEW].hex()
    omitted = len(data) - _BGP_VALUE_PREVIEW
    return (
        f"{attribute.type_name} {preview}... "
        f"(+{omitted} more bytes, {len(data)} in all)"
    )


def _bgp_update_lines(layer: BGP) -> list[str]:
    """The withdrawn-routes, path-attributes and NLRI lines of a BGP
    UPDATE, each only when that part is non-empty, each list capped:
    one UPDATE can carry hundreds of prefixes.

    :raises ProtocolError: if a part overruns the message; the caller
        renders this inside a guard.
    """
    withdrawn = layer.withdrawn_routes or ()
    attributes = layer.path_attributes or ()
    nlri = layer.nlri or ()
    parts = (
        (f"Withdrawn ({len(withdrawn)})", [str(p.network) for p in withdrawn]),
        (
            "Attributes",
            [_bgp_attribute_text(a) for a in attributes],
        ),
        (f"NLRI ({len(nlri)})", [str(p.network) for p in nlri]),
    )
    return [f"{label}: {_capped(items)}" for label, items in parts if items]


#: Most characters a free-text field (an LLDP System Description, a CDP
#: Software Version) shows: either can run to hundreds of bytes, most
#: of them a vendor banner.
_TEXT_LIMIT = 128


def _cut(text: str) -> str:
    """*text*, cut at :data:`_TEXT_LIMIT` characters with a count of
    the rest, in :func:`_capped`'s ``(+N more)`` style."""
    if len(text) <= _TEXT_LIMIT:
        return text
    return f"{text[:_TEXT_LIMIT]}... (+{len(text) - _TEXT_LIMIT} more chars)"


def _wire_text(value: bytes) -> str:
    """A TLV's bytes as display text: ASCII, any other byte shown as
    ``\\xNN``, sanitized and on one line (see :func:`_inline_text`),
    and cut (see :func:`_cut`)."""
    return _cut(_inline_text(value.decode("ascii", errors="backslashreplace")))


#: LLDP's Chassis ID and Port ID subtypes that carry a MAC address.
_LLDP_MAC_SUBTYPES = frozenset({"MAC address"})


def _lldp_id_text(identifier: LLDPChassisID | LLDPPortID | None) -> str:
    """An LLDP Chassis ID or Port ID as ``"MAC address 02:..:0a"`` or
    ``"Interface name eth0"``: a 6-byte MAC subtype as a MAC, anything
    else as text (see :func:`_wire_text`); ``"n/a"`` when the TLV is
    missing or misplaced."""
    if identifier is None:
        return "n/a"
    raw = identifier.id
    if identifier.subtype_name in _LLDP_MAC_SUBTYPES and len(raw) == 6:
        return f"{identifier.subtype_name} {raw.hex(':')}"
    return f"{identifier.subtype_name} {_wire_text(raw)}"


#: The LLDP text TLVs shown on their own lines, by label and type.
_LLDP_TEXT_TLVS = (
    ("System Name", 5),
    ("Port Description", 4),
    ("System Description", 6),
)

#: LLDP TLV types already shown, left out of the "Other TLVs" line:
#: End, Chassis ID, Port ID, Time to Live and the text TLVs.
_LLDP_SHOWN_TLVS = frozenset({0, 1, 2, 3, 4, 5, 6})

#: LLDP's Organizationally Specific TLV type.
_LLDP_ORG_SPECIFIC = 127


def _lldp_tlv_text(tlv: LLDPTLV) -> str:
    """One LLDP TLV for the "Other TLVs" line: its name and size, and
    for an Organizationally Specific TLV its OUI and subtype, which
    say whose extension it is (IEEE 802.1, 802.3, a vendor's)."""
    if tlv.type == _LLDP_ORG_SPECIFIC and len(tlv.value) >= 4:
        oui = tlv.value[:3].hex("-")
        return f"OUI {oui} subtype {tlv.value[3]} ({len(tlv.value)} bytes)"
    return f"{tlv.type_name} ({len(tlv.value)} bytes)"


#: CDP TLV types already shown, left out of the "Other TLVs" line:
#: Device ID, Addresses, Port ID, Capabilities, Software Version,
#: Platform and Management Address.
_CDP_SHOWN_TLVS = frozenset({1, 2, 3, 4, 5, 6, 22})


def _cdp_addresses_text(addresses: tuple[CDPAddress, ...] | None) -> str:
    """A CDP address list: each IPv4/IPv6 address as text, any other
    protocol by its protocol type, capped; ``"none"`` when absent."""
    if not addresses:
        return "none"
    return _capped(
        [
            address.ip
            if address.ip is not None
            else f"{address.protocol_type_name} ({len(address.address)} bytes)"
            for address in addresses
        ]
    )


def _stp_flags_text(layer: STP) -> str:
    """The flags of a Configuration or RST BPDU: Topology Change and its
    Acknowledgment, and an RST BPDU's port role and its proposal,
    learning, forwarding and agreement bits; ``"none"`` when clear."""
    bits = [
        name
        for name, value in (
            ("TC", layer.topology_change),
            ("TCA", layer.topology_change_ack),
            ("Proposal", layer.proposal),
            ("Learning", layer.learning),
            ("Forwarding", layer.forwarding),
            ("Agreement", layer.agreement),
        )
        if value
    ]
    if layer.port_role_name is not None:
        bits.insert(0, f"Role {layer.port_role_name}")
    return ", ".join(bits) or "none"


def _mpls_label_text(entry: MPLSLabel) -> str:
    """One MPLS label stack entry as ``"16001 (TC 5, TTL 64)"``, a
    special-purpose label by name too, the bottom of the stack marked
    ``[S]``."""
    name = f" {entry.label_name}" if entry.label_name else ""
    bottom = " [S]" if entry.bottom_of_stack else ""
    return (
        f"{entry.label}{name} (TC {entry.traffic_class}, TTL {entry.ttl})"
        f"{bottom}"
    )


def _ethertype_name(value: int) -> str:
    """*value*'s EtherType display name (``"IPv4"``), or ``"unknown"``."""
    try:
        return EtherType(value).display_name
    except ValueError:
        return "unknown"


def _is_whole_table_request(routes: tuple[RIPEntry, ...]) -> bool:
    """Whether *routes* is RFC 2453 §3.9.1's request for the whole
    routing table: exactly one entry, address family 0, metric 16."""
    return (
        len(routes) == 1
        and routes[0].afi == 0
        and routes[0].metric == _RIP_INFINITY
    )


#: The Next Header values that make AH (or any IP header) carry a whole
#: IP packet: IPv4 (4) and IPv6 (41) encapsulation -- tunnel mode.
_IP_IN_IP = frozenset({4, 41})


def _tftp_summary(layer: TFTP) -> str:
    """The fields after a TFTP opcode on its header line, with a leading
    space: ``" boot.bin (octet)"``, ``" block 3 (512 bytes)"``,
    ``" block 3"``, ``" 1 (File not found): no such file"``; ``""``
    for an OACK, whose options have a line of their own."""
    if layer.filename is not None:
        mode = _cut(_inline_text(layer.mode or ""))
        return f" {_cut(_inline_text(layer.filename))} ({mode})"
    if layer.data is not None:
        return f" block {layer.block} ({len(layer.data)} bytes)"
    if layer.block is not None:
        return f" block {layer.block}"
    if layer.error_code is not None:
        message = _cut(_inline_text(layer.error_message or ""))
        return f" {layer.error_code} ({layer.error_name}): {message}"
    return ""


#: The HTTP fields shown on lines of their own, every occurrence: what
#: an analyst triages a request or response on. Credentials
#: (Authorization, Cookie) are named on the "Fields" line only; ``-d``
#: shows the raw head.
_HTTP_SHOWN_FIELDS = (
    "Host",
    "User-Agent",
    "Referer",
    "Content-Type",
    "Server",
    "Location",
)

#: The HTTP anomalies that make a message's end ambiguous -- the ones a
#: request-smuggling or response-splitting attack rests on (RFC 9112
#: §6.3, §11.2): conflicting or malformed Content-Length and
#: Transfer-Encoding, framing fields where they do not belong, and a
#: Host two parsers could read differently.
_HTTP_FRAMING_ANOMALIES = frozenset(
    {
        HTTPAnomalyKind.CL_AND_TE,
        HTTPAnomalyKind.CONTENT_LENGTH_REPEATED,
        HTTPAnomalyKind.INVALID_CONTENT_LENGTH,
        HTTPAnomalyKind.CONTENT_LENGTH_UNRECOVERABLE,
        HTTPAnomalyKind.TE_PARAMETERS,
        HTTPAnomalyKind.TE_INVALID_OCTET,
        HTTPAnomalyKind.TE_CHUNKED_REPEATED,
        HTTPAnomalyKind.TE_IN_HTTP10,
        HTTPAnomalyKind.REQUEST_FRAMING_UNDETERMINABLE,
        HTTPAnomalyKind.RESPONSE_TE_NOT_CHUNKED,
        HTTPAnomalyKind.FRAMING_FIELD_MISPLACED,
        HTTPAnomalyKind.CONNECTION_LISTS_FRAMING_FIELD,
        HTTPAnomalyKind.WHITESPACE_BEFORE_COLON,
        HTTPAnomalyKind.CHUNK_EXTENSION_INVALID,
        HTTPAnomalyKind.HOST_AMBIGUOUS,
        HTTPAnomalyKind.HOST_DUPLICATE,
    }
)


def _http_start_line(layer: HTTP) -> str:
    """An HTTP message's start line for its header line:
    ``"GET /hello (HTTP/1.1)"`` or ``"200 OK (HTTP/1.1)"``, each part
    sanitized, on one line and cut."""
    if layer.is_response:
        parts = [str(layer.status_code), layer.reason_phrase or ""]
    else:
        parts = [layer.method or "", layer.target or ""]
    shown = " ".join(_cut(_inline_text(part)) for part in parts if part)
    return f"{shown} ({_cut(_inline_text(layer.http_version))})"


def _http_body_text(layer: HTTP) -> str:
    """An HTTP body's framing and size: ``"42 bytes (content_length)"``,
    ``"none"``, a chunked body's size without its framing and its
    trailer count."""
    framing = layer.framing.value
    if framing == "none":
        return "none"
    text = f"{len(layer.content)} bytes ({framing})"
    if trailers := layer.trailers:
        text += (
            f", {len(trailers)} trailer field{'s' if len(trailers) > 1 else ''}"
        )
    return text


def _http_anomaly_text(anomaly: HTTPAnomaly) -> str:
    """One HTTP anomaly: its kind, the field it is in (sanitized: the
    sender named it) and how often it occurred, e.g.
    ``"cl_and_te (content-length)"`` or ``"obs_fold (x-a) x3"``."""
    text = anomaly.kind.value
    if anomaly.field is not None:
        text += f" ({_cut(_inline_text(anomaly.field))})"
    if anomaly.occurrences > 1:
        text += f" x{anomaly.occurrences}"
    return text


def _http_anomalies(
    anomalies: tuple[HTTPAnomaly, ...],
) -> tuple[list[str], list[str]]:
    """*anomalies* as text, split into the framing anomalies (see
    :data:`_HTTP_FRAMING_ANOMALIES`) and the rest."""
    framing: list[str] = []
    other: list[str] = []
    for anomaly in anomalies:
        bucket = framing if anomaly.kind in _HTTP_FRAMING_ANOMALIES else other
        bucket.append(_http_anomaly_text(anomaly))
    return framing, other


#: RADIUS attribute types whose Value is text (RFC 2865 §5, RFC 2866
#: §5.5): User-Name, Reply-Message, Called-Station-Id,
#: Calling-Station-Id, NAS-Identifier and Acct-Session-Id.
_RADIUS_TEXT_ATTRIBUTES = frozenset({1, 18, 30, 31, 32, 44})


def _radius_text(data: bytes) -> str:
    """A RADIUS text attribute's Value for display: UTF-8 (RFC 2865 §5),
    any undecodable byte shown as ``\\xNN``, sanitized, on one line and
    cut -- the NAS or the user chose every byte."""
    return _cut(_inline_text(data.decode("utf-8", errors="backslashreplace")))


def _radius_attribute_text(attribute: RADIUSAttribute) -> str:
    """One non-text RADIUS attribute for the "Attributes" line: its name
    and value when NETProtocols reads it as an address or a number
    (``"NAS-Port 7"``), its name and size otherwise -- a User-Password
    or CHAP-Password included, hidden with the shared secret."""
    value = attribute.value
    if isinstance(value, (ipaddress.IPv4Address, int)):
        return f"{attribute.type_name} {value}"
    return f"{attribute.type_name} ({len(attribute.data)} bytes)"


#: The size of a STUN FINGERPRINT's value: a CRC-32.
_STUN_FINGERPRINT_LEN = 4


def _stun_fingerprint_text(layer: STUN) -> str:
    """A STUN message's FINGERPRINT as hex, flagged when it does not
    verify (see :func:`_checksum_note`); a FINGERPRINT that is not the
    last attribute, which RFC 8489 §14.7 does not define and receivers
    reject, flagged as misplaced, and one whose value is not 4 bytes
    flagged as invalid (NETProtocols cannot compute the value either
    should have); ``"none"`` without one."""
    if (fingerprint := layer.fingerprint) is not None:
        return f"{fingerprint:#010x}{_checksum_note(layer)}"
    if (found := layer.attribute(STUN.FINGERPRINT)) is None:
        return "none"
    if len(found.value) != _STUN_FINGERPRINT_LEN:
        return f"[!] invalid ({len(found.value)} bytes, not 4, RFC 8489 §14.7)"
    return "[!] misplaced (not the last attribute, RFC 8489 §14.7)"


def _stun_address_text(address: STUNAddress) -> str:
    """A STUN address and port: ``"10.0.0.1:3478"``, or
    ``"[2001:db8::1]:3478"`` for IPv6."""
    if address.family_name == "IPv6":
        return f"[{address.address}]:{address.port}"
    return f"{address.address}:{address.port}"


def _stun_detail_lines(layer: STUN) -> list[str]:
    """The STUN attribute lines that NETProtocols reads without raising:
    the mapped addresses, ERROR-CODE (its reason sanitized, on one line
    and cut, and an out-of-range code shown as invalid), SOFTWARE
    (likewise), UNKNOWN-ATTRIBUTES' types, and MESSAGE-INTEGRITY's
    presence."""
    lines: list[str] = []
    addresses = [
        f"{label}: {_stun_address_text(address)}"
        for label, address in (
            ("XOR-Mapped", layer.xor_mapped_address),
            ("Mapped", layer.mapped_address),
        )
        if address is not None
    ]
    if addresses:
        lines.append(" | ".join(addresses))
    if (reason := layer.error_reason) is not None:
        code = layer.error_code
        lines.append(
            f"Error: {'invalid code' if code is None else code} "
            f"{_cut(_inline_text(reason))}"
        )
    if (software := layer.software) is not None:
        lines.append(f"Software: {_cut(_inline_text(software))}")
    if unknown := layer.unknown_attributes:
        kinds = [f"{kind:#06x}" for kind in unknown]
        lines.append(f"Unknown attributes: {_capped(kinds)}")
    if layer.message_integrity is not None:
        lines.append("Message-Integrity: present (HMAC-SHA1, not verified)")
    return lines


class OutputToPcap(Output):
    """Write every frame's exact captured bytes to a classic pcap file.

    :param path: Destination file, created (or overwritten) on
        construction.
    """

    def __init__(self, path: str) -> None:
        self._writer = PcapWriter(path)

    def update(self, frame: DecodedFrame) -> None:
        self._writer.write(frame.raw, frame.timestamp)

    def close(self) -> None:
        self._writer.close()


def _json_default(value: Any) -> Any:
    """``json.dumps`` fallback for the values a layer's fields hold.

    ``dataclasses.asdict`` recurses into nested dataclasses, lists and
    tuples, so a non-JSON value can sit at any depth: LLDP's and CDP's
    TLV tuples hold raw ``bytes`` values two levels down, for example,
    and LLDP is decoded by default (EtherType 0x88CC). ``json.dumps``
    calls this hook at whatever depth it meets such a value, which a
    top-level-only conversion cannot do.

    - ``bytes``/``bytearray``/``memoryview`` → lowercase hex, as at the
      top level before.
    - An :class:`enum.Enum` → its ``value`` (an ``IntEnum`` already
      encodes as its int and never reaches here).
    - ``ipaddress`` objects → their string form.
    - ``set``/``frozenset`` → a sorted list, for stable output.
    - Anything else → ``str(value)``, with a one-time warning on stderr
      per type (:func:`_warn_unencodable`): an output must never kill a
      capture over a field type a future NETProtocols release adds, but
      it must not hide it either.
    """
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value).hex()
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(
        value,
        ipaddress.IPv4Address
        | ipaddress.IPv6Address
        | ipaddress.IPv4Network
        | ipaddress.IPv6Network,
    ):
        return str(value)
    if isinstance(value, set | frozenset):
        return sorted(value, key=repr)
    _warn_unencodable(type(value))
    return str(value)


#: Types :func:`_json_default` has already warned about, so a field type
#: that appears in every frame warns once, not once per frame.
_WARNED_TYPES: set[type] = set()


def _warn_unencodable(kind: type) -> None:
    """Say once on stderr that a field type has no JSON encoding and is
    being emitted as its ``str()`` form.

    The fallback keeps the capture alive, but silently: a consumer would
    see an opaque string such as ``<object object at 0x...>`` and no one
    would know a NETProtocols release had added a type this module
    should encode properly. stderr already carries ``--json`` mode's
    banner and statistics, so stdout stays pure NDJSON.
    """
    if kind in _WARNED_TYPES:
        return
    _WARNED_TYPES.add(kind)
    print(
        f"[!] NDJSON: no JSON encoding for {kind.__module__}."
        f"{kind.__qualname__}; emitting its str() form",
        file=sys.stderr,
    )


def _layer_record(layer: Protocol) -> dict[str, Any]:
    """One layer as a JSON-ready mapping: ``"type"`` (the class name)
    first, then the dataclass fields.

    ``"type"`` is the record's discriminator, so it always holds the
    class name. A layer with a wire field of its own called ``type``
    (ICMPv4/ICMPv6, IGMP, BGP, OSPF, PIM, VRRP) emits that field as
    ``"type_"`` instead; spreading the fields over the discriminator
    used to replace ``"ICMPv4"`` with the message type number.
    Underscored fields are decode context the library keeps beside the
    wire fields (BGP's ``_followed``), not data, and are left out.
    """
    # Every concrete Protocol is a dataclass; the ABC itself is not,
    # hence the cast.
    fields = dataclasses.asdict(cast(Any, layer))
    record: dict[str, Any] = {"type": type(layer).__name__}
    for key, value in fields.items():
        if key.startswith("_"):
            continue
        record["type_" if key == "type" else key] = value
    return record


class OutputToNDJSON(Output):
    """Emit one JSON object per frame, newline-delimited.

    Layer fields come straight from the dataclasses, nested values
    included (``bytes`` hex-encoded at any depth; see
    :func:`_json_default`); the raw payload is deliberately omitted —
    its length is reported as ``payload_len``, and the frame's trailer
    (padding, FCS) as ``trailer_len``. ``l7_miss`` carries the reason a
    port-dispatched application decoder declined the payload, or
    ``null``, and ``sni_peek`` the SNI host name of a ClientHello split
    across segments (see :attr:`DecodedFrame.sni_peek`), or ``null``.
    Lines are flushed as they are
    written so the output pipes cleanly into consumers like ``jq``.

    :param stream: Destination stream; defaults to stdout.
    """

    def __init__(self, stream: IO[str] | None = None) -> None:
        self._stream = stream if stream is not None else sys.stdout

    def update(self, frame: DecodedFrame) -> None:
        """Serialize *frame* as one compact JSON object and flush it, so a
        downstream consumer such as ``jq`` sees each frame as it arrives."""
        record = {
            "number": frame.number,
            "timestamp": frame.timestamp,
            "interface": frame.interface,
            "length": frame.length,
            "truncated": frame.truncated,
            "malformed_length": frame.malformed_length,
            "error": frame.error,
            "l7_miss": frame.l7_miss,
            "payload_len": len(frame.payload),
            "trailer_len": len(frame.trailer),
            "sni_peek": frame.sni_peek,
            "layers": [_layer_record(layer) for layer in frame.layers],
        }
        print(
            json.dumps(record, separators=(",", ":"), default=_json_default),
            file=self._stream,
            flush=True,
        )


#: Innermost-layer classes counted by name in the statistics report.
_STATS_BUCKETS = (TCP, UDP, SCTP, ICMPv4, ICMPv6, ARP)

#: Most conversations the summary tracks. Every new 5-tuple costs an
#: entry, and a scan or a spoofed flood mints one per frame: past this
#: many, frames of conversations not yet seen are counted, not tracked.
_FLOW_LIMIT = 65_536

#: Conversations the summary lists, largest by bytes first.
_FLOW_SHOWN = 10

#: Transport names for a :class:`~netprotocols.flow.FlowKey`'s protocol.
_FLOW_PROTOCOLS = {6: "TCP", 17: "UDP", 132: "SCTP"}


def _frame_flow_key(frame: DecodedFrame) -> FlowKey | None:
    """The conversation *frame* belongs to, or ``None`` when it has none.

    The conversation is the innermost IP datagram's: the last IPv4/IPv6
    header and the TCP, UDP or SCTP header after it, keyed by
    :func:`netprotocols.flow.flow_key`, the same for both directions,
    with the Routing header in between applied (see
    :func:`_enclosing_ip`). A tunnelled frame therefore counts towards
    the conversation inside the tunnel -- IP-in-IP, GRE, AH tunnel mode,
    VXLAN; ESP encrypts its inner datagram, so the walk ends there: ESP
    straight over IP has no conversation, and UDP-encapsulated ESP
    (NAT-T, decoded with ``--decode-as udp.port=4500:ESP``) counts under
    its UDP flow -- and a frame whose innermost
    datagram carries no transport (an ICMP echo, inside a VXLAN tunnel
    or not) has none,
    rather than being counted under the tunnel's underlay flow -- nor
    does a transport that carries a whole Ethernet frame, as VXLAN's UDP
    does around an inner ARP, which has no IP header to key.
    :meth:`netprotocols.Packet.flow_key` keys the *first* transport
    instead, which for VXLAN is the underlay; RootWire reports what the
    analyst sees inside.
    """
    inner = next(
        (
            index
            for index in range(len(frame.layers) - 1, -1, -1)
            if isinstance(frame.layers[index], (IPv4, IPv6))
        ),
        None,
    )
    if inner is None:
        return None
    tail = frame.layers[inner + 1 :]
    transport = next(
        (layer for layer in tail if isinstance(layer, (TCP, UDP, SCTP))),
        None,
    )
    if transport is None or any(
        isinstance(layer, (VXLAN, Ethernet)) for layer in tail
    ):
        # No transport, or one carrying a whole layer-2 frame (VXLAN's
        # UDP around an inner ARP, which has no IP header of its own, or
        # around an inner frame too short to decode): a tunnel's
        # underlay, not a conversation.
        return None
    ip, routing = _enclosing_ip(frame, transport)
    try:
        return flow_key(transport, ip=ip, routing=routing)
    except ProtocolError:
        # Only an absent ``ip`` raises, and _enclosing_ip always finds
        # the one at ``inner``; a statistics line must never stop a
        # capture all the same.
        return None


def _endpoint_text(address: str, port: int | None) -> str:
    """``"10.0.0.1:80"``, ``"[2001:db8::1]:80"``, or the bare address
    when there is no port."""
    if port is None:
        return address
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def _flow_text(key: FlowKey, frames: int, octets: int) -> str:
    """One conversation line: transport, both endpoints, and its frame
    and byte counts."""
    name = _FLOW_PROTOCOLS.get(key.protocol, f"proto {key.protocol}")
    return (
        f"{name} {_endpoint_text(key.addr_a, key.port_a)} <-> "
        f"{_endpoint_text(key.addr_b, key.port_b)}: {frames:,} frame"
        f"{'' if frames == 1 else 's'}, {octets:,} bytes"
    )


class StatsCollector(Output):
    """Accumulate capture statistics; render them with :meth:`report`.

    The per-protocol tally buckets each frame by its innermost decoded
    layer among TCP/UDP/SCTP/ICMPv4/ICMPv6/ARP — unambiguous even when a
    chain ends at an extension header or a non-first fragment, which
    count as ``other``.

    The conversation tally counts frames and bytes per TCP/UDP/SCTP
    conversation, both directions together (see
    :func:`_frame_flow_key`), and the report lists the largest by bytes.
    At most :data:`_FLOW_LIMIT` conversations are tracked; frames of a
    conversation first seen past that are counted as untracked.
    """

    def __init__(self) -> None:
        self._started = time.monotonic()
        self._frames = 0
        self._bytes = 0
        self._malformed = 0
        self._truncated = 0
        self._buckets: Counter[str] = Counter()
        self._flow_frames: Counter[FlowKey] = Counter()
        self._flow_bytes: Counter[FlowKey] = Counter()
        self._untracked = 0

    def update(self, frame: DecodedFrame) -> None:
        """Count *frame*: its size, its malformed and truncated flags,
        its protocol bucket and its conversation."""
        self._update_flow(frame)
        self._frames += 1
        self._bytes += frame.length
        if frame.error is not None or frame.malformed_length:
            self._malformed += 1
        if frame.truncated:
            self._truncated += 1
        for layer in reversed(frame.layers):
            if isinstance(layer, _STATS_BUCKETS):
                self._buckets[type(layer).__name__] += 1
                break
        else:
            self._buckets["other"] += 1

    def _update_flow(self, frame: DecodedFrame) -> None:
        """Count *frame* towards its conversation, if it has one and the
        conversation is tracked (see :data:`_FLOW_LIMIT`)."""
        key = _frame_flow_key(frame)
        if key is None:
            return
        if key not in self._flow_frames and len(self._flow_frames) >= (
            _FLOW_LIMIT
        ):
            self._untracked += 1
            return
        self._flow_frames[key] += 1
        self._flow_bytes[key] += frame.length

    def _report_flows(self, stream: IO[str]) -> None:
        """The conversation lines of the summary: how many, the largest
        :data:`_FLOW_SHOWN` by bytes, and the untracked frames."""
        if not self._flow_frames and not self._untracked:
            return
        count = len(self._flow_frames)
        if count > _FLOW_SHOWN:
            heading = (
                f"{count:,} conversations, the {_FLOW_SHOWN} largest by bytes"
            )
        else:
            heading = f"{count} conversation{'' if count == 1 else 's'}"
        print(f"[=] {heading}:", file=stream)
        for key, octets in self._flow_bytes.most_common(_FLOW_SHOWN):
            text = _flow_text(key, self._flow_frames[key], octets)
            print(f"[=]   {text}", file=stream)
        if self._untracked:
            print(
                f"[=]   (+{self._untracked:,} frames of conversations past "
                f"the {_FLOW_LIMIT:,} tracked)",
                file=stream,
            )

    def report(self, stream: IO[str] | None = None) -> None:
        """Write the capture summary (to stderr by default)."""
        stream = stream if stream is not None else sys.stderr
        duration = time.monotonic() - self._started
        rate = self._frames / duration if duration > 0 else 0.0
        tallies = ", ".join(
            f"{name}: {count}"
            for name, count in sorted(
                self._buckets.items(), key=lambda item: -item[1]
            )
        )
        print(
            f"[=] {self._frames} frames, {self._bytes:,} bytes in "
            f"{duration:.1f}s ({rate:,.0f} frames/s)",
            file=stream,
        )
        if tallies:
            print(f"[=] {tallies}", file=stream)
        if self._malformed or self._truncated:
            print(
                f"[=] malformed: {self._malformed}, "
                f"truncated: {self._truncated}",
                file=stream,
            )
        self._report_flows(stream)
