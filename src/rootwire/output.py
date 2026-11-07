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
from collections.abc import Iterator
from contextlib import contextmanager
from functools import singledispatchmethod
from typing import IO, Any, cast

from netprotocols import (
    ARP,
    DHCP,
    DNS,
    GRE,
    IGMP,
    TCP,
    UDP,
    VLAN,
    DNSOverTCP,
    Ethernet,
    ICMPv4,
    ICMPv6,
    IPv4,
    IPv4Option,
    IPv6,
    IPv6DestinationOptions,
    IPv6Fragment,
    IPv6HopByHopOptions,
    IPv6Routing,
    Protocol,
    ProtocolError,
    TCPOption,
    compute,
    verify,
)

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
    in a tunnel (IP-in-IP, GRE, VXLAN, AH/ESP tunnel mode), not the
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
    follows it (TCP, UDP), with its enclosing IP and Routing headers;
    ``""`` for a non-reassembled fragment (see :func:`_is_fragmented`)."""
    if _is_fragmented(frame, layer):
        return ""
    ip, routing = _enclosing_ip(frame, layer)
    return _checksum_note(
        layer, ip=ip, routing=routing, payload=_trailing_bytes(frame, layer)
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
            self._print(
                f"{_II}Options: "
                + ", ".join(_format_option(option) for option in options)
            )

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
                name = _sanitize_for_terminal(question.name)
                self._print(f"{_II}Q: {name} (type {question.qtype})")
            for answer in answers:
                name = _sanitize_for_terminal(answer.name)
                rdata = _sanitize_for_terminal(answer.rdata_text)
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
    - Anything else → ``str(value)``: an output must never kill a
      capture over a field type a future NETProtocols release adds.
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
    return str(value)


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
    ``null``. Lines are flushed as they are
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
            "layers": [_layer_record(layer) for layer in frame.layers],
        }
        print(
            json.dumps(record, separators=(",", ":"), default=_json_default),
            file=self._stream,
            flush=True,
        )


#: Innermost-layer classes counted by name in the statistics report.
_STATS_BUCKETS = (TCP, UDP, ICMPv4, ICMPv6, ARP)


class StatsCollector(Output):
    """Accumulate capture statistics; render them with :meth:`report`.

    The per-protocol tally buckets each frame by its innermost decoded
    layer among TCP/UDP/ICMPv4/ICMPv6/ARP — unambiguous even when a
    chain ends at an extension header or a non-first fragment, which
    count as ``other``.
    """

    def __init__(self) -> None:
        self._started = time.monotonic()
        self._frames = 0
        self._bytes = 0
        self._malformed = 0
        self._truncated = 0
        self._buckets: Counter[str] = Counter()

    def update(self, frame: DecodedFrame) -> None:
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
