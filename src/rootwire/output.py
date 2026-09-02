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
import json
import sys
import time
from abc import ABC, abstractmethod
from collections import Counter
from functools import singledispatchmethod
from typing import IO, Any, cast

from netprotocols import (
    ARP,
    TCP,
    UDP,
    VLAN,
    Ethernet,
    ICMPv4,
    ICMPv6,
    IPv4,
    IPv6,
    IPv6DestinationOptions,
    IPv6Fragment,
    IPv6HopByHopOptions,
    IPv6Routing,
    Protocol,
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

    def update(self, frame: DecodedFrame) -> None:
        local_time = time.strftime("%H:%M:%S", time.localtime(frame.timestamp))
        interface = frame.interface or "all"
        self._print(
            f"[>] Frame #{frame.number} at {local_time} "
            f"({interface}, {frame.length} bytes)"
        )
        for layer in frame.layers:
            self._render(layer, frame)
        if frame.error is not None:
            self._print(f"{_I}[!] Malformed header: {frame.error}")
        if frame.truncated:
            self._print(
                f"{_I}[!] Truncated: the IP datagram declares more bytes "
                f"than were captured"
            )
        if self._display_payload and frame.payload:
            text = frame.payload.decode(errors="ignore")
            self._print(f"{_I}[+] Payload ({len(frame.payload)} bytes):")
            self._print(f"{_II}{text.replace(chr(10), chr(10) + _II)}")
        self._print("")

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
            f"Checksum: {layer.checksum_hex_str}"
            + (
                f" | Options: {len(layer.options)} bytes"
                if layer.options
                else ""
            )
        )

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
    def _(self, layer: ICMPv4, frame: DecodedFrame) -> None:
        self._render_icmp(layer, frame, version=4)

    @_render.register
    def _(self, layer: ICMPv6, frame: DecodedFrame) -> None:
        self._render_icmp(layer, frame, version=6)

    def _render_icmp(
        self, layer: ICMPv4 | ICMPv6, frame: DecodedFrame, *, version: int
    ) -> None:
        ip: IPv4 | IPv6 | None
        ip = frame.layer(IPv4) if version == 4 else frame.layer(IPv6)
        route = f" {ip.src} -> {ip.dst}" if ip is not None else ""
        self._print(f"{_I}[+] ICMPv{version}{route}")
        self._print(
            f"{_II}Type: {layer.type} ({layer.type_name}) | "
            f"Code: {layer.code} | Checksum: {layer.checksum_hex_str}"
        )

    @_render.register
    def _(self, layer: TCP, frame: DecodedFrame) -> None:
        self._print(f"{_I}[+] TCP {layer.src_port} -> {layer.dst_port}")
        self._print(
            f"{_II}Flags: {layer.flags_hex_str} ({layer.flags_str}) | "
            f"Seq: {layer.seq} | Ack: {layer.ack}"
        )
        self._print(
            f"{_II}Window: {layer.window} | "
            f"Checksum: {layer.checksum_hex_str}"
            + (
                f" | Options: {len(layer.options)} bytes"
                if layer.options
                else ""
            )
        )

    @_render.register
    def _(self, layer: UDP, frame: DecodedFrame) -> None:
        self._print(f"{_I}[+] UDP {layer.src_port} -> {layer.dst_port}")
        self._print(
            f"{_II}Length: {layer.length} | Checksum: {layer.checksum_hex_str}"
        )

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


def _json_safe(value: Any) -> Any:
    return value.hex() if isinstance(value, bytes) else value


class OutputToNDJSON(Output):
    """Emit one JSON object per frame, newline-delimited.

    Layer fields come straight from the dataclasses (bytes values
    hex-encoded); the raw payload is deliberately omitted — its length
    is reported as ``payload_len``. Lines are flushed as they are
    written so the output pipes cleanly into consumers like ``jq``.

    :param stream: Destination stream; defaults to stdout.
    """

    def __init__(self, stream: IO[str] | None = None) -> None:
        self._stream = stream if stream is not None else sys.stdout

    def update(self, frame: DecodedFrame) -> None:
        record = {
            "number": frame.number,
            "timestamp": frame.timestamp,
            "interface": frame.interface,
            "length": frame.length,
            "truncated": frame.truncated,
            "error": frame.error,
            "payload_len": len(frame.payload),
            "layers": [
                {
                    "type": type(layer).__name__,
                    **{
                        key: _json_safe(value)
                        # Every concrete Protocol is a dataclass; the
                        # ABC itself is not, hence the cast.
                        for key, value in dataclasses.asdict(
                            cast(Any, layer)
                        ).items()
                    },
                }
                for layer in frame.layers
            ],
        }
        print(
            json.dumps(record, separators=(",", ":")),
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
        if frame.error is not None:
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
