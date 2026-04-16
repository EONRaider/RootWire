#!/usr/bin/env python3
"""
Bridge between decoded live frames and the DHCP audit pipeline.

:class:`core.Decoder` attaches protocol objects (``ethernet``, ``ipv4``,
``udp``, …) and stores the remaining bytes as ``frame.data``. This module
recognises DHCP traffic (UDP/67–68) and builds :class:`dhcp_alerts.DhcpObservation`
instances without importing capture-specific APIs into the parser itself.
"""

from __future__ import annotations

from typing import Any, Optional

from dhcp_alerts import DhcpObservation
from dhcp_parser import parse_dhcp_udp_payload


def observation_from_decoder_frame(frame: Any) -> Optional[DhcpObservation]:
    """
    Convert a live-decoded ``Decoder`` instance into a :class:`DhcpObservation`.

    The function is defensive: non-IP traffic, non-UDP stacks, or other frames
    simply return ``None`` so observers can call it for every capture without
    extra guards.

    :param frame: Object yielded by :meth:`core.Decoder.execute` (same reference
        passed to :class:`output.OutputToScreen`).
    :return: An observation for DHCP UDP payloads, otherwise ``None``.
    """
    udp = getattr(frame, "udp", None)
    ethernet = getattr(frame, "ethernet", None)
    ipv4 = getattr(frame, "ipv4", None)
    if udp is None or ethernet is None or ipv4 is None:
        return None

    sport = int(udp.sport)
    dport = int(udp.dport)
    if sport not in (67, 68) and dport not in (67, 68):
        return None

    payload = getattr(frame, "data", b"") or b""
    payload_bytes = bytes(payload)
    message, parse_error = parse_dhcp_udp_payload(payload_bytes)

    return DhcpObservation(
        timestamp=float(getattr(frame, "epoch_time", 0.0)),
        frame_index=int(getattr(frame, "packet_num", 0)) or None,
        eth_src=str(ethernet.src),
        eth_dst=str(ethernet.dst),
        ipv4_src=str(ipv4.src),
        ipv4_dst=str(ipv4.dst),
        udp_sport=sport,
        udp_dport=dport,
        parse_error=parse_error,
        message=message,
    )


def observation_from_pcap_envelope(envelope: Any) -> DhcpObservation:
    """
    Build an observation from :class:`pcap_reader.EthernetFrame`.

    :param envelope: Named tuple produced by :func:`pcap_reader.iter_dhcp_frames`.
    :return: Parsed observation (``parse_error`` is set when the BOOTP/DHCP
        portion is malformed).
    """
    payload = bytes(getattr(envelope, "payload", b"") or b"")
    message, parse_error = parse_dhcp_udp_payload(payload)
    return DhcpObservation(
        timestamp=float(envelope.timestamp),
        frame_index=None,
        eth_src=str(envelope.eth_src),
        eth_dst=str(envelope.eth_dst),
        ipv4_src=str(envelope.ipv4_src),
        ipv4_dst=str(envelope.ipv4_dst),
        udp_sport=int(envelope.udp_sport),
        udp_dport=int(envelope.udp_dport),
        parse_error=parse_error,
        message=message,
    )
