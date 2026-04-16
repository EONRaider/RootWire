#!/usr/bin/env python3
"""
PCAP ingestion helpers for offline DHCP auditing.

The live sniffer already decodes frames via :mod:`core` and ``NETProtocols``.
For files, this module uses ``dpkt`` solely to obtain Ethernet frames and
their timestamps — **DHCP semantics remain in** :mod:`dhcp_parser` **and**
:mod:`dhcp_alerts`, per the project requirements.
"""

from __future__ import annotations

from typing import Iterator, NamedTuple, Optional

import dpkt

# EtherType for vanilla Ethernet II IPv4 payloads (no 802.1Q tag).
_ETHERTYPE_IPV4 = 0x0800


class EthernetFrame(NamedTuple):
    """
    Minimal L2/L3/L4 view for a UDP/67–68 datagram extracted from a PCAP record.

    Only DHCP-sized traffic is surfaced by :func:`iter_dhcp_frames` so the
    ``payload`` is always the BOOTP/DHCP portion carried inside UDP.
    """

    timestamp: float
    eth_src: str
    eth_dst: str
    ipv4_src: str
    ipv4_dst: str
    udp_sport: int
    udp_dport: int
    payload: bytes


def _mac_to_str(mac: bytes) -> str:
    """Render six octets as ``aa:bb:cc:dd:ee:ff`` lowercase."""
    return ":".join(f"{b:02x}" for b in mac)


def _decode_dhcp_udp_frame(buf: bytes, ts: float) -> Optional[EthernetFrame]:
    """
    Parse a single PCAP buffer as Ethernet → IPv4 → UDP.

    VLAN-tagged frames (EtherType ``0x8100``) are **skipped** in the MVP: the
    offset to IPv4 would differ and is intentionally out of scope for the first
    delivery.

    :param buf: Raw bytes from ``dpkt.pcap.Reader``.
    :param ts: PCAP timestamp in seconds (float, includes fractional part).
    :return: Populated :class:`EthernetFrame`, or ``None`` if the record is not
        a simple IPv4/UDP datagram.
    """
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.NeedData, dpkt.UnpackError, ValueError):
        return None

    if eth.type != _ETHERTYPE_IPV4:
        return None

    ip = eth.data
    if not isinstance(ip, dpkt.ip.IP):
        return None
    if ip.p != dpkt.ip.IP_PROTO_UDP:
        return None

    udp = ip.data
    if not isinstance(udp, dpkt.udp.UDP):
        return None

    sport, dport = int(udp.sport), int(udp.dport)
    if sport not in (67, 68) and dport not in (67, 68):
        return None

    return EthernetFrame(
        timestamp=float(ts),
        eth_src=_mac_to_str(eth.src),
        eth_dst=_mac_to_str(eth.dst),
        ipv4_src=dpkt.utils.inet_to_str(ip.src),
        ipv4_dst=dpkt.utils.inet_to_str(ip.dst),
        udp_sport=sport,
        udp_dport=dport,
        payload=bytes(udp.data),
    )


def iter_dhcp_frames(path: str) -> Iterator[EthernetFrame]:
    """
    Yield DHCP-carrying Ethernet/IP/UDP summaries from a ``.pcap`` / ``.pcapng``.

    Non-Ethernet captures, non-IPv4 frames, non-UDP traffic, and UDP ports other
    than 67/68 are skipped so downstream parsers only see relevant payloads.

    :param path: Filesystem location of the capture.
    :raises FileNotFoundError: If ``path`` does not exist.
    """
    with open(path, "rb") as handle:
        reader = dpkt.pcap.Reader(handle)
        for ts, buf in reader:
            frame = _decode_dhcp_udp_frame(buf, ts)
            if frame is None:
                continue
            yield frame
