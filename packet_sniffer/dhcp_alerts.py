#!/usr/bin/env python3
"""
Heuristic alerts for DHCP capture auditing.

The rules implemented here mirror the course proposal:

* **H1** — evidence of multiple DHCP servers (distinct server identifiers or
  distinct Ethernet sources among OFFER/ACK messages in the observation
  window).
* **H2** — critical parameters (default router, DNS list) disagree across
  messages that share the same DHCP transaction id (``xid``).
* **H3** — structural / parsing failures surfaced by :mod:`dhcp_parser`.

The module is capture-agnostic: callers append :class:`DhcpObservation`
instances (from live capture or PCAP) and then run :func:`analyze_observations`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Set, Tuple

from dhcp_parser import DhcpMessage, _MSG_ACK, _MSG_OFFER, summarize_message

# Option 53 values considered "server-originated answers" for H1.
_SERVER_MSG_TYPES = {_MSG_OFFER, _MSG_ACK}


@dataclass(frozen=True)
class DhcpObservation:
    """
    One UDP/DHCP datagram seen on the wire with minimal framing metadata.

    This bundles everything the heuristics need: timestamps for windowing,
    Ethernet addresses for multi-server hints, IP/UDP endpoints for context,
    and either a parsed :class:`DhcpMessage` or a parse error string (H3).
    """

    timestamp: float
    frame_index: Optional[int]
    eth_src: str
    eth_dst: str
    ipv4_src: str
    ipv4_dst: str
    udp_sport: int
    udp_dport: int
    parse_error: Optional[str]
    message: Optional[DhcpMessage] = None


@dataclass(frozen=True)
class Alert:
    """
    A single alert emitted by :func:`analyze_observations`.

    ``rule`` is a short machine-readable tag (``H1``, ``H2``, ``H3``);
    ``details`` is meant for humans and includes field names referenced by
    the rule, per the project specification.
    """

    rule: str
    severity: str
    summary: str
    evidence: Tuple[str, ...] = field(default_factory=tuple)


def _apply_observation_window(
    observations: Sequence[DhcpObservation],
    window_seconds: Optional[float],
) -> List[DhcpObservation]:
    """
    Optionally restrict observations to a time window anchored at the first
    sample.

    :param observations: Chronological or arbitrary-order samples; they will be
        sorted by ``timestamp`` before windowing.
    :param window_seconds: If ``None``, all observations are retained. If set,
        only events with ``timestamp <= t0 + window_seconds`` are kept, where
        ``t0`` is the earliest timestamp in the input.
    :return: Filtered list (sorted by timestamp).
    """
    if not observations:
        return []
    ordered = sorted(observations, key=lambda o: o.timestamp)
    if window_seconds is None:
        return list(ordered)
    t0 = ordered[0].timestamp
    cutoff = t0 + float(window_seconds)
    return [o for o in ordered if o.timestamp <= cutoff]


def _normalize_mac(s: str) -> str:
    """Normalize MAC strings for comparison (lowercase, strip whitespace)."""
    return s.strip().lower()


def _first_router(msg: DhcpMessage) -> Optional[str]:
    return msg.routers[0] if msg.routers else None


def _dns_signature(msg: DhcpMessage) -> Tuple[str, ...]:
    """Stable tuple used to compare DNS server sets between messages."""
    return tuple(msg.dns_servers)


def analyze_observations(
    observations: Sequence[DhcpObservation],
    *,
    observation_window_seconds: Optional[float] = None,
) -> List[Alert]:
    """
    Run H1–H3 heuristics over a sequence of observations.

    :param observations: Typically all DHCP-tagged UDP packets from a trace.
    :param observation_window_seconds: Optional upper bound on how long after
        the first seen timestamp events remain eligible for **H1** and the
        per-``xid`` grouping for **H2**. When ``None``, the full sorted trace is
        used (common for offline PCAP analysis).
    :return: A list of :class:`Alert` instances (possibly empty).
    """
    alerts: List[Alert] = []
    scoped = _apply_observation_window(observations, observation_window_seconds)

    # H3: any explicit parse failure.
    for obs in scoped:
        if obs.parse_error:
            alerts.append(
                Alert(
                    rule="H3",
                    severity="error",
                    summary="DHCP payload could not be parsed",
                    evidence=(
                        f"reason={obs.parse_error}",
                        f"eth_src={obs.eth_src}",
                        f"eth_dst={obs.eth_dst}",
                        f"udp={obs.udp_sport}->{obs.udp_dport}",
                    ),
                )
            )

    # H1 / H2 require successful parses.
    parsed: List[DhcpObservation] = [
        o for o in scoped if o.parse_error is None and o.message is not None
    ]

    server_replies: List[DhcpObservation] = []
    for obs in parsed:
        mt = obs.message.message_type if obs.message else None
        if mt in _SERVER_MSG_TYPES:
            server_replies.append(obs)

    # H1 — multiple probable servers (option 54 and/or Ethernet source).
    server_ids: Set[str] = set()
    eth_sources: Set[str] = set()
    for obs in server_replies:
        msg = obs.message
        if msg is None:
            continue
        if msg.server_identifier:
            server_ids.add(msg.server_identifier)
        eth_sources.add(_normalize_mac(obs.eth_src))

    if len(server_ids) > 1:
        alerts.append(
            Alert(
                rule="H1",
                severity="warning",
                summary="Multiple DHCP Server Identifier (option 54) values seen",
                evidence=(
                    "field=option_54",
                    f"values={', '.join(sorted(server_ids))}",
                ),
            )
        )

    if len(eth_sources) > 1:
        alerts.append(
            Alert(
                rule="H1",
                severity="warning",
                summary="Multiple Ethernet source MACs seen on DHCP OFFER/ACK",
                evidence=(
                    "field=eth_src",
                    f"macs={', '.join(sorted(eth_sources))}",
                ),
            )
        )

    # H2 — disagreeing routers/DNS among messages sharing the same xid.
    by_xid: dict[int, List[DhcpObservation]] = {}
    for obs in parsed:
        msg = obs.message
        if msg is None:
            continue
        by_xid.setdefault(msg.xid, []).append(obs)

    for xid, group in by_xid.items():
        if len(group) < 2:
            continue
        routers = {_first_router(o.message) for o in group if o.message}
        routers.discard(None)
        if len(routers) > 1:
            alerts.append(
                Alert(
                    rule="H2",
                    severity="warning",
                    summary="Conflicting default routers (option 3) for the same xid",
                    evidence=(
                        f"xid=0x{xid:08x}",
                        f"routers={', '.join(sorted(r for r in routers if r))}",
                    ),
                )
            )

        dns_sets = {_dns_signature(o.message) for o in group if o.message}
        if len(dns_sets) > 1:
            pretty = [";".join(s) for s in dns_sets]
            alerts.append(
                Alert(
                    rule="H2",
                    severity="warning",
                    summary="Conflicting DNS server lists (option 6) for the same xid",
                    evidence=(
                        f"xid=0x{xid:08x}",
                        f"dns_sets={' | '.join(sorted(pretty))}",
                    ),
                )
            )

    # Note relayed traffic conservatively (informational; not H1–H3).
    relayed = [o for o in parsed if o.message and o.message.is_relayed]
    if relayed:
        alerts.append(
            Alert(
                rule="INFO",
                severity="info",
                summary="Some DHCP messages have giaddr != 0 (relay context); "
                "interpret H1/H2 conservatively",
                evidence=(f"count={len(relayed)}",),
            )
        )

    return alerts


def format_observation_line(obs: DhcpObservation) -> str:
    """Pretty one-line description for verbose logging."""
    head = (
        f"t={obs.timestamp:.6f} "
        f"eth {obs.eth_src} -> {obs.eth_dst} "
        f"IPv4 {obs.ipv4_src}->{obs.ipv4_dst} "
        f"UDP {obs.udp_sport}->{obs.udp_dport}"
    )
    if obs.parse_error:
        return f"{head} PARSE_ERROR: {obs.parse_error}"
    if obs.message is None:
        return f"{head} (no message)"
    msg = obs.message
    return f"{head} DHCP {msg.message_type_name} {summarize_message(msg)}"
