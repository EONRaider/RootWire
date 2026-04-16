#!/usr/bin/env python3
"""
High-level orchestration for DHCP audits (PCAP replay and report rendering).

This keeps :mod:`sniffer` thin: argument parsing delegates to these functions so
the DHCP-specific workflow stays documented and testable in isolation.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from dhcp_alerts import Alert, DhcpObservation, analyze_observations, format_observation_line
from dhcp_integration import observation_from_pcap_envelope
from pcap_reader import iter_dhcp_frames


def _dhcp_message_to_dict(msg: Any) -> Optional[Dict[str, Any]]:
    """Serialize a :class:`dhcp_parser.DhcpMessage` into JSON-friendly structures."""
    if msg is None:
        return None
    return {
        "op": msg.op,
        "htype": msg.htype,
        "hlen": msg.hlen,
        "hops": msg.hops,
        "xid": f"0x{msg.xid:08x}",
        "secs": msg.secs,
        "flags": msg.flags,
        "ciaddr": msg.ciaddr,
        "yiaddr": msg.yiaddr,
        "siaddr": msg.siaddr,
        "giaddr": msg.giaddr,
        "chaddr": msg.chaddr,
        "sname": msg.sname,
        "file": msg.file,
        "message_type": msg.message_type,
        "message_type_name": msg.message_type_name,
        "server_identifier": msg.server_identifier,
        "subnet_mask": msg.subnet_mask,
        "routers": list(msg.routers),
        "dns_servers": list(msg.dns_servers),
        "lease_time": msg.lease_time,
        "is_relayed": msg.is_relayed,
        "raw_options_hex": {str(code): raw.hex() for code, raw in msg.raw_options.items()},
    }


def _observation_to_dict(obs: DhcpObservation) -> Dict[str, Any]:
    """Serialize a :class:`dhcp_alerts.DhcpObservation` for structured export."""
    return {
        "timestamp": obs.timestamp,
        "frame_index": obs.frame_index,
        "eth_src": obs.eth_src,
        "eth_dst": obs.eth_dst,
        "ipv4_src": obs.ipv4_src,
        "ipv4_dst": obs.ipv4_dst,
        "udp_sport": obs.udp_sport,
        "udp_dport": obs.udp_dport,
        "parse_error": obs.parse_error,
        "message": _dhcp_message_to_dict(obs.message),
    }


def _alert_to_dict(alert: Alert) -> Dict[str, Any]:
    """Serialize a :class:`dhcp_alerts.Alert` for JSON output."""
    return {
        "rule": alert.rule,
        "severity": alert.severity,
        "summary": alert.summary,
        "evidence": list(alert.evidence),
    }


def render_report_text(
    observations: List[DhcpObservation],
    alerts: List[Alert],
    *,
    include_observations: bool,
) -> None:
    """
    Print a human-readable audit report to stdout.

    :param observations: Parsed DHCP datagrams (including parse failures).
    :param alerts: Heuristic findings from :func:`dhcp_alerts.analyze_observations`.
    :param include_observations: When false, only the alert section is printed
        (useful for very large captures).
    """
    if include_observations:
        print("=== DHCP observations ===")
        if not observations:
            print("(none)")
        for obs in observations:
            print(format_observation_line(obs))
        print()

    print("=== Alerts ===")
    if not alerts:
        print("(none)")
        return

    for alert in alerts:
        print(f"[{alert.rule}/{alert.severity}] {alert.summary}")
        for line in alert.evidence:
            print(f"    - {line}")


def render_report_json(observations: List[DhcpObservation], alerts: List[Alert]) -> str:
    """
    Build a JSON document summarising observations and alerts.

    :return: Pretty-printed JSON string (UTF-8 text) suitable for writing to disk.
    """
    document = {
        "observations": [_observation_to_dict(o) for o in observations],
        "alerts": [_alert_to_dict(a) for a in alerts],
    }
    return json.dumps(document, indent=2, ensure_ascii=False)


def collect_observations_from_pcap(path: str) -> List[DhcpObservation]:
    """
    Walk a PCAP/PCAPNG file and return DHCP observations in capture order.

    Only UDP/67–68 payloads are considered; all other frames are ignored at the
    :mod:`pcap_reader` layer for efficiency.
    """
    observations: List[DhcpObservation] = []
    for envelope in iter_dhcp_frames(path):
        observations.append(observation_from_pcap_envelope(envelope))
    return observations


def run_pcap_dhcp_audit(
    path: str,
    *,
    observation_window_seconds: Optional[float],
    json_output: bool,
    verbose_observations: bool,
) -> None:
    """
    Execute the offline DHCP audit CLI workflow.

    :param path: PCAP path on disk.
    :param observation_window_seconds: Forwarded to :func:`analyze_observations`.
    :param json_output: When true, emit JSON only (no human headings).
    :param verbose_observations: When true and ``json_output`` is false, list
        every observation before the alert section.
    """
    observations = collect_observations_from_pcap(path)
    alerts = analyze_observations(
        observations,
        observation_window_seconds=observation_window_seconds,
    )
    if json_output:
        print(render_report_json(observations, alerts))
        return

    render_report_text(
        observations,
        alerts,
        include_observations=verbose_observations,
    )
