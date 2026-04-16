#!/usr/bin/env python3
"""
CLI entry point for live capture, optional DHCP auditing, and PCAP replay.

Live capture continues to require elevated privileges on GNU/Linux because of
``SOCK_RAW``. Offline ``--pcap`` analysis does **not** require ``root``.
"""

import argparse
import os
import sys
from typing import List, Optional

from core import PacketSniffer
from dhcp_audit_observer import DhcpAuditObserver
from dhcp_audit_runner import run_pcap_dhcp_audit
from output import OutputToScreen


def _build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI parser with backwards-compatible defaults."""
    parser = argparse.ArgumentParser(
        description="Network packet sniffer with optional DHCP auditing",
    )
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        default=None,
        help="Interface from which Ethernet frames will be captured (monitors "
        "all available interfaces by default).",
    )
    parser.add_argument(
        "-d",
        "--data",
        action="store_true",
        help="Output packet data during capture.",
    )
    parser.add_argument(
        "--dhcp-audit",
        action="store_true",
        help="Record and analyse DHCP/BOOTP traffic seen during live capture.",
    )
    parser.add_argument(
        "--pcap",
        metavar="FILE",
        type=str,
        default=None,
        help="Replay a .pcap/.pcapng file and run the DHCP audit (no live capture).",
    )
    parser.add_argument(
        "--dhcp-window",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Optional observation window (seconds from first DHCP packet) for "
        "H1/H2 heuristics. Omit to analyse the entire trace.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit structured JSON (PCAP mode or DHCP summary after live capture).",
    )
    parser.add_argument(
        "--dhcp-verbose",
        action="store_true",
        help="Print each DHCP datagram as it is parsed (very chatty on busy LANs).",
    )
    parser.add_argument(
        "--audit-quiet",
        action="store_true",
        help="Hide the standard per-packet sniffer output during live capture "
        "(use together with --dhcp-audit).",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """
    Parse CLI arguments and dispatch to PCAP replay or live capture.

    :param argv: Optional argument vector (defaults to ``sys.argv[1:]``).
    :return: Process exit code (0 on success, non-zero for usage errors).
    """
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if args.pcap and not os.path.isfile(args.pcap):
        parser.error(f"PCAP not found: {args.pcap}")

    if args.audit_quiet and not args.dhcp_audit:
        parser.error("--audit-quiet requires --dhcp-audit")

    if args.pcap:
        run_pcap_dhcp_audit(
            args.pcap,
            observation_window_seconds=args.dhcp_window,
            json_output=args.json,
            verbose_observations=args.dhcp_verbose and not args.json,
        )
        return 0

    if os.getuid() != 0:
        print(
            "Error: Permission denied. Live capture requires administrator "
            "privileges (SOCK_RAW). For PCAP-only analysis use --pcap FILE.",
            file=sys.stderr,
        )
        return 1

    sniffer = PacketSniffer()

    if args.dhcp_audit:
        DhcpAuditObserver(
            sniffer,
            observation_window_seconds=args.dhcp_window,
            json_on_exit=args.json,
            verbose=args.dhcp_verbose,
        )

    if not args.audit_quiet:
        OutputToScreen(subject=sniffer, display_data=args.data)

    try:
        for _ in sniffer.listen(args.interface):
            pass
    except KeyboardInterrupt:
        print("\n[!] Aborting packet capture...")
    finally:
        sniffer.finalize_observers()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
