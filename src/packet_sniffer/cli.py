"""Command-line interface: argument parsing, privilege guidance, and
the loop wiring frames from a source (live capture or pcap replay)
through the decoder to the outputs.

Everything informational — banner, abort notice, statistics — goes to
stderr, so stdout stays clean for machine-readable output
(``--json`` NDJSON pipes straight into ``jq``).
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator, Sequence

from packet_sniffer import __version__
from packet_sniffer.decoder import decode_frame
from packet_sniffer.output import (
    Output,
    OutputToNDJSON,
    OutputToPcap,
    OutputToScreen,
    StatsCollector,
)

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packet-sniffer",
        description=(
            "Monitor network traffic: capture Ethernet frames from an "
            "interface (or replay them from a pcap file), decode their "
            "protocol stack and render each frame."
        ),
    )
    parser.add_argument(
        "-i",
        "--interface",
        default=None,
        help="interface to capture frames from (default: all interfaces)",
    )
    parser.add_argument(
        "-r",
        "--read",
        metavar="FILE",
        default=None,
        help=(
            "replay frames from a classic pcap file instead of live "
            "capture (no privileges required); mutually exclusive with -i"
        ),
    )
    parser.add_argument(
        "-w",
        "--write",
        metavar="FILE",
        default=None,
        help="also write every captured frame to a classic pcap file",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "emit one NDJSON object per frame on stdout instead of the "
            "human-readable rendering"
        ),
    )
    parser.add_argument(
        "-d",
        "--data",
        action="store_true",
        help="also display each frame's raw payload (ignored with --json)",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def run(
    source: Iterator[tuple[bytes, float]],
    interface: str | None,
    outputs: Sequence[Output],
) -> int:
    """Decode and dispatch every frame the source yields.

    :returns: The number of frames processed.
    """
    number = 0
    for number, (data, timestamp) in enumerate(source, start=1):
        frame = decode_frame(
            data, number=number, timestamp=timestamp, interface=interface
        )
        for output in outputs:
            output.update(frame)
    return number


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.read is not None and args.interface is not None:
        build_parser().error("-r/--read and -i/--interface are exclusive")

    stats = StatsCollector()
    outputs: list[Output] = [
        OutputToNDJSON()
        if args.json
        else OutputToScreen(display_payload=args.data)
    ]
    if args.write is not None:
        outputs.append(OutputToPcap(args.write))
    outputs.append(stats)

    if args.read is not None:
        from packet_sniffer.pcap import read_pcap

        source = read_pcap(args.read)
        interface = args.read
    else:
        from packet_sniffer.capture import capture  # Linux-only import

        source = capture(args.interface)
        interface = args.interface

    print(
        "[>>>] Packet Sniffer initialized. "
        + (
            f"Replaying {args.read}..."
            if args.read
            else "Waiting for incoming data. Press Ctrl-C to abort..."
        ),
        file=sys.stderr,
    )
    exit_code = 0
    try:
        run(source, interface, outputs)
    except PermissionError:
        print(
            "Error: opening a raw socket requires elevated privileges. "
            "Run with sudo, or grant the interpreter the CAP_NET_RAW "
            "capability.",
            file=sys.stderr,
        )
        exit_code = 1
    except ValueError as e:  # unreadable/foreign pcap on -r
        print(f"Error: {e}", file=sys.stderr)
        exit_code = 1
    except KeyboardInterrupt:
        print("[!] Capture aborted.", file=sys.stderr)
    finally:
        for output in outputs:
            output.close()
        if exit_code == 0:
            stats.report()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
