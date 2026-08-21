"""Command-line interface: argument parsing, privilege guidance, and
the capture loop wiring frames through the decoder to the renderers."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from packet_sniffer import __version__
from packet_sniffer.decoder import decode_frame
from packet_sniffer.output import Output, OutputToScreen

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packet-sniffer",
        description=(
            "Monitor network traffic: capture Ethernet frames from an "
            "interface, decode their protocol stack and render each frame "
            "on screen."
        ),
    )
    parser.add_argument(
        "-i",
        "--interface",
        default=None,
        help="interface to capture frames from (default: all interfaces)",
    )
    parser.add_argument(
        "-d",
        "--data",
        action="store_true",
        help="also display each frame's raw payload",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def run(interface: str | None, outputs: Sequence[Output]) -> int:
    """Capture, decode, and dispatch frames until interrupted.

    :returns: The number of frames processed.
    """
    from packet_sniffer.capture import capture  # Linux-only import

    number = 0
    for number, (data, timestamp) in enumerate(capture(interface), start=1):
        frame = decode_frame(
            data, number=number, timestamp=timestamp, interface=interface
        )
        for output in outputs:
            output.update(frame)
    return number


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    outputs = [OutputToScreen(display_payload=args.data)]
    print(
        "[>>>] Packet Sniffer initialized. Waiting for incoming data. "
        "Press Ctrl-C to abort...\n"
    )
    try:
        run(args.interface, outputs)
    except PermissionError:
        print(
            "Error: opening a raw socket requires elevated privileges. "
            "Run with sudo, or grant the interpreter the CAP_NET_RAW "
            "capability.",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        print("[!] Capture aborted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
