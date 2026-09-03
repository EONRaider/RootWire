"""Command-line interface: argument parsing, privilege guidance, and
the loop wiring frames from a source (live capture or pcap replay)
through the decoder to the outputs.

Everything informational — banner, abort notice, statistics — goes to
stderr, so stdout stays clean for machine-readable output
(``--json`` NDJSON pipes straight into ``jq``).
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
from collections.abc import Iterator, Sequence
from types import FrameType
from typing import NoReturn

from rootwire import __version__
from rootwire.decoder import decode_frame
from rootwire.output import (
    Output,
    OutputToNDJSON,
    OutputToPcap,
    OutputToScreen,
    StatsCollector,
)

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rootwire",
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


class _Terminated(KeyboardInterrupt):
    """Raised by the SIGTERM handler.

    A :class:`KeyboardInterrupt` subclass so a SIGTERM abort shares
    Ctrl-C's shutdown path (flush outputs, report stats, exit 0) without
    a second ``except`` clause, while still being distinguishable for the
    shutdown message.
    """


def _raise_terminated(signum: int, frame: FrameType | None) -> NoReturn:
    """SIGTERM handler: raise to interrupt whatever is currently
    blocked (a raw-socket ``recv`` or the replay loop) instead of
    Python's default disposition, which terminates the process outright
    and skips ``finally`` blocks — losing unflushed output and the
    stats summary.
    """
    raise _Terminated


def _same_file(a: str, b: str) -> bool:
    """Whether two path strings name the same file on disk.

    :func:`os.path.samefile` compares device and inode, so it sees
    through symlinks, hardlinks, and different spellings of an existing
    path. It raises when a path does not exist yet — as the write target
    normally does not — and a normalized textual comparison is then the
    best remaining signal.
    """
    try:
        return os.path.samefile(a, b)
    except OSError:
        return os.path.realpath(a) == os.path.realpath(b)


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
    if (
        args.read is not None
        and args.write is not None
        and _same_file(args.read, args.write)
    ):
        # The writer truncates its target on open, before the lazy
        # replay reader has read a byte, so this would silently destroy
        # the very capture being replayed. Refuse before anything opens.
        build_parser().error(
            "-w/--write and -r/--read refer to the same file; refusing "
            "to overwrite the capture being replayed"
        )

    stats = StatsCollector()
    outputs: list[Output] = [
        OutputToNDJSON()
        if args.json
        else OutputToScreen(display_payload=args.data)
    ]
    if args.write is not None:
        try:
            outputs.append(OutputToPcap(args.write))
        except OSError as error:
            # A bad directory or a write-permission denial must not
            # surface as a raw traceback, nor be folded into the capture
            # handler below, whose "run with sudo" hint would misdiagnose
            # it. No output holds a resource yet, so returning is clean.
            print(
                f"Error: cannot open '{args.write}' for writing: "
                f"{error.strerror or error}",
                file=sys.stderr,
            )
            return 1
    outputs.append(stats)

    if args.read is not None:
        from rootwire.pcap import read_pcap

        source = read_pcap(args.read)
        interface = args.read
    else:
        from rootwire.capture import capture  # Linux-only import

        source = capture(args.interface)
        interface = args.interface

    print(
        "[>>>] RootWire initialized. "
        + (
            f"Replaying {args.read}..."
            if args.read
            else "Waiting for incoming data. Press Ctrl-C to abort..."
        ),
        file=sys.stderr,
    )
    exit_code = 0
    report_stats = False
    # Only for the duration of the capture: a service manager's SIGTERM
    # should stop the run cleanly, the same as Ctrl-C, instead of hitting
    # Python's default disposition (immediate termination, no `finally`,
    # unflushed output). Restored below so importing rootwire as a
    # library never hijacks the caller's signal handling.
    previous_sigterm_handler = signal.signal(signal.SIGTERM, _raise_terminated)
    try:
        run(source, interface, outputs)
        report_stats = True
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
    except KeyboardInterrupt as abort:
        print(
            "[!] Terminated."
            if isinstance(abort, _Terminated)
            else "[!] Capture aborted.",
            file=sys.stderr,
        )
        report_stats = True
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm_handler)
        for output in outputs:
            output.close()
        # Report only on a clean run or an abort (Ctrl-C or SIGTERM) —
        # never while an unexpected exception is still propagating, where
        # a summary (with the exit code still reading 0) would disguise
        # the crash.
        if report_stats:
            stats.report()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
