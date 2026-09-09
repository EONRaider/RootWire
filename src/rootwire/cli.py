"""Command-line interface: argument parsing, privilege guidance, and
the loop wiring frames from a source (live capture or pcap replay)
through the decoder to the outputs.

Everything informational — banner, abort notice, statistics — goes to
stderr, so stdout stays clean for machine-readable output
(``--json`` NDJSON pipes straight into ``jq``).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
from collections.abc import AsyncIterator, Iterator, Sequence

from rootwire import __version__
from rootwire.bpf import CANNED_FILTERS, FilterProgram
from rootwire.bpf_compiler import BPFCompileError, compile_expression
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
        action="append",
        default=None,
        help=(
            "interface to capture frames from; repeat to capture on "
            "several interfaces concurrently (default: all interfaces)"
        ),
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
        "--filter",
        metavar="NAME_OR_EXPR",
        default=None,
        help=(
            "attach a kernel-side capture filter so only matching frames "
            "reach userspace: a canned name "
            f"({', '.join(sorted(CANNED_FILTERS))}) or a filter expression "
            "(protocols tcp/udp/icmp/arp/ip/ip6; host/port, each "
            "optionally prefixed with src/dst; and/or/not; parentheses -- "
            "e.g. 'tcp and port 80'); mutually exclusive with -r"
        ),
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


async def _replay_source(
    frames: Iterator[tuple[bytes, int]], interface: str
) -> AsyncIterator[tuple[bytes, int, str]]:
    """Adapt :func:`rootwire.pcap.read_pcap`'s sync ``(bytes,
    timestamp)`` pairs into the async ``(bytes, timestamp, interface)``
    triples :func:`run` expects from every source, tagging every frame
    with the replayed file's path — a classic pcap file carries no
    interface metadata of its own.

    The ``await asyncio.sleep(0)`` per frame is not a formality: a bare
    ``for: yield`` loop with no real ``await`` inside never actually
    hands control back to the event loop between items, so a task
    cancelled from outside (SIGTERM, via ``_drive()``) would not be
    able to interrupt it until the *entire* file finished replaying —
    confirmed empirically, not assumed, since the failure mode is easy
    to miss on the small fixtures this project's own tests replay.
    """
    for data, timestamp in frames:
        await asyncio.sleep(0)
        yield data, timestamp, interface


async def run(
    source: AsyncIterator[tuple[bytes, int, str | None]],
    outputs: Sequence[Output],
) -> int:
    """Decode and dispatch every frame the source yields.

    :returns: The number of frames processed.
    """
    number = 0
    async for data, timestamp, interface in source:
        number += 1
        frame = decode_frame(
            data, number=number, timestamp=timestamp, interface=interface
        )
        for output in outputs:
            output.update(frame)
    return number


async def _drive(
    source: AsyncIterator[tuple[bytes, int, str | None]],
    outputs: Sequence[Output],
) -> int:
    """Run :func:`run` to completion, converting ``SIGTERM`` into the
    same orderly cancellation Ctrl-C already gets for free.

    ``asyncio.run`` (via ``asyncio.Runner``, since Python 3.11) installs
    its own ``SIGINT`` handler that cancels the running task and
    re-raises the cancellation as ``KeyboardInterrupt`` at the
    ``asyncio.run`` call site — indistinguishable from the old
    synchronous Ctrl-C path, so it needs no code here at all. A
    cancellation *this* function triggers itself, via ``SIGTERM``, is
    not eligible for that conversion (it is specific to ``Runner``'s own
    internal counter) and surfaces as a plain ``asyncio.CancelledError``
    instead — which is exactly how ``main()`` tells the two apart.
    """
    loop = asyncio.get_running_loop()
    task = asyncio.ensure_future(run(source, outputs))
    loop.add_signal_handler(signal.SIGTERM, task.cancel)
    try:
        return await task
    finally:
        # Only undoes *this* registration; main() separately restores
        # whatever SIGTERM disposition the caller had before main() was
        # ever called — remove_signal_handler always resets to SIG_DFL,
        # not "whatever was there before", which is not the same thing.
        loop.remove_signal_handler(signal.SIGTERM)


def _validate_args(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> None:
    """Argument combinations argparse's own mutual-exclusion groups
    can't express (they depend on values, not just presence). Each
    check reports the same way an argparse-native error would --
    usage message, exit 2, via ``parser.error()``, which never
    returns."""
    if args.read is not None and args.interface is not None:
        parser.error("-r/--read and -i/--interface are exclusive")
    if args.read is not None and args.filter is not None:
        parser.error(
            "-r/--read and --filter are exclusive: replay has no socket "
            "to attach a kernel filter to"
        )
    if (
        args.read is not None
        and args.write is not None
        and _same_file(args.read, args.write)
    ):
        # The writer truncates its target on open, before the lazy
        # replay reader has read a byte, so this would silently destroy
        # the very capture being replayed. Refuse before anything opens.
        parser.error(
            "-w/--write and -r/--read refer to the same file; refusing "
            "to overwrite the capture being replayed"
        )


def _resolve_filter_program(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> FilterProgram | None:
    """``--filter`` is either a canned name (``bpf.py``) or an
    expression (``bpf_compiler.py``); either way this is argument
    validation, not a runtime capture failure, so a bad one is
    reported and exits the same way argparse's own "invalid choice"
    errors do (usage message, exit 2), not folded into ``main()``'s
    later ``PermissionError``/``ValueError`` capture-error handling.
    """
    if args.filter is None:
        return None
    instructions = CANNED_FILTERS.get(args.filter)
    if instructions is None:
        try:
            instructions = compile_expression(args.filter)
        except BPFCompileError as error:
            parser.error(str(error))
    return FilterProgram(instructions)


def _build_outputs(
    args: argparse.Namespace, stats: StatsCollector
) -> list[Output] | None:
    """Assemble the output chain, or ``None`` (having already printed a
    clean error) if ``-w``'s target can't be opened."""
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
            return None
    outputs.append(stats)
    return outputs


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _validate_args(args, parser)
    filter_program = _resolve_filter_program(args, parser)

    stats = StatsCollector()
    outputs = _build_outputs(args, stats)
    if outputs is None:
        return 1

    source: AsyncIterator[tuple[bytes, int, str | None]]
    if args.read is not None:
        from rootwire.pcap import read_pcap

        source = _replay_source(read_pcap(args.read), args.read)
    else:
        from rootwire.capture import capture_async  # Linux-only import

        source = capture_async(args.interface, filter_program)

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
    previous_sigterm_handler = signal.getsignal(signal.SIGTERM)
    try:
        asyncio.run(_drive(source, outputs))
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
    except KeyboardInterrupt:
        print("[!] Capture aborted.", file=sys.stderr)
        report_stats = True
    except asyncio.CancelledError:  # SIGTERM, via _drive()
        print("[!] Terminated.", file=sys.stderr)
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
