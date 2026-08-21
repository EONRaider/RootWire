"""Shared replay loop and RSS sampling for the two benchmark scripts."""

import struct
import time
from collections.abc import Callable
from pathlib import Path

FRAMES = Path(__file__).parent / "frames.bin"


def load_frames() -> list[bytes]:
    frames = []
    data = FRAMES.read_bytes()
    cursor = 0
    while cursor < len(data):
        (length,) = struct.unpack_from("!H", data, cursor)
        cursor += 2
        frames.append(data[cursor : cursor + length])
        cursor += length
    return frames


def rss_kib() -> int:
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return -1


def run(name: str, decode_one: Callable[[bytes, int], object]) -> None:
    frames = load_frames()
    passes = 30
    rss_samples = []
    decoded = 0
    start = time.perf_counter()
    for _ in range(passes):
        for data in frames:
            decoded += 1
            decode_one(data, decoded)
        rss_samples.append(rss_kib())
    elapsed = time.perf_counter() - start
    print(
        f"{name}: {decoded} frames in {elapsed:.2f}s "
        f"= {decoded / elapsed:,.0f} frames/s"
    )
    print(
        f"{name}: RSS first-pass {rss_samples[0]} KiB, "
        f"last-pass {rss_samples[-1]} KiB, "
        f"drift {rss_samples[-1] - rss_samples[0]:+d} KiB over "
        f"{passes} passes"
    )
