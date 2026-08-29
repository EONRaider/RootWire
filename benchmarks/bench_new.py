"""Benchmark the 3.0 decoder. Run: uv run python benchmarks/bench_new.py"""

from _common import run

from rootwire.decoder import decode_frame


def main() -> None:
    run(
        "new (DecodedFrame)",
        lambda data, n: decode_frame(
            data, number=n, timestamp=0.0, interface="bench"
        ),
    )


if __name__ == "__main__":
    main()
