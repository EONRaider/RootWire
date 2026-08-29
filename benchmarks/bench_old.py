"""Benchmark the 2.x decoder against netprotocols 0.8.0.

The old application cannot import next to netprotocols 1.0 (same
import name), so this vendors the decode chain of the 2.1.0
Decoder._attach_protocols verbatim and must run in an isolated
environment:

    uv run --no-project --with netprotocols==0.8.0 \
        python benchmarks/bench_old.py

Not apples-to-apples: the old chain mis-slices TCP (header_len=32
hardcoded), ignores IPv4 IHL, and does less validation. This is an
order-of-magnitude sanity check.
"""

import netprotocols
from _common import run


class OldDecoder:
    """The decode chain of rootwire/core.py at v2.1.0."""

    def __init__(self) -> None:
        self.data = None
        self.protocol_queue = ["Ethernet"]

    def _attach_protocols(self, frame: bytes) -> None:
        start = end = 0
        for proto in self.protocol_queue:
            try:
                proto_class = getattr(netprotocols, proto)
            except AttributeError:
                continue
            end = start + proto_class.header_len
            protocol = proto_class.decode(frame[start:end])
            setattr(self, proto.lower(), protocol)
            if protocol.encapsulated_proto in (None, "undefined"):
                break
            self.protocol_queue.append(protocol.encapsulated_proto)
            start = end
        self.data = frame[end:]

    def decode(self, frame: bytes) -> "OldDecoder":
        self._attach_protocols(frame)
        del self.protocol_queue[1:]
        return self


def main() -> None:
    decoder = OldDecoder()
    run(
        "old (2.1.0 chain, netprotocols 0.8.0)",
        lambda data, n: decoder.decode(data),
    )


if __name__ == "__main__":
    main()
