"""Raw-socket frame source.

This is the only module in the application that touches ``PF_PACKET``
(a Linux-only socket family) — everything else works with plain bytes
and runs on any OS, which is what keeps the decoder and renderers
testable without root privileges.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from socket import PF_PACKET, SOCK_RAW, htons, socket

__all__ = ["BUFFER_SIZE", "capture"]

#: Every EtherType (linux/if_ether.h).
_ETH_P_ALL = 0x0003

#: Largest capturable frame: a maximum-size IP datagram (65,535 bytes)
#: behind an Ethernet header, with headroom. The loopback interface
#: carries frames far larger than any physical MTU, so anything smaller
#: silently truncates local traffic.
BUFFER_SIZE = 65_550


def capture(interface: str | None) -> Iterator[tuple[bytes, float]]:
    """Yield ``(frame, timestamp)`` pairs from a raw socket, forever.

    Each frame is one freshly allocated, immutable ``bytes`` object —
    never a reused buffer — so frames remain valid for as long as any
    consumer holds them.

    :param interface: Interface to bind to, or ``None`` to capture on
        all interfaces.
    :raises PermissionError: If the process lacks the privileges for a
        raw socket (root or ``CAP_NET_RAW``).
    """
    with socket(PF_PACKET, SOCK_RAW, htons(_ETH_P_ALL)) as sock:
        if interface is not None:
            sock.bind((interface, 0))
        while True:
            yield sock.recv(BUFFER_SIZE), time.time()
