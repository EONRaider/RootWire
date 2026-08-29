"""RootWire: monitor network traffic by decoding raw Ethernet
frames with the netprotocols library.

Formerly known as Packet-Sniffer."""

from rootwire.frame import DecodedFrame

__version__ = "5.0.0"

__all__ = ["DecodedFrame", "__version__"]
