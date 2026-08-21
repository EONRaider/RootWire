"""packet_sniffer: monitor network traffic by decoding raw Ethernet
frames with the netprotocols library."""

from packet_sniffer.frame import DecodedFrame

__version__ = "4.0.0"

__all__ = ["DecodedFrame", "__version__"]
