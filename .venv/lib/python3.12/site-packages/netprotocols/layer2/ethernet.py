#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

from ctypes import c_ubyte, c_uint16

from netprotocols import Protocol


class Ethernet(Protocol):       # IEEE 802.3 standard
    _fields_ = [
        ("_dst", c_ubyte * 6),  # Destination hardware address
        ("_src", c_ubyte * 6),  # Source hardware address
        ("eth", c_uint16)       # Ethertype
    ]
    header_len = 14             # Length of the header in bytes
    ethertypes = {
        0x0806: "ARP",
        0x0800: "IPv4",
        0x86dd: "IPv6"
    }

    def __init__(self, *, dst: str, src: str, eth: int):
        super().__init__()
        self.dst = dst
        self.src = src
        self._dst = self.hdwr_to_addr_array(self.dst)
        self._src = self.hdwr_to_addr_array(self.src)
        self.eth = eth

    @classmethod
    def decode(cls, packet: bytes):
        header = cls.from_buffer_copy(packet)
        header.src = cls.addr_array_to_hdwr(header._src)
        header.dst = cls.addr_array_to_hdwr(header._dst)
        return header

    @property
    def encapsulated_proto(self) -> str:
        return self.ethertypes.get(self.eth, None)
