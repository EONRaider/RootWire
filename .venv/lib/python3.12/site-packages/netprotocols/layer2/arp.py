#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = 'EONRaider @ keybase.io/eonraider'


from ctypes import c_ubyte, c_uint8, c_uint16

from netprotocols import Protocol
from netprotocols.layer2.ethernet import Ethernet


class ARP(Protocol):            # IETF RFC 826
    _fields_ = [
        ("htype", c_uint16),    # Hardware type
        ("ptype", c_uint16),    # Protocol type
        ("hlen", c_uint8),      # Hardware length
        ("plen", c_uint8),      # Protocol length
        ("oper", c_uint16),     # Operation code
        ("_sha", c_ubyte * 6),  # Sender hardware address
        ("_spa", c_ubyte * 4),  # Sender protocol address
        ("_tha", c_ubyte * 6),  # Target hardware address
        ("_tpa", c_ubyte * 4),  # Target protocol address
    ]
    header_len = 28             # Length of the header in bytes
    operation_names = {
        1: "request",
        2: "reply"
    }

    def __init__(self, *,
                 htype: int,
                 ptype: int,
                 hlen: int,
                 plen: int,
                 oper: int,
                 sha: str,
                 spa: str,
                 tha: str,
                 tpa: str):
        super().__init__()
        self.htype = htype
        self.ptype = ptype
        self.hlen = hlen
        self.plen = plen
        self.oper = oper
        self.sha = sha
        self.spa = spa
        self.tha = tha
        self.tpa = tpa
        self._sha = self.hdwr_to_addr_array(self.sha)
        self._spa = self.proto_addr_to_array(self.spa)
        self._tha = self.hdwr_to_addr_array(self.tha)
        self._tpa = self.proto_addr_to_array(self.tpa)

    @classmethod
    def decode(cls, packet: bytes):
        header = cls.from_buffer_copy(packet)
        header.sha = cls.addr_array_to_hdwr(header._sha)
        header.spa = cls.array_to_proto_addr(header._spa)
        header.tha = cls.addr_array_to_hdwr(header._tha)
        header.tpa = cls.array_to_proto_addr(header._tpa)
        return header

    @property
    def ptype_hex_str(self) -> str:
        """
        Gets a string representation of the hexadecimal value of the
        EtherType value set on the header.
        Ex: From 2048 to 'IPv4'
        """
        return self.int_to_hex_str(self.ptype)

    @property
    def ptype_str(self):
        """
        Gets a string representation of the name of the EtherType set on
        the packet.
        Ex: 'IPv4'
        """
        return Ethernet.ethertypes.get(self.ptype, "unknown")

    @property
    def oper_str(self):
        """
        Gets a string representation of the name of the operation type
        set on the packet.
        Ex: 'request' or 'reply'
        """
        return self.operation_names.get(self.oper, "Error")
