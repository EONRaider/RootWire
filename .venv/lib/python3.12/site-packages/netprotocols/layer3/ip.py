#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

from ctypes import c_ubyte, c_uint8, c_uint16, c_uint32
from socket import AF_INET6

from netprotocols import Protocol


class IP(Protocol):
    protocol_numbers = {  # As defined by RFC 790
        0x01: "ICMPv4",
        0x02: "IGMP",
        0x06: "TCP",
        0x11: "UDP",
        0x3a: "ICMPv6"
    }


class IPv4(IP):                    # IETF RFC 791
    _fields_ = [
        ("version", c_uint8, 4),   # Protocol version
        ("ihl", c_uint8, 4),       # Internet header length
        ("dscp", c_uint8, 6),      # Differentiated services code point
        ("ecp", c_uint8, 2),       # Explicit congestion notification
        ("len", c_uint16),         # Total packet length
        ("id", c_uint16),          # Identification
        ("flags", c_uint16, 3),    # Fragmentation control flags
        ("offset", c_uint16, 13),  # Fragment offset
        ("ttl", c_uint8),          # Time to live
        ("proto", c_uint8),        # Encapsulated protocol
        ("chksum", c_uint16),      # Header checksum
        ("_src", c_ubyte * 4),     # Source address
        ("_dst", c_ubyte * 4)      # Destination address
    ]
    header_len = 20                # Length of the header in bytes
    flag_names = {
        0: "Not set",
        1: "More fragments (MF)",
        2: "Don't fragment (DF)"
    }

    def __init__(self, *,
                 version: int,
                 ihl: int,
                 dscp: int,
                 ecp: int,
                 len: int,
                 id: int,
                 flags: int,
                 offset: int,
                 ttl: int,
                 proto: int,
                 chksum: int,
                 src: str,
                 dst: str):
        super().__init__()
        self.version = version
        self.ihl = ihl
        self.dscp = dscp
        self.ecp = ecp
        self.len = len
        self.id = id
        self.flags = flags
        self.offset = offset
        self.ttl = ttl
        self.proto = proto
        self.chksum = chksum
        self.src = self.proto_addr_to_array(src)
        self.dst = self.proto_addr_to_array(dst)

    @classmethod
    def decode(cls, packet: bytes):
        header = cls.from_buffer_copy(packet)
        header.src = cls.array_to_proto_addr(header._src)
        header.dst = cls.array_to_proto_addr(header._dst)
        return header

    @property
    def encapsulated_proto(self) -> str:
        return self.protocol_numbers.get(self.proto, None)

    @property
    def chksum_hex_str(self) -> str:
        """
        Gets a string representation of the hexadecimal value of the
        IP checksum value set on the header.
        Ex: From 62030 to '0xf24e'
        """
        return self.int_to_hex_str(self.chksum)
    
    @property
    def flags_str(self) -> str:
        """
        Gets a string representation of the name of the IP flag set on
        the packet.
        Ex: 'Not set', 'Don't fragment (DF)' or 'More fragments (MF)'
        """
        return self.flag_names.get(self.flags, "Error")


class IPv6(IP):                     # IETF RFC 2460 / 8200
    _fields_ = [
        ("version", c_uint32, 4),   # Protocol version
        ("tclass", c_uint32, 8),    # Traffic class
        ("flabel", c_uint32, 20),   # Flow label
        ("payload_len", c_uint16),  # Payload length
        ("next_header", c_uint8),   # Type of next header
        ("hop_limit", c_uint8),     # Hop limit (replaces IPv4 TTL)
        ("_src", c_ubyte * 16),     # Source address
        ("_dst", c_ubyte * 16)      # Destination address
    ]
    header_len = 40                 # Length of the header in bytes

    def __init__(self, *,
                 version: int,
                 tclass: int,
                 flabel: int,
                 payload_len: int,
                 next_header: int,
                 hop_limit: int,
                 src: str,
                 dst: str):
        super().__init__()
        self.version = version
        self.tclass = tclass
        self.flabel = flabel
        self.payload_len = payload_len
        self.next_header = next_header
        self.hop_limit = hop_limit
        self.src = self.proto_addr_to_array(src, addr_family=AF_INET6)
        self.dst = self.proto_addr_to_array(dst, addr_family=AF_INET6)

    @classmethod
    def decode(cls, packet: bytes):
        header = cls.from_buffer_copy(packet)
        header.src = cls.array_to_proto_addr(header._src, addr_family=AF_INET6)
        header.dst = cls.array_to_proto_addr(header._dst, addr_family=AF_INET6)
        return header

    @property
    def encapsulated_proto(self) -> str:
        return self.protocol_numbers.get(self.next_header, None)

    @property
    def tclass_hex_str(self):
        return self.int_to_hex_str(self.tclass)

    @property
    def flabel_hex_str(self):
        return self.int_to_hex_str(self.flabel)
