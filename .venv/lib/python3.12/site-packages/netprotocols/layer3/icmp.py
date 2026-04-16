#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

from ctypes import c_ubyte, c_uint8, c_uint16

from netprotocols import Protocol


class ICMP(Protocol):
    icmp_types = {}  # Implementation dependent on the protocol version

    @property
    def chksum_hex_str(self) -> str:
        """
        Gets a string representation of the hexadecimal value of the
        ICMP checksum value set on the header.
        Ex: From 62030 to '0xf24e'
        """
        return self.int_to_hex_str(self.chksum)

    @property
    def type_str(self) -> str:
        return self.icmp_types.get(
            self.type, "Unknown, Unassigned or Deprecated")


class ICMPv4(ICMP):             # IETF RFC 792
    _fields_ = [
        ("type", c_uint8),      # Control message type
        ("code", c_uint8),      # Control message subtype
        ("chksum", c_uint16),   # Header checksum
        ("_rest", c_ubyte * 4)  # Rest of header (contents vary)
    ]
    header_len = 8              # Length of the header in bytes
    icmp_types = {
        0: "Echo reply",
        3: "Destination Unreachable",
        4: "Source Quench",
        5: "Redirect Message",
        8: "Echo Request",
        9: "Router Advertisement",
        10: "Router Solicitation",
        11: "Time Exceeded",
        12: "Parameter Problem: Bad IP Header",
        13: "Timestamp",
        14: "Timestamp Reply",
        15: "Information Request",
        16: "Information Reply",
        17: "Address Mask Request",
        18: "Address Mask Reply",
        30: "Traceroute",
        42: "Extended Echo Request",
        43: "Extended Echo Reply"
    }

    def __init__(self, *,
                 type: int,
                 code: int,
                 chksum: int,
                 rest: bytes):
        super().__init__()
        self.type = type
        self.code = code
        self.chksum = chksum
        self.rest = (c_ubyte * 4)(*rest)

    @classmethod
    def decode(cls, packet: bytes):
        header = cls.from_buffer_copy(packet)
        header.rest = bytes(header._rest)
        return header


class ICMPv6(ICMP):               # IETF RFC 4443
    _fields_ = [
        ("type", c_uint8),        # Control message type
        ("code", c_uint8),        # Control message subtype
        ("chksum", c_uint16),     # Header checksum
        ("_m_body", c_ubyte * 4)  # Message body
    ]
    header_len = 8                # Length of the header in bytes
    icmp_types = {
        1: "Destination Unreachable",
        2: "Packet Too Big",
        3: "Time Exceeded",
        4: "Parameter Problem",
        100: "Private Experimentation",
        101: "Private Experimentation",
        127: "Reserved for Expansion of ICMPv6 Error Messages",
        128: "Echo Request",
        129: "Echo Reply",
        130: "Multicast Listener Query",
        131: "Multicast Listener Report",
        132: "Multicast Listener Done",
        133: "Router Solicitation",
        134: "Router Advertisement",
        135: "Neighbor Solicitation",
        136: "Neighbor Advertisement",
        137: "Redirect Message",
        138: "Router Renumbering",
        139: "ICMP Node Information Query",
        140: "ICMP Node Information Response",
        141: "Inverse Neighbor Discovery Solicitation Message",
        142: "Inverse Neighbor Discovery Advertisement Message",
        143: "Multicast Listener Discovery reports",
        144: "Home Agent Address Discovery Request Message",
        145: "Home Agent Address Discovery Reply Message",
        146: "Mobile Prefix Solicitation",
        147: "Mobile Prefix Advertisement",
        148: "Certification Path Solicitation",
        149: "Certification Path Advertisement",
        151: "Multicast Router Advertisement",
        152: "Multicast Router Solicitation",
        153: "Multicast Router Termination",
        155: "RPL Control Message",
        200: "Private Experimentation",
        201: "Private Experimentation",
        255: "Reserved for Expansion of ICMPv6 Informational Messages"
    }

    def __init__(self, *,
                 type: int,
                 code: int,
                 chksum: int,
                 m_body: bytes):
        super().__init__()
        self.type = type
        self.code = code
        self.chksum = chksum
        self.m_body = (c_ubyte * 4)(*m_body)

    @classmethod
    def decode(cls, packet: bytes):
        header = cls.from_buffer_copy(packet)
        header.m_body = bytes(header._m_body)
        return header
