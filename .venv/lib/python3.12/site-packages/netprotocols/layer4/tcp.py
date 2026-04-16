#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

from ctypes import c_uint16, c_uint32
from typing import Iterator

from netprotocols import Protocol


class TCP(Protocol):                # IETF RFC 793
    _fields_ = [
        ("sport", c_uint16),        # Source port
        ("dport", c_uint16),        # Destination port
        ("seq", c_uint32),          # Sequence number
        ("ack", c_uint32),          # Acknowledgement number
        ("offset", c_uint16, 4),    # Data offset
        ("reserved", c_uint16, 3),  # Reserved field
        ("flags", c_uint16, 9),     # TCP flag codes
        ("window", c_uint16),       # Window size
        ("chksum", c_uint16),       # TCP header checksum
        ("urg", c_uint16),          # Urgent pointer
    ]
    header_len = 32
    flag_names = "FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "NS"

    def __init__(self, *,
                 sport: int,
                 dport: int,
                 seq: int,
                 ack: int,
                 offset: int,
                 reserved: int,
                 flags: int,
                 window: int,
                 chksum: int,
                 urg: int):
        super().__init__()
        self.sport = sport
        self.dport = dport
        self.seq = seq
        self.ack = ack
        self.offset = offset
        self.reserved = reserved
        self.flags = flags
        self.window = window
        self.chksum = chksum
        self.urg = urg

    @property
    def flags_hex_str(self) -> str:
        """
        Gets a string representation of the hexadecimal value of the
        TCP flags set on the segment.
        Ex: '0x018' or '0x010'
        """
        return self.int_to_hex_str(self.flags)

    @property
    def chksum_hex_str(self) -> str:
        """
        Gets a string representation of the hexadecimal value of the
        TCP checksum value set on the header.
        Ex: From 62030 to '0xf24e'
        """
        return self.int_to_hex_str(self.chksum)

    @property
    def flags_str(self) -> str:
        """
        Gets a space-separated string representation of the names of
        the TCP flags set on the segment.
        Ex: 'SYN ACK' or 'PSH ACK'
        """
        '''Yield the least-significant bit of a 9-bit flag value at each 
        iteration until there are no more bits left.'''
        flag_bits: Iterator = ((self.flags >> shift) & 1 for shift in range(9))

        '''Yield the string representation of a flag name if the 
        corresponding bit is set.'''
        flags: Iterator = (flag_name for flag_name, flag_bit in
                           zip(self.flag_names, flag_bits) if flag_bit == 1)
        return " ".join(flags)
