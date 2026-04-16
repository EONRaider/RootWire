#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

from ctypes import c_uint16

from netprotocols import Protocol


class UDP(Protocol):          # IETF RFC 768
    _fields_ = [
        ("sport", c_uint16),  # Source port
        ("dport", c_uint16),  # Destination port
        ("len", c_uint16),    # Header length
        ("chksum", c_uint16)  # Header checksum
    ]
    header_len = 8

    def __init__(self, *,
                 sport: int,
                 dport: int,
                 len: int,
                 chksum: int):
        super().__init__()
        self.sport = sport
        self.dport = dport
        self.len = len
        self.chksum = chksum
