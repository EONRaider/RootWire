#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

import re
import socket
from ctypes import (
    Array,
    BigEndianStructure,
    create_string_buffer,
    c_ubyte,
    sizeof
)
from socket import inet_ntop, inet_pton, AF_INET
from typing import Union


class Protocol(BigEndianStructure):
    _pack_ = 1

    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, *args):
        super().__init__()

    def __str__(self):
        return create_string_buffer(sizeof(self))[:]

    @classmethod
    def decode(cls, packet: bytes):
        """Decode a raw network packet into a new instance of the
        protocol."""
        header = cls.from_buffer_copy(packet)
        return header

    @property
    def encapsulated_proto(self) -> Union[None, str]:
        """The string representation of the name of the encapsulated
        protocol. Override as required by the specific protocol being
        implemented."""
        return "undefined"

    @staticmethod
    def hdwr_to_addr_array(hdwr_addr: str) -> Array:
        """
        Convert an IEEE 802 MAC address to c_ubyte array of 6
        bytes.

        Ex: From "00:c0:ca:a8:19:74" to instance of Array with length
        equal to 6.
        """
        mac_to_bytes = b"".join(bytes.fromhex(octet)
                                for octet in re.split("[:-]", hdwr_addr))
        return (c_ubyte * 6)(*mac_to_bytes)

    @staticmethod
    def addr_array_to_hdwr(addr_array: Array) -> str:
        """
        Convert a c_ubyte array of 6 bytes to IEEE 802.3 MAC address.

        Ex: From instance of Array with length equal to 6 to
        "00:c0:ca:a8:19:74".
        """
        return ":".join(format(octet, "02x") for octet in bytes(addr_array))

    @staticmethod
    def proto_addr_to_array(proto_addr: str,
                            addr_family: socket.AddressFamily = AF_INET):
        """
        Convert an IPv4 address string in dotted-decimal notation
        to a c_ubyte array of 4 bytes or an IPv6 address string to a
        c_ubyte array of 16 bytes.

        Ex1: From "185.159.104.91" to instance of Array with length
        equal to 4.

        Ex2: From "fe80::200:86ff:fe05:80da" to instance of Array with
        length equal to 16.
        """
        try:
            addr_to_bytes = inet_pton(addr_family, proto_addr)
        except OSError:
            raise TypeError("Only addresses of family AF_INET and AF_INET6 are "
                            "supported.")
        return (c_ubyte * 4)(*addr_to_bytes) if addr_family == AF_INET else \
            (c_ubyte * 16)(*addr_to_bytes)

    @staticmethod
    def array_to_proto_addr(addr_array: Array,
                            addr_family: socket.AddressFamily = AF_INET) -> str:
        """
        Convert a packed IPv4/IPv6 address array to its RFC 791/2460
        string representation.

        Ex1: From instance of Array with length equal to 4 to
        "185.159.104.91"

        Ex2: From instance of Array with length equal to 16 to
        "fe80::200:86ff:fe05:80da"
        """
        try:
            return inet_ntop(addr_family, bytes(addr_array))
        except OSError:
            raise TypeError("Only addresses of family AF_INET and AF_INET6 are "
                            "supported.")

    @staticmethod
    def int_to_hex_str(number: int) -> str:
        """
        Obtain the string representation of an integer as a hexadecimal
        value.
        Ex: From 62030 to '0xf24e'
        """
        return format(number, "#0{}x".format(5))
