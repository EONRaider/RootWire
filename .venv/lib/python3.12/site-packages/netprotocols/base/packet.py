#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

from netprotocols import Protocol


class Packet:
    def __init__(self, *protocols):
        for protocol in protocols:
            setattr(self, protocol.__class__.__name__, protocol)

    def __setattr__(self, protocol_name, protocol_class):
        valid_protocols = (cls.__name__ for cls in Protocol.__subclasses__())
        if protocol_name not in valid_protocols:
            raise AttributeError(f"Cannot build packet. Invalid protocol: "
                                 f"{protocol_name}")
        super().__setattr__(protocol_name.lower(), protocol_class)

    def __bytes__(self):
        return b"".join(proto for proto in self.__dict__.values())

    @property
    def payload(self):
        return self.__bytes__()
