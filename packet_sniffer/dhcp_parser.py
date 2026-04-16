#!/usr/bin/env python3
"""
BOOTP/DHCP message parsing for IPv4 (UDP payload).

This module implements a small, explicit decoder for the fixed BOOTP header
(RFC 2131) and a minimal subset of DHCP options (RFC 2132) required for
auditing and anomaly heuristics. It is intentionally independent from live
capture so the same logic can be exercised from PCAP files and unit tests.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# DHCP magic cookie separating the BOOTP fixed fields from option TLVs.
_DHCP_MAGIC = b"\x63\x82\x53\x63"

# Fixed layout of the BOOTP portion (excluding the 4-byte magic cookie).
# See RFC 2131, figure 2 ("Format of a DHCP message").
_BOOTP_STRUCT = struct.Struct("!4B I H H 4s 4s 4s 4s 16s 64s 128s")
_BOOTP_LEN = _BOOTP_STRUCT.size  # 236

# DHCP option codes referenced by the course proposal / audit logic.
OPT_PAD = 0
OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_LEASE_TIME = 51
OPT_SERVER_ID = 54
OPT_MSG_TYPE = 53
OPT_END = 255

# DHCP message types carried in option 53 (single byte).
_MSG_DISCOVER = 1
_MSG_OFFER = 2
_MSG_REQUEST = 3
_MSG_DECLINE = 4
_MSG_ACK = 5
_MSG_NAK = 6
_MSG_RELEASE = 7
_MSG_INFORM = 8

_MSG_TYPE_NAMES: Dict[int, str] = {
    _MSG_DISCOVER: "DISCOVER",
    _MSG_OFFER: "OFFER",
    _MSG_REQUEST: "REQUEST",
    _MSG_DECLINE: "DECLINE",
    _MSG_ACK: "ACK",
    _MSG_NAK: "NAK",
    _MSG_RELEASE: "RELEASE",
    _MSG_INFORM: "INFORM",
}


def _ipv4_to_str(octets: bytes) -> str:
    """Return dotted-quad text for four IPv4 octets."""
    return ".".join(str(b) for b in octets)


def _format_hw_addr(chaddr: bytes, hlen: int) -> str:
    """
    Format the client hardware address field as a colon-separated MAC.

    The BOOTP ``chaddr`` field is 16 bytes; only the first ``hlen`` bytes are
    significant for Ethernet (typically 6). Remaining bytes are commonly zero.
    """
    if hlen <= 0:
        return ""
    segment = chaddr[:hlen]
    return ":".join(f"{b:02x}" for b in segment)


def _decode_ipv4_list(raw: bytes) -> Tuple[str, ...]:
    """
    Decode a DHCP option payload consisting of zero or more IPv4 addresses.

    Options such as Router (3) and DNS (6) encode each address as four bytes;
    the option length must therefore be a multiple of four.
    """
    if len(raw) % 4 != 0:
        raise ValueError("IPv4 list option length must be a multiple of 4")
    return tuple(_ipv4_to_str(raw[i : i + 4]) for i in range(0, len(raw), 4))


@dataclass(frozen=True)
class DhcpMessage:
    """
    Parsed BOOTP/DHCP message with a focused view of common options.

    Attributes correspond to the on-wire BOOTP header plus a curated set of
    options used for auditing (message type, server id, lease time, mask,
    routers, DNS). Unknown options are still preserved in ``raw_options``.
    """

    op: int
    htype: int
    hlen: int
    hops: int
    xid: int
    secs: int
    flags: int
    ciaddr: str
    yiaddr: str
    siaddr: str
    giaddr: str
    chaddr: str
    sname: str
    file: str
    message_type: Optional[int]
    server_identifier: Optional[str]
    subnet_mask: Optional[str]
    routers: Tuple[str, ...]
    dns_servers: Tuple[str, ...]
    lease_time: Optional[int]
    raw_options: Dict[int, bytes] = field(default_factory=dict)

    @property
    def message_type_name(self) -> str:
        """Human-readable DHCP message type from option 53, if present."""
        if self.message_type is None:
            return "UNKNOWN"
        return _MSG_TYPE_NAMES.get(self.message_type, f"TYPE({self.message_type})")

    @property
    def is_relayed(self) -> bool:
        """True when ``giaddr`` is non-zero (likely relay/agent involvement)."""
        return self.giaddr != "0.0.0.0"


def parse_dhcp_options(options_blob: bytes) -> Tuple[Dict[int, bytes], Optional[str]]:
    """
    Parse a DHCP options buffer as TLV triplets until ``OPT_END`` (255).

    :param options_blob: Bytes following the DHCP magic cookie.
    :return: Tuple ``(options_map, error)`` where ``error`` is set on malformed
        encodings (truncated length, missing value bytes, etc.). Partial options
        collected before the fault are still returned to aid debugging.
    """
    opts: Dict[int, bytes] = {}
    idx = 0
    length = len(options_blob)

    while idx < length:
        code = options_blob[idx]
        idx += 1

        if code == OPT_PAD:
            continue
        if code == OPT_END:
            break

        if idx >= length:
            return opts, "option length byte missing (truncated options)"

        opt_len = options_blob[idx]
        idx += 1

        if idx + opt_len > length:
            return opts, f"option {code} value extends past buffer ({opt_len} bytes)"

        value = options_blob[idx : idx + opt_len]
        idx += opt_len
        opts[code] = value

    return opts, None


def parse_dhcp_udp_payload(payload: bytes) -> Tuple[Optional[DhcpMessage], Optional[str]]:
    """
    Decode a UDP payload as BOOTP/DHCP.

    The caller is responsible for ensuring the UDP ports are 67/68; this
    function only validates structural constraints (minimum length, DHCP
    magic cookie, ``hlen`` vs ``chaddr``, and well-formed options).

    :param payload: UDP datagram payload (starts with BOOTP header).
    :return: ``(message, None)`` on success, or ``(None, error_reason)`` on
        failure. Failures are treated as structural anomalies (H3 heuristics).
    """
    if len(payload) < _BOOTP_LEN + len(_DHCP_MAGIC):
        return None, "payload shorter than BOOTP header plus DHCP magic cookie"

    bootp = payload[:_BOOTP_LEN]
    (
        op,
        htype,
        hlen,
        hops,
        xid,
        secs,
        flags,
        ciaddr_b,
        yiaddr_b,
        siaddr_b,
        giaddr_b,
        chaddr,
        sname_b,
        file_b,
    ) = _BOOTP_STRUCT.unpack(bootp)

    if not (1 <= hlen <= 16):
        return None, f"invalid hardware address length hlen={hlen}"

    chaddr_bytes = bytes(chaddr)

    tail = payload[_BOOTP_LEN:]
    if len(tail) < 4:
        return None, "missing DHCP magic cookie after BOOTP header"

    cookie = tail[:4]
    if cookie != _DHCP_MAGIC:
        return None, "invalid DHCP magic cookie (expected 0x63825363)"

    options_blob = tail[4:]
    raw_opts, opt_err = parse_dhcp_options(options_blob)
    if opt_err is not None:
        return None, f"DHCP options malformed: {opt_err}"

    msg_type: Optional[int] = None
    if OPT_MSG_TYPE in raw_opts:
        mt = raw_opts[OPT_MSG_TYPE]
        if len(mt) != 1:
            return None, "option 53 (message type) must be exactly 1 byte"
        msg_type = mt[0]

    server_id: Optional[str] = None
    if OPT_SERVER_ID in raw_opts:
        sid = raw_opts[OPT_SERVER_ID]
        if len(sid) != 4:
            return None, "option 54 (server identifier) must be 4 bytes"
        server_id = _ipv4_to_str(sid)

    subnet_mask: Optional[str] = None
    if OPT_SUBNET_MASK in raw_opts:
        sm = raw_opts[OPT_SUBNET_MASK]
        if len(sm) != 4:
            return None, "option 1 (subnet mask) must be 4 bytes"
        subnet_mask = _ipv4_to_str(sm)

    routers: Tuple[str, ...] = ()
    if OPT_ROUTER in raw_opts:
        try:
            routers = _decode_ipv4_list(raw_opts[OPT_ROUTER])
        except ValueError:
            return None, "option 3 (router) length is not a multiple of 4"

    dns_servers: Tuple[str, ...] = ()
    if OPT_DNS in raw_opts:
        try:
            dns_servers = _decode_ipv4_list(raw_opts[OPT_DNS])
        except ValueError:
            return None, "option 6 (DNS) length is not a multiple of 4"

    lease_time: Optional[int] = None
    if OPT_LEASE_TIME in raw_opts:
        lt = raw_opts[OPT_LEASE_TIME]
        if len(lt) != 4:
            return None, "option 51 (lease time) must be 4 bytes"
        lease_time = int.from_bytes(lt, "big")

    message = DhcpMessage(
        op=op,
        htype=htype,
        hlen=hlen,
        hops=hops,
        xid=xid,
        secs=secs,
        flags=flags,
        ciaddr=_ipv4_to_str(ciaddr_b),
        yiaddr=_ipv4_to_str(yiaddr_b),
        siaddr=_ipv4_to_str(siaddr_b),
        giaddr=_ipv4_to_str(giaddr_b),
        chaddr=_format_hw_addr(chaddr_bytes, hlen),
        sname=sname_b.split(b"\x00", 1)[0].decode(errors="replace"),
        file=file_b.split(b"\x00", 1)[0].decode(errors="replace"),
        message_type=msg_type,
        server_identifier=server_id,
        subnet_mask=subnet_mask,
        routers=routers,
        dns_servers=dns_servers,
        lease_time=lease_time,
        raw_options=dict(raw_opts),
    )
    return message, None


def summarize_message(msg: DhcpMessage) -> str:
    """Return a single-line human summary for logging or JSON previews."""
    parts: List[str] = [
        f"xid=0x{msg.xid:08x}",
        f"type={msg.message_type_name}",
        f"yiaddr={msg.yiaddr}",
    ]
    if msg.server_identifier:
        parts.append(f"server_id={msg.server_identifier}")
    if msg.routers:
        parts.append(f"routers={','.join(msg.routers)}")
    if msg.dns_servers:
        parts.append(f"dns={','.join(msg.dns_servers)}")
    return " ".join(parts)
