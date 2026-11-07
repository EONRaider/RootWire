"""Parse ``--decode-as`` overrides into NETProtocols' ``decode_as`` form.

One override is ``TABLE.FIELD=KEY:CLASS``, e.g. ``udp.port=40000:TFTP``:
decode what that table resolves to *KEY* as *CLASS* for this capture, on
top of the default registry. *KEY* is a wire value in any base Python's
``int(x, 0)`` reads (``8080``, ``0x88B5``); *CLASS* is the name of a
decoder NETProtocols exports, in any letter case, or ``none`` to
withhold the key, so it dispatches to nothing (``udp.port=1812:none``
ends the walk at UDP for RADIUS's port).

The table names are NETProtocols' own (:data:`netprotocols.registry.TABLES`):
``ethertype``, ``llc.dsap``, ``llc.snap``, ``ip.proto``, ``ip.proto.v6``,
``udp.port`` and ``tcp.port``. A port table is the one this flag exists
for: a stateless walk reaches TFTP's replies, HTTP on any port and a
service on a non-standard port only when told to.

Everything here is argument validation: :func:`parse_decode_as` raises
:class:`DecodeAsError` with a message fit for ``parser.error``, and the
CLI exits with usage and status 2 as for any other bad argument.
"""

from __future__ import annotations

from collections.abc import Sequence

import netprotocols
from netprotocols import Protocol
from netprotocols.registry import TABLES, WITHHELD, WithheldType

__all__ = ["DecodeAsError", "decoder_names", "parse_decode_as"]

#: The largest key each table's wire field can carry: a 16-bit
#: EtherType or port, an 8-bit DSAP or IP protocol, and SNAP's 24-bit
#: OUI with its 16-bit PID. NETProtocols checks only the two LLC
#: tables' ranges; a port of 70000 would otherwise be accepted and
#: simply never match.
_KEY_MAX = {
    "ethertype": 0xFFFF,
    "llc.dsap": 0xFF,
    "llc.snap": 2**40 - 1,
    "ip.proto": 0xFF,
    "ip.proto.v6": 0xFF,
    "udp.port": 0xFFFF,
    "tcp.port": 0xFFFF,
}

#: The word that withholds a key instead of naming a class.
_WITHHOLD = "none"

#: One override set: table, then key, then class or WITHHELD.
Overrides = dict[str, dict[int, type[Protocol] | WithheldType]]


class DecodeAsError(ValueError):
    """A ``--decode-as`` value that cannot be applied."""


def _decoders() -> dict[str, type[Protocol]]:
    """Every decoder NETProtocols exports at its top level, keyed by its
    lower-cased name: each concrete :class:`~netprotocols.Protocol`
    subclass, ``Protocol`` itself excluded."""
    found: dict[str, type[Protocol]] = {}
    for name in dir(netprotocols):
        candidate = getattr(netprotocols, name)
        if (
            isinstance(candidate, type)
            and issubclass(candidate, Protocol)
            and candidate is not Protocol
        ):
            found[name.lower()] = candidate
    return found


#: Decoders by lower-cased name. Built once: the names are fixed for a
#: given NETProtocols release, and no two differ in letter case alone
#: (``AH``/``AHv6`` and ``VRRP``/``VRRPv6`` differ in more).
_DECODERS = _decoders()


def decoder_names() -> list[str]:
    """The decoder names ``--decode-as`` accepts, sorted, as exported."""
    return sorted(cls.__name__ for cls in _DECODERS.values())


def _split(spec: str) -> tuple[str, str, str]:
    """*spec*'s table, key and class text: split at the first ``=``
    (a table name has none) and then at the last ``:`` (a class name has
    none)."""
    table, equals, rest = spec.partition("=")
    key, colon, name = rest.rpartition(":")
    if not equals or not colon or not table or not key or not name:
        raise DecodeAsError(
            f"--decode-as {spec!r}: expected TABLE=KEY:CLASS, "
            f"e.g. udp.port=40000:TFTP"
        )
    return table.strip(), key.strip(), name.strip()


def _key(spec: str, table: str, text: str) -> int:
    """*text* as a key of *table*: an integer in any base ``int(x, 0)``
    reads, within the range the table's wire field carries."""
    if table not in TABLES:
        raise DecodeAsError(
            f"--decode-as {spec!r}: unknown table {table!r} "
            f"(one of {', '.join(TABLES)})"
        )
    try:
        key = int(text, 0)
    except ValueError:
        raise DecodeAsError(
            f"--decode-as {spec!r}: key {text!r} is not an integer"
        ) from None
    if not 0 <= key <= _KEY_MAX[table]:
        raise DecodeAsError(
            f"--decode-as {spec!r}: key {key} is outside {table}'s "
            f"range 0-{_KEY_MAX[table]:#x}"
        )
    return key


def _decoder(spec: str, name: str) -> type[Protocol] | WithheldType:
    """The decoder named *name*, in any letter case, or
    :data:`~netprotocols.registry.WITHHELD` for ``none``."""
    if name.lower() == _WITHHOLD:
        return WITHHELD
    try:
        return _DECODERS[name.lower()]
    except KeyError:
        raise DecodeAsError(
            f"--decode-as {spec!r}: unknown decoder {name!r} "
            f"(one of {', '.join(decoder_names())}, or none)"
        ) from None


def parse_decode_as(specs: Sequence[str]) -> Overrides:
    """Every ``--decode-as`` value in *specs*, as one override set.

    :param specs: The flag's values, in the order given.
    :returns: ``{table: {key: class or WITHHELD}}``, as
        :func:`netprotocols.decode_frame`'s ``decode_as`` and
        :meth:`~netprotocols.registry.Registry.derive` take it.
    :raises DecodeAsError: on a malformed value, an unknown table or
        decoder, a key outside its table's range, or a table and key
        given twice -- which would otherwise silently keep the last.
    """
    overrides: Overrides = {}
    for spec in specs:
        table, key_text, name = _split(spec)
        key = _key(spec, table, key_text)
        entries = overrides.setdefault(table, {})
        if key in entries:
            raise DecodeAsError(
                f"--decode-as {spec!r}: {table} key {key} is given twice"
            )
        entries[key] = _decoder(spec, name)
    return overrides
