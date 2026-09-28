"""Coerce JSON-decoded query parameters to the types a prepared statement expects.

The MCP `query` tool (a later step) hands this module a JSON-decoded
parameter list (Python ``int``/``float``/``bool``/``str``/``None``/``list``/
``dict``, the only shapes JSON has) and the parameter types the *prepared*
user statement itself reports through ``PreparedStatement.get_parameters()``.
asyncpg's codecs are strict about the Python type they accept per Postgres
type; passing the "obvious" JSON value for several common non-text types
raises ``asyncpg.exceptions.DataError`` instead of converting it. Verified
against asyncpg 0.31 / Postgres 16 by experiment:

- ``date``/``timestamp``/``timestamptz``/``time``/``timetz``: asyncpg
  requires a real :mod:`datetime` object; a plain ISO-8601 string raises
  ``DataError`` ("'str' object has no attribute 'toordinal'" for ``date``).
  Coerced here via ``fromisoformat``.
- ``uuid``: asyncpg's codec already accepts a plain string directly
  (verified) -- no coercion needed.
- ``bytea``: asyncpg requires real ``bytes``; coerced here from a
  base64-encoded string (the same encoding :mod:`pgwarden.db.serialize`
  uses on the way out).
- ``numeric``: asyncpg accepts ``int``/``float``/``Decimal`` directly, but a
  JSON float goes through Python's binary ``float`` first and picks up
  representation error (``3.14`` round-trips as
  ``3.140000000000000124...``). Coerced here via ``Decimal(str(value))`` so
  a JSON number reproduces the exact decimal text the caller wrote.
- ``json``/``jsonb``: asyncpg's default codec requires an already-serialized
  JSON string (``DataError`` on a raw ``dict``); a non-string value is
  re-encoded with :func:`json.dumps` here. A string value is assumed to
  already be JSON text and passed through unchanged.
- ``int2``/``int4``/``int8``/``float4``/``float8``/``bool``/text-like types:
  JSON's native types already match what asyncpg expects; passed through
  unchanged.

For anything else (composite types, ranges, enums, domains, and any
mismatch not listed above, such as a JSON float for an integer column) the
value is passed through unchanged and Postgres reports its own clear type
error -- this module never guesses at an ambiguous conversion.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import json
from collections.abc import Sequence
from decimal import Decimal, InvalidOperation
from typing import Any

from asyncpg.types import Type as PgType

_DATE_TYPES = frozenset({"date"})
_TIMESTAMP_TYPES = frozenset({"timestamp", "timestamptz"})
_TIME_TYPES = frozenset({"time", "timetz"})
_NUMERIC_TYPES = frozenset({"numeric"})
_JSON_TYPES = frozenset({"json", "jsonb"})


def _coerce_scalar(type_name: str, value: Any) -> Any:
    if value is None:
        return value
    if type_name in _DATE_TYPES and isinstance(value, str):
        try:
            return datetime.date.fromisoformat(value)
        except ValueError:
            return value
    if type_name in _TIMESTAMP_TYPES and isinstance(value, str):
        try:
            return datetime.datetime.fromisoformat(value)
        except ValueError:
            return value
    if type_name in _TIME_TYPES and isinstance(value, str):
        try:
            return datetime.time.fromisoformat(value)
        except ValueError:
            return value
    if type_name == "bytea" and isinstance(value, str):
        try:
            return base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error):
            return value
    is_number = isinstance(value, int | float) and not isinstance(value, bool)
    if type_name in _NUMERIC_TYPES and is_number:
        try:
            return Decimal(str(value))
        except InvalidOperation:
            return value
    if type_name in _JSON_TYPES and not isinstance(value, str):
        return json.dumps(value)
    return value


def _coerce_one(pg_type: PgType, value: Any) -> Any:
    if value is None:
        return None
    if pg_type.kind == "array" and isinstance(value, list) and pg_type.name.endswith("[]"):
        elem_name = pg_type.name[:-2]
        return [_coerce_scalar(elem_name, item) for item in value]
    if pg_type.kind == "scalar":
        return _coerce_scalar(pg_type.name, value)
    # composite / range / enum / domain / unknown: pass through, let Postgres error.
    return value


def coerce_params(values: Sequence[Any], param_types: Sequence[PgType]) -> list[Any]:
    """Coerce ``values`` (JSON-decoded) against ``param_types`` (positional).

    A length mismatch between ``values`` and ``param_types`` is not checked
    here: the extra or missing arguments are passed through and asyncpg
    itself raises a clear ``InterfaceError`` for the mismatch when the
    coerced list is bound to the prepared statement.
    """
    coerced: list[Any] = []
    for i, value in enumerate(values):
        if i >= len(param_types):
            coerced.append(value)
            continue
        coerced.append(_coerce_one(param_types[i], value))
    return coerced


__all__ = ["coerce_params"]
