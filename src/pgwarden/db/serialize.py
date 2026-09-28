"""Serialize asyncpg row values to JSON-safe Python primitives, capped by size.

Used only by the read path (:mod:`pgwarden.db.readpath`) to turn
``asyncpg.Record`` rows into the JSON the MCP `query` tool result carries.
Every common asyncpg return type is handled explicitly;
anything else falls back to ``str(value)`` rather than raising, since a
crash on an unanticipated extension type would be worse than a slightly
lossy value.

- ``Decimal`` -> its exact decimal string (never a JSON number: a float
  would reintroduce the representation error ``params.py`` coerces away on
  the way in).
- ``date``/``datetime``/``time`` (naive or tz-aware) -> ``.isoformat()``.
- ``UUID`` -> its string form.
- ``bytes``/``bytearray``/``memoryview`` (``bytea``) -> base64 text.
- ``list``/``tuple`` (Postgres arrays) -> recursively serialized.
- ``asyncpg.Range`` -> ``{"lower", "upper", "lower_inc", "upper_inc",
  "empty"}`` with ``lower``/``upper`` themselves recursively serialized.
- ``json``/``jsonb`` columns -> asyncpg's default codec returns these as a
  raw JSON *string*; :func:`serialize_column_value` parses it back with
  ``json.loads`` so the value is embedded as native JSON in the response
  ("passthrough": no double-encoding), falling back to the raw string if it
  somehow is not valid JSON.
"""

from __future__ import annotations

import base64
import dataclasses
import datetime
import decimal
import json
import uuid
from typing import Any

import asyncpg
from asyncpg import Record

_JSON_COLUMN_TYPES = frozenset({"json", "jsonb"})


@dataclasses.dataclass(frozen=True)
class Column:
    """One result column, as reported by ``PreparedStatement.get_attributes()``."""

    name: str
    type: str


def serialize_value(value: Any) -> Any:
    """Serialize a single Python value asyncpg produced, ignoring column type.

    Used for array elements and ``Range`` bounds, where the column's own
    declared type does not distinguish ``json``/``jsonb`` specially (an
    array or range of JSON is not part of the demo schema; if one shows up,
    its elements fall back through the normal type-based rules below).
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, decimal.Decimal):
        return str(value)
    if isinstance(value, datetime.datetime | datetime.date | datetime.time):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, bytes | bytearray | memoryview):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, asyncpg.Range):
        return {
            "lower": serialize_value(value.lower),
            "upper": serialize_value(value.upper),
            "lower_inc": value.lower_inc,
            "upper_inc": value.upper_inc,
            "empty": value.isempty,
        }
    if isinstance(value, list | tuple):
        return [serialize_value(v) for v in value]
    if isinstance(value, int | float | str):
        return value
    # Composite records, and any other extension type asyncpg might return.
    return str(value)


def serialize_column_value(column_type: str, value: Any) -> Any:
    """Serialize ``value`` for a result column of Postgres type ``column_type``."""
    if value is None:
        return None
    if column_type in _JSON_COLUMN_TYPES and isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return serialize_value(value)


def row_to_json_safe(row: Record, columns: list[Column]) -> dict[str, Any]:
    return {c.name: serialize_column_value(c.type, row[c.name]) for c in columns}


def serialize_rows(
    rows: list[Record], columns: list[Column], max_bytes: int
) -> tuple[list[dict[str, Any]], bool]:
    """Serialize ``rows`` up to ``max_bytes`` of JSON. Returns ``(rows, bytes_truncated)``.

    Rows already fetched (subject to the row cap in :mod:`readpath`) are
    added one at a time; a row that would push the running total over
    ``max_bytes`` stops the loop and sets ``bytes_truncated``. If the very
    first row already exceeds ``max_bytes`` on its own, it is dropped and
    the result has zero rows with ``bytes_truncated=True`` -- pgwarden
    cannot bound a single oversized row without dropping it (the
    "oversized row" residual risk in ``docs/threat-model.md``).

    The byte count is an estimate (each row's own ``json.dumps`` length,
    summed), not a byte-exact count of the final combined array; it is
    exact enough to bound peak response size in practice.
    """
    out: list[dict[str, Any]] = []
    total = 2  # "[" + "]"
    for row in rows:
        obj = row_to_json_safe(row, columns)
        size = len(json.dumps(obj, default=str).encode("utf-8")) + 1  # +1 for a separator
        if total + size > max_bytes:
            return out, True
        total += size
        out.append(obj)
    return out, False


__all__ = [
    "Column",
    "row_to_json_safe",
    "serialize_column_value",
    "serialize_rows",
    "serialize_value",
]
