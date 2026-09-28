"""Unit tests for row/value serialization (no Postgres needed).

`row_to_json_safe`/`serialize_rows` only ever index rows by column name
(`row[c.name]`), so a plain dict stands in for `asyncpg.Record` here without
needing a live connection.
"""

from __future__ import annotations

import base64
import datetime
import decimal
import json
import uuid
from typing import Any

import asyncpg

from pgwarden.db.serialize import (
    Column,
    row_to_json_safe,
    serialize_column_value,
    serialize_rows,
    serialize_value,
)


def test_decimal_serialized_as_exact_string() -> None:
    assert serialize_value(decimal.Decimal("3.140000000000000124")) == "3.140000000000000124"


def test_datetime_with_tz_serialized_isoformat() -> None:
    dt = datetime.datetime(2024, 1, 1, 10, 0, tzinfo=datetime.UTC)
    assert serialize_value(dt) == dt.isoformat()


def test_date_serialized_isoformat() -> None:
    assert serialize_value(datetime.date(2024, 1, 1)) == "2024-01-01"


def test_time_serialized_isoformat() -> None:
    assert serialize_value(datetime.time(10, 30)) == "10:30:00"


def test_uuid_serialized_as_string() -> None:
    u = uuid.UUID("123e4567-e89b-12d3-a456-426614174000")
    assert serialize_value(u) == str(u)


def test_bytes_serialized_as_base64() -> None:
    assert serialize_value(b"hello") == base64.b64encode(b"hello").decode("ascii")


def test_array_serialized_recursively() -> None:
    assert serialize_value([1, decimal.Decimal("2.5"), None]) == [1, "2.5", None]


def test_range_serialized_as_object() -> None:
    r = asyncpg.Range(1, 10, lower_inc=True, upper_inc=False)
    out = serialize_value(r)
    assert out == {"lower": 1, "upper": 10, "lower_inc": True, "upper_inc": False, "empty": False}


def test_range_of_dates_serializes_bounds_recursively() -> None:
    r = asyncpg.Range(datetime.date(2024, 1, 1), datetime.date(2024, 6, 1))
    out = serialize_value(r)
    assert out["lower"] == "2024-01-01"
    assert out["upper"] == "2024-06-01"


def test_none_passthrough() -> None:
    assert serialize_value(None) is None


def test_bool_int_str_passthrough() -> None:
    assert serialize_value(True) is True
    assert serialize_value(7) == 7
    assert serialize_value("hi") == "hi"


def test_unknown_type_falls_back_to_str() -> None:
    class Weird:
        def __str__(self) -> str:
            return "weird-value"

    assert serialize_value(Weird()) == "weird-value"


def test_jsonb_column_parsed_back_to_native_json() -> None:
    raw = json.dumps({"a": 1, "b": [1, 2]})
    out = serialize_column_value("jsonb", raw)
    assert out == {"a": 1, "b": [1, 2]}


def test_json_column_invalid_text_falls_back_to_raw_string() -> None:
    out = serialize_column_value("jsonb", "not-json")
    assert out == "not-json"


def test_non_json_column_uses_generic_serialization() -> None:
    assert serialize_column_value("numeric", decimal.Decimal("1.5")) == "1.5"


def test_row_to_json_safe_maps_columns_by_name() -> None:
    columns = [Column(name="id", type="int4"), Column(name="tags", type="jsonb")]
    row: dict[str, Any] = {"id": 1, "tags": json.dumps(["a", "b"])}
    out = row_to_json_safe(row, columns)  # type: ignore[arg-type]
    assert out == {"id": 1, "tags": ["a", "b"]}


def test_serialize_rows_under_cap_returns_all_rows() -> None:
    columns = [Column(name="id", type="int4")]
    rows: list[dict[str, Any]] = [{"id": i} for i in range(5)]
    out, truncated = serialize_rows(rows, columns, max_bytes=10_000)  # type: ignore[arg-type]
    assert len(out) == 5
    assert truncated is False


def test_serialize_rows_over_cap_truncates_and_flags() -> None:
    columns = [Column(name="id", type="int4")]
    rows: list[dict[str, Any]] = [{"id": i} for i in range(100)]
    # Each serialized row is small; pick a cap that only fits a few.
    out, truncated = serialize_rows(rows, columns, max_bytes=40)  # type: ignore[arg-type]
    assert 0 < len(out) < 100
    assert truncated is True


def test_serialize_rows_single_oversized_row_dropped_and_flagged() -> None:
    columns = [Column(name="blob", type="text")]
    rows: list[dict[str, Any]] = [{"blob": "x" * 1000}]
    out, truncated = serialize_rows(rows, columns, max_bytes=50)  # type: ignore[arg-type]
    assert out == []
    assert truncated is True


def test_serialize_rows_empty_input() -> None:
    out, truncated = serialize_rows([], [], max_bytes=100)
    assert out == []
    assert truncated is False
