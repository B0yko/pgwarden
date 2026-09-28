"""Unit tests for JSON -> asyncpg parameter coercion (no Postgres needed)."""

from __future__ import annotations

import base64
import datetime
import json
from decimal import Decimal

from asyncpg.types import Type as PgType

from pgwarden.db.params import coerce_params


def _scalar(name: str) -> PgType:
    return PgType(oid=0, name=name, kind="scalar", schema="pg_catalog")


def _array(name: str) -> PgType:
    return PgType(oid=0, name=name, kind="array", schema="pg_catalog")


def test_date_coerced_from_iso_string() -> None:
    out = coerce_params(["2024-01-01"], [_scalar("date")])
    assert out == [datetime.date(2024, 1, 1)]


def test_timestamptz_coerced_from_iso_string() -> None:
    out = coerce_params(["2024-01-01T10:00:00+00:00"], [_scalar("timestamptz")])
    assert out == [datetime.datetime(2024, 1, 1, 10, 0, tzinfo=datetime.UTC)]


def test_time_coerced_from_iso_string() -> None:
    out = coerce_params(["10:30:00"], [_scalar("time")])
    assert out == [datetime.time(10, 30, 0)]


def test_bytea_coerced_from_base64() -> None:
    encoded = base64.b64encode(b"hello").decode("ascii")
    out = coerce_params([encoded], [_scalar("bytea")])
    assert out == [b"hello"]


def test_numeric_from_float_uses_exact_decimal_text() -> None:
    out = coerce_params([3.14], [_scalar("numeric")])
    assert out == [Decimal("3.14")]


def test_numeric_from_int() -> None:
    out = coerce_params([3], [_scalar("numeric")])
    assert out == [Decimal("3")]


def test_numeric_from_already_decimal_like_string_passes_through() -> None:
    # A JSON string for a numeric param is not one of the documented
    # coercions; it passes through unchanged (Postgres/asyncpg errors).
    out = coerce_params(["3.14"], [_scalar("numeric")])
    assert out == ["3.14"]


def test_jsonb_dict_encoded_to_json_text() -> None:
    out = coerce_params([{"a": 1}], [_scalar("jsonb")])
    assert out == [json.dumps({"a": 1})]


def test_jsonb_string_passed_through_as_already_json() -> None:
    out = coerce_params(['{"a": 1}'], [_scalar("json")])
    assert out == ['{"a": 1}']


def test_json_list_encoded() -> None:
    out = coerce_params([[1, 2, 3]], [_scalar("jsonb")])
    assert out == [json.dumps([1, 2, 3])]


def test_uuid_string_passes_through_unchanged() -> None:
    # asyncpg's own uuid codec accepts a plain string; no coercion needed.
    out = coerce_params(["123e4567-e89b-12d3-a456-426614174000"], [_scalar("uuid")])
    assert out == ["123e4567-e89b-12d3-a456-426614174000"]


def test_int_bool_str_none_pass_through_unchanged() -> None:
    types = [_scalar("int4"), _scalar("bool"), _scalar("text"), _scalar("int4")]
    out = coerce_params([7, True, "hello", None], types)
    assert out == [7, True, "hello", None]


def test_none_passes_through_for_any_type() -> None:
    out = coerce_params([None], [_scalar("date")])
    assert out == [None]


def test_ambiguous_bool_for_int_passes_through_unchanged() -> None:
    # Documented as ambiguous: pgwarden does not guess, Postgres errors.
    out = coerce_params([True], [_scalar("int4")])
    assert out == [True]


def test_ambiguous_float_for_int_passes_through_unchanged() -> None:
    out = coerce_params([3.0], [_scalar("int4")])
    assert out == [3.0]


def test_invalid_iso_date_string_passes_through_unchanged() -> None:
    out = coerce_params(["not-a-date"], [_scalar("date")])
    assert out == ["not-a-date"]


def test_int_array_elements_coerced_recursively() -> None:
    out = coerce_params([[1, 2, 3]], [_array("int4[]")])
    assert out == [[1, 2, 3]]


def test_date_array_elements_coerced_from_iso_strings() -> None:
    out = coerce_params([["2024-01-01", "2024-06-15"]], [_array("date[]")])
    assert out == [[datetime.date(2024, 1, 1), datetime.date(2024, 6, 15)]]


def test_non_list_value_for_array_type_passes_through() -> None:
    out = coerce_params(["not-a-list"], [_array("int4[]")])
    assert out == ["not-a-list"]


def test_composite_kind_passes_through_unchanged() -> None:
    weird = PgType(oid=0, name="mytype", kind="composite", schema="public")
    out = coerce_params([{"x": 1}], [weird])
    assert out == [{"x": 1}]


def test_extra_values_beyond_declared_types_pass_through() -> None:
    out = coerce_params([1, "2024-01-01"], [_scalar("int4")])
    assert out == [1, "2024-01-01"]
