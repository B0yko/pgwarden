"""Integration tests for the demo `shop` database: load, determinism, content."""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "demo"))

pytestmark = pytest.mark.pg


def with_dbname(dsn: str, dbname: str) -> str:
    parts = urlsplit(dsn)
    return urlunsplit((parts.scheme, parts.netloc, f"/{dbname}", parts.query, ""))


ALLOWED_EMAIL_DOMAINS = {"example.com", "example.org", "example.net"}
PHONE_RE = re.compile(r"^(\+1-202-555-01\d{2}|\+44 7700 900\d{3})$")
CARD_LIKE_RE = re.compile(r"\d{13,19}")

EXPECTED_ROW_COUNTS = {
    "regions": 3,
    "customers": 5000,
    "products": 200,
    "orders": 20000,
    "order_items": 60000,
    "support_tickets": 3000,
}


async def test_load_is_fast(pg_admin_dsn: str) -> None:
    """A load into a *fresh* database takes under 10 s (the demo's own budget)."""
    from load import load_demo_sql

    dbname = "pgw_shop_timing"
    admin = await asyncpg.connect(pg_admin_dsn, timeout=10)
    try:
        await admin.execute(f'DROP DATABASE IF EXISTS "{dbname}"')
        await admin.execute(f'CREATE DATABASE "{dbname}"')
    finally:
        await admin.close()

    start = time.monotonic()
    await load_demo_sql(with_dbname(pg_admin_dsn, dbname))
    elapsed = time.monotonic() - start

    admin = await asyncpg.connect(pg_admin_dsn, timeout=10)
    try:
        await admin.execute(f'DROP DATABASE "{dbname}"')
    finally:
        await admin.close()

    assert elapsed < 10.0


async def test_row_counts(pg_shop_dsn: str) -> None:
    conn = await asyncpg.connect(pg_shop_dsn, timeout=10)
    try:
        counts = {
            table: await conn.fetchval(f"SELECT count(*) FROM {table}")
            for table in EXPECTED_ROW_COUNTS
        }
        payment_methods = await conn.fetchval("SELECT count(*) FROM billing.payment_methods")
    finally:
        await conn.close()
    assert counts == EXPECTED_ROW_COUNTS
    assert payment_methods == 20


async def test_load_is_deterministic(pg_admin_dsn: str) -> None:
    """Loading the same SQL into two fresh databases produces identical data."""
    from load import load_demo_sql

    async def checksum(dbname: str) -> str:
        admin = await asyncpg.connect(pg_admin_dsn, timeout=10)
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{dbname}"')
            await admin.execute(f'CREATE DATABASE "{dbname}"')
        finally:
            await admin.close()
        dsn = with_dbname(pg_admin_dsn, dbname)
        await load_demo_sql(dsn)
        conn = await asyncpg.connect(dsn, timeout=10)
        try:
            value = await conn.fetchval(
                "SELECT md5("
                "  coalesce((SELECT string_agg(c::text, '|' ORDER BY id) FROM customers c), '')"
                "  || '#' ||"
                "  coalesce((SELECT string_agg(p::text, '|' ORDER BY id) FROM products p), '')"
                "  || '#' ||"
                "  coalesce((SELECT string_agg(o::text, '|' ORDER BY id) FROM orders o), '')"
                "  || '#' ||"
                "  coalesce((SELECT string_agg(t::text, '|' ORDER BY id)"
                "  FROM support_tickets t), '')"
                ")"
            )
        finally:
            await conn.close()
        admin = await asyncpg.connect(pg_admin_dsn, timeout=10)
        try:
            await admin.execute(f'DROP DATABASE "{dbname}"')
        finally:
            await admin.close()
        return str(value)

    checksum_a = await checksum("pgw_shop_determinism_a")
    checksum_b = await checksum("pgw_shop_determinism_b")
    assert checksum_a == checksum_b


async def test_customer_emails_and_phones_are_synthetic(pg_shop_dsn: str) -> None:
    conn = await asyncpg.connect(pg_shop_dsn, timeout=10)
    try:
        rows = await conn.fetch("SELECT email, phone FROM customers")
    finally:
        await conn.close()
    assert rows
    for row in rows:
        domain = row["email"].rsplit("@", 1)[-1]
        assert domain in ALLOWED_EMAIL_DOMAINS, row["email"]
        assert PHONE_RE.match(row["phone"]), row["phone"]


async def test_no_card_like_digit_runs_outside_canary_tokens(pg_shop_dsn: str) -> None:
    conn = await asyncpg.connect(pg_shop_dsn, timeout=10)
    try:
        texts = [r["body"] for r in await conn.fetch("SELECT body FROM support_tickets")]
        texts += [r["description"] for r in await conn.fetch("SELECT description FROM products")]
        texts += [r["full_name"] for r in await conn.fetch("SELECT full_name FROM customers")]
        tokens = [r["token"] for r in await conn.fetch("SELECT token FROM billing.payment_methods")]
    finally:
        await conn.close()

    for text in texts:
        for match in CARD_LIKE_RE.finditer(text):
            pytest.fail(f"card-like digit run {match.group()!r} found in: {text!r}")

    assert tokens
    for token in tokens:
        assert token.startswith("CANARY-PM-"), token


async def test_planted_injection_markers(pg_shop_dsn: str) -> None:
    conn = await asyncpg.connect(pg_shop_dsn, timeout=10)
    try:
        ticket_markers = await conn.fetch(
            "SELECT id, region, body FROM support_tickets WHERE body ~ 'PWINJ-' ORDER BY id"
        )
        product_markers = await conn.fetch(
            "SELECT id, description FROM products WHERE description ~ 'PWINJ-' ORDER BY id"
        )
    finally:
        await conn.close()
    assert len(ticket_markers) == 8
    assert len(product_markers) == 4
    assert {r["id"] for r in ticket_markers if r["region"] == "EU"} == {
        2701,
        2702,
        2703,
        2704,
        2705,
        2706,
    }
    assert {r["id"] for r in ticket_markers if r["region"] == "US"} == {1301, 1302}


async def test_fixed_eu_tickets_are_the_newest(pg_shop_dsn: str) -> None:
    conn = await asyncpg.connect(pg_shop_dsn, timeout=10)
    try:
        rows = await conn.fetch(
            "SELECT id FROM support_tickets WHERE region = 'EU' ORDER BY created_at DESC LIMIT 15"
        )
    finally:
        await conn.close()
    newest_ids = {r["id"] for r in rows}
    assert {2701, 2702, 2703, 2704, 2705, 2706}.issubset(newest_ids)
