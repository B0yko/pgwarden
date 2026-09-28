"""Integration tests for the append-only, hash-chained audit log and its
tamper tests.

These run against the shared ``pg_state_dsn``; only this module inserts into
``audit_log``, and the one test that deliberately breaks the chain heals it in a
``finally`` so later tests still see an intact chain.
"""

from __future__ import annotations

import datetime as dt
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest

from pgwarden.state.audit import (
    AuditError,
    compute_row_hash,
    export_events,
    hash_params,
    record,
    verify_chain,
)

pytestmark = pytest.mark.pg


def _with_dbname(dsn: str, dbname: str) -> str:
    parts = urlsplit(dsn)
    return urlunsplit((parts.scheme, parts.netloc, f"/{dbname}", parts.query, ""))


async def _seed(conn: asyncpg.Connection, n: int) -> None:
    for i in range(n):
        await record(
            conn,
            event="tool_call",
            outcome="ok",
            request_id=f"req-{i}",
            identity_sub="person:pw_u_alice",
            identity_email="alice@example.com",
            pg_role="pw_u_alice",
            client_id="client-1",
            tool="query",
            sql_text="SELECT 1" if i % 2 == 0 else None,
            params_sha256=hash_params([i]),
            rows_returned=i,
            duration_ms=i * 2,
        )


async def test_chain_verifies_after_records(pg_state_dsn: str) -> None:
    conn = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        await _seed(conn, 5)
        result = await verify_chain(conn)
        assert result.ok, result.detail
        assert result.head_hash is not None and len(result.head_hash) == 64
        assert result.rows_checked >= 5
        # seq is gapless and starts at 1
        seqs = [
            r["seq"] for r in await conn.fetch("SELECT seq FROM pgwarden.audit_log ORDER BY seq")
        ]
        assert seqs == list(range(1, len(seqs) + 1))
    finally:
        await conn.close()


async def test_python_hash_matches_the_sql_trigger(pg_state_dsn: str) -> None:
    """The Python recomputation must equal the hash the SQL trigger stored."""
    conn = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        rec = await record(
            conn,
            event="proposal",
            outcome="started",
            request_id="req-hash",
            sql_text="UPDATE t SET x = $1",
            params_sha256=hash_params(["secret-value"]),
            rows_affected=3,
        )
        row = await conn.fetchrow("SELECT * FROM pgwarden.audit_log WHERE seq = $1", rec.seq)
        assert row is not None
        recomputed = compute_row_hash(bytes(row["prev_hash"]), dict(row))
        assert recomputed == bytes(row["hash"]) == rec.hash
    finally:
        await conn.close()


async def test_verify_is_independent_of_timezone_and_datestyle(pg_state_dsn: str) -> None:
    conn = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        await _seed(conn, 3)
        await conn.execute("SET TimeZone = 'Asia/Kolkata'")
        await conn.execute("SET DateStyle = 'German, DMY'")
        result = await verify_chain(conn)
        assert result.ok, result.detail
    finally:
        await conn.close()


async def test_params_are_never_stored_raw(pg_state_dsn: str) -> None:
    conn = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        rec = await record(
            conn,
            event="tool_call",
            outcome="ok",
            params_sha256=hash_params(["super-secret-token"]),
        )
        row = await conn.fetchrow("SELECT * FROM pgwarden.audit_log WHERE seq = $1", rec.seq)
        assert row is not None
        assert len(row["params_sha256"]) == 64  # a hex sha256
        assert "super-secret-token" not in " ".join(str(v) for v in row.values())
    finally:
        await conn.close()


async def test_update_delete_truncate_disable_trigger_all_fail_as_app(pg_state_dsn: str) -> None:
    conn = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        rec = await record(conn, event="auth", outcome="ok")
        for stmt, args in (
            ("UPDATE pgwarden.audit_log SET outcome = 'denied' WHERE seq = $1", (rec.seq,)),
            ("DELETE FROM pgwarden.audit_log WHERE seq = $1", (rec.seq,)),
            ("TRUNCATE pgwarden.audit_log", ()),
            ("ALTER TABLE pgwarden.audit_log DISABLE TRIGGER audit_assign", ()),
            ("DROP TABLE pgwarden.audit_log", ()),
        ):
            with pytest.raises(asyncpg.PostgresError):
                await conn.execute(stmt, *args)
    finally:
        await conn.close()


async def test_app_role_has_no_update_grant_on_audit_log(pg_state_dsn: str) -> None:
    conn = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        can_update = await conn.fetchval(
            "SELECT has_table_privilege('pgwarden_app', 'pgwarden.audit_log', 'UPDATE')"
        )
        can_insert = await conn.fetchval(
            "SELECT has_table_privilege('pgwarden_app', 'pgwarden.audit_log', 'INSERT')"
        )
        can_select = await conn.fetchval(
            "SELECT has_table_privilege('pgwarden_app', 'pgwarden.audit_log', 'SELECT')"
        )
    finally:
        await conn.close()
    assert can_insert and can_select and not can_update


async def test_superuser_row_edit_is_detected(pg_state_dsn: str, pg_admin_dsn: str) -> None:
    conn = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        await _seed(conn, 3)
        target = await conn.fetchval("SELECT max(seq) FROM pgwarden.audit_log")
    finally:
        await conn.close()

    # As the cluster superuser, rewrite a stored field without recomputing the
    # hash -- the documented residual risk. Restore it afterwards so the shared
    # chain stays intact for later tests.
    admin = await asyncpg.connect(_with_dbname(pg_admin_dsn, "pgw_state"), timeout=5)
    try:
        original = await admin.fetchval(
            "SELECT sql_text FROM pgwarden.audit_log WHERE seq = $1", target
        )
        await admin.execute("ALTER TABLE pgwarden.audit_log DISABLE TRIGGER USER")
        try:
            await admin.execute(
                "UPDATE pgwarden.audit_log SET sql_text = 'TAMPERED' WHERE seq = $1", target
            )

            probe = await asyncpg.connect(pg_state_dsn, timeout=5)
            try:
                result = await verify_chain(probe)
                assert not result.ok
                assert result.first_broken_seq == target
            finally:
                await probe.close()

            await admin.execute(
                "UPDATE pgwarden.audit_log SET sql_text = $2 WHERE seq = $1", target, original
            )
        finally:
            await admin.execute("ALTER TABLE pgwarden.audit_log ENABLE TRIGGER USER")
    finally:
        await admin.close()

    # healed
    conn = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        assert (await verify_chain(conn)).ok
    finally:
        await conn.close()


async def test_export_jsonl_and_csv(pg_state_dsn: str) -> None:
    import json

    conn = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        await _seed(conn, 2)
        jsonl = [line async for line in export_events(conn, since=None, fmt="jsonl")]
        assert jsonl
        parsed = json.loads(jsonl[-1])
        assert {"seq", "event", "outcome", "hash", "prev_hash"} <= parsed.keys()
        int(parsed["hash"], 16)  # hash is hex

        csv_lines = [line async for line in export_events(conn, since=None, fmt="csv")]
        assert csv_lines[0].startswith("id,seq,ts")

        future = dt.datetime(2999, 1, 1, tzinfo=dt.UTC)
        empty = [line async for line in export_events(conn, since=future, fmt="jsonl")]
        assert empty == []
    finally:
        await conn.close()


async def test_record_raises_auditerror_on_failure(pg_state_dsn: str) -> None:
    """Fail-closed: a bad insert raises AuditError (a CHECK violation here)."""
    conn = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        with pytest.raises(AuditError):
            await record(conn, event="not_a_valid_event", outcome="ok")  # type: ignore[arg-type]
    finally:
        await conn.close()
