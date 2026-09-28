"""The append-only, hash-chained audit log (item 8): recording events,
verifying the chain in pure Python (independently of the SQL trigger), and
exporting it.

The canonical row hash mirrors ``pgwarden.audit_row_hash`` in migration
``0002_audit.sql`` exactly. It must stay in lockstep with that SQL: each field
contributes a fixed 32-byte digest (``sha256`` of its UTF-8 text, or a fixed
sentinel for NULL), concatenated in a fixed order after the previous row's
hash, then hashed. Timestamps are UTC epoch microseconds. Any change here is a
breaking change to the chain format and must be mirrored in the SQL (and the
sentinel string bumped).
"""

from __future__ import annotations

import csv
import dataclasses
import datetime as dt
import hashlib
import io
import json
from collections.abc import AsyncIterator, Sequence
from typing import Any, Literal

import asyncpg

GENESIS_PREV_HASH = bytes(32)
_NULL_SENTINEL = hashlib.sha256(b"pgwarden-audit-null-v1").digest()
_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.UTC)

Event = Literal["tool_call", "auth", "consent", "proposal", "approval", "admin_view"]
Outcome = Literal["ok", "denied", "error", "blocked", "rate_limited", "started"]

#: The audit columns, in the fixed order the hash covers (after prev_hash).
_HASH_FIELDS: tuple[str, ...] = (
    "seq",
    "ts",
    "request_id",
    "event",
    "identity_sub",
    "identity_email",
    "pg_role",
    "client_id",
    "tool",
    "sql_text",
    "params_sha256",
    "rows_returned",
    "rows_affected",
    "duration_ms",
    "outcome",
    "sqlstate",
)

#: Every stored column, for export.
_ALL_COLUMNS: tuple[str, ...] = ("id", *_HASH_FIELDS, "prev_hash", "hash")


class AuditError(RuntimeError):
    """Raised when the audit chain cannot be written or is found broken."""


@dataclasses.dataclass(frozen=True)
class AuditRecord:
    """The identifying result of a recorded event."""

    seq: int
    hash: bytes


@dataclasses.dataclass(frozen=True)
class VerifyResult:
    ok: bool
    rows_checked: int
    head_seq: int | None
    head_hash: str | None
    first_broken_seq: int | None
    detail: str


def _epoch_micros(ts: dt.datetime) -> int:
    """UTC epoch microseconds, computed exactly (no float), matching the SQL."""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.UTC)
    delta = ts.astimezone(dt.UTC) - _EPOCH
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


def _field_text(name: str, value: object) -> str | None:
    """Canonical text for one field (mirrors the SQL casts), or None for NULL."""
    if value is None:
        return None
    if name == "ts":
        assert isinstance(value, dt.datetime)
        return str(_epoch_micros(value))
    if name in ("seq", "rows_returned", "rows_affected", "duration_ms"):
        return str(int(value))  # type: ignore[call-overload]
    return str(value)


def _field_digest(text: str | None) -> bytes:
    if text is None:
        return _NULL_SENTINEL
    return hashlib.sha256(text.encode("utf-8")).digest()


def compute_row_hash(prev_hash: bytes, row: dict[str, object]) -> bytes:
    """Recompute a row's hash from its fields, exactly as the SQL trigger does."""
    parts = bytearray(prev_hash)
    for name in _HASH_FIELDS:
        parts += _field_digest(_field_text(name, row.get(name)))
    return hashlib.sha256(bytes(parts)).digest()


async def record(
    conn: asyncpg.Connection[Any] | asyncpg.pool.PoolConnectionProxy[Any],
    *,
    event: Event,
    outcome: Outcome,
    request_id: str | None = None,
    identity_sub: str | None = None,
    identity_email: str | None = None,
    pg_role: str | None = None,
    client_id: str | None = None,
    tool: str | None = None,
    sql_text: str | None = None,
    params_sha256: str | None = None,
    rows_returned: int | None = None,
    rows_affected: int | None = None,
    duration_ms: int | None = None,
    sqlstate: str | None = None,
) -> AuditRecord:
    """Append one event. The trigger assigns ``seq``, ``prev_hash`` and ``hash``.

    Raises :class:`AuditError` if the insert fails, so a caller can fail closed
    (return an error and no data when the event cannot be recorded).
    """
    try:
        row = await conn.fetchrow(
            "INSERT INTO pgwarden.audit_log ("
            "request_id, event, identity_sub, identity_email, pg_role, client_id, tool, "
            "sql_text, params_sha256, rows_returned, rows_affected, duration_ms, outcome, sqlstate"
            ") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING seq, hash",
            request_id,
            event,
            identity_sub,
            identity_email,
            pg_role,
            client_id,
            tool,
            sql_text,
            params_sha256,
            rows_returned,
            rows_affected,
            duration_ms,
            outcome,
            sqlstate,
        )
    except asyncpg.PostgresError as exc:  # pragma: no cover - exercised via fail-closed test
        raise AuditError(f"audit insert failed: {exc}") from exc
    if row is None:  # pragma: no cover - RETURNING always yields a row on success
        raise AuditError("audit insert returned no row")
    return AuditRecord(seq=int(row["seq"]), hash=bytes(row["hash"]))


def hash_params(params: Sequence[object]) -> str:
    """A stable SHA-256 hex of a parameter list (parameters are never stored raw)."""
    canonical = json.dumps(list(params), default=str, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def verify_chain(conn: asyncpg.Connection) -> VerifyResult:
    """Walk the chain by ``seq`` and report the first broken link, plus the head hash.

    Recomputes every row's hash in Python (not by trusting the stored value or
    the SQL) and checks both that each row's hash is correct and that each row's
    ``prev_hash`` equals the previous row's ``hash``.
    """
    rows = await conn.fetch(
        f"SELECT {', '.join(_ALL_COLUMNS)} FROM pgwarden.audit_log ORDER BY seq ASC"
    )
    if not rows:
        return VerifyResult(True, 0, None, None, None, "audit log is empty")

    prev_hash = GENESIS_PREV_HASH
    expected_seq = 1
    for row in rows:
        seq = int(row["seq"])
        if seq != expected_seq:
            return VerifyResult(
                False,
                expected_seq - 1,
                None,
                None,
                seq,
                f"seq gap: expected {expected_seq}, found {seq}",
            )
        stored_prev = bytes(row["prev_hash"])
        if stored_prev != prev_hash:
            return VerifyResult(False, seq - 1, None, None, seq, f"prev_hash mismatch at seq {seq}")
        recomputed = compute_row_hash(prev_hash, dict(row))
        if recomputed != bytes(row["hash"]):
            return VerifyResult(False, seq - 1, None, None, seq, f"hash mismatch at seq {seq}")
        prev_hash = bytes(row["hash"])
        expected_seq += 1

    head_seq = int(rows[-1]["seq"])
    return VerifyResult(
        True,
        len(rows),
        head_seq,
        prev_hash.hex(),
        None,
        f"chain intact through seq {head_seq}",
    )


async def export_events(
    conn: asyncpg.Connection, *, since: dt.datetime | None, fmt: Literal["jsonl", "csv"]
) -> AsyncIterator[str]:
    """Yield audit rows at or after ``since`` as JSONL or CSV lines (bytea as hex)."""
    if since is None:
        rows = await conn.fetch(
            f"SELECT {', '.join(_ALL_COLUMNS)} FROM pgwarden.audit_log ORDER BY seq ASC"
        )
    else:
        rows = await conn.fetch(
            f"SELECT {', '.join(_ALL_COLUMNS)} FROM pgwarden.audit_log "
            "WHERE ts >= $1 ORDER BY seq ASC",
            since,
        )

    def _jsonable(name: str, value: object) -> object:
        if value is None:
            return None
        if name in ("prev_hash", "hash"):
            assert isinstance(value, (bytes, bytearray, memoryview))
            return bytes(value).hex()
        if isinstance(value, dt.datetime):
            return value.astimezone(dt.UTC).isoformat()
        return value

    if fmt == "jsonl":
        for row in rows:
            record_dict = {name: _jsonable(name, row[name]) for name in _ALL_COLUMNS}
            yield json.dumps(record_dict, separators=(",", ":"))
        return

    header = io.StringIO()
    csv.writer(header).writerow(_ALL_COLUMNS)
    yield header.getvalue().rstrip("\r\n")
    for row in rows:
        buf = io.StringIO()
        csv.writer(buf).writerow([_jsonable(name, row[name]) for name in _ALL_COLUMNS])
        yield buf.getvalue().rstrip("\r\n")


@dataclasses.dataclass(frozen=True)
class AuditFilter:
    """Filters for the admin audit page and its export (all optional, AND-ed)."""

    identity: str | None = None  # matches identity_sub or identity_email, case-insensitive
    tool: str | None = None
    outcome: str | None = None
    event: str | None = None
    since: dt.datetime | None = None
    until: dt.datetime | None = None

    def where(self) -> tuple[str, list[object]]:
        clauses: list[str] = []
        args: list[object] = []

        def add(sql: str, value: object) -> None:
            args.append(value)
            clauses.append(sql.replace("?", f"${len(args)}"))

        if self.identity:
            # both placeholders bind the same parameter
            add("(identity_sub ILIKE ? OR identity_email ILIKE ?)", f"%{self.identity}%")
        if self.tool:
            add("tool = ?", self.tool)
        if self.outcome:
            add("outcome = ?", self.outcome)
        if self.event:
            add("event = ?", self.event)
        if self.since:
            add("ts >= ?", self.since)
        if self.until:
            add("ts < ?", self.until)
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", args


async def query_events(
    conn: asyncpg.Connection[Any] | asyncpg.pool.PoolConnectionProxy[Any],
    flt: AuditFilter,
    *,
    limit: int | None = None,
    offset: int = 0,
    newest_first: bool = True,
) -> list[asyncpg.Record]:
    where, args = flt.where()
    order = "DESC" if newest_first else "ASC"
    sql = f"SELECT {', '.join(_ALL_COLUMNS)} FROM pgwarden.audit_log{where} ORDER BY seq {order}"
    if limit is not None:
        args = [*args, limit, offset]
        sql += f" LIMIT ${len(args) - 1} OFFSET ${len(args)}"
    return list(await conn.fetch(sql, *args))


def _jsonable_value(name: str, value: object) -> object:
    if value is None:
        return None
    if name in ("prev_hash", "hash"):
        assert isinstance(value, (bytes, bytearray, memoryview))
        return bytes(value).hex()
    if isinstance(value, dt.datetime):
        return value.astimezone(dt.UTC).isoformat()
    return value


def format_events(rows: list[asyncpg.Record], fmt: Literal["jsonl", "csv"]) -> str:
    """Render rows as JSON Lines or CSV text (bytea as hex, timestamps in UTC ISO 8601)."""
    if fmt == "jsonl":
        return "".join(
            json.dumps({n: _jsonable_value(n, r[n]) for n in _ALL_COLUMNS}, separators=(",", ":"))
            + "\n"
            for r in rows
        )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_ALL_COLUMNS)
    for r in rows:
        writer.writerow([_jsonable_value(n, r[n]) for n in _ALL_COLUMNS])
    return buf.getvalue()


__all__ = [
    "GENESIS_PREV_HASH",
    "AuditError",
    "AuditFilter",
    "AuditRecord",
    "Event",
    "Outcome",
    "VerifyResult",
    "compute_row_hash",
    "export_events",
    "format_events",
    "hash_params",
    "query_events",
    "record",
    "verify_chain",
]
