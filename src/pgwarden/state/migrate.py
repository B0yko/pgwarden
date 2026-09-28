"""State database migrations: plain ordered SQL files, tracked in ``pgwarden.schema_migrations``.

Each file in ``state/migrations/`` runs once, in filename order, inside its
own transaction, immediately followed by a row recording its version in
``pgwarden.schema_migrations`` -- created by migration ``0001`` itself, so
the very first migration both creates and populates that table in one
transaction. Migration files must not contain their own ``BEGIN``/``COMMIT``:
the transaction boundary is this module's job, not theirs.
"""

from __future__ import annotations

from pathlib import Path

import asyncpg

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def migration_files() -> list[Path]:
    """Migration files in application order (sorted by filename)."""
    return sorted(MIGRATIONS_DIR.glob("*.sql"))


def migration_version(path: Path) -> str:
    """The version string tracked for a migration file: its filename stem."""
    return path.stem


async def applied_versions(conn: asyncpg.Connection) -> set[str]:
    """Versions already recorded, or an empty set on a brand new database."""
    exists = await conn.fetchval("SELECT to_regclass('pgwarden.schema_migrations') IS NOT NULL")
    if not exists:
        return set()
    rows = await conn.fetch("SELECT version FROM pgwarden.schema_migrations")
    return {row["version"] for row in rows}


async def migrate(conn: asyncpg.Connection) -> list[str]:
    """Apply every not-yet-applied migration file, in order.

    Returns the versions newly applied by this call (empty if the database
    was already up to date -- a second run is a no-op).
    """
    applied = await applied_versions(conn)
    newly_applied: list[str] = []
    for path in migration_files():
        version = migration_version(path)
        if version in applied:
            continue
        sql = path.read_text(encoding="utf-8")
        async with conn.transaction():
            await conn.execute(sql)
            await conn.execute(
                "INSERT INTO pgwarden.schema_migrations (version) VALUES ($1)", version
            )
        newly_applied.append(version)
    return newly_applied


__all__ = ["applied_versions", "migrate", "migration_files", "migration_version"]
