"""Python loader for the demo "shop" database, used by the test suite.

Not part of the installable package (``demo/`` is outside the wheel, like
``devtools/``); tests import it by adding this directory to ``sys.path``. It
does the same job as ``demo/load.sh``, in Python, so integration tests can
load the demo data without shelling out to ``psql``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import asyncpg

SQL_DIR = Path(__file__).parent / "sql"


def sql_files() -> list[Path]:
    """The demo SQL files, in the order they are applied."""
    return sorted(SQL_DIR.glob("*.sql"))


async def load_demo_sql(dsn: str) -> None:
    """Apply every file from :func:`sql_files` over one connection, in order.

    Each file is sent as a single multi-statement command (the simple query
    protocol), which is appropriate here because this SQL is the product's
    own trusted demo fixture, never user input; user SQL must never take
    this path (see the read path in ``pgwarden.db``).
    """
    conn = await asyncpg.connect(dsn)
    try:
        for path in sql_files():
            await conn.execute(path.read_text(encoding="utf-8"))
    finally:
        await conn.close()


def sql_checksum() -> str:
    """A SHA-256 over the concatenated bytes of every demo SQL file.

    Two loads from the same checkout apply byte-identical SQL; this is used
    together with a checksum of the loaded data to test that the load is
    deterministic.
    """
    digest = hashlib.sha256()
    for path in sql_files():
        digest.update(path.read_bytes())
    return digest.hexdigest()
