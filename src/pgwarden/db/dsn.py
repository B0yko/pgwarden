"""DSN helpers shared by the provisioning CLI commands.

``PGWARDEN_ADMIN_DSN`` carries credentials and a host (and port), but its own
database part is never what a command actually needs: `roles sync`,
`masking apply` and `doctor` must land on the database named in
``PGWARDEN_TARGET_DSN``, while `db init` must land on the state database
named in ``PGWARDEN_STATE_DSN`` (via the ``postgres`` maintenance database
first, to create it if missing). One admin DSN then works unchanged for the
compose stack and for Cloud SQL, where the same admin user is valid cluster
wide. Callers swap in the right database name with :func:`with_dbname`.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


def with_dbname(dsn: str, dbname: str) -> str:
    """``dsn`` with its path replaced by ``/dbname``; everything else unchanged."""
    parts = urlsplit(dsn)
    return urlunsplit((parts.scheme, parts.netloc, f"/{dbname}", parts.query, ""))


def dbname_from_dsn(dsn: str) -> str:
    """The database name in ``dsn``'s path, without the leading slash.

    Raises :class:`ValueError` if ``dsn`` does not name a database.
    """
    parts = urlsplit(dsn)
    dbname = parts.path.lstrip("/")
    if not dbname:
        raise ValueError(f"DSN does not name a database (path was {parts.path!r})")
    return dbname


__all__ = ["dbname_from_dsn", "with_dbname"]
