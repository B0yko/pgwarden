"""Unit tests for pgwarden.db.dsn (no Postgres needed).

These are the two functions the item-0 fix relies on: `roles sync`,
`masking apply` and `doctor` build their working DSN as
`with_dbname(admin_dsn, dbname_from_dsn(target_dsn))`, so PGWARDEN_ADMIN_DSN
only ever needs credentials and a host.
"""

from __future__ import annotations

import pytest

from pgwarden.db.dsn import dbname_from_dsn, with_dbname


def test_with_dbname_replaces_the_path_only() -> None:
    dsn = "postgresql://admin:secret@dbhost:5432/whatever?sslmode=verify-full"
    result = with_dbname(dsn, "pgw_shop")
    assert result == "postgresql://admin:secret@dbhost:5432/pgw_shop?sslmode=verify-full"


def test_with_dbname_works_when_admin_dsn_has_no_path() -> None:
    dsn = "postgresql://admin:secret@dbhost:5432"
    result = with_dbname(dsn, "postgres")
    assert result == "postgresql://admin:secret@dbhost:5432/postgres"


def test_dbname_from_dsn_extracts_the_database_name() -> None:
    assert dbname_from_dsn("postgresql://h:5432/pgw_shop?sslmode=disable") == "pgw_shop"


def test_dbname_from_dsn_rejects_a_dsn_with_no_database() -> None:
    with pytest.raises(ValueError, match="does not name a database"):
        dbname_from_dsn("postgresql://h:5432")


def test_with_dbname_then_dbname_from_dsn_round_trips() -> None:
    dsn = "postgresql://admin:secret@dbhost:5432/anything"
    combined = with_dbname(dsn, "target_db")
    assert dbname_from_dsn(combined) == "target_db"


def test_one_admin_dsn_serves_both_the_target_and_the_state_database() -> None:
    # The exact scenario item 0 fixes: PGWARDEN_ADMIN_DSN carries no
    # meaningful database of its own, and each command swaps in the one it
    # actually needs.
    admin_dsn = "postgresql://admin:secret@clusterhost:5432"
    target_dsn = "postgresql://clusterhost:5432/shop?sslmode=verify-full"
    state_dsn = "postgresql://pgwarden_app:x@clusterhost:5432/pgwarden"

    for_roles_sync = with_dbname(admin_dsn, dbname_from_dsn(target_dsn))
    for_db_init = with_dbname(admin_dsn, dbname_from_dsn(state_dsn))

    assert for_roles_sync == "postgresql://admin:secret@clusterhost:5432/shop"
    assert for_db_init == "postgresql://admin:secret@clusterhost:5432/pgwarden"
