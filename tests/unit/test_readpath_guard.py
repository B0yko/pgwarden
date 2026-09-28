"""Static guard: user SQL must only ever reach Postgres through `conn.prepare()`.

`Connection.execute()` called with no bound arguments uses the simple query
protocol, which accepts several semicolon-separated statements -- the exact
bypass a public read-only Postgres MCP server suffered (`COMMIT; <statement>`,
see the spec). This test greps the source of the two modules that ever touch
a live connection with user-supplied SQL and fails if the user-SQL variable
(`sql`) is ever passed to `.execute()`/`.fetch()`/`.fetchval()`/`.fetchrow()`
directly, anywhere but the one allowed `conn.prepare(sql)` call.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
READPATH = REPO_ROOT / "src" / "pgwarden" / "db" / "readpath.py"
POOLS = REPO_ROOT / "src" / "pgwarden" / "db" / "pools.py"

# Any call of one of these methods with `sql` (or `sql,`/`sql)`/`sql ` as the
# first argument -- i.e. the user-SQL variable passed directly.
_FORBIDDEN = re.compile(r"\.(execute|fetch|fetchval|fetchrow)\(\s*sql\b")
_ALLOWED_PREPARE = re.compile(r"\.prepare\(\s*sql\s*[,)]")


def test_user_sql_never_reaches_execute_or_fetch_directly() -> None:
    for path in (READPATH, POOLS):
        text = path.read_text(encoding="utf-8")
        matches = _FORBIDDEN.findall(text)
        assert not matches, f"{path}: user SQL variable passed directly to {matches}"


def test_readpath_does_use_prepare_for_user_sql() -> None:
    # Guards against the check above passing vacuously because `sql` was
    # renamed or the prepare call was removed entirely.
    text = READPATH.read_text(encoding="utf-8")
    assert _ALLOWED_PREPARE.search(text), "expected exactly one conn.prepare(sql) call"


def test_readpath_never_calls_conn_execute_with_the_sql_parameter_by_alias() -> None:
    # A slightly different phrasing of the same guard: no line in readpath.py
    # binds the `sql` parameter to a local variable and then calls execute on
    # it either -- keep this simple by asserting `sql` is never reassigned.
    text = READPATH.read_text(encoding="utf-8")
    assert not re.search(r"^\s*sql\s*=", text, re.MULTILINE), (
        "sql (the user-SQL parameter) must never be reassigned/aliased in readpath.py"
    )


# The write path handles user SQL too: the validator (EXPLAIN prefix + user SQL)
# and the executor (the stored statement). Same rule: prepare() only.
VALIDATE = REPO_ROOT / "src" / "pgwarden" / "approvals" / "validate.py"
SERVICE = REPO_ROOT / "src" / "pgwarden" / "approvals" / "service.py"
_FORBIDDEN_SUBSCRIPT = re.compile(r"\.(execute|fetch|fetchval|fetchrow)\(\s*\w+\[\s*[\"']sql_text")


def test_write_path_user_sql_only_goes_through_prepare() -> None:
    for path in (VALIDATE, SERVICE):
        text = path.read_text(encoding="utf-8")
        assert not _FORBIDDEN.findall(text), f"{path}: user SQL passed to execute/fetch"
        assert not _FORBIDDEN_SUBSCRIPT.findall(text), f"{path}: stored SQL passed to execute/fetch"
    assert re.search(r"\.prepare\(\s*EXPLAIN_PREFIX \+ sql\s*[,)]", VALIDATE.read_text("utf-8"))
    assert _ALLOWED_PREPARE.search(SERVICE.read_text("utf-8"))
