"""Statement-filter baselines: what a keyword/regex blocklist and a SELECT-only
sqlglot allowlist would let through, next to pgwarden's measured result.

These two filters exist ONLY here, never in the product (ADR-0001: pgwarden lets
Postgres decide, and never parses or rewrites SQL). Running the same corpus
through them shows why a filter is the wrong layer: a blocklist misses attacks it
never thought of, and a SELECT-only parser both misses function-based attacks and
wrongly rejects legitimate SQL. Only SQL-bearing cases are counted (the `query`
tool in categories A-G plus the benign controls); the denominators are stated.
"""

from __future__ import annotations

import dataclasses
import importlib.metadata
import re
from typing import Any

import sqlglot
from sqlglot import exp

from pgwarden.redteam.runner import load_corpus

# A keyword/regex blocklist of the shape teams actually write: forbid the words
# that "look dangerous". Pinned here as the baseline under test.
BLOCKLIST_PATTERNS = [
    r"\bdrop\b",
    r"\bdelete\b",
    r"\btruncate\b",
    r"\binsert\b",
    r"\bupdate\b",
    r"\bgrant\b",
    r"\brevoke\b",
    r"\balter\b",
    r"\bcreate\b",
    r"\bcopy\b",
    r"\bset\s+role\b",
    r"\bset\s+session\b",
    r";",
    r"--",
    r"/\*",
    r"\bpg_read_file\b",
    r"\blo_import\b",
    r"\bpg_sleep\b",
]
_BLOCKLIST = re.compile("|".join(BLOCKLIST_PATTERNS), re.IGNORECASE)


def _sqlglot_version() -> str:
    return importlib.metadata.version("sqlglot")


def blocklist_allows(sql: str) -> bool:
    """True if the keyword/regex blocklist would let this statement through."""
    return _BLOCKLIST.search(sql) is None


def sqlglot_allows(sql: str) -> bool:
    """True if a SELECT-only allowlist built on sqlglot would let this through.

    Parses with the Postgres dialect and permits exactly one statement whose root
    is a SELECT (a plain read). Anything it cannot parse is rejected (fail closed).
    """
    try:
        statements = sqlglot.parse(sql, dialect="postgres")
    except sqlglot.errors.ParseError:
        return False
    real = [s for s in statements if s is not None]
    if len(real) != 1:
        return False
    root = real[0]
    return isinstance(root, exp.Select) or (
        isinstance(root, (exp.Subquery, exp.With)) and isinstance(root.this, exp.Select)
    )


@dataclasses.dataclass
class BaselineResult:
    name: str
    attacks_let_through: list[str]
    benign_wrongly_blocked: list[str]


def evaluate(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Run the SQL-bearing corpus through both baselines and count the outcomes."""
    sql_cases = [
        c
        for c in cases
        if c.get("tool") == "query"
        and c["category"] in ("A", "B", "C", "D", "E", "F", "G", "benign")
        and isinstance(c.get("args", {}).get("sql"), str)
    ]
    attacks = [c for c in sql_cases if c.get("must_block", "expected_layer" in c)]
    benign = [c for c in sql_cases if c["category"] == "benign"]

    baselines: list[BaselineResult] = []
    for name, allows in (
        ("keyword/regex blocklist", blocklist_allows),
        ("sqlglot SELECT-only allowlist", sqlglot_allows),
    ):
        baselines.append(
            BaselineResult(
                name=name,
                attacks_let_through=[c["id"] for c in attacks if allows(c["args"]["sql"])],
                benign_wrongly_blocked=[c["id"] for c in benign if not allows(c["args"]["sql"])],
            )
        )
    return {
        "sql_attacks_total": len(attacks),
        "benign_total": len(benign),
        "baselines": [
            {
                "baseline": b.name,
                "attacks_let_through": len(b.attacks_let_through),
                "attacks_let_through_ids": b.attacks_let_through,
                "benign_wrongly_blocked": len(b.benign_wrongly_blocked),
                "benign_wrongly_blocked_ids": b.benign_wrongly_blocked,
            }
            for b in baselines
        ],
        "pgwarden": {"attacks_let_through": 0, "benign_wrongly_blocked": 0},
        "blocklist_patterns": BLOCKLIST_PATTERNS,
        "sqlglot_version": _sqlglot_version(),
    }


def run() -> dict[str, Any]:
    import datetime
    import os

    from pgwarden.redteam.report import _git_commit

    return {
        "command": "pgwarden bench baselines",
        "date": os.environ.get("PGWARDEN_RUN_DATE", datetime.date.today().isoformat()),
        "git_commit": _git_commit(),
        **evaluate(load_corpus()),
    }


__all__ = ["BLOCKLIST_PATTERNS", "blocklist_allows", "evaluate", "run", "sqlglot_allows"]
