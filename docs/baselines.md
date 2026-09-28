# Statement-filter baselines

These two filters are the comparison behind
[ADR-0001](adr/0001-enforce-access-in-the-database.md). They were written for this
comparison, live only in `src/pgwarden/bench/baselines.py`, and are not part of the
product: pgwarden never parses, rewrites or allowlists SQL.

`pgwarden bench baselines` (needs the `bench` extra) runs the SQL-bearing part of the
red-team corpus through both filters without executing anything: the `query` cases of
categories A to G that must be blocked (88 attacks) and the benign controls that send
SQL (29). The recorded run is in
[results/baselines-2026-09-28.json](results/baselines-2026-09-28.json).

## Baseline 1: keyword/regex blocklist

A statement is rejected if it matches any pattern below (case-insensitive). This is the
shape of filter teams usually write: forbid the words that look dangerous.

```text
\bdrop\b        \bdelete\b      \btruncate\b    \binsert\b      \bupdate\b
\bgrant\b       \brevoke\b      \balter\b       \bcreate\b      \bcopy\b
\bset\s+role\b  \bset\s+session\b
;               --              /\*
\bpg_read_file\b  \blo_import\b  \bpg_sleep\b
```

It wrongly blocks benign controls that contain a semicolon or comment marker inside a
string literal (BENIGN01, BENIGN02) and a harmless `pg_sleep(0.1)` (BENIGN08), and it lets through every attack that does not use one of the listed words
(function-based reads, `LOCK`, `lo_create`, `pg_reload_conf`, cross-region reads, masking
bypasses, resource exhaustion).

## Baseline 2: SELECT-only allowlist on sqlglot

Parses the statement with the `postgres` dialect of sqlglot **30.20.0** (the version
pinned in `uv.lock`) and accepts it only if it is exactly one statement whose root is a
`SELECT` (including a `WITH ... SELECT`). Anything the parser rejects is refused.

It stops stacked statements and plain writes, but every read-shaped attack is a valid
`SELECT`: cross-region reads, masked-column reads, canary-table reads, `pg_sleep`,
`query_to_xml`, `set_config`. It also wrongly refuses plain `EXPLAIN` (BENIGN07) and a
`UNION` of two selects (BENIGN26), whose parse-tree root is not a `SELECT`.

## Result

| Baseline | Attacks it would let through | Benign queries it would wrongly block |
| --- | ---: | ---: |
| keyword/regex blocklist | 54 / 88 | 3 / 29 |
| sqlglot SELECT-only allowlist | 54 / 88 | 2 / 29 |
| pgwarden (database-enforced) | 0 / 88 | 0 / 29 |

The point is not that these filters are badly written: a filter decides from the text of
a statement, and the text does not say what the database will do with it.
