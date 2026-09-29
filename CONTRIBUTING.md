# Contributing to pgwarden

Thanks for your interest. pgwarden is a security product, so the bar for changes
is correctness and clear evidence.

## Development setup

```bash
uv sync                       # runtime + dev dependencies
uv run pytest tests/unit -q   # unit tests, no database
devtools/testpg.sh up         # a local Postgres 16 (+ a transaction-mode PgBouncer)
PGWARDEN_TEST_ADMIN_DSN="$(devtools/testpg.sh env | cut -d= -f2-)" uv run pytest -q
```

Integration tests carry the `pg` marker and skip without `PGWARDEN_TEST_ADMIN_DSN`
(set `PGWARDEN_REQUIRE_PG=1` to fail instead). Stack tests carry the `stack` marker
and need `docker compose up -d --wait`. The benchmarks and the LLM run need the
`bench` and API access respectively and are never in default CI.

## Before you open a pull request

Everything below runs in CI and must pass:

```bash
uv run ruff check
uv run ruff format --check
uv run mypy --strict src/
uv run pytest                 # with a Postgres available
uv run pgwarden report --check
```

- Add SQL to the read or write path? Keep user SQL going only through
  `conn.prepare(sql, name=...)`; `tests/unit/test_readpath_guard.py` enforces it.
- Change a config model? Regenerate the docs with `pgwarden report` (CI checks it).
- Add a security-relevant behaviour? Add a red-team case in `src/pgwarden/redteam/`
  with an oracle, and a `doctor` check if it is a deployment invariant.
- Change the look of the README header or the social preview? Edit
  `devtools/screenshots/brand.py` (the mark is `docs/assets/logo.svg`) and run it; the
  README screenshots come from `devtools/screenshots/run.py` against a running stack.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/).

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not open a public issue for a
vulnerability.
