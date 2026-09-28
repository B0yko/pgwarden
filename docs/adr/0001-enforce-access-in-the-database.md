# ADR-0001: enforce access in the database, never by parsing SQL

## Status

Accepted.

## Context

An MCP gateway to Postgres has to decide what a query is allowed to do. The
tempting approach is to inspect the SQL the assistant sends: a keyword blocklist,
or a parser that only permits `SELECT`. Both fail. A `SELECT` can call a function
that runs other SQL (`query_to_xml`), take locks, change session settings, or read
another table through a join; a text filter cannot know who is asking or which
rows they may see. The public bypass of a reference read-only Postgres MCP server
(`COMMIT; <statement>`, Datadog Security Labs, 2025) is exactly this class of
failure.

## Decision

pgwarden never parses, rewrites or allowlists user SQL. It connects to Postgres
as the person's own login role and lets the database decide: grants, row-level
security keyed on `session_user`, generated masking views, a read-only
transaction, and per-role limits. The read path prepares the user's statement
through the extended protocol (which rejects a second statement at Parse) and
runs it unchanged; the only text pgwarden ever prepends to user SQL is the
`EXPLAIN (FORMAT JSON)` prefix used to validate a proposed write.

## Consequences

The blocking layer is always the database, so the same guarantee holds for SQL
we never thought of. `bench baselines` runs the attack corpus through a keyword
blocklist and a `sqlglot` SELECT-only allowlist for comparison: both let dozens
of attacks through and wrongly block legitimate queries, while pgwarden lets none
through and blocks none — the evidence for this decision. The cost is that
pgwarden depends on the DBA configuring grants, RLS and masking correctly;
`pgwarden doctor` checks the invariants that matter.
