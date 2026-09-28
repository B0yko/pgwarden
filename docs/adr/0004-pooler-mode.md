# ADR-0004: no transaction-mode poolers; direct or session-mode connections only

## Status

Accepted.

## Context

The read path (item 5) relies on per-connection state that a transaction-mode
pooler (PgBouncer in `pool_mode = transaction`, or a hosted "transaction
pooler" endpoint) does not preserve across statements on what the client
believes is one connection:

- `conn.prepare()` (the extended protocol's Parse) creates a server-side
  prepared statement tied to the *physical* backend connection. A
  transaction-mode pooler can hand a client's next statement to a
  *different* backend, at which point the prepared statement no longer
  exists there.
- `pgwarden.db.pools.PoolManager`'s own release-time reset (`DISCARD ALL`,
  run outside any transaction) assumes it is cleaning the same backend the
  next caller will get. Under transaction-mode pooling the backend a client
  socket maps to can change between transactions, so this reset would clean
  the wrong session, or clean nothing the next caller can see.
- Session-level state the read path's hygiene test exercises on purpose
  (`LISTEN`, advisory locks, a `WITH HOLD` cursor) is tied to the backend
  process, not to the client socket; a transaction-mode pooler can silently
  detach a client from that state between transactions.

## Decision

pgwarden supports direct connections and session-mode pooling only.
Transaction-mode pooling is explicitly out of scope (also stated in the
spec's "Out of scope for v0.1") and is detected, not silently tolerated:
`pgwarden doctor`'s pooler-mode check connects to the target host and port
with a derived person or machine credential -- never the admin DSN -- and:

1. Opens two client connections at once and compares `pg_backend_pid()` on
   each. A direct connection guarantees two distinct backend processes for
   two distinct client connections; a transaction-mode pooler can hand both
   idle client connections the same backend.
2. On one of those connections, compares `pg_backend_pid()` across two
   separate transactions. A direct or session-mode connection keeps the
   same backend for the connection's whole lifetime; a transaction-mode
   pooler can swap backends between transactions on what the client still
   sees as one connection.

A shared or changing backend pid on either check fails the doctor check
with a message pointing back at this document.

### Verified against a real PgBouncer

The failing fixture is a real PgBouncer 1.25.2 (`edoburu/pgbouncer`, pinned
by digest) in `pool_mode = transaction`, `devtools/testpg.sh`'s
`pgwarden-testbouncer` container on `127.0.0.1:55434`, proxying to
`pgwarden-testpg`. Verified by experiment: two concurrent `asyncpg`
connections through the bouncer, both querying `pg_backend_pid()`, returned
the *same* backend pid; two connections opened directly against
`pgwarden-testpg` (no pooler) always returned two *different* pids. The
doctor test (`tests/integration/test_doctor.py`) asserts both outcomes
against the real containers, and skips only when the bouncer fixture is
absent and `PGWARDEN_REQUIRE_PG` is unset (CI starts a PgBouncer container for it).

## Consequences

- Deployments must connect directly to Postgres, or through a session-mode
  pooler (which preserves one physical backend per client connection for
  its lifetime, the same guarantee a direct connection gives). This is
  documented in `docs/own-database.md`.
- The Terraform module (`deploy/terraform/gcp-cloud-run/`) connects through
  the Cloud SQL Auth Proxy's unix socket with Cloud SQL's managed
  connection pooling left disabled -- ADR-0008 records that choice
  explicitly so a future change does not silently reintroduce
  transaction-mode pooling in front of the gateway.
- `pgwarden doctor` is the only place this product talks to Postgres with
  a derived person/machine credential purely to *test* the network path,
  rather than to serve a real request; it deliberately avoids the admin
  DSN for this check so the check reflects exactly what a real `query` call
  would experience.
