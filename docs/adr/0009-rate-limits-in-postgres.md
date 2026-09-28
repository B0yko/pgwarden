# ADR-0009: rate limits stored in Postgres

## Status

Accepted.

## Context

Rate limits must hold across several stateless gateway replicas, so they cannot
live in a single process's memory.

## Decision

Fixed windows are stored in `pgwarden.rate_windows` and bumped with one atomic
`INSERT ... ON CONFLICT DO UPDATE ... RETURNING count`, which is correct across
replicas sharing the state database. The defaults are 60 queries per minute per
identity, 10 proposals per hour per identity, and 20 client registrations per hour
per IP. A rejected call returns a tool error with `retry_after_s` and is audited as
`rate_limited`; concurrency is additionally bounded by the per-person pool and the
role's `CONNECTION LIMIT`.

## Consequences

The 61st query in a minute is rejected even when the calls are spread over two
gateway processes (tested). Fixed windows allow bursts of up to about twice the
limit at a window edge, which is a documented limitation. Old window rows
accumulate; the gateway may prune its own with a periodic delete.
