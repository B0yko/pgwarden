# ADR-0007: an append-only, hash-chained audit log, verified independently

## Status

Accepted.

## Context

Every call must land in an audit log that a compromised runtime cannot rewrite
undetectably, and whose integrity anyone can verify without trusting pgwarden's
own code.

## Decision

`pgwarden.audit_log` is append-only for the runtime role `pgwarden_app` (INSERT
and SELECT only; a BEFORE UPDATE/DELETE trigger raises; TRUNCATE is never granted;
the table and triggers are owned by the migration role). A BEFORE INSERT trigger
takes a transaction-level advisory lock, assigns the next gapless `seq`, and sets
`hash = sha256(prev_hash || per-field digests)` with the built-in `sha256()`. The
canonical encoding is independent of session settings: each field contributes a
fixed 32-byte digest (so no delimiter can collide), NULL is a fixed sentinel,
timestamps are UTC epoch microseconds, field order is fixed. Parameters are never
stored — only their SHA-256. `pgwarden audit verify` recomputes the whole chain in
Python, independently of the SQL, and prints the head hash. Audit is fail-closed:
if the insert fails, the tool returns an error and no data.

## Consequences

A superuser can still rewrite the table and recompute the chain, so the head hash
that `audit verify` prints should be exported somewhere the superuser cannot write;
this is a documented residual risk. The chain verifies after the full test run, the
20-way load test, and from a session with a different `TimeZone` and `DateStyle`. A
row modified as superuser is caught at the first broken link. The audit log stores
SQL text, which may contain literals — also documented.
