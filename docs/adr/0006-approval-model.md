# ADR-0006: writes through single-use, time-limited, hash-bound approvals

## Status

Accepted.

## Context

Writes must be possible without the assistant ever holding write credentials, and
a human must approve each one. The approval must bind to the exact statement that
was reviewed, and a statement must execute at most once even under crashes or
concurrent calls.

## Decision

`propose_write` validates the statement by asking Postgres — `EXPLAIN (FORMAT JSON)`
as the person's writer role, accepted only if the whole plan tree has exactly one
`ModifyTable` root of Insert/Update/Delete — then stores the exact SQL, parameters
and an HMAC binding over (SQL, parameters, writer role). A configured approver,
who may not be the proposer, approves through a login-gated, CSRF-protected page;
approval creates a single-use grant valid 15 minutes. `execute_approved_write`
checks the caller is the proposer and the binding still matches, then claims the
grant atomically (`UPDATE ... WHERE state = 'approved' AND grant_expires_at > now()
RETURNING`) and writes an audit `started` row in the same state-database
transaction, fail-closed, before running the stored statement as the writer role in
a read-write transaction. More rows than `max_rows` rolls back and fails.

## Consequences

Two concurrent executions resolve to exactly one (the atomic claim); a crash after
the claim leaves the proposal `executing` forever, never re-runnable. Notifications
carry a summary and a signed link only, never SQL or parameters, so PII does not
leak into chat or mailboxes. RLS `WITH CHECK` and table constraints decide the
outcome (a foreign-region write or an over-limit refund fails at execution and is
audited), because the write runs as the person's writer role in the database.
