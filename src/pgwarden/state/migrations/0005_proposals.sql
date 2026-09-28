-- The write-approval queue (item 7).
--
-- A proposal moves pending -> approved | rejected | expired; approved ->
-- executing | expired; executing -> executed | failed. Every transition is a
-- guarded UPDATE (WHERE state = <expected>) so two requests can never both win,
-- and every transition is audited. An 'executing' row that never finishes (a
-- crash mid-execution) stays 'executing' and can never run again.
--
-- The stored SQL and parameters are what executes; the caller of
-- execute_approved_write passes only the id. binding_sha256 is an HMAC-SHA256
-- (keyed with the session secret) over (SQL, parameters, writer role), and
-- approved_binding records the value the approver saw; execution recomputes the
-- binding from the stored fields and refuses on any mismatch. Parameters live
-- here because they are needed to execute; they are never written to the audit
-- log and never sent to notification channels.

CREATE TABLE pgwarden.proposals (
    id text PRIMARY KEY,
    state text NOT NULL,
    sql_text text NOT NULL,
    params jsonb NOT NULL,
    binding_sha256 text NOT NULL,
    approved_binding text,
    proposer_subject text NOT NULL,
    proposer_email text,
    pg_role text NOT NULL,
    writer_role text NOT NULL,
    client_id text,
    reason text NOT NULL,
    max_rows integer NOT NULL,
    plan_operation text NOT NULL,
    plan_relation text,
    plan_rows_estimate bigint,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    approver_provider text,
    approver_subject text,
    approver_email text,
    decided_at timestamptz,
    grant_expires_at timestamptz,
    executed_at timestamptz,
    rows_affected bigint,
    error_sqlstate text,
    error text,
    CONSTRAINT proposals_state_valid CHECK (
        state IN ('pending', 'approved', 'rejected', 'expired', 'executing', 'executed', 'failed')
    ),
    CONSTRAINT proposals_operation_valid CHECK (plan_operation IN ('Insert', 'Update', 'Delete')),
    CONSTRAINT proposals_max_rows_valid CHECK (max_rows >= 1)
);

COMMENT ON TABLE pgwarden.proposals IS
    'Write proposals awaiting, or past, human approval (item 7).';

CREATE INDEX proposals_state_idx ON pgwarden.proposals (state, expires_at);
CREATE INDEX proposals_proposer_idx ON pgwarden.proposals (proposer_subject, created_at);
