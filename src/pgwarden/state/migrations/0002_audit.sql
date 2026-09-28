-- Append-only, tamper-evident audit log (item 8).
--
-- The table, its trigger functions and its triggers are owned by whoever runs
-- migrations (the admin/migration role), never by pgwarden_app. db init grants
-- pgwarden_app SELECT and INSERT only (the blanket UPDATE grant is revoked for
-- this table in bootstrap.py); a BEFORE UPDATE/DELETE trigger rejects mutation
-- even from the owner, and TRUNCATE is never granted and is blocked by a
-- statement-level trigger too. So the only way to add history is an INSERT,
-- and the only way to rewrite it is to be a superuser (a documented residual
-- risk: export the head hash that `audit verify` prints).
--
-- Hash chain: a BEFORE INSERT trigger takes one transaction-level advisory
-- lock, assigns the next gapless `seq` (the `id` identity default is drawn
-- before the lock and may interleave under load, `seq` may not), then sets
-- hash = sha256(prev_hash || per-field digests). The canonical encoding is
-- independent of every session setting: each field is hashed on its own (fixed
-- 32-byte contribution, so no delimiter or escaping can ever collide), NULL is
-- a fixed sentinel digest, timestamps are UTC epoch microseconds, and the field
-- order is fixed. pgwarden.audit.verify_chain recomputes the exact same value
-- in Python, independently of this SQL.

CREATE TABLE pgwarden.audit_log (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    seq bigint NOT NULL,
    ts timestamptz NOT NULL DEFAULT now(),
    request_id text,
    event text NOT NULL,
    identity_sub text,
    identity_email text,
    pg_role text,
    client_id text,
    tool text,
    sql_text text,
    params_sha256 text,
    rows_returned bigint,
    rows_affected bigint,
    duration_ms bigint,
    outcome text NOT NULL,
    sqlstate text,
    prev_hash bytea NOT NULL,
    hash bytea NOT NULL,
    CONSTRAINT audit_log_seq_unique UNIQUE (seq),
    CONSTRAINT audit_log_event_valid CHECK (
        event IN ('tool_call', 'auth', 'consent', 'proposal', 'approval', 'admin_view')
    ),
    CONSTRAINT audit_log_outcome_valid CHECK (
        outcome IN ('ok', 'denied', 'error', 'blocked', 'rate_limited', 'started')
    )
);

COMMENT ON TABLE pgwarden.audit_log IS
    'Append-only, hash-chained audit log (item 8). INSERT/SELECT only for pgwarden_app.';

-- One field's fixed 32-byte contribution to the row hash. NULL maps to a fixed
-- sentinel digest so a NULL and the empty string are distinguishable, and no
-- value can collide across field boundaries (every field is exactly 32 bytes).
CREATE FUNCTION pgwarden.audit_field_digest(val text) RETURNS bytea
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT CASE
        WHEN val IS NULL THEN sha256(convert_to('pgwarden-audit-null-v1', 'UTF8'))
        ELSE sha256(convert_to(val, 'UTF8'))
    END
$$;

-- The canonical row hash. Argument order is the fixed field order; changing it
-- (or the encoding) is a breaking change to the chain format and must bump the
-- null sentinel string above and the Python mirror in pgwarden.state.audit.
CREATE FUNCTION pgwarden.audit_row_hash(
    prev_hash bytea,
    p_seq bigint,
    p_ts timestamptz,
    p_request_id text,
    p_event text,
    p_identity_sub text,
    p_identity_email text,
    p_pg_role text,
    p_client_id text,
    p_tool text,
    p_sql_text text,
    p_params_sha256 text,
    p_rows_returned bigint,
    p_rows_affected bigint,
    p_duration_ms bigint,
    p_outcome text,
    p_sqlstate text
) RETURNS bytea
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT sha256(
        prev_hash
        || pgwarden.audit_field_digest(p_seq::text)
        || pgwarden.audit_field_digest((extract(epoch from p_ts) * 1000000)::bigint::text)
        || pgwarden.audit_field_digest(p_request_id)
        || pgwarden.audit_field_digest(p_event)
        || pgwarden.audit_field_digest(p_identity_sub)
        || pgwarden.audit_field_digest(p_identity_email)
        || pgwarden.audit_field_digest(p_pg_role)
        || pgwarden.audit_field_digest(p_client_id)
        || pgwarden.audit_field_digest(p_tool)
        || pgwarden.audit_field_digest(p_sql_text)
        || pgwarden.audit_field_digest(p_params_sha256)
        || pgwarden.audit_field_digest(p_rows_returned::text)
        || pgwarden.audit_field_digest(p_rows_affected::text)
        || pgwarden.audit_field_digest(p_duration_ms::text)
        || pgwarden.audit_field_digest(p_outcome)
        || pgwarden.audit_field_digest(p_sqlstate)
    )
$$;

CREATE FUNCTION pgwarden.audit_assign_seq_hash() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_prev_hash bytea;
    v_last_seq bigint;
BEGIN
    -- Serialize chain assignment; the id default was already drawn above.
    PERFORM pg_advisory_xact_lock(4923017423);
    SELECT hash, seq INTO v_prev_hash, v_last_seq
    FROM pgwarden.audit_log
    ORDER BY seq DESC
    LIMIT 1;
    IF NOT FOUND THEN
        v_prev_hash := decode(repeat('0', 64), 'hex');  -- 32 zero bytes: the genesis
        NEW.seq := 1;
    ELSE
        NEW.seq := v_last_seq + 1;
    END IF;
    IF NEW.ts IS NULL THEN
        NEW.ts := now();
    END IF;
    NEW.prev_hash := v_prev_hash;
    NEW.hash := pgwarden.audit_row_hash(
        NEW.prev_hash, NEW.seq, NEW.ts, NEW.request_id, NEW.event,
        NEW.identity_sub, NEW.identity_email, NEW.pg_role, NEW.client_id, NEW.tool,
        NEW.sql_text, NEW.params_sha256, NEW.rows_returned, NEW.rows_affected,
        NEW.duration_ms, NEW.outcome, NEW.sqlstate
    );
    RETURN NEW;
END;
$$;

CREATE FUNCTION pgwarden.audit_reject_change() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'pgwarden.audit_log is append-only; % is not allowed', TG_OP
        USING ERRCODE = 'raise_exception';
END;
$$;

CREATE TRIGGER audit_assign
    BEFORE INSERT ON pgwarden.audit_log
    FOR EACH ROW EXECUTE FUNCTION pgwarden.audit_assign_seq_hash();

CREATE TRIGGER audit_no_update_delete
    BEFORE UPDATE OR DELETE ON pgwarden.audit_log
    FOR EACH ROW EXECUTE FUNCTION pgwarden.audit_reject_change();

CREATE TRIGGER audit_no_truncate
    BEFORE TRUNCATE ON pgwarden.audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION pgwarden.audit_reject_change();
