-- Fixed-window rate limits, stored in the state database so they hold across
-- replicas (item 9). One row per (scope, subject, window_start); the window is
-- a fixed clock-aligned bucket and the count is bumped with a single
-- INSERT ... ON CONFLICT DO UPDATE ... RETURNING, which is atomic across
-- concurrent gateway processes sharing this database.
--
-- Fixed windows admit bursts of up to about twice the limit at a window edge;
-- this is documented in the README's Limitations section.

CREATE TABLE pgwarden.rate_windows (
    scope text NOT NULL,
    subject text NOT NULL,
    window_start timestamptz NOT NULL,
    count integer NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, subject, window_start),
    CONSTRAINT rate_windows_scope_valid CHECK (scope IN ('query', 'proposal', 'registration'))
);

COMMENT ON TABLE pgwarden.rate_windows IS
    'Fixed-window rate-limit counters (item 9), shared across replicas.';

-- An index to make pruning old windows cheap (a periodic DELETE by window_start).
CREATE INDEX rate_windows_window_start_idx ON pgwarden.rate_windows (window_start);
