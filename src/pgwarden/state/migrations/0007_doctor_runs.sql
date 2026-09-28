-- Latest `pgwarden doctor --record` results, shown on the admin Health page.
-- doctor runs with the admin DSN (the gateway never does); --record stores the
-- outcome here through the state DSN so the running gateway can display it.
CREATE TABLE pgwarden.doctor_runs (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ran_at timestamptz NOT NULL DEFAULT now(),
    ok boolean NOT NULL,
    results jsonb NOT NULL
);

COMMENT ON TABLE pgwarden.doctor_runs IS
    'Results of `pgwarden doctor --record`, for the admin Health page.';
