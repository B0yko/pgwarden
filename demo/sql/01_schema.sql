-- pgwarden demo database "shop": schema.
--
-- This file (and its siblings in demo/sql/, applied in filename order) plays
-- the part of the DBA's own migrations: pgwarden itself never creates
-- application tables, bundle roles or RLS policies. It is pure SQL with no
-- external dependencies, so it can be replayed against any Postgres 16.

SET client_min_messages = warning;

CREATE SCHEMA IF NOT EXISTS internal;
CREATE SCHEMA IF NOT EXISTS billing;

-- Postgres 15+ already omits this grant on a freshly initialised database;
-- kept explicit so the doctor check holds regardless of cluster history.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE TABLE regions (
    code text PRIMARY KEY
);

CREATE TABLE customers (
    id integer PRIMARY KEY,
    full_name text NOT NULL,
    email text NOT NULL,
    phone text NOT NULL,
    region text NOT NULL REFERENCES regions (code),
    lifetime_value numeric(12, 2) NOT NULL
);

CREATE TABLE products (
    id integer PRIMARY KEY,
    name text NOT NULL,
    description text NOT NULL,
    category text NOT NULL,
    price numeric(10, 2) NOT NULL
);

CREATE TABLE orders (
    id integer PRIMARY KEY,
    customer_id integer NOT NULL REFERENCES customers (id),
    region text NOT NULL REFERENCES regions (code),
    order_date date NOT NULL,
    status text NOT NULL,
    total_amount numeric(12, 2) NOT NULL
);

CREATE TABLE order_items (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    order_id integer NOT NULL REFERENCES orders (id),
    product_id integer NOT NULL REFERENCES products (id),
    quantity integer NOT NULL,
    unit_price numeric(10, 2) NOT NULL
);

CREATE TABLE support_tickets (
    id integer PRIMARY KEY,
    customer_id integer NOT NULL REFERENCES customers (id),
    region text NOT NULL REFERENCES regions (code),
    status text NOT NULL,
    subject text NOT NULL,
    body text NOT NULL,
    created_at timestamptz NOT NULL
);

-- Write targets. Start empty; populated only through the approval queue at
-- runtime (a later build step), never by this loader.
CREATE TABLE ticket_notes (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ticket_id integer NOT NULL REFERENCES support_tickets (id),
    region text NOT NULL,
    note_body text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE refunds (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ticket_id integer NOT NULL REFERENCES support_tickets (id),
    region text NOT NULL,
    amount numeric(10, 2) NOT NULL CHECK (amount <= 500),
    reason text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Canary table: no bundle grants it SELECT, ever. Tokens are fakes, never
-- real card data.
CREATE TABLE billing.payment_methods (
    id integer PRIMARY KEY,
    customer_id integer NOT NULL REFERENCES customers (id),
    token text NOT NULL,
    created_at date NOT NULL
);

-- Feeds internal.can_see_region(). Never exposed to person/machine roles
-- directly; only the SECURITY DEFINER function below may read it.
CREATE TABLE internal.region_access (
    login_role text NOT NULL,
    region text NOT NULL REFERENCES regions (code),
    PRIMARY KEY (login_role, region)
);

-- Looked up by session_user, never by current_user or a settable GUC: a
-- session cannot change session_user, so RLS keyed on it cannot be spoofed
-- by SET ROLE or set_config (see docs/adr/0002-*.md). Fixed search_path
-- prevents search_path hijacking of this SECURITY DEFINER function.
CREATE OR REPLACE FUNCTION internal.can_see_region(p_region text)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = internal, pg_catalog
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM internal.region_access
        WHERE login_role = session_user
          AND region = p_region
    );
$$;

REVOKE ALL ON FUNCTION internal.can_see_region(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION internal.can_see_region(text) TO PUBLIC;

-- ticket_notes.region and refunds.region are derived, never supplied by the
-- writer, so a proposal cannot claim a region other than the ticket's own.
CREATE OR REPLACE FUNCTION internal.copy_ticket_region()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    SELECT region INTO NEW.region FROM support_tickets WHERE id = NEW.ticket_id;
    IF NEW.region IS NULL THEN
        RAISE EXCEPTION 'ticket % does not exist', NEW.ticket_id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER ticket_notes_set_region
    BEFORE INSERT ON ticket_notes
    FOR EACH ROW EXECUTE FUNCTION internal.copy_ticket_region();

CREATE TRIGGER refunds_set_region
    BEFORE INSERT ON refunds
    FOR EACH ROW EXECUTE FUNCTION internal.copy_ticket_region();
