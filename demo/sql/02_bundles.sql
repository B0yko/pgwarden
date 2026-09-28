-- Bundle roles, created and granted by the "DBA" (this demo), never by
-- pgwarden. All NOLOGIN; pgwarden's own `roles sync` grants them to
-- pw_u_<role>/pw_m_<role> login roles WITH INHERIT TRUE, SET FALSE (or, for
-- a writer role, WITH INHERIT FALSE, SET TRUE).

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'analyst') THEN
        CREATE ROLE analyst NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'support') THEN
        CREATE ROLE support NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'support_writer') THEN
        CREATE ROLE support_writer NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'reporting') THEN
        CREATE ROLE reporting NOLOGIN;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO analyst, support, support_writer, reporting;

-- analyst: products, orders, order items and regions; masked customers is
-- granted later by `pgwarden masking apply` from masking.view_grants, never
-- raw customers; no tickets.
GRANT SELECT ON regions, products, orders, order_items TO analyst;

-- reporting: analyst-like, for machines.
GRANT SELECT ON regions, products, orders, order_items TO reporting;

-- support: raw customers, tickets, notes and orders, all still subject to
-- the region RLS policies below. Listed in masking.raw_access_bundles.
GRANT SELECT ON customers, support_tickets, ticket_notes, orders TO support;

-- support_writer: the write actions, plus exactly the columns its own WHERE
-- clauses use. Its SELECT stays a subset of support's SELECT (support has
-- full-row SELECT on support_tickets; this is narrower).
GRANT SELECT (id, region) ON support_tickets TO support_writer;
GRANT UPDATE (status) ON support_tickets TO support_writer;
GRANT INSERT ON ticket_notes TO support_writer;
GRANT INSERT ON refunds TO support_writer;
