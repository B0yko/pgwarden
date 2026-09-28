-- Row-level security, keyed on session_user via internal.can_see_region().
-- Policies are TO PUBLIC so they also bind pw_masker (the masking views'
-- owner, added in a later step) and writer roles reached through SET ROLE:
-- a session can change current_user but never session_user, so this cannot
-- be bypassed by SET ROLE, SET SESSION AUTHORIZATION or set_config.

ALTER TABLE customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE support_tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE ticket_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE refunds ENABLE ROW LEVEL SECURITY;

CREATE POLICY region_access ON customers
    FOR ALL TO PUBLIC
    USING (internal.can_see_region(region))
    WITH CHECK (internal.can_see_region(region));

CREATE POLICY region_access ON orders
    FOR ALL TO PUBLIC
    USING (internal.can_see_region(region))
    WITH CHECK (internal.can_see_region(region));

CREATE POLICY region_access ON support_tickets
    FOR ALL TO PUBLIC
    USING (internal.can_see_region(region))
    WITH CHECK (internal.can_see_region(region));

CREATE POLICY region_access ON ticket_notes
    FOR ALL TO PUBLIC
    USING (internal.can_see_region(region))
    WITH CHECK (internal.can_see_region(region));

CREATE POLICY region_access ON refunds
    FOR ALL TO PUBLIC
    USING (internal.can_see_region(region))
    WITH CHECK (internal.can_see_region(region));
