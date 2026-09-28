# ADR-0005: column masking through generated views and search_path

## Status

Accepted.

## Context

PII columns must not reach the model's context for people who should see only
masked values, and the masking must be enforced by the database, not by
post-processing result sets (which aliases, expressions and `row_to_json` trivially
bypass).

## Decision

`pgwarden masking apply` generates one `security_barrier` view per tagged table in
schema `pw_masked`, selecting from the base table with each tagged column wrapped
in a `pw_fn` masking function (`mask_email`, `mask_phone`, `mask_name`, `redact`,
`pseudonym`). The views are owned by `pw_masker`, a NOLOGIN role that does not own
the base tables, so the base tables' RLS still applies through the view. People
without a raw-access bundle get `pw_masked` first in their `search_path` and no
SELECT on the base table, so `SELECT * FROM customers` returns masked data while
`public.customers` is denied. `pseudonym` is a salted SHA-256 prefix (keeps joins
possible), SECURITY DEFINER with a fixed `search_path`, its salt readable only by
`pw_masker`.

## Consequences

Postgres checks a view's underlying-table privileges against the view owner, so
RLS keyed on `session_user` (TO PUBLIC) is carried through the view rather than
bypassed — verified against the demo. A function call embedded in the view's
SELECT list is, unlike the table, checked against the querying role, so
`masking apply` also grants EXECUTE on each used `pw_fn` function to the bundles
whose view uses it. Masking is all-or-nothing per person (raw or masked view), and
pseudonyms are linkable by design; both are documented limitations. There is no
result-set post-processing anywhere in the product.
