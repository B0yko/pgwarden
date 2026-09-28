# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-28

The first release: a working MCP gateway for governed Postgres access.

### Added

- OAuth 2.1 authorization-server facade in front of an upstream OIDC provider
  (generic OIDC, Google, Entra, GitHub), with per-client consent, EdDSA access
  tokens, rotating refresh-token families, dynamic client registration and Client
  ID Metadata Documents.
- One Postgres login role per person with SCRAM credentials derived from a secret;
  access enforced by grants, row-level security keyed on `session_user`, and
  generated masking views.
- Stateless MCP server over streamable HTTP with `whoami`, `list_tables`,
  `describe_table`, `query`, and the human-approved write path (`propose_write`,
  `get_proposal`, `execute_approved_write`).
- Append-only, hash-chained audit log with independent verification and export.
- Rate limits stored in Postgres; a server-rendered admin UI and approval page.
- `pgwarden doctor`, a red-team suite with oracle-verified results, statement-filter
  baselines, latency and load benchmarks, an LLM indirect-injection run, a threat
  model, a one-command demo stack, and a Terraform module for Cloud Run + Cloud SQL.

[0.1.0]: https://github.com/B0yko/pgwarden/releases/tag/v0.1.0
