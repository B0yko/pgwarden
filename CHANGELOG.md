# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Upgraded authlib 1.8.0 to 1.9.10 (fixes CVE-2026-96760, CVE-2026-114615,
  CVE-2026-114616, CVE-2026-116672 and the other advisories fixed in 1.9.0/1.9.1),
  joserfc 1.7.5 to 1.8.0 (CVE-2026-119284) and opentelemetry-api 1.45.0 to 1.45.2
  (CVE-2026-126360, GHSA-xcq7-p3pf-p88h). `uv audit` reports no known vulnerabilities.
- Raised the authlib requirement to >=1.9.1 so installs without the lockfile cannot
  resolve a version with these advisories.

### Fixed

- The brand-image checks match the README's cover header again (the light/dark banner
  pair was replaced by the cover on 2026-11-06); `devtools/screenshots/brand.py` renders
  the banners only and no longer overwrites the designed social-preview cover.

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

[Unreleased]: https://github.com/B0yko/pgwarden/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/B0yko/pgwarden/releases/tag/v0.1.0
