# pgwarden documentation

Start with the [README](../README.md) for the quickstart and the recorded results.

## Guides

| Guide | What it covers |
| --- | --- |
| [Run it on your own database](own-database.md) | bundle roles and RLS, `pgwarden.yaml`, the minimal admin privileges, provisioning and `serve`; CI runs every block in it |
| [Identity providers](identity-providers.md) | generic OIDC, Google, Microsoft Entra ID and GitHub |
| [Configuration reference](configuration.md) | every setting and environment variable, generated from the code |
| [Threat model](threat-model.md) | the OWASP LLM, Agentic and MCP Top 10, mapped to layers and tests |
| [Statement-filter baselines](baselines.md) | the blocklist and the sqlglot allowlist the red-team corpus is compared with |
| [Deploy on Cloud Run](../deploy/terraform/gcp-cloud-run/) | Terraform for Cloud Run and Cloud SQL |
| [Recorded results](results/) | the JSON behind every table in the README |

## Architecture decisions

| ADR | Decision |
| --- | --- |
| [0001](adr/0001-enforce-access-in-the-database.md) | Enforce access in the database, never by parsing SQL |
| [0002](adr/0002-login-role-per-person.md) | One Postgres login role per person, with derived SCRAM credentials |
| [0003](adr/0003-oauth-authorization-server-facade.md) | The gateway is its own OAuth 2.1 authorization server |
| [0004](adr/0004-pooler-mode.md) | No transaction-mode poolers; direct or session-mode connections only |
| [0005](adr/0005-masking-via-views-and-search-path.md) | Column masking through generated views and `search_path` |
| [0006](adr/0006-approval-model.md) | Writes through single-use, time-limited, hash-bound approvals |
| [0007](adr/0007-audit-hash-chain.md) | An append-only, hash-chained audit log, verified independently |
| [0008](adr/0008-cloud-run-and-cloud-sql.md) | Cloud Run and Cloud SQL rather than Fly.io |
| [0009](adr/0009-rate-limits-in-postgres.md) | Rate limits stored in Postgres |
| [0010](adr/0010-mcp-sdk-choice.md) | The official MCP Python SDK for transport and tool registration |
| [0011](adr/0011-in-repo-mock-idp.md) | An in-repo mock OIDC identity provider |
