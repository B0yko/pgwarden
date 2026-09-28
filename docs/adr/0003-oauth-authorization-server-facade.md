# ADR-0003: the gateway is its own OAuth 2.1 authorization server

## Status

Accepted.

## Context

MCP clients authenticate to the resource with OAuth 2.1. The gateway must
establish identity, bind tokens to itself, and obtain consent before sending a
browser to the organisation's IdP (the confused-deputy problem the MCP Security
Best Practices describe). Neither MCP SDK's built-in OAuth server is used, so
that audience binding, consent and identity mapping live in one reviewed module.

## Decision

pgwarden is the authorization server for the single resource `<public_url>/mcp`.
Access tokens are its own EdDSA (Ed25519) JWTs, `typ: at+jwt` (RFC 9068), 10-minute
TTL, audience-bound to the canonical MCP URL; the `sub` is a stable principal key
(`person:<role>` / `machine:<name>`), never an email. Refresh tokens are opaque,
hashed, rotated on every use; a family's absolute lifetime is 8 hours from the
upstream login and rotation never extends it, and reuse of a rotated token revokes
the family. The `resource` parameter (RFC 8707) is required on `/authorize` and
`/token` and must equal the canonical URL; a different value is `invalid_target`.
The MCP authorization specification requires clients to send it and MCP Inspector
does (verified in this build), so an absent value is rejected. Other clients,
including Claude Code and Cursor, have not been verified against this gateway. Metadata is served per RFC 9728 and RFC 8414;
CIMD is advertised and preferred, with RFC 7591 dynamic registration kept for
clients that use it. Consent is shown, and the upstream `state` cookie set, only
after the user approves — before the browser is sent upstream.

## Consequences

Token passthrough is impossible: an upstream IdP token is not signed by this
gateway's key and fails at `/mcp`. Offboarding at the IdP takes effect within the
8-hour family lifetime unless the person is suspended or removed from config,
which is a documented limitation. `/.well-known/openid-configuration` is not
served — pgwarden is not an OIDC provider and issues no ID tokens.
