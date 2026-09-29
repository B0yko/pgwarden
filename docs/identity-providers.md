# Identity providers

pgwarden logs people in through one upstream OIDC (or GitHub OAuth) provider,
configured under `upstream:` in `pgwarden.yaml`. The redirect URI to register at the
provider is always `<public_url>/oauth/callback`. pgwarden never trusts an upstream
token at `/mcp`; it exchanges the upstream login for its own access token
([ADR-0003](adr/0003-oauth-authorization-server-facade.md)).

Identity binding: a config entry is `{subject}`, `{email}` or (Entra) `{oid, tid}`.
Immutable ids (`sub`, the GitHub numeric id, Entra `oid`+`tid`) match directly. An
`{email}` entry matches only when the provider asserts the email verified; on the
first match pgwarden records the immutable id and afterwards refuses the same email
with a different id.

## Generic OIDC

```yaml
upstream:
  name: corp
  preset: oidc
  issuer: https://idp.example.com          # must equal the discovery document's issuer
  discovery_url: https://idp.example.com/.well-known/openid-configuration  # optional
  client_id: pgwarden
  scopes: [openid, email, profile]
```

Register a confidential client with redirect URI `<public_url>/oauth/callback` and
provide its secret in `PGWARDEN_OIDC_CLIENT_SECRET`. The provider must support the
authorization code flow with PKCE (S256). The ID token is validated for signature
(JWKS), `iss`, `aud`, `exp` and `nonce`.

## Google

```yaml
upstream: { name: google, preset: google, issuer: https://accounts.google.com, client_id: "<id>.apps.googleusercontent.com" }
```

Create an OAuth client (type "Web application") in Google Cloud, add the redirect
URI, and set the secret in `PGWARDEN_OIDC_CLIENT_SECRET`. `email_verified` is honoured.
pgwarden does not restrict logins by the `hd` (hosted-domain) claim: only people mapped in
`pgwarden.yaml` get a role, whatever the account's domain.

## Microsoft Entra ID (single tenant)

```yaml
upstream:
  name: entra
  preset: entra
  issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
  tenant_id: <tenant-id>
  client_id: <application-id>
```

Register an application, add the redirect URI, and create a client secret. The
identity is `<tid>:<oid>` from the ID token; the Entra `email` claim is **not**
treated as verified, so use `{oid, tid}` config entries. Only single-tenant Entra is
supported in v0.1.

## GitHub

```yaml
upstream: { name: github, preset: github, issuer: https://github.com, client_id: <oauth-app-client-id> }
```

Register an OAuth app (redirect URI `<public_url>/oauth/callback`) and set the
secret. GitHub OAuth apps are OAuth 2.0 and issue no ID token, so pgwarden takes the
identity from the GitHub user API: the numeric user id and the verified primary
email (scope `user:email`). Match with `{subject: "<numeric id>"}` or a verified
`{email}`.

## Verified at v0.1.0

The demo stack runs against an in-repo mock OIDC provider. The generic-OIDC, Google,
Entra and GitHub presets are covered by unit tests against hand-written, recorded
discovery documents and token/API responses; they have not been exercised against a
live Google/Entra/GitHub tenant in this release.
