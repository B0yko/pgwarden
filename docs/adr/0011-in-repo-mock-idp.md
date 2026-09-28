# ADR-0011: in-repo mock OIDC identity provider

## Status

Accepted.

## Context

The demo compose stack needs an upstream OIDC provider so the gateway's
authorization-code flow, PKCE, nonce handling and ID-token validation can be
exercised end to end without depending on a real IdP account.

A compose network makes the same service reachable under two different
names: the browser resolves it as `http://localhost:<mock IdP port>` (the
host publishes the container's port), while the gateway container resolves
it as `http://mock-idp:9400` on the compose network. `pgwarden.yaml`
already separates `upstream.issuer` from `upstream.discovery_url` for this
reason: the discovery document's `issuer` and `authorization_endpoint` must
be the browser-facing URL, because the browser follows them directly, while
`token_endpoint`, `jwks_uri` and `userinfo_endpoint` are called
container-to-container and must resolve on the compose network. No public
mock-IdP project serves a discovery document with a split browser/container
URL out of the box, and standing up a general-purpose OSS OIDC server
(Keycloak, Dex, ORY Hydra) for six fixed demo users adds a second heavyweight
service, its own admin API, and its own image to keep patched, for
functionality this repository can express directly against the OIDC
primitives it already implements upstream of.

## Decision

Write a small, standalone FastAPI application at `devtools/mock_idp/`:

- Package-free layout (`app.py`, `templates/`, `users.yaml`, its own pinned
  `requirements.txt` / `pyproject.toml`, its own `Dockerfile`). It does not
  import `pgwarden` and is not part of the `pgwarden` wheel or the
  production gateway image; it ships only in the demo compose stack.
- `MOCK_IDP_ISSUER` (browser-facing) and `MOCK_IDP_INTERNAL_URL`
  (container-facing) are separate settings, mirroring the gateway's
  `issuer` / `discovery_url` split. The discovery document places
  `issuer` and `authorization_endpoint` on the issuer base and
  `token_endpoint`, `jwks_uri` and `userinfo_endpoint` on the internal
  base.
- Standard code flow with PKCE (S256 only), `state` and `nonce`
  passthrough, RS256-signed ID tokens with `kid`, and a `/jwks` endpoint,
  so the gateway's upstream-login code path is exactly the generic-OIDC
  path it would use against a real IdP.
- A user-picker page lists the fixed demo identities and issues a
  single-use, 60-second authorization code with no password prompt — the
  point is to test the gateway's OAuth handling, not to simulate a login
  form.
- It refuses to start unless `MOCK_IDP_DEV_ONLY=1` is set, so it cannot be
  mistaken for, or accidentally deployed as, a real identity provider. The
  guard runs at module import time (before the FastAPI app is built), so
  both `uvicorn app:app` and any direct import fail fast with a clear,
  non-zero exit.

## Consequences

- The demo stack has one more service, but it is small, has no database of
  its own, and its image is not part of what gets published or deployed.
- Because it speaks plain generic OIDC, no gateway code path exists solely
  to talk to the mock IdP; the same discovery/authorize/token/jwks/userinfo
  code that talks to Google, Entra or a real generic OIDC provider talks to
  it, so the demo genuinely exercises the upstream-login implementation.
- The dev-only guard means this service must never be pointed at by a
  non-demo `pgwarden.yaml`; `docs/identity-providers.md` and the compose
  file are the only places its issuer URL appears.
