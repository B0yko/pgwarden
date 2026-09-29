# ADR-0008: Cloud Run + Cloud SQL rather than Fly.io

## Status

Accepted. Terraform module written, validated and scanned (see below).
**Not applied to a real project in v0.1**; see "Applied or not" below.

## Context

pgwarden is a single always-on FastAPI process that needs:

- a stable public HTTPS URL, because the OAuth 2.1 authorization server
  facade fixes the token audience and the OAuth redirect URI to that URL,
  and MCP clients (Claude, ChatGPT, Cursor, Inspector) connect to `/mcp`
  over HTTPS;
- a way to store four kinds of secrets (role secret, EdDSA signing key,
  session secret, OIDC client secret) plus optional notifier credentials,
  without putting them in a Docker image or a repository;
- a Postgres connection to both its own state database and the target
  database it governs, ideally without managing a connection pooler
  itself.

The project's local dev/demo environment already runs everything under
Docker Compose. For the "deploy this for real" story, the choice is
between a managed container platform (Fly.io, Cloud Run, Render, ...) and
a self-managed VM/Kubernetes.

## Decision

Google Cloud Run (v2) for the service and the one-shot init job, Cloud SQL
for PostgreSQL 16 for both the state and target databases, Secret Manager
for secrets, all behind one required input, `public_url`.

Reasons, in order of how much they actually drove the decision:

1. **A managed HTTPS URL is not optional here.** Cloud Run gives every
   service a working `https://SERVICE-PROJECT_NUMBER.REGION.run.app` URL
   with a Google-managed certificate the moment it exists, with no load
   balancer, no DNS records and no certificate to provision. Since the
   OAuth audience and redirect URI are fixed at deploy time
   (`public_url`), and since MCP's own security guidance treats a stable,
   TLS-terminated origin as a precondition, this removes an entire class
   of setup steps that a bare VM or a platform without automatic HTTPS
   would need (a reverse proxy, cert renewal, a load balancer resource).
   Fly.io also provides managed HTTPS URLs, so this alone does not
   distinguish the two; the next two points do.

2. **Secret Manager plus the *_FILE convention the app already uses.**
   pgwarden's secrets module reads `PGWARDEN_*_FILE` variants everywhere,
   which map directly onto Cloud Run's native secret volumes and secret
   env vars -- no extra glue, no init container that fetches secrets and
   writes files by hand. Cloud Run additionally distinguishes secret env
   vars (value injected once at container start) and secret volumes
   (files, so a rotated secret version can be picked up without a new
   revision if the app re-reads the file); this module uses volumes only
   for the two secrets whose consumer already expects a path
   (`PGWARDEN_STATE_DSN_FILE`, `PGWARDEN_CONFIG`) and secret env vars for
   the rest, per the file mounts the application defines.

3. **The built-in Cloud SQL connection is a direct connection, not a
   pooler, as long as managed connection pooling stays off.** Cloud Run's
   `cloud_sql_instance` volume type mounts a unix socket
   (`/cloudsql/PROJECT:REGION:INSTANCE`) backed by the Cloud SQL Auth
   Proxy running alongside the container. This is exactly the "direct
   connection" pooler mode ADR-0004 requires: one real backend connection
   per client connection, so the per-person pool's prepared statements and
   `DISCARD ALL` reset still behave the way the read path assumes.
   Verified at build time: Cloud SQL for PostgreSQL does offer **Managed
   Connection Pooling** now (GA), but it is **off by default**, requires
   the **Enterprise Plus** edition, and its default mode is
   *transaction-level* pooling -- which is precisely the mode ADR-0004
   rules out, because a transaction-pooled backend can be handed to a
   different session between statements, breaking per-connection prepared
   statements and session-level `SET`/`DISCARD ALL`. This module never
   sets `settings.connection_pool_config` on `google_sql_database_instance`
   (see the comment in `gcp-cloud-run/sql.tf`), so pooling stays off and
   the unix-socket connection stays direct. A `terraform test` run
   (`tests/service.tftest.hcl`) asserts this stays true.

4. **The public `run.invoker` binding is intentional, not an oversight.**
   Cloud Run's own IAM layer (`roles/run.invoker`) is not where this
   product authenticates callers: pgwarden is itself an OAuth 2.1
   authorization server facade, and every `/mcp` call, every `/approve`
   page and every `/admin` page is already checked against a verified
   Principal or a configured-approver OIDC login at the application layer.
   Requiring a *Google* identity on top of that would not add security (no
   real MCP client or approver has one) and would break the product's own
   auth flow (an MCP client cannot present a Google-signed ID token to
   Cloud Run's front door). The module therefore grants
   `roles/run.invoker` to `allUsers` on the service, and documents it as
   an accepted finding (`.trivyignore` in `deploy/terraform/`) rather than
   hiding it.

## Why not Fly.io

Fly.io was the other real candidate. It was not chosen here because:

- Fly Postgres does not offer an equivalent to Cloud SQL's unix-socket
  auth-proxy integration or Secret Manager's fine-grained per-secret IAM
  (`roles/secretmanager.secretAccessor` scoped to one secret ID); the
  closest equivalents (Fly volumes, `fly secrets`) are coarser-grained (an
  app-wide secret set, not one IAM binding per secret), which would make
  the "service account can never read the admin secret" invariant this
  module tests for harder to express and to verify statically.

This is a build-time engineering trade-off, not a claim that Fly.io is
unsuitable for this kind of service in general.

## Consequences

- Two Cloud SQL Postgres users are provisioned by Terraform itself
  (`google_sql_user`, via the Cloud SQL Admin API, not a direct SQL
  connection): an admin user for the `pgwarden-init` job and a
  `pgwarden_app` user for the running service's state-database
  connection. Both get Terraform-generated passwords.
- Every value Terraform generates (role secret, EdDSA private key PEM,
  session secret, both Postgres passwords, both composed DSNs) is stored
  in the Terraform state file in plaintext, because Terraform must know
  the value to write the Secret Manager version. `deploy/terraform/
  gcp-cloud-run/secrets.tf` documents this explicitly: the module ships no
  backend configuration, and real use must configure a remote backend with
  encryption at rest and state-file access restricted to whoever is
  allowed to see these secrets.
- Raising `max_instance_count` raises the peak number of Postgres
  connections a fully scaled-out deployment can hold open
  (`pool.global_cap x max_instance_count + admin`), so it requires raising
  `max_replicas` in `pgwarden.yaml` and re-running `pgwarden roles sync`
  (which sets each role's `CONNECTION LIMIT`) to keep the two in sync --
  and, for a module-managed instance, may require raising `var.tier` and
  the `max_connections` database flag this module derives from the same
  formula.
- Cloud Run can deploy an image directly from a *public* ghcr.io
  repository, but Google caches such pulls for only up to an hour and
  recommends the Artifact Registry remote-repository proxy path even for
  public images, for availability. This module creates that proxy
  (`google_artifact_registry_repository`, `mode = REMOTE_REPOSITORY`,
  `docker_repository.custom_repository.uri = "https://ghcr.io"`) by
  default and points the default image at it; set
  `use_artifact_registry_proxy = false` to pull straight from ghcr.io
  instead.

## Applied or not

This module was validated and scanned (`terraform fmt`, `validate`,
`test`, `tflint`, `trivy config`) but **not applied to a real GCP project**
in v0.1. `deploy/terraform/check.sh` runs the checks
through pinned Docker images (Terraform 1.16.4, TFLint 0.64.0, Trivy 0.74.0), and CI runs it
on every push. It was not applied because doing so
requires a project and a Google identity; applying it
still needs the operator to supply the OIDC client secret value (Secret
Manager container only, see `secrets.tf`) before the service is reachable.
