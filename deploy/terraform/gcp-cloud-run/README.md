# gcp-cloud-run

Terraform module that deploys pgwarden to Google Cloud Run (v2) with Cloud
SQL for PostgreSQL 16, Secret Manager and (by default) an Artifact
Registry proxy for its ghcr.io image. See
`docs/adr/0008-cloud-run-and-cloud-sql.md` for why this shape was chosen,
and `deploy/terraform/examples/minimal/` for a runnable example.

**Validated and scanned, not applied in v0.1.** `terraform fmt`,
`validate`, `test` (mock providers, no credentials), `tflint` and `trivy
config` all run clean through pinned Docker images (`deploy/terraform/check.sh`;
the image versions are pinned at the top of that script). The module has not
been applied to a real Google Cloud project.

## What it creates

- Two service accounts: one for the running Cloud Run service
  (`roles/cloudsql.client` + `secretAccessor` on its own runtime secrets
  only), one for the `pgwarden-init` job (also `cloudsql.client`, plus
  `secretAccessor` on the role secret, the admin DSN and the config --
  nothing else). The service account never has access to the admin DSN
  secret; `tests/service.tftest.hcl` asserts this.
- A Cloud SQL for PostgreSQL 16 instance (unless `create_sql_instance =
  false`): deletion protection, backups with point-in-time recovery,
  `ssl_mode = ENCRYPTED_ONLY`, no `authorized_networks` entries, and a
  `max_connections` database flag sized as `pool_global_cap x
  max_instance_count + admin_reserve_connections`. Managed connection
  pooling is never configured (see the comment in `sql.tf` and ADR-0008).
- The `pgwarden` state database, the target database (unless
  `manage_target_database = false`), and two Postgres users provisioned
  through the Cloud SQL Admin API with Terraform-generated passwords: an
  admin user for the init job and `pgwarden_app` for the running service.
- Nine Secret Manager secrets: role secret, EdDSA signing key, session
  secret, OIDC client secret (container only -- add the value yourself),
  optional Slack webhook URL and SMTP URL (container only, off by
  default), the state DSN, the admin DSN, and `pgwarden.yaml`.
- The Cloud Run v2 service: Cloud SQL unix-socket volume at `/cloudsql`,
  `pgwarden.yaml` and the state DSN mounted from secret volumes,
  everything else as secret env vars, `/healthz` as the startup probe and
  `/readyz` as the liveness probe (Cloud Run v2 has no separate readiness
  probe type), container port 8080, scaling 0..`max_instance_count`, and
  a public `roles/run.invoker` binding (intentional -- see ADR-0008).
- The `pgwarden-init` Cloud Run job, which runs `pgwarden db init &&
  pgwarden roles sync && pgwarden masking apply` with the admin DSN. It is
  the only resource that ever references the admin DSN secret.
- Optionally (`use_artifact_registry_proxy`, default `true`), an Artifact
  Registry remote repository proxying `https://ghcr.io`, and the default
  `image` points at it.

## Usage

```hcl
module "pgwarden" {
  source = "github.com/B0yko/pgwarden//deploy/terraform/gcp-cloud-run"

  project_id = "my-project"
  region     = "europe-west1"
  public_url = "https://pgwarden-123456789012.europe-west1.run.app"

  pgwarden_config_yaml = file("${path.module}/pgwarden.yaml")
}
```

See `deploy/terraform/examples/minimal/` for a complete root module
(providers, a `terraform.tfvars.example`, and outputs).

After `apply`, run the init job once (and again after any schema or config
change):

```sh
gcloud run jobs execute pgwarden-init --region <region> --project <project>
```

...and add the OIDC client secret value, since this module only creates
its container:

```sh
printf '%s' 'the-real-client-secret' | \
  gcloud secrets versions add pgwarden-oidc-client-secret --data-file=-
```

## State file

Every value this module generates (role secret, signing key, session
secret, both Postgres passwords, the composed state and admin DSNs) ends
up in the Terraform state file in plaintext -- Terraform has to know a
value to write it into Secret Manager. This module ships no backend
configuration. Before applying for real, configure a remote backend with
encryption at rest and state-file access restricted to whoever is allowed
to see these secrets (for example a GCS backend, a bucket with its own IAM
policy, uniform bucket-level access and no public access), and treat
`terraform.tfstate` itself as a secret.

## Inputs

| Name | Type | Default | Description |
|---|---|---|---|
| `project_id` | `string` | *(required)* | GCP project id. |
| `region` | `string` | `"europe-west1"` | Region for Cloud Run, Cloud SQL and Artifact Registry. |
| `service_name` | `string` | `"pgwarden"` | Cloud Run service name and resource prefix. |
| `public_url` | `string` | *(required)* | Public HTTPS URL, fixes the OAuth token audience and redirect URI. Must start with `https://`. |
| `image` | `string` | `null` | Full image reference. Defaults to the Artifact Registry proxy (or ghcr.io directly, see `use_artifact_registry_proxy`). |
| `ghcr_image_path` | `string` | `"b0yko/pgwarden"` | Image path on ghcr.io, no host or tag. |
| `image_tag` | `string` | `"latest"` | Tag used to build the default image. Ignored if `image` is set. |
| `use_artifact_registry_proxy` | `bool` | `true` | Create the Artifact Registry remote repo proxying ghcr.io and default the image to it. |
| `create_sql_instance` | `bool` | `true` | Create a new Cloud SQL instance. `false` brings your own via `existing_instance_*`. |
| `existing_instance_name` | `string` | `null` | Existing instance name, used when `create_sql_instance = false`. |
| `existing_instance_connection_name` | `string` | `null` | Existing instance connection name (`PROJECT:REGION:INSTANCE`), used when `create_sql_instance = false`. |
| `tier` | `string` | `"db-custom-1-3840"` | Cloud SQL machine tier. Only used when `create_sql_instance = true`. |
| `availability_type` | `string` | `"ZONAL"` | `ZONAL` or `REGIONAL`. Only used when `create_sql_instance = true`. |
| `deletion_protection` | `bool` | `true` | Terraform-level and Cloud SQL API-level deletion protection. |
| `target_database_name` | `string` | `"shop"` | Name of the application database pgwarden governs. |
| `manage_target_database` | `bool` | `true` | Create the target database. Set `false` if it already exists. |
| `admin_username` | `string` | `"pgwarden_admin"` | Postgres user Terraform provisions for CLI provisioning commands. |
| `state_app_username` | `string` | `"pgwarden_app"` | Postgres user the running service connects to the state database as. |
| `pool_global_cap` | `number` | `60` | `pgwarden.yaml` `pool.global_cap`, used only to size `max_connections`. |
| `admin_reserve_connections` | `number` | `5` | Extra connections reserved above `pool_global_cap x max_instance_count`. |
| `max_instance_count` | `number` | `1` | Max Cloud Run replicas (min is always 0). Raising it requires raising `max_replicas` in `pgwarden.yaml` and re-running `roles sync`. |
| `cpu` | `string` | `"1"` | Cloud Run container CPU allocation. |
| `memory` | `string` | `"512Mi"` | Cloud Run container memory limit. |
| `pgwarden_config_yaml` | `string` | *(required)* | Full contents of `pgwarden.yaml`. Sensitive. |
| `enable_slack_webhook_secret` | `bool` | `false` | Create the (empty) Slack webhook secret container. |
| `enable_smtp_url_secret` | `bool` | `false` | Create the (empty) SMTP URL secret container. |
| `labels` | `map(string)` | `{}` | Labels applied to resources that support them. |

## Outputs

| Name | Description |
|---|---|
| `service_url` | The Cloud Run-assigned URL. |
| `redirect_uri` | `<public_url>/oauth/callback`, to register at the IdP. |
| `init_job_name` | Name of the `pgwarden-init` Cloud Run job. |
| `instance_connection_name` | Cloud SQL instance connection name (`PROJECT:REGION:INSTANCE`). |
| `service_account_email` | Email of the running service's service account. |
| `init_job_service_account_email` | Email of the init job's service account. |

## Checks

Run `deploy/terraform/check.sh` (from anywhere; it resolves its own
paths). It runs `terraform fmt -check`, `validate` (module and example),
`terraform test`, `tflint` (with the pinned google ruleset) and `trivy
config`, all through pinned Docker images with `terraform init
-backend=false`, an empty `HOME`/`CLOUDSDK_CONFIG`, and no `GOOGLE_*`
variables -- it never authenticates to Google Cloud.
