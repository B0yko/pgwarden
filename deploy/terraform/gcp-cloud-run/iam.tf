# Two service accounts, scoped tightly:
#   - service:   what the running Cloud Run service uses. Cloud SQL client
#                role, plus Secret Manager access to its own runtime
#                secrets only. Never the admin DSN.
#   - init_job:  what the `pgwarden-init` Cloud Run job uses. Also Cloud
#                SQL client, plus the role secret, the admin DSN and the
#                config, and nothing the service has that it doesn't need.

resource "google_service_account" "service" {
  project      = var.project_id
  account_id   = "${var.service_name}-run"
  display_name = "pgwarden Cloud Run service"

  depends_on = [google_project_service.required]
}

resource "google_service_account" "init_job" {
  project      = var.project_id
  account_id   = "${var.service_name}-init"
  display_name = "pgwarden init job (db init / roles sync / masking apply)"

  depends_on = [google_project_service.required]
}

resource "google_project_iam_member" "service_cloudsql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.service.email}"
}

resource "google_project_iam_member" "init_job_cloudsql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.init_job.email}"
}

# --- Secret access: the service account ------------------------------------
# Its own runtime secrets only. Deliberately excludes the admin DSN.

locals {
  service_secret_ids = concat(
    [
      google_secret_manager_secret.role_secret.secret_id,
      google_secret_manager_secret.signing_key.secret_id,
      google_secret_manager_secret.session_secret.secret_id,
      google_secret_manager_secret.oidc_client_secret.secret_id,
      google_secret_manager_secret.state_dsn.secret_id,
      google_secret_manager_secret.config.secret_id,
    ],
    var.enable_slack_webhook_secret ? [google_secret_manager_secret.slack_webhook_url[0].secret_id] : [],
    var.enable_smtp_url_secret ? [google_secret_manager_secret.smtp_url[0].secret_id] : [],
  )
}

resource "google_secret_manager_secret_iam_member" "service_access" {
  for_each = toset(local.service_secret_ids)

  project   = var.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.service.email}"
}

# --- Secret access: the init job --------------------------------------------
# Role secret (to derive SCRAM verifiers), admin DSN, and config. Nothing
# else -- it never runs the token-signing or web-session code paths.

locals {
  init_job_secret_ids = [
    google_secret_manager_secret.role_secret.secret_id,
    google_secret_manager_secret.admin_dsn.secret_id,
    google_secret_manager_secret.config.secret_id,
  ]
}

resource "google_secret_manager_secret_iam_member" "init_job_access" {
  for_each = toset(local.init_job_secret_ids)

  project   = var.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.init_job.email}"
}
