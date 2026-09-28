# The pgwarden Cloud Run service.
#
# Secrets are delivered two ways on purpose:
#   - most secrets (role secret, signing key, session secret, OIDC client
#     secret, Slack webhook, SMTP URL) are plain Cloud Run "secret env
#     vars" (value_source.secret_key_ref): Cloud Run injects the current
#     version's value into the process environment at container start.
#   - pgwarden.yaml and the state DSN are files, because the product reads
#     PGWARDEN_CONFIG as a path and PGWARDEN_STATE_DSN_FILE as a *_FILE
#     secret mount (see the main project's config.py / secrets.py).
#
# The admin DSN is never referenced anywhere in this resource -- only the
# pgwarden-init job (job.tf) can read it. tests/service.tftest.hcl asserts
# this.

resource "google_cloud_run_v2_service" "this" {
  project  = var.project_id
  name     = var.service_name
  location = var.region

  deletion_protection = var.deletion_protection

  ingress = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.service.email

    scaling {
      min_instance_count = 0
      max_instance_count = var.max_instance_count
    }

    volumes {
      name = "config"
      secret {
        secret = google_secret_manager_secret.config.secret_id
        items {
          path    = "pgwarden.yaml"
          version = "latest"
        }
      }
    }

    volumes {
      name = "state-secret"
      secret {
        secret = google_secret_manager_secret.state_dsn.secret_id
        items {
          path    = "state-dsn"
          version = "latest"
        }
      }
    }

    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [local.instance_connection_name]
      }
    }

    containers {
      image = local.image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = var.cpu
          memory = var.memory
        }
      }

      volume_mounts {
        name       = "config"
        mount_path = "/etc/pgwarden"
      }

      volume_mounts {
        name       = "state-secret"
        mount_path = "/etc/pgwarden/secrets"
      }

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }

      env {
        name  = "PGWARDEN_TARGET_DSN"
        value = local.target_dsn
      }

      env {
        name  = "PGWARDEN_CONFIG"
        value = "/etc/pgwarden/pgwarden.yaml"
      }

      env {
        name  = "PGWARDEN_STATE_DSN_FILE"
        value = "/etc/pgwarden/secrets/state-dsn"
      }

      env {
        name = "PGWARDEN_ROLE_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.role_secret.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "PGWARDEN_SIGNING_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.signing_key.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "PGWARDEN_SESSION_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.session_secret.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "PGWARDEN_OIDC_CLIENT_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.oidc_client_secret.secret_id
            version = "latest"
          }
        }
      }

      dynamic "env" {
        for_each = var.enable_slack_webhook_secret ? [1] : []
        content {
          name = "PGWARDEN_SLACK_WEBHOOK_URL"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.slack_webhook_url[0].secret_id
              version = "latest"
            }
          }
        }
      }

      dynamic "env" {
        for_each = var.enable_smtp_url_secret ? [1] : []
        content {
          name = "PGWARDEN_SMTP_URL"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.smtp_url[0].secret_id
              version = "latest"
            }
          }
        }
      }

      # Cloud Run v2 has no separate "readiness probe" resource: only
      # startup_probe and liveness_probe exist. /healthz (cheap, no
      # dependency checks) gates the startup probe so traffic is not
      # routed before the process is up; /readyz (checks the state DB and
      # pool) is polled by the liveness probe so an unhealthy replica is
      # restarted.
      startup_probe {
        http_get {
          path = "/healthz"
        }
        period_seconds    = 10
        timeout_seconds   = 3
        failure_threshold = 6
      }

      liveness_probe {
        http_get {
          path = "/readyz"
        }
        period_seconds    = 30
        timeout_seconds   = 5
        failure_threshold = 3
      }
    }
  }

  depends_on = [
    google_project_service.required,
    google_secret_manager_secret_iam_member.service_access,
  ]
}

# Public invoker binding: intentional. Authentication happens at the
# application layer (OAuth 2.1 + OIDC login, per-request token checks on
# /mcp and the admin/approval pages), not at the Cloud Run IAM layer, so
# every /mcp client and every browser reaching /approve or /admin can
# reach the service without a Google identity. Accept this as a documented
# scanner finding (see .trivyignore and docs/adr/0008-cloud-run-and-cloud-sql.md).
resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.this.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
