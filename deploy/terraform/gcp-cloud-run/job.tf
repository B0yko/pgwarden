# One-shot provisioning job: `pgwarden db init && pgwarden roles sync &&
# pgwarden masking apply`, run with the admin DSN. Run manually after every
# apply that changes pgwarden.yaml or the schema:
#   gcloud run jobs execute pgwarden-init --region <region> --project <project>
#
# This is the only place the admin DSN is mounted. The Cloud Run service in
# cloud_run.tf never references google_secret_manager_secret.admin_dsn.

resource "google_cloud_run_v2_job" "init" {
  project  = var.project_id
  name     = "${var.service_name}-init"
  location = var.region

  deletion_protection = false

  template {
    template {
      service_account = google_service_account.init_job.email

      max_retries = 0

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
        name = "admin-secret"
        secret {
          secret = google_secret_manager_secret.admin_dsn.secret_id
          items {
            path    = "admin-dsn"
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
        image   = local.image
        command = ["sh", "-c"]
        args    = ["pgwarden db init && pgwarden roles sync && pgwarden masking apply"]

        volume_mounts {
          name       = "config"
          mount_path = "/etc/pgwarden"
        }

        volume_mounts {
          name       = "admin-secret"
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
          name  = "PGWARDEN_ADMIN_DSN_FILE"
          value = "/etc/pgwarden/secrets/admin-dsn"
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
      }
    }
  }

  depends_on = [
    google_project_service.required,
    google_secret_manager_secret_iam_member.init_job_access,
  ]
}
