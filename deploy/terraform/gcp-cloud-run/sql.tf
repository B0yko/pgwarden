# Cloud SQL for PostgreSQL 16.
#
# Managed connection pooling (google_sql_database_instance.settings.
# connection_pool_config) is intentionally left unset everywhere in this
# file. It is a real, GA feature for Postgres, but it is off by default,
# requires the Cloud SQL Enterprise Plus edition, and defaults to
# transaction-level pooling -- which breaks the per-connection prepared
# statements and session-level cleanup (DISCARD ALL) the read path relies
# on (ADR-0004 in the main project). Cloud Run reaches the instance through
# the built-in unix-socket connector (direct connection), never through
# managed pooling. See docs/adr/0008-cloud-run-and-cloud-sql.md.

resource "google_sql_database_instance" "this" {
  count = var.create_sql_instance ? 1 : 0

  project             = var.project_id
  name                = "${var.service_name}-pg"
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = var.deletion_protection

  settings {
    tier              = var.tier
    availability_type = var.availability_type

    ip_configuration {
      ipv4_enabled = true
      ssl_mode     = "ENCRYPTED_ONLY"
      # No authorized_networks blocks: the only intended path in is the
      # Cloud Run unix-socket connector (IAM/Cloud SQL Admin API
      # authenticated), not a raw IP allowlist.
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }

    database_flags {
      name  = "max_connections"
      value = tostring(local.min_max_connections)
    }

    # Diagnostic logging flags: cheap, and directly useful for a project
    # whose whole point is auditability. Also clears trivy config's
    # GCP-0014/0016/0020/0022/0025 checks (written as static blocks, not a
    # dynamic block over a map, because trivy's Terraform evaluator did not
    # resolve the dynamic form's name/value pairs when this was checked).
    database_flags {
      name  = "log_temp_files"
      value = "0"
    }

    database_flags {
      name  = "log_connections"
      value = "on"
    }

    database_flags {
      name  = "log_disconnections"
      value = "on"
    }

    database_flags {
      name  = "log_lock_waits"
      value = "on"
    }

    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }

    deletion_protection_enabled = var.deletion_protection
  }

  depends_on = [google_project_service.required]
}

# State database. Always managed by this module (it is pgwarden's own, not
# part of "your own database").
resource "google_sql_database" "state" {
  project  = var.project_id
  instance = local.instance_name
  name     = "pgwarden"

  depends_on = [google_project_service.required]
}

# Target (application) database. Optional: on a bring-your-own instance the
# database usually already exists with real data.
resource "google_sql_database" "target" {
  count = var.manage_target_database ? 1 : 0

  project  = var.project_id
  instance = local.instance_name
  name     = var.target_database_name

  depends_on = [google_project_service.required]
}

# Admin user for CLI provisioning (db init / roles sync / masking apply).
# A fresh user created by this module, never the instance's built-in root
# user, so its credentials can be scoped and rotated independently.
resource "random_password" "admin" {
  length           = 32
  special          = true
  override_special = "-_"
}

resource "google_sql_user" "admin" {
  project  = var.project_id
  instance = local.instance_name
  name     = var.admin_username
  password = random_password.admin.result

  depends_on = [google_project_service.required]
}

# Runtime user the service connects as for the state database
# (PGWARDEN_STATE_DSN, role `pgwarden_app` in the product's role model).
resource "random_password" "state_app" {
  length           = 32
  special          = true
  override_special = "-_"
}

resource "google_sql_user" "state_app" {
  project  = var.project_id
  instance = local.instance_name
  name     = var.state_app_username
  password = random_password.state_app.result

  depends_on = [google_project_service.required]
}
