# Secret Manager.
#
# State-file warning: every value this module generates (role secret,
# signing key, session secret, admin and state-app passwords, and the two
# composed DSNs) is stored in the Terraform state file in plaintext,
# because Terraform must know it to write the Secret Manager version. This
# module ships no backend configuration on purpose (see examples/minimal),
# but real use MUST configure a remote backend with encryption at rest and
# state-file access restricted to the people/service accounts who are
# allowed to see these secrets (for example a GCS backend with a bucket
# that has its own IAM policy, uniform bucket-level access, and no public
# access). Treat `terraform.tfstate` itself as a secret.
#
# Secrets marked "container only" below get a google_secret_manager_secret
# with no version: Cloud Run will not become Ready until the operator adds
# one (gcloud secrets versions add / console), which is intentional -- this
# module never invents a placeholder value for a credential it was not
# given.

resource "random_password" "role_secret" {
  length  = 64
  special = false
}

resource "tls_private_key" "signing_key" {
  algorithm = "ED25519"
}

resource "random_password" "session_secret" {
  length  = 64
  special = false
}

locals {
  secret_ids = {
    role_secret        = "${var.service_name}-role-secret"
    signing_key        = "${var.service_name}-signing-key"
    session_secret     = "${var.service_name}-session-secret"
    oidc_client_secret = "${var.service_name}-oidc-client-secret"
    slack_webhook_url  = "${var.service_name}-slack-webhook-url"
    smtp_url           = "${var.service_name}-smtp-url"
    state_dsn          = "${var.service_name}-state-dsn"
    admin_dsn          = "${var.service_name}-admin-dsn"
    config             = "${var.service_name}-config"
  }
}

resource "google_secret_manager_secret" "role_secret" {
  project   = var.project_id
  secret_id = local.secret_ids.role_secret
  labels    = local.common_labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "role_secret" {
  secret      = google_secret_manager_secret.role_secret.id
  secret_data = random_password.role_secret.result
}

resource "google_secret_manager_secret" "signing_key" {
  project   = var.project_id
  secret_id = local.secret_ids.signing_key
  labels    = local.common_labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "signing_key" {
  secret      = google_secret_manager_secret.signing_key.id
  secret_data = tls_private_key.signing_key.private_key_pem
}

resource "google_secret_manager_secret" "session_secret" {
  project   = var.project_id
  secret_id = local.secret_ids.session_secret
  labels    = local.common_labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "session_secret" {
  secret      = google_secret_manager_secret.session_secret.id
  secret_data = random_password.session_secret.result
}

# Container only: the OIDC client secret value comes from the upstream
# identity provider's app registration, which this module cannot know.
resource "google_secret_manager_secret" "oidc_client_secret" {
  project   = var.project_id
  secret_id = local.secret_ids.oidc_client_secret
  labels    = local.common_labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.required]
}

# Container only, created when enabled: Slack incoming webhook URL.
resource "google_secret_manager_secret" "slack_webhook_url" {
  count = var.enable_slack_webhook_secret ? 1 : 0

  project   = var.project_id
  secret_id = local.secret_ids.slack_webhook_url
  labels    = local.common_labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.required]
}

# Container only, created when enabled: SMTP URL for the email notifier.
resource "google_secret_manager_secret" "smtp_url" {
  count = var.enable_smtp_url_secret ? 1 : 0

  project   = var.project_id
  secret_id = local.secret_ids.smtp_url
  labels    = local.common_labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret" "state_dsn" {
  project   = var.project_id
  secret_id = local.secret_ids.state_dsn
  labels    = local.common_labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "state_dsn" {
  secret      = google_secret_manager_secret.state_dsn.id
  secret_data = local.state_dsn
}

# Init-job only. Never referenced by the Cloud Run service.
resource "google_secret_manager_secret" "admin_dsn" {
  project   = var.project_id
  secret_id = local.secret_ids.admin_dsn
  labels    = local.common_labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "admin_dsn" {
  secret      = google_secret_manager_secret.admin_dsn.id
  secret_data = local.admin_dsn
}

# pgwarden.yaml, mounted as a secret volume (PGWARDEN_CONFIG). Its content
# is an input: this module stores and serves it, it does not render it.
resource "google_secret_manager_secret" "config" {
  project   = var.project_id
  secret_id = local.secret_ids.config
  labels    = local.common_labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "config" {
  secret      = google_secret_manager_secret.config.id
  secret_data = var.pgwarden_config_yaml
}
