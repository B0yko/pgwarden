# terraform test with mock providers: no credentials, no network calls to
# Google Cloud. Verifies the module's security invariants (see ADR-0008).

mock_provider "google" {}
mock_provider "random" {}
mock_provider "tls" {}

variables {
  project_id           = "test-project"
  public_url           = "https://pgwarden-abc123def-ew.a.run.app"
  pgwarden_config_yaml = "public_url: https://pgwarden-abc123def-ew.a.run.app\n"
}

run "plan_defaults" {
  command = plan

  assert {
    condition     = length(google_sql_database_instance.this) == 1
    error_message = "expected a Cloud SQL instance to be planned when create_sql_instance is true (the default)"
  }

  # Cloud SQL managed connection pooling must never be configured: it is
  # off by default and this module leaves settings.connection_pool_config
  # unset everywhere, so it stays off.
  assert {
    condition     = length(coalesce(google_sql_database_instance.this[0].settings[0].connection_pool_config, [])) == 0
    error_message = "Cloud SQL managed connection pooling must never be enabled"
  }

  # No IAM binding/member gives the service's account access to the admin
  # secret.
  assert {
    condition = alltrue([
      for k, v in google_secret_manager_secret_iam_member.service_access :
      v.secret_id != google_secret_manager_secret.admin_dsn.secret_id
    ])
    error_message = "the service account must never be granted access to the admin DSN secret"
  }

  # The init job's account is the only one with admin secret access.
  assert {
    condition = anytrue([
      for k, v in google_secret_manager_secret_iam_member.init_job_access :
      v.secret_id == google_secret_manager_secret.admin_dsn.secret_id
    ])
    error_message = "the init job's account should have access to the admin DSN secret"
  }

  # The Cloud Run service must never receive the admin DSN as an env var.
  assert {
    condition = length([
      for e in google_cloud_run_v2_service.this.template[0].containers[0].env : e.name
      if e.name == "PGWARDEN_ADMIN_DSN" || e.name == "PGWARDEN_ADMIN_DSN_FILE"
    ]) == 0
    error_message = "the Cloud Run service must never receive the admin DSN as an env var"
  }

  # The Cloud Run service must never mount the admin DSN secret as a volume.
  assert {
    condition = length([
      for v in google_cloud_run_v2_service.this.template[0].volumes : v.name
      if try(v.secret[0].secret, "") == google_secret_manager_secret.admin_dsn.secret_id
    ]) == 0
    error_message = "the Cloud Run service must never mount the admin DSN secret"
  }

  # Public invoker binding exists (intentional, documented) and is scoped
  # to this service only.
  assert {
    condition     = google_cloud_run_v2_service_iam_member.public_invoker.member == "allUsers"
    error_message = "expected the documented public run.invoker binding"
  }
}

run "public_url_is_required" {
  command = plan

  variables {
    public_url = ""
  }

  expect_failures = [var.public_url]
}

run "public_url_must_be_https" {
  command = plan

  variables {
    public_url = "http://insecure.example.test"
  }

  expect_failures = [var.public_url]
}

run "bring_your_own_instance_creates_no_instance" {
  command = plan

  variables {
    create_sql_instance               = false
    existing_instance_name            = "byo-instance"
    existing_instance_connection_name = "test-project:europe-west1:byo-instance"
  }

  assert {
    condition     = length(google_sql_database_instance.this) == 0
    error_message = "create_sql_instance = false must not create a Cloud SQL instance"
  }

  assert {
    condition     = google_sql_database.state.instance == "byo-instance"
    error_message = "the state database must attach to the existing instance"
  }
}
