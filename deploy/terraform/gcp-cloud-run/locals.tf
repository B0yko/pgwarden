locals {
  # Connection name (PROJECT:REGION:INSTANCE) of the instance this module
  # points at, whether freshly created or brought by the operator.
  instance_connection_name = var.create_sql_instance ? google_sql_database_instance.this[0].connection_name : var.existing_instance_connection_name
  instance_name            = var.create_sql_instance ? google_sql_database_instance.this[0].name : var.existing_instance_name

  # Peak connections a single gateway replica's per-person pools can hold
  # open, times the maximum number of replicas, plus headroom for the admin
  # user and operator access. Documents the formula the spec requires:
  # max_connections >= pool.global_cap x max_instance_count + admin.
  min_max_connections = var.pool_global_cap * var.max_instance_count + var.admin_reserve_connections

  ar_repository_id = "${var.service_name}-remote"

  default_image = var.use_artifact_registry_proxy ? (
    "${var.region}-docker.pkg.dev/${var.project_id}/${local.ar_repository_id}/${var.ghcr_image_path}:${var.image_tag}"
  ) : "ghcr.io/${var.ghcr_image_path}:${var.image_tag}"

  image = coalesce(var.image, local.default_image)

  # asyncpg-form DSNs through the Cloud SQL unix socket. See README for the
  # exact host= query parameter shape.
  socket_host = "/cloudsql/${local.instance_connection_name}"

  target_dsn = "postgresql:///${var.target_database_name}?host=${local.socket_host}"

  state_dsn = "postgresql://${var.state_app_username}:${urlencode(random_password.state_app.result)}@/${google_sql_database.state.name}?host=${local.socket_host}"

  # Admin DSN targets the state database ("pgwarden"), which is what
  # `pgwarden db init` needs directly. Cloud SQL Postgres users created by
  # this module are members of the built-in cloudsqlsuperuser role, which
  # has CREATEDB/CREATEROLE and cross-database privileges on the instance,
  # so the same credentials also work for `roles sync` and `masking apply`
  # against the target database once the CLI selects that database's host
  # (PGWARDEN_TARGET_DSN, supplied separately). This module does not invent
  # the CLI's own DSN-selection logic; it only documents the assumption.
  admin_dsn = "postgresql://${var.admin_username}:${urlencode(random_password.admin.result)}@/${google_sql_database.state.name}?host=${local.socket_host}"

  common_labels = merge({
    app = var.service_name
  }, var.labels)
}
