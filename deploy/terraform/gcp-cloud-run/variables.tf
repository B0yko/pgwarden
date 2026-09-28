variable "project_id" {
  description = "GCP project id to deploy pgwarden into."
  type        = string
}

variable "region" {
  description = "GCP region for Cloud Run, Cloud SQL and Artifact Registry resources."
  type        = string
  default     = "europe-west1"
}

variable "service_name" {
  description = "Name of the Cloud Run service and prefix for related resources."
  type        = string
  default     = "pgwarden"
}

variable "public_url" {
  description = <<-EOT
    The public HTTPS URL the service is reachable at (custom domain, or the
    deterministic Cloud Run run.app URL). Required: this fixes the OAuth
    token audience and the OAuth redirect URI, so it cannot default to a
    value only known after the first deploy. See the README for how to
    compute the deterministic run.app URL before first apply.
  EOT
  type        = string

  validation {
    condition     = length(var.public_url) > 0 && can(regex("^https://", var.public_url))
    error_message = "public_url is required and must be an https:// URL; it fixes the OAuth token audience."
  }
}

# ---------------------------------------------------------------------------
# Container image
# ---------------------------------------------------------------------------

variable "image" {
  description = <<-EOT
    Full container image reference to deploy. Leave null to use the default:
    the ghcr.io image proxied through the Artifact Registry remote
    repository this module creates (see use_artifact_registry_proxy).
  EOT
  type        = string
  default     = null
}

variable "ghcr_image_path" {
  description = "Image path on ghcr.io, without registry host or tag, e.g. \"b0yko/pgwarden\"."
  type        = string
  default     = "b0yko/pgwarden"
}

variable "image_tag" {
  description = "Tag used to build the default image reference. Ignored if var.image is set."
  type        = string
  default     = "latest"
}

variable "use_artifact_registry_proxy" {
  description = <<-EOT
    Create an Artifact Registry remote repository that proxies ghcr.io and
    default the image to it. Cloud Run can pull public ghcr.io images
    directly, but Google recommends the Artifact Registry proxy path for
    availability (ghcr.io direct pulls are cached only up to one hour).
    Set false to deploy straight from ghcr.io instead.
  EOT
  type        = bool
  default     = true
}

# ---------------------------------------------------------------------------
# Cloud SQL
# ---------------------------------------------------------------------------

variable "create_sql_instance" {
  description = "Create a new Cloud SQL for PostgreSQL instance. Set false to bring your own instance via existing_instance_connection_name / existing_instance_name."
  type        = bool
  default     = true
}

variable "existing_instance_name" {
  description = "Name of an existing Cloud SQL instance to use when create_sql_instance = false."
  type        = string
  default     = null
}

variable "existing_instance_connection_name" {
  description = "Connection name (PROJECT:REGION:INSTANCE) of an existing Cloud SQL instance to use when create_sql_instance = false."
  type        = string
  default     = null
}

variable "tier" {
  description = "Cloud SQL machine tier. Only used when create_sql_instance = true. Default is the smallest valid db-custom tier (1 vCPU, 3840 MB)."
  type        = string
  default     = "db-custom-1-3840"
}

variable "availability_type" {
  description = "Cloud SQL availability type: ZONAL or REGIONAL. Only used when create_sql_instance = true."
  type        = string
  default     = "ZONAL"
}

variable "deletion_protection" {
  description = "Enable both Terraform-level and Cloud SQL API-level deletion protection on the instance."
  type        = bool
  default     = true
}

variable "target_database_name" {
  description = "Name of the application (target) database pgwarden governs access to."
  type        = string
  default     = "shop"
}

variable "manage_target_database" {
  description = "Create the target database via Terraform. Set false if it already exists on a bring-your-own instance."
  type        = bool
  default     = true
}

variable "admin_username" {
  description = "Postgres username Terraform provisions for administrative CLI commands (db init, roles sync, masking apply). This is a fresh user created by this module, not the instance's built-in root user."
  type        = string
  default     = "pgwarden_admin"
}

variable "state_app_username" {
  description = "Postgres username the running service connects as for the state database (role pgwarden_app in the product's design)."
  type        = string
  default     = "pgwarden_app"
}

variable "pool_global_cap" {
  description = "pgwarden.yaml pool.global_cap value (max connections held open by one gateway replica's per-person pools). Used only to size the Cloud SQL max_connections database flag; does not itself configure the application."
  type        = number
  default     = 60
}

variable "admin_reserve_connections" {
  description = "Extra Postgres connections reserved above pool_global_cap x max_instance_count, for the admin/init job and operator access."
  type        = number
  default     = 5
}

# ---------------------------------------------------------------------------
# Cloud Run
# ---------------------------------------------------------------------------

variable "max_instance_count" {
  description = <<-EOT
    Maximum number of Cloud Run replicas (min is always 0: scale to zero).
    Raising this raises the peak number of Postgres connections the service
    can open (see pool_global_cap). Raising it also requires raising
    max_replicas in pgwarden.yaml and re-running `pgwarden roles sync` so
    per-role CONNECTION LIMITs stay consistent with the new ceiling.
  EOT
  type        = number
  default     = 1
}

variable "cpu" {
  description = "Cloud Run container CPU allocation, e.g. \"1\" or \"2\"."
  type        = string
  default     = "1"
}

variable "memory" {
  description = "Cloud Run container memory limit, e.g. \"512Mi\"."
  type        = string
  default     = "512Mi"
}

# ---------------------------------------------------------------------------
# Application config (pgwarden.yaml)
# ---------------------------------------------------------------------------

variable "pgwarden_config_yaml" {
  description = <<-EOT
    Full contents of pgwarden.yaml (people, upstream IdP, masking policy,
    limits, pool settings, etc). This module only stores it in Secret
    Manager and mounts it into the containers; it does not validate or
    render it. See docs/configuration.md in the main project for the schema.
  EOT
  type        = string
  sensitive   = true
}

# ---------------------------------------------------------------------------
# Optional notification secrets
# ---------------------------------------------------------------------------

variable "enable_slack_webhook_secret" {
  description = "Create the (empty) PGWARDEN_SLACK_WEBHOOK_URL secret container and mount it. The value itself is added by the operator afterwards."
  type        = bool
  default     = false
}

variable "enable_smtp_url_secret" {
  description = "Create the (empty) PGWARDEN_SMTP_URL secret container and mount it. The value itself is added by the operator afterwards."
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------

variable "labels" {
  description = "Labels applied to created resources that support labels."
  type        = map(string)
  default     = {}
}
