variable "project_id" {
  description = "GCP project id. Placeholder only -- replace in terraform.tfvars, never commit a real one here."
  type        = string
}

variable "region" {
  description = "GCP region."
  type        = string
  default     = "europe-west1"
}

variable "public_url" {
  description = "Public HTTPS URL the service will be reachable at. See the module README for how to compute the deterministic run.app URL before first apply."
  type        = string
}

variable "target_database_name" {
  description = "Name of the application database pgwarden governs access to."
  type        = string
  default     = "shop"
}
