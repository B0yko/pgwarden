# Minimal runnable example: deploys pgwarden to Cloud Run with a fresh
# Cloud SQL for PostgreSQL 16 instance.
#
# This is a root module: it configures providers and a backend, then calls
# the reusable module in deploy/terraform/gcp-cloud-run. Copy this
# directory, fill in terraform.tfvars from terraform.tfvars.example, and
# `terraform init && terraform plan`.
#
# No backend is configured here on purpose (state stays local by default).
# Before running this for real, configure a remote backend with encryption
# at rest and restricted IAM -- see the module README's "State file"
# section, because the state will contain generated secrets in plaintext.

terraform {
  required_version = ">= 1.16.0, < 2.0.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "= 8.4.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

module "pgwarden" {
  source = "../../gcp-cloud-run"

  project_id = var.project_id
  region     = var.region
  public_url = var.public_url

  target_database_name = var.target_database_name
  pgwarden_config_yaml = file("${path.module}/pgwarden.yaml.example")
}

output "service_url" {
  value = module.pgwarden.service_url
}

output "redirect_uri" {
  value = module.pgwarden.redirect_uri
}

output "init_job_name" {
  value = module.pgwarden.init_job_name
}
