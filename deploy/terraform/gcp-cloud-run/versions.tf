terraform {
  # Terraform CLI: the latest stable release when this was written was 1.16.4 (2026-09-23).
  # Allow later 1.x releases but never a 2.x major without re-review.
  required_version = ">= 1.16.0, < 2.0.0"

  required_providers {
    # Pinned to an exact version on purpose: the google provider ships breaking
    # changes across minors, and pinning avoids silently picking up an
    # untested release in CI. Bump deliberately after reading the changelog.
    google = {
      source  = "hashicorp/google"
      version = "= 8.4.0" # latest on registry.terraform.io on 2026-09-22
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}
