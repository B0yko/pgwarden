# Required APIs. disable_on_destroy = false so `terraform destroy` never
# disables project-wide APIs other resources might also depend on.

locals {
  required_apis = distinct(concat(
    [
      "run.googleapis.com",
      "sqladmin.googleapis.com",
      "secretmanager.googleapis.com",
      "iam.googleapis.com",
      "cloudresourcemanager.googleapis.com",
    ],
    var.use_artifact_registry_proxy ? ["artifactregistry.googleapis.com"] : [],
  ))
}

resource "google_project_service" "required" {
  for_each = toset(local.required_apis)

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}
