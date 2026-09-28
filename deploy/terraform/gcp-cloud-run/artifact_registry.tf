# Optional Artifact Registry remote repository proxying ghcr.io.
#
# Verified at build time (Google Cloud "Deploying container images" docs):
# Cloud Run can deploy directly from Artifact Registry or Docker Hub; a
# *public* ghcr.io image can also be deployed directly, but Google caches
# it for only up to one hour and recommends the Artifact Registry
# remote-repository proxy path for reliability, even for public images.
# This module follows that recommendation by default.

resource "google_artifact_registry_repository" "ghcr_proxy" {
  count = var.use_artifact_registry_proxy ? 1 : 0

  project       = var.project_id
  location      = var.region
  repository_id = local.ar_repository_id
  format        = "DOCKER"
  mode          = "REMOTE_REPOSITORY"
  description   = "Remote proxy of ghcr.io for pgwarden images"

  remote_repository_config {
    description = "Proxy for ghcr.io"

    docker_repository {
      custom_repository {
        uri = "https://ghcr.io"
      }
    }
  }

  depends_on = [google_project_service.required]
}
