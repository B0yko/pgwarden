output "service_url" {
  description = "The Cloud Run-assigned URL of the service. If public_url is a custom domain, map it separately (Cloud Run domain mapping or a load balancer) and register that domain at the IdP instead."
  value       = google_cloud_run_v2_service.this.uri
}

output "redirect_uri" {
  description = "OAuth redirect URI to register with the upstream identity provider."
  value       = "${var.public_url}/oauth/callback"
}

output "init_job_name" {
  description = "Name of the pgwarden-init Cloud Run job. Run it with: gcloud run jobs execute <name> --region <region> --project <project>."
  value       = google_cloud_run_v2_job.init.name
}

output "instance_connection_name" {
  description = "Cloud SQL instance connection name (PROJECT:REGION:INSTANCE)."
  value       = local.instance_connection_name
}

output "service_account_email" {
  description = "Email of the Cloud Run service's runtime service account."
  value       = google_service_account.service.email
}

output "init_job_service_account_email" {
  description = "Email of the pgwarden-init job's service account."
  value       = google_service_account.init_job.email
}
