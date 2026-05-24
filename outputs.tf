###############################################################################
# outputs.tf
###############################################################################

output "security_policy_id" {
  description = "Self-link of the Cloud Armor security policy"
  value       = google_compute_security_policy.main.self_link
}

output "security_policy_name" {
  description = "Name of the Cloud Armor security policy"
  value       = google_compute_security_policy.main.name
}

output "security_policy_fingerprint" {
  description = "Fingerprint of the security policy (changes on every update)"
  value       = google_compute_security_policy.main.fingerprint
}

output "cloudbuild_trigger_id" {
  description = "ID of the Cloud Build trigger"
  value       = google_cloudbuild_trigger.armor_trigger.trigger_id
}

output "cloudbuild_trigger_name" {
  description = "Name of the Cloud Build trigger"
  value       = google_cloudbuild_trigger.armor_trigger.name
}

output "cloudbuild_sa_email" {
  description = "Email of the Cloud Build service account"
  value       = google_service_account.cloudbuild_sa.email
}

output "build_artifacts_bucket" {
  description = "GCS bucket used for build artifacts and logs"
  value       = google_storage_bucket.build_artifacts.name
}

output "source_repo_url" {
  description = "URL of the Cloud Source Repository (empty if using GitHub)"
  value       = var.create_source_repo ? google_sourcerepo_repository.app_repo[0].url : "N/A – using GitHub"
}
