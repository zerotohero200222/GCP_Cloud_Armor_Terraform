resource "google_compute_security_policy" "armor" {

  name        = var.security_policy_name
  description = "Cloud Armor Policy"

  rule {
    priority = 1000
    action   = "allow"

    match {
      versioned_expr = "SRC_IPS_V1"

      config {
        src_ip_ranges = ["*"]
      }
    }
  }

  rule {
    priority = 2147483647
    action   = "allow"

    match {
      versioned_expr = "SRC_IPS_V1"

      config {
        src_ip_ranges = ["*"]
      }
    }
  }
}

data "google_compute_backend_service" "existing" {
  name = var.backend_service_name
}

resource "google_compute_backend_service" "attach_policy" {

  name            = data.google_compute_backend_service.existing.name

  security_policy = google_compute_security_policy.armor.id
}
