###############################################################################
# main.tf — Google Cloud Armor + Cloud Build Trigger
###############################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
  }

  # ── Optional: GCS remote state ──────────────────────────────────────────────
  # backend "gcs" {
  #   bucket = "your-tfstate-bucket"
  #   prefix = "cloud-armor/state"
  # }
}

###############################################################################
# Provider
###############################################################################
provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

###############################################################################
# Enable required APIs
###############################################################################
resource "google_project_service" "apis" {
  for_each = toset([
    "compute.googleapis.com",
    "cloudbuild.googleapis.com",
    "sourcerepo.googleapis.com",
    "iam.googleapis.com",
    "logging.googleapis.com",
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

###############################################################################
# Cloud Armor — Security Policy
###############################################################################
resource "google_compute_security_policy" "main" {
  provider    = google-beta
  name        = var.security_policy_name
  description = "Cloud Armor WAF policy managed by Terraform"
  project     = var.project_id

  depends_on = [google_project_service.apis]

  # ── Adaptive Protection (ML-based DDoS) ──────────────────────────────────
  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable          = var.enable_adaptive_protection
      rule_visibility = "STANDARD"
    }
  }

  # ── Advanced Options ──────────────────────────────────────────────────────
  advanced_options_config {
    json_parsing = "STANDARD"
    log_level    = "VERBOSE"
  }

  # ── Rule 1: OWASP Top-10 Pre-configured WAF rules ────────────────────────
  rule {
    priority    = 1000
    description = "OWASP CRS – SQL Injection"
    action      = "deny(403)"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sqli-v33-stable')"
      }
    }
  }

  rule {
    priority    = 1010
    description = "OWASP CRS – Cross-Site Scripting"
    action      = "deny(403)"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('xss-v33-stable')"
      }
    }
  }

  rule {
    priority    = 1020
    description = "OWASP CRS – Local File Inclusion"
    action      = "deny(403)"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('lfi-v33-stable')"
      }
    }
  }

  rule {
    priority    = 1030
    description = "OWASP CRS – Remote File Inclusion"
    action      = "deny(403)"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('rfi-v33-stable')"
      }
    }
  }

  rule {
    priority    = 1040
    description = "OWASP CRS – Remote Code Execution"
    action      = "deny(403)"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('rce-v33-stable')"
      }
    }
  }

  rule {
    priority    = 1050
    description = "OWASP CRS – Scanner Detection"
    action      = "deny(403)"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('scannerdetection-v33-stable')"
      }
    }
  }

  rule {
    priority    = 1060
    description = "OWASP CRS – Protocol Attack"
    action      = "deny(403)"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('protocolattack-v33-stable')"
      }
    }
  }

  # ── Rule 2: IP Allowlist ──────────────────────────────────────────────────
  dynamic "rule" {
    for_each = length(var.allowed_ip_ranges) > 0 ? [1] : []
    content {
      priority    = 500
      description = "Allow trusted IP ranges"
      action      = "allow"
      match {
        versioned_expr = "SRC_IPS_V1"
        config {
          src_ip_ranges = var.allowed_ip_ranges
        }
      }
    }
  }

  # ── Rule 3: IP Blocklist ──────────────────────────────────────────────────
  dynamic "rule" {
    for_each = length(var.blocked_ip_ranges) > 0 ? [1] : []
    content {
      priority    = 600
      description = "Block known malicious IP ranges"
      action      = "deny(403)"
      match {
        versioned_expr = "SRC_IPS_V1"
        config {
          src_ip_ranges = var.blocked_ip_ranges
        }
      }
    }
  }

  # ── Rule 4: Geo-based restriction ────────────────────────────────────────
  dynamic "rule" {
    for_each = length(var.blocked_countries) > 0 ? [1] : []
    content {
      priority    = 700
      description = "Block traffic from specific countries"
      action      = "deny(403)"
      match {
        expr {
          expression = "origin.region_code.matches('${join("|", var.blocked_countries)}')"
        }
      }
    }
  }

  # ── Rule 5: Rate Limiting ─────────────────────────────────────────────────
  rule {
    priority    = 800
    description = "Rate limit – throttle excessive requests per IP"
    action      = "throttle"

    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }

    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = var.rate_limit_count
        interval_sec = var.rate_limit_interval_sec
      }
    }
  }

  # ── Rule 6: Bot Management (reCAPTCHA) ────────────────────────────────────
  rule {
    priority    = 900
    description = "Redirect bots to reCAPTCHA challenge"
    action      = "redirect"

    match {
      expr {
        expression = "request.headers['user-agent'].lower().contains('bot') || request.headers['user-agent'].lower().contains('crawler')"
      }
    }

    redirect_options {
      type   = "EXTERNAL_302"
      target = "https://www.google.com/recaptcha/api2/siteverify"
    }
  }

  # ── Default Rule: Allow all other traffic ────────────────────────────────
  rule {
    priority    = 2147483647
    description = "Default – allow"
    action      = "allow"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }
}

###############################################################################
# Cloud Source Repository (optional — skip if using GitHub/GitLab)
###############################################################################
resource "google_sourcerepo_repository" "app_repo" {
  count   = var.create_source_repo ? 1 : 0
  name    = var.source_repo_name
  project = var.project_id

  depends_on = [google_project_service.apis]
}

###############################################################################
# Cloud Build — Service Account
###############################################################################
resource "google_service_account" "cloudbuild_sa" {
  account_id   = "cloudbuild-armor-sa"
  display_name = "Cloud Build – Cloud Armor deployer"
  project      = var.project_id

  depends_on = [google_project_service.apis]
}

# IAM bindings for Cloud Build SA
resource "google_project_iam_member" "cloudbuild_roles" {
  for_each = toset([
    "roles/compute.securityAdmin",
    "roles/logging.logWriter",
    "roles/storage.objectViewer",
    "roles/cloudbuild.builds.builder",
    "roles/iam.serviceAccountUser",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.cloudbuild_sa.email}"
}

###############################################################################
# Cloud Build — Trigger (GitHub)
###############################################################################
resource "google_cloudbuild_trigger" "armor_trigger" {
  name        = var.trigger_name
  description = "Deploys Cloud Armor policy on push to ${var.trigger_branch}"
  project     = var.project_id
  location    = var.region

  service_account = google_service_account.cloudbuild_sa.id

  depends_on = [
    google_project_service.apis,
    google_project_iam_member.cloudbuild_roles,
  ]

  # ── GitHub source ──────────────────────────────────────────────────────────
  dynamic "github" {
    for_each = var.github_owner != "" ? [1] : []
    content {
      owner = var.github_owner
      name  = var.github_repo_name

      push {
        branch = "^${var.trigger_branch}$"
      }
    }
  }

  # ── Cloud Source Repository (fallback if GitHub not configured) ───────────
  dynamic "trigger_template" {
    for_each = var.github_owner == "" ? [1] : []
    content {
      repo_name   = var.create_source_repo ? google_sourcerepo_repository.app_repo[0].name : var.source_repo_name
      branch_name = "^${var.trigger_branch}$"
      project_id  = var.project_id
    }
  }

  # ── Build steps inline (or delegate to cloudbuild.yaml) ───────────────────
  filename = "cloudbuild.yaml"

  # Substitutions passed into cloudbuild.yaml
  substitutions = {
    _PROJECT_ID          = var.project_id
    _SECURITY_POLICY     = var.security_policy_name
    _REGION              = var.region
    _TF_STATE_BUCKET     = var.tf_state_bucket
    _ENV                 = var.environment
  }

  # Include / exclude file filters
  included_files = ["terraform/**", "cloudbuild.yaml"]
  ignored_files  = ["**.md", "docs/**"]
}

###############################################################################
# Cloud Build — Artifact Storage Bucket
###############################################################################
resource "google_storage_bucket" "build_artifacts" {
  name                        = "${var.project_id}-build-artifacts-${var.environment}"
  location                    = var.region
  project                     = var.project_id
  force_destroy               = false
  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  lifecycle_rule {
    action { type = "Delete" }
    condition { age = 30 }
  }

  depends_on = [google_project_service.apis]
}

resource "google_storage_bucket_iam_member" "build_sa_bucket" {
  bucket = google_storage_bucket.build_artifacts.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.cloudbuild_sa.email}"
}

###############################################################################
# Cloud Logging — Export sink for Cloud Armor logs
###############################################################################
resource "google_logging_project_sink" "armor_sink" {
  name        = "cloud-armor-log-sink"
  project     = var.project_id
  destination = "storage.googleapis.com/${google_storage_bucket.build_artifacts.name}"
  filter      = "resource.type=\"http_load_balancer\" AND jsonPayload.enforcedSecurityPolicy.name=\"${var.security_policy_name}\""

  unique_writer_identity = true
}

resource "google_storage_bucket_iam_member" "log_sink_writer" {
  bucket = google_storage_bucket.build_artifacts.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.armor_sink.writer_identity
}
