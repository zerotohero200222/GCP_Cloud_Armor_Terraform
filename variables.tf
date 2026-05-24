###############################################################################
# variables.tf
###############################################################################

# ── Project & Region ─────────────────────────────────────────────────────────
variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP region for regional resources"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Deployment environment (dev / staging / prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

# ── Cloud Armor ───────────────────────────────────────────────────────────────
variable "security_policy_name" {
  description = "Name of the Cloud Armor security policy"
  type        = string
  default     = "cloud-armor-waf-policy"
}

variable "enable_adaptive_protection" {
  description = "Enable Cloud Armor Adaptive Protection (ML-based DDoS)"
  type        = bool
  default     = true
}

variable "allowed_ip_ranges" {
  description = "CIDR ranges that are always allowed (allowlist)"
  type        = list(string)
  default     = []
  # example: ["203.0.113.0/24", "198.51.100.5/32"]
}

variable "blocked_ip_ranges" {
  description = "CIDR ranges that are always denied (blocklist)"
  type        = list(string)
  default     = []
  # example: ["192.0.2.0/24"]
}

variable "blocked_countries" {
  description = "ISO 3166-1 alpha-2 country codes to block"
  type        = list(string)
  default     = []
  # example: ["CN", "RU", "KP"]
}

variable "rate_limit_count" {
  description = "Number of requests allowed per IP per interval before throttling"
  type        = number
  default     = 100
}

variable "rate_limit_interval_sec" {
  description = "Interval in seconds for rate limiting window"
  type        = number
  default     = 60

  validation {
    condition     = contains([1, 10, 60, 120, 600, 3600], var.rate_limit_interval_sec)
    error_message = "interval_sec must be one of: 1, 10, 60, 120, 600, 3600."
  }
}

# ── Source Repository ─────────────────────────────────────────────────────────
variable "create_source_repo" {
  description = "Create a Cloud Source Repository (set false if using GitHub/GitLab)"
  type        = bool
  default     = false
}

variable "source_repo_name" {
  description = "Cloud Source Repository name (used if create_source_repo = true)"
  type        = string
  default     = "cloud-armor-repo"
}

# ── Cloud Build Trigger ───────────────────────────────────────────────────────
variable "trigger_name" {
  description = "Name of the Cloud Build trigger"
  type        = string
  default     = "deploy-cloud-armor"
}

variable "trigger_branch" {
  description = "Git branch that fires the trigger (regex)"
  type        = string
  default     = "main"
}

variable "github_owner" {
  description = "GitHub organisation or username (leave empty to use Cloud Source Repos)"
  type        = string
  default     = ""
}

variable "github_repo_name" {
  description = "GitHub repository name"
  type        = string
  default     = ""
}

# ── Terraform State ───────────────────────────────────────────────────────────
variable "tf_state_bucket" {
  description = "GCS bucket used to store Terraform state (referenced in cloudbuild.yaml)"
  type        = string
  default     = ""
}
