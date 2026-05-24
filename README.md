# Cloud Armor + Cloud Build — Terraform Deployment

## Repository layout

```
.
├── cloudbuild.yaml          # CI/CD pipeline definition
└── terraform/
    ├── main.tf              # Core resources
    ├── variables.tf         # Input variables
    ├── outputs.tf           # Output values
    └── terraform.tfvars     # Your values (copy from terraform.tfvars.example)
```

---

## Prerequisites

| Tool | Version |
|------|---------|
| Terraform | ≥ 1.5.0 |
| gcloud CLI | latest |
| A GCP project with billing enabled | — |

---

## Quick Start

### 1 — Authenticate

```bash
gcloud auth application-default login
gcloud config set project YOUR_PROJECT_ID
```

### 2 — Create GCS bucket for Terraform state

```bash
gsutil mb -l us-central1 gs://YOUR_PROJECT_ID-tfstate
gsutil versioning set on gs://YOUR_PROJECT_ID-tfstate
```

### 3 — Configure variables

```bash
cp terraform.tfvars.example terraform/terraform.tfvars
# Edit terraform/terraform.tfvars with your values
```

### 4 — Deploy locally (first-time bootstrap)

```bash
cd terraform
terraform init \
  -backend-config="bucket=YOUR_PROJECT_ID-tfstate" \
  -backend-config="prefix=cloud-armor/prod/state"

terraform plan
terraform apply
```

### 5 — Subsequent deploys via CI/CD

Push to `main` — Cloud Build trigger fires automatically and:
- `fmt` → `validate` → `tfsec scan` → `plan` → `apply` → `verify`

---

## Cloud Armor Rules (priority order)

| Priority | Rule | Action |
|----------|------|--------|
| 500 | IP Allowlist | allow |
| 600 | IP Blocklist | deny(403) |
| 700 | Geo Restriction | deny(403) |
| 800 | Rate Limiting | throttle / deny(429) |
| 900 | Bot Detection | redirect to reCAPTCHA |
| 1000 | SQLi (OWASP CRS) | deny(403) |
| 1010 | XSS (OWASP CRS) | deny(403) |
| 1020 | LFI (OWASP CRS) | deny(403) |
| 1030 | RFI (OWASP CRS) | deny(403) |
| 1040 | RCE (OWASP CRS) | deny(403) |
| 1050 | Scanner Detection | deny(403) |
| 1060 | Protocol Attack | deny(403) |
| 2147483647 | Default | allow |

---

## Attach to a Backend Service

After deploying, attach the policy to your Load Balancer backend service:

```bash
gcloud compute backend-services update YOUR_BACKEND_SERVICE \
  --security-policy=cloud-armor-waf-policy \
  --global
```

Or via Terraform:

```hcl
resource "google_compute_backend_service" "app" {
  name            = "my-app-backend"
  security_policy = google_compute_security_policy.main.self_link
  ...
}
```

---

## Destroy

```bash
cd terraform
terraform destroy
```
