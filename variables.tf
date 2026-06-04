variable "project_id" {
  type = string
}

variable "security_policy_name" {
  type    = string
  default = "cloud-armor-policy"
}

variable "backend_service_name" {
  type = string
}
