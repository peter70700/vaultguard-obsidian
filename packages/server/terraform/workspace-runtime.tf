# Source-only deployment inputs. Defaults preserve disabled capabilities.
variable "workspace_mcp_profile" {
  type    = string
  default = "workspace-read-v1"
  validation {
    condition     = contains(["workspace-read-v1", "workspace-proposal-v1", "workspace-access-v1", "workspace-transfer-v1"], var.workspace_mcp_profile)
    error_message = "Use an existing reviewed connector admission profile."
  }
}
variable "mcp_transfer_nonce_key_secret_arn" {
  type    = string
  default = ""
}
variable "workspace_cost_controls" {
  type    = string
  default = ""
  validation {
    condition     = contains(["", "budget-v1"], var.workspace_cost_controls)
    error_message = "Cost controls must be absent or budget-v1."
  }
}
variable "workspace_cost_telemetry" {
  type    = string
  default = ""
  validation {
    condition     = contains(["", "content-free-v1"], var.workspace_cost_telemetry)
    error_message = "Only content-free cost telemetry is supported."
  }
}
variable "workspace_semantic_provider_profile" {
  type    = string
  default = ""
  validation {
    condition     = contains(["", "openai-embeddings-v1"], var.workspace_semantic_provider_profile)
    error_message = "Only the reviewed embeddings provider profile is supported."
  }
}
variable "workspace_semantic_secret_arn" {
  type    = string
  default = ""
}

variable "workspace_mcp_write_admission" {
  type    = bool
  default = false
}

variable "workspace_slo_telemetry" {
  type    = string
  default = ""
  validation {
    condition     = contains(["", "content-free-v1"], var.workspace_slo_telemetry)
    error_message = "Only content-free SLO telemetry is supported."
  }
}

variable "workspace_cohort_controls_enabled" {
  type    = bool
  default = false
  description = "Explicit shared writer-fence/routing participation; not first-party sync activation. Keep enabled for any adopted cohort even while product capabilities are off."
}

variable "workspace_projection_delivery_enabled" {
  type    = bool
  default = false
}

variable "workspace_operator_enabled" {
  type    = bool
  default = false
}
variable "workspace_operator_environment_id" {
  type    = string
  default = ""
}
variable "workspace_migration_redaction_key_secret_arn" {
  type    = string
  default = ""
}
