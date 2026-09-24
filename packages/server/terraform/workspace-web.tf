# An explicit key is required only when revision_reads is intentionally enabled.
variable "workspace_web_cursor_key_secret_arn" {
  type        = string
  default     = ""
  description = "Secret ARN for browser workspace continuation cursors. Source default does not create or activate it."
}

variable "workspace_web_origin" {
  type        = string
  default     = ""
  description = "Explicit browser HTTPS origin for safe human handoffs; empty keeps generic handoffs unavailable."
}
