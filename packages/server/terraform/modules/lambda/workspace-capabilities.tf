# Operational flags affect access only; revision/outbox storage is unconditional.
variable "workspace_capabilities" {
  type = object({
    remote_mcp       = optional(bool, false)
    revision_reads   = optional(bool, false)
    revision_writes  = optional(bool, false)
    projections      = optional(bool, false)
    context          = optional(bool, false)
    web_editing      = optional(bool, false)
    first_party_sync = optional(bool, false)
  })
  default  = {}
  nullable = false
}
