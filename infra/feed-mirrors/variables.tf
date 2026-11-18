variable "resource_group_name" {
  description = "An existing resource group in the security platform subscription that holds the mirror."
  type        = string
}

variable "location" {
  description = "Azure region; the same region as the private-endpoint virtual network."
  type        = string
}

variable "name_prefix" {
  description = "Lower-case letters and digits, 3-11 characters; the account and registry names are derived from it."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9]{3,11}$", var.name_prefix))
    error_message = "name_prefix must be 3-11 lower-case letters or digits."
  }
}

variable "private_endpoint_subnet_id" {
  description = "The subnet the private endpoints are placed in (the platform's private-endpoint subnet)."
  type        = string
}

variable "dns_zone_ids" {
  description = <<-EOT
    Existing private DNS zones, when the platform keeps them centrally (the usual hub pattern): keys
    "web" (privatelink.web.core.windows.net), "blob" (privatelink.blob.core.windows.net) and "registry"
    (privatelink.azurecr.io). A key left out is created here and linked to dns_link_vnet_ids.
  EOT
  type        = map(string)
  default     = {}
}

variable "dns_link_vnet_ids" {
  description = "Virtual networks linked to the zones this module creates: the runners' network at least."
  type        = list(string)
  default     = []
}

variable "github_repository" {
  description = "owner/repo of the repository that runs the refresh (templates/feed-mirror-refresh.yml)."
  type        = string
}

variable "github_environment" {
  description = "The environment the refresh job runs in; the federated credential trusts only it."
  type        = string
  default     = "feed-mirror"
}

variable "oidc_issuer" {
  description = <<-EOT
    The GitHub Actions OIDC issuer. github.com: https://token.actions.githubusercontent.com. A GHE.com
    (data residency) tenant has its own issuer -- use the value its documentation gives for the tenant.
  EOT
  type        = string
  default     = "https://token.actions.githubusercontent.com"
}

variable "enable_registry" {
  description = "Create the scanner-image mirror registry (Premium: the private endpoint requires it)."
  type        = bool
  default     = true
}

variable "log_analytics_workspace_id" {
  description = "Where the account's blob write/delete audit logs go. Empty sends none (not recommended)."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
