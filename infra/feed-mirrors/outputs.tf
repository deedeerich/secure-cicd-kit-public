# The values the refresh template and every consuming repository need (docs/adoption/FEED_MIRRORS.md).

output "storage_account_name" {
  description = "-> repository variable KIT_FEED_MIRROR_ACCOUNT (the refresh repository)."
  value       = azurerm_storage_account.mirror.name
}

output "mirror_url" {
  description = "-> organisation variable KIT_FEED_MIRROR_URL (every consumer) and the refresh's mirror_url."
  value       = azurerm_storage_account.mirror.primary_web_endpoint
}

output "registry_login_server" {
  description = "-> organisation variable KIT_SCANNER_IMAGE_REGISTRY. Empty when enable_registry is false."
  value       = var.enable_registry ? azurerm_container_registry.mirror[0].login_server : ""
}

output "refresh_identity_client_id" {
  description = "-> variable AZURE_CLIENT_ID of the refresh repository's feed-mirror environment."
  value       = azurerm_user_assigned_identity.refresh.client_id
}

output "refresh_identity_tenant_id" {
  description = "-> variable AZURE_TENANT_ID of the feed-mirror environment."
  value       = azurerm_user_assigned_identity.refresh.tenant_id
}
