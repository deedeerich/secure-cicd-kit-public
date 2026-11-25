variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "tenant_id" { type = string }

resource "azurerm_key_vault" "app" {
  name                          = "fixture-kv"
  location                      = var.location
  resource_group_name           = var.resource_group_name
  tenant_id                     = var.tenant_id
  sku_name                      = "standard"
  purge_protection_enabled      = false # planted: no purge protection
  soft_delete_retention_days    = 7
  public_network_access_enabled = true # planted: public network access
}
