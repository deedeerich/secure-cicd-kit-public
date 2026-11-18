variable "name" { type = string }
variable "resource_group_name" { type = string }
variable "location" { type = string }

resource "azurerm_storage_account" "data" {
  name                            = var.name
  resource_group_name             = var.resource_group_name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true     # planted: public blob access
  min_tls_version                 = "TLS1_0" # planted: weak TLS
  enable_https_traffic_only       = false    # planted: HTTP allowed
}

resource "azurerm_storage_container" "exports" {
  name                  = "exports"
  storage_account_name  = azurerm_storage_account.data.name
  container_access_type = "blob" # planted: anonymous read on a container
}

output "id" { value = azurerm_storage_account.data.id }
