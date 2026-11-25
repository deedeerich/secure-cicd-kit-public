variable "resource_group_name" { type = string }
variable "location" { type = string }

resource "azurerm_kubernetes_cluster" "app" {
  name                              = "fixture-aks"
  location                          = var.location
  resource_group_name               = var.resource_group_name
  dns_prefix                        = "fixture"
  role_based_access_control_enabled = false # planted: RBAC off
  private_cluster_enabled           = false # planted: public API server
  local_account_disabled            = false

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
}
