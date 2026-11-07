# The root: wires the six modules. No provider block, no backend, nothing applied, ever.
variable "location" {
  type    = string
  default = "eastus"
}

variable "tenant_id" { type = string }

variable "admin_password_placeholder" {
  type      = string
  sensitive = true
}

resource "azurerm_resource_group" "app" {
  name     = "fixture-rg"
  location = var.location
}

module "network" {
  source              = "../../modules/network"
  resource_group_name = azurerm_resource_group.app.name
  location            = var.location
}

module "storage" {
  source              = "../../modules/storage"
  name                = "fixturestorageheavy"
  resource_group_name = azurerm_resource_group.app.name
  location            = var.location
}

module "compute" {
  source                     = "../../modules/compute"
  resource_group_name        = azurerm_resource_group.app.name
  location                   = var.location
  subnet_id                  = module.network.subnet_id
  admin_password_placeholder = var.admin_password_placeholder
}

module "database" {
  source                     = "../../modules/database"
  resource_group_name        = azurerm_resource_group.app.name
  location                   = var.location
  admin_login                = "fixtureadmin"
  admin_password_placeholder = var.admin_password_placeholder
}

module "kubernetes" {
  source              = "../../modules/kubernetes"
  resource_group_name = azurerm_resource_group.app.name
  location            = var.location
}

module "keyvault" {
  source              = "../../modules/keyvault"
  resource_group_name = azurerm_resource_group.app.name
  location            = var.location
  tenant_id           = var.tenant_id
}
