variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "admin_login" { type = string }

# A variable with no value, never a literal: this fixture plants IaC findings, not secrets.
variable "admin_password_placeholder" {
  type      = string
  sensitive = true
}

resource "azurerm_mssql_server" "app" {
  name                          = "fixture-sql"
  resource_group_name           = var.resource_group_name
  location                      = var.location
  version                       = "12.0"
  administrator_login           = var.admin_login
  administrator_login_password  = var.admin_password_placeholder
  public_network_access_enabled = true  # planted: public network access
  minimum_tls_version           = "1.0" # planted: weak TLS
}

resource "azurerm_mssql_firewall_rule" "everyone" {
  name             = "allow-everyone"
  server_id        = azurerm_mssql_server.app.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255" # planted: the whole internet
}

resource "azurerm_mssql_database" "app" {
  name      = "appdb"
  server_id = azurerm_mssql_server.app.id
}
