resource "azurerm_storage_account" "bad" {
  name                            = "fixturestorage"
  resource_group_name             = "rg"
  location                        = "eastus"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true    # checkov: public blob access
  min_tls_version                 = "TLS1_0" # checkov: weak TLS
  enable_https_traffic_only       = false    # checkov: http allowed
}

resource "azurerm_network_security_rule" "wide_open" {
  name                        = "allow-all"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"          # checkov: 0.0.0.0/0 inbound
  destination_address_prefix  = "*"
  resource_group_name         = "rg"
  network_security_group_name = "nsg"
}
