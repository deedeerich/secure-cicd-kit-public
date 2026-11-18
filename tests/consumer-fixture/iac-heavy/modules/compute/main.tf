variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "subnet_id" { type = string }

# A variable with no value, never a literal: this fixture plants IaC findings, not secrets.
variable "admin_password_placeholder" {
  type      = string
  sensitive = true
}

resource "azurerm_network_interface" "vm" {
  name                = "app-nic"
  location            = var.location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "app" {
  name                            = "app-vm"
  resource_group_name             = var.resource_group_name
  location                        = var.location
  size                            = "Standard_B2s"
  admin_username                  = "fixtureadmin"
  admin_password                  = var.admin_password_placeholder
  disable_password_authentication = false # planted: password authentication on Linux
  encryption_at_host_enabled      = false # planted: no encryption at host
  network_interface_ids           = [azurerm_network_interface.vm.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }
}
