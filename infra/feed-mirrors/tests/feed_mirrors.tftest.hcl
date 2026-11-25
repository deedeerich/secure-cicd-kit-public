# infra/feed-mirrors: the security posture the module promises, planned and applied against a MOCK
# azurerm provider (no Azure, no credential). Run: terraform -chdir=infra/feed-mirrors test
mock_provider "azurerm" {
  mock_resource "azurerm_storage_account" {
    defaults = {
      id                   = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec/providers/Microsoft.Storage/storageAccounts/kitfeedmirror"
      primary_web_endpoint = "https://kitfeedmirror.z13.web.core.windows.net/"
    }
  }
  mock_resource "azurerm_user_assigned_identity" {
    defaults = {
      id           = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-kit-feed-mirror-refresh"
      principal_id = "11111111-1111-1111-1111-111111111111"
      client_id    = "22222222-2222-2222-2222-222222222222"
      tenant_id    = "33333333-3333-3333-3333-333333333333"
    }
  }
  mock_resource "azurerm_container_registry" {
    defaults = {
      id           = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec/providers/Microsoft.ContainerRegistry/registries/kitscanmirror"
      login_server = "kitscanmirror.azurecr.io"
    }
  }
  mock_resource "azurerm_private_dns_zone" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec/providers/Microsoft.Network/privateDnsZones/zone"
    }
  }
}

variables {
  resource_group_name        = "rg-sec"
  location                   = "eastus2"
  name_prefix                = "kit"
  private_endpoint_subnet_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet/subnets/pe"
  dns_link_vnet_ids          = ["/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet"]
  github_repository          = "example-org/scan-refresh"
  log_analytics_workspace_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-log/providers/Microsoft.OperationalInsights/workspaces/law"
}

run "plan_security_posture" {
  command = plan

  assert {
    condition     = azurerm_storage_account.mirror.public_network_access == "Disabled"
    error_message = "storage: public network access must be Disabled"
  }
  assert {
    condition     = azurerm_storage_account.mirror.shared_access_key_enabled == false && azurerm_storage_account.mirror.default_to_oauth_authentication == true
    error_message = "storage: shared key must be off and Entra the default"
  }
  assert {
    condition     = azurerm_storage_account.mirror.allow_nested_items_to_be_public == false && azurerm_storage_account.mirror.min_tls_version == "TLS1_2" && azurerm_storage_account.mirror.https_traffic_only_enabled == true
    error_message = "storage: anonymous blob off, TLS1_2, https only"
  }
  assert {
    condition     = azurerm_storage_account.mirror.cross_tenant_replication_enabled == false && azurerm_storage_account.mirror.infrastructure_encryption_enabled == true && azurerm_storage_account.mirror.account_replication_type == "ZRS"
    error_message = "storage: replication/encryption posture changed"
  }
  assert {
    condition     = azurerm_storage_account.mirror.network_rules[0].default_action == "Deny"
    error_message = "storage: network rules must deny by default"
  }
  assert {
    condition     = azurerm_container_registry.mirror[0].public_network_access_enabled == false && azurerm_container_registry.mirror[0].admin_enabled == false && azurerm_container_registry.mirror[0].anonymous_pull_enabled == true && azurerm_container_registry.mirror[0].sku == "Premium" && azurerm_container_registry.mirror[0].network_rule_bypass_option == "None"
    error_message = "registry posture changed"
  }
  assert {
    condition     = azurerm_private_endpoint.web.private_service_connection[0].subresource_names == tolist(["web"]) && azurerm_private_endpoint.blob.private_service_connection[0].subresource_names == tolist(["blob"]) && azurerm_private_endpoint.registry[0].private_service_connection[0].subresource_names == tolist(["registry"])
    error_message = "private endpoints changed"
  }
  assert {
    condition     = length(azurerm_private_dns_zone.zone) == 3 && length(azurerm_private_dns_zone_virtual_network_link.link) == 3
    error_message = "zones/links count changed"
  }
  assert {
    condition     = azurerm_federated_identity_credential.refresh.subject == "repo:example-org/scan-refresh:environment:feed-mirror" && azurerm_federated_identity_credential.refresh.issuer == "https://token.actions.githubusercontent.com" && azurerm_federated_identity_credential.refresh.audience == tolist(["api://AzureADTokenExchange"])
    error_message = "federated credential trust changed"
  }
  assert {
    condition     = azurerm_role_assignment.refresh_web.role_definition_name == "Storage Blob Data Contributor" && azurerm_role_assignment.refresh_web.principal_type == "ServicePrincipal"
    error_message = "web role changed"
  }
  assert {
    condition     = azurerm_role_assignment.refresh_acr[0].role_definition_name == "AcrPush"
    error_message = "acr role changed"
  }
  assert {
    condition     = length(azurerm_monitor_diagnostic_setting.blob_audit) == 1
    error_message = "audit setting missing"
  }
}

run "apply_mocked_wiring" {
  command = apply

  assert {
    condition     = azurerm_role_assignment.refresh_web.scope == "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec/providers/Microsoft.Storage/storageAccounts/kitfeedmirror/blobServices/default/containers/$web"
    error_message = "web grant is not scoped to the $web container"
  }
  assert {
    condition     = azurerm_monitor_diagnostic_setting.blob_audit[0].target_resource_id == "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec/providers/Microsoft.Storage/storageAccounts/kitfeedmirror/blobServices/default"
    error_message = "audit target changed"
  }
  assert {
    condition     = output.mirror_url == "https://kitfeedmirror.z13.web.core.windows.net/" && output.registry_login_server == "kitscanmirror.azurecr.io" && output.refresh_identity_client_id == "22222222-2222-2222-2222-222222222222"
    error_message = "outputs changed"
  }
}
