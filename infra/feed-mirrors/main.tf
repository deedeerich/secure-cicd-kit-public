# THE MIRROR: one storage account whose static website ($web) holds the feeds, reachable ONLY through
# private endpoints (owner rule R8: public endpoints only where a private one is technically impossible --
# Azure Storage and Azure Container Registry both support private endpoints, so neither is public).
#
# WHY A STATIC WEBSITE. The NVD datafeed is read by Dependency-Check itself, over plain HTTP(S) with no
# bearer token (it supports only basic credentials), and Trivy and the KEV check read files. A static
# website serves the $web container anonymously -- "Disabling anonymous access on a storage account ...
# doesn't affect static websites" (Microsoft Learn, Static website hosting) -- so readers need no
# credential at all, and the private `web` endpoint with public network access off is the access
# control: only the private network can read, and what it reads is public data (NVD, CISA, Trivy) whose
# integrity the manifest's sha256 carries. Writes use the `blob` endpoint with Entra only.
#
# WHY NOT THE LEASE STORE'S ACCOUNT (KDEC-030). Recommended: SEPARATE accounts, same private network. The
# lease store holds release records and lease state that must never be anonymously readable; this account
# is anonymous-readable on its network by design. Sharing one account would put an anonymous `web`
# endpoint and a second team's grants next to the release ledger, and account-level settings (network
# rules, static website, diagnostics) would serve two owners. Separate accounts cost only transactions.

locals {
  account_name  = "${var.name_prefix}feedmirror"
  registry_name = "${var.name_prefix}scanmirror"
  zones = {
    web      = "privatelink.web.core.windows.net"
    blob     = "privatelink.blob.core.windows.net"
    registry = "privatelink.azurecr.io"
  }
  wanted_zones = var.enable_registry ? ["web", "blob", "registry"] : ["web", "blob"]
  create_zones = toset([for k in local.wanted_zones : k if !contains(keys(var.dns_zone_ids), k)])
  zone_id      = { for k in local.wanted_zones : k => contains(keys(var.dns_zone_ids), k) ? var.dns_zone_ids[k] : azurerm_private_dns_zone.zone[k].id }
  links        = { for pair in setproduct(tolist(local.create_zones), var.dns_link_vnet_ids) : "${pair[0]}-${md5(pair[1])}" => { zone = pair[0], vnet = pair[1] } }
  # Storage Blob Data Contributor, scoped below to the $web container only -- not the account.
  web_container_scope = "${azurerm_storage_account.mirror.id}/blobServices/default/containers/$web"
}

# AZU-0057 asks for classic Storage Analytics logging, which this provider exposes only for QUEUES (this
# account has none) and only through the shared-key-era data plane. The audit that matters -- every blob
# write and delete -- is the Azure Monitor diagnostic setting `blob_audit` below.
#trivy:ignore:AVD-AZU-0057
resource "azurerm_storage_account" "mirror" {
  name                = local.account_name
  resource_group_name = var.resource_group_name
  location            = var.location
  account_kind        = "StorageV2"
  account_tier        = "Standard"
  # ZRS, not geo-redundant (AZU-0058, LOW): everything here is public data rebuilt by the next daily
  # refresh; a regional outage is a refresh away from recovery, and the runners are regional too.
  account_replication_type = "ZRS"

  public_network_access_enabled     = false
  shared_access_key_enabled         = false
  default_to_oauth_authentication   = true
  allow_nested_items_to_be_public   = false
  min_tls_version                   = "TLS1_2"
  https_traffic_only_enabled        = true
  cross_tenant_replication_enabled  = false
  infrastructure_encryption_enabled = true

  # With public network access OFF nothing public reaches the account, trusted Azure services included;
  # these rules only matter if someone turns it back on, and then they deny by default.
  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }

  tags = var.tags
}

# The static website: creates and serves the $web container. A data-plane setting, applied with Entra
# (provider storage_use_azuread) over the private endpoint -- so it depends on the blob endpoint below.
resource "azurerm_storage_account_static_website" "mirror" {
  storage_account_id = azurerm_storage_account.mirror.id
  index_document     = "index.html"
  depends_on         = [azurerm_private_endpoint.blob]
}

resource "azurerm_private_dns_zone" "zone" {
  for_each            = local.create_zones
  name                = local.zones[each.key]
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "link" {
  for_each              = local.links
  name                  = "link-${each.key}"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.zone[each.value.zone].name
  virtual_network_id    = each.value.vnet
  registration_enabled  = false
  tags                  = var.tags
}

# Readers (every scan job, and the refresh's own read-back) use the static website endpoint.
resource "azurerm_private_endpoint" "web" {
  name                = "pe-${local.account_name}-web"
  resource_group_name = var.resource_group_name
  location            = var.location
  subnet_id           = var.private_endpoint_subnet_id
  private_service_connection {
    name                           = "web"
    private_connection_resource_id = azurerm_storage_account.mirror.id
    subresource_names              = ["web"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "web"
    private_dns_zone_ids = [local.zone_id["web"]]
  }
  tags = var.tags
}

# The writer (the refresh identity) uses the blob endpoint.
resource "azurerm_private_endpoint" "blob" {
  name                = "pe-${local.account_name}-blob"
  resource_group_name = var.resource_group_name
  location            = var.location
  subnet_id           = var.private_endpoint_subnet_id
  private_service_connection {
    name                           = "blob"
    private_connection_resource_id = azurerm_storage_account.mirror.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "blob"
    private_dns_zone_ids = [local.zone_id["blob"]]
  }
  tags = var.tags
}

# THE SCANNER-IMAGE MIRROR. Premium (a private endpoint requires it); anonymous pull, so a scan job's
# `container:` needs no credential -- the private endpoint with public access off is the access control,
# exactly as for the static website, and the images are public images pinned by digest.
resource "azurerm_container_registry" "mirror" {
  count                         = var.enable_registry ? 1 : 0
  name                          = local.registry_name
  resource_group_name           = var.resource_group_name
  location                      = var.location
  sku                           = "Premium"
  admin_enabled                 = false
  public_network_access_enabled = false
  anonymous_pull_enabled        = true
  network_rule_bypass_option    = "None"
  zone_redundancy_enabled       = true
  tags                          = var.tags
}

resource "azurerm_private_endpoint" "registry" {
  count               = var.enable_registry ? 1 : 0
  name                = "pe-${local.registry_name}-registry"
  resource_group_name = var.resource_group_name
  location            = var.location
  subnet_id           = var.private_endpoint_subnet_id
  private_service_connection {
    name                           = "registry"
    private_connection_resource_id = azurerm_container_registry.mirror[0].id
    subresource_names              = ["registry"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "registry"
    private_dns_zone_ids = [local.zone_id["registry"]]
  }
  tags = var.tags
}

# THE REFRESH IDENTITY: a user-assigned managed identity, federated to ONE environment of ONE repository.
# No secret exists for it anywhere.
resource "azurerm_user_assigned_identity" "refresh" {
  name                = "id-${var.name_prefix}-feed-mirror-refresh"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

resource "azurerm_federated_identity_credential" "refresh" {
  name                = "github-${var.github_environment}"
  resource_group_name = var.resource_group_name
  parent_id           = azurerm_user_assigned_identity.refresh.id
  issuer              = var.oidc_issuer
  audience            = ["api://AzureADTokenExchange"]
  subject             = "repo:${var.github_repository}:environment:${var.github_environment}"
}

# LEAST PRIVILEGE: write the $web container, nothing else on the account (no keys, no network rules, no
# other container). The scans need NO role: they read anonymously through the private web endpoint.
resource "azurerm_role_assignment" "refresh_web" {
  scope                = local.web_container_scope
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.refresh.principal_id
  principal_type       = "ServicePrincipal"
  depends_on           = [azurerm_storage_account_static_website.mirror]
}

# Push to the mirror registry only (a registry that holds nothing but mirrored scanner images).
resource "azurerm_role_assignment" "refresh_acr" {
  count                = var.enable_registry ? 1 : 0
  scope                = azurerm_container_registry.mirror[0].id
  role_definition_name = "AcrPush"
  principal_id         = azurerm_user_assigned_identity.refresh.principal_id
  principal_type       = "ServicePrincipal"
}

# Who wrote or deleted which blob, and when (the refresh is the only writer; anything else is an alert).
resource "azurerm_monitor_diagnostic_setting" "blob_audit" {
  count                      = var.log_analytics_workspace_id == "" ? 0 : 1
  name                       = "feed-mirror-audit"
  target_resource_id         = "${azurerm_storage_account.mirror.id}/blobServices/default"
  log_analytics_workspace_id = var.log_analytics_workspace_id
  enabled_log {
    category = "StorageWrite"
  }
  enabled_log {
    category = "StorageDelete"
  }
}
