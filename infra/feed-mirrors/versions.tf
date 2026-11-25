# Release 4 feed mirrors (KDEC-032 PROPOSED) -- the Azure side, for the platform team to deploy into the
# security platform subscription. Terraform, because the landing zone's IaC is Terraform
# (docs/architecture/LZ_KIT_SEAM_CONTRACT.md): one toolchain, one state backend, one review path.
# Step-by-step: docs/adoption/FEED_MIRRORS.md. NOT APPLIED to any subscription yet.

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.14"
    }
  }
}

provider "azurerm" {
  features {}
  # Shared key is OFF on the account (main.tf), so the provider's own data-plane calls -- enabling the
  # static website -- must authenticate with Entra too. The identity applying this therefore needs a
  # data-plane path (a private-network runner, like every other job here) and is the one the platform
  # team already uses for its applies.
  storage_use_azuread = true
  # 5.x registers NO resource providers by default (4.x registered ~60). Say so explicitly, so a
  # later default change cannot silently widen what the applying identity attempts. The
  # subscription must already have these registered: Microsoft.Storage, Microsoft.Network,
  # Microsoft.ContainerRegistry, Microsoft.ManagedIdentity, Microsoft.Insights.
  resource_provider_registrations = "none"
}
