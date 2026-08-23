# Provider pinning. azuread v3 is assumed throughout: it names the client-id
# attribute `client_id` (not the deprecated `application_id`) and uses the v3
# argument names on azuread_application_pre_authorized. Authentication is the
# Azure CLI by default -- `az login` as an identity that can create application
# registrations and grant application permissions (see README.md).
terraform {
  required_version = ">= 1.5"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azuread" {
  tenant_id = var.tenant_id
}
