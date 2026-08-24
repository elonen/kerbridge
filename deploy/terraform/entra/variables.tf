# Inputs. The only one you must set is tenant_id; the rest default to the
# KerBridge conventions and change the deployment's shape only if you mean to.
# Every value the realm's configs/idp_<source>.toml needs comes back out through
# outputs.tf -- see print-provider-config.sh, which prints the six of them as a
# [provider_config] fragment to paste into that file.

variable "tenant_id" {
  description = "Entra tenant (directory) ID. Becomes [provider_config] tenant_id, and is the only tenant these three registrations and the group live in."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$", var.tenant_id))
    error_message = "tenant_id must be a GUID."
  }
}

variable "scope_name" {
  description = "The delegated scope the broker API exposes and the client requests. The broker checks for its presence in scp on every token, so this is [provider_config] scope and the two must agree. Leave it access_as_user unless you have a reason not to."
  type        = string
  default     = "access_as_user"
}

variable "admission_group_name" {
  description = "Display name of the admission group. Not a [provider_config] value of its own: print-provider-config.sh prints admission_group_id, and an id and a name together are refused, so a later rename does not break admission."
  type        = string
  default     = "KerBridge Allowed On-prem Users"
}

variable "public_client_redirect_uris" {
  description = "Browser-flow redirect URIs for the client. It does authorization-code + PKCE against an ephemeral loopback port, and Entra ignores the port when matching, so http://127.0.0.1 is the whole set -- and it must be 127.0.0.1, because that is the host kerbridge-client sends. The WAM redirect (ms-appx-web://microsoft.aad.brokerplugin/<client id>) is NOT listed here: it embeds the client id Entra assigns, so main.tf appends it automatically."
  type        = list(string)
  default     = ["http://127.0.0.1"]
}

variable "name_prefix" {
  description = "Prepended to the three application display names and the sync secret's label, so several KerBridge deployments in one tenant stay legible in the portal. Each name is the [provider_config] key it fills, minus the _id -- KerBridge broker API supplies broker_api_client_id. Not part of any [provider_config] value."
  type        = string
  default     = "KerBridge"
}

variable "create_sync_secret" {
  description = "Whether Terraform creates the sync app's Graph client secret itself. Default false keeps the live credential out of Terraform state: you create the secret out of band and Terraform never sees it (README.md @ The sync credential). Setting true writes the secret to a Terraform output AND to state -- treat the state file as a secret if you do, and prefer the out-of-band path."
  type        = bool
  default     = false
}

variable "sync_secret_end_date_relative" {
  description = "Lifetime of the Terraform-created sync secret, as a Go duration from apply time. Ignored unless create_sync_secret is true. The portal caps a new secret at 24 months (17520h); a tenant application-management policy may cap it lower or forbid secrets outright."
  type        = string
  default     = "17520h"
}
