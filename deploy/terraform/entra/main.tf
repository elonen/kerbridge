# The three Entra app registrations KerBridge needs, the admission group,
# and the admin consent that makes the sync app usable. This is the whole of
# what the manual portal walk in docs/setup/entra-manual.md does by hand -- the point
# of doing it here is that the six values the realm's idp_<source>.toml must
# match are generated once and read straight out with `terraform output`, so no
# GUID is ever transcribed from the portal.
#
# What is deliberately NOT here: the sync app's Graph *secret* (kept out of
# state by default -- see variables.tf and README.md), and everything on-prem
# (realm, DNS, TLS, ticket policy). This module knows nothing about Samba.

# Microsoft Graph's well-known service principal, read so the sync app's app-only
# role ids come from the tenant rather than hardcoded GUIDs.
#
# Read, not managed. As a resource with use_existing it would be adopted on apply
# and *deleted* on destroy -- Terraform would offer to remove the tenant's Graph
# service principal, taking every consented app in the tenant with it. Reading it
# also means the role ids below resolve at plan time, so `terraform plan` is a
# real authenticated Graph read rather than a syntax check.
data "azuread_application_published_app_ids" "well_known" {}

data "azuread_service_principal" "msgraph" {
  client_id = data.azuread_application_published_app_ids.well_known.result["MicrosoftGraph"]
}

# A stable id for the exposed scope. Generated once and kept in state; not
# sensitive, only immutable -- the public client's required-resource-access and
# the pre-authorization both reference it.
resource "random_uuid" "broker_scope" {}

# --- 1. Broker API -----------------------------------------------------------
# Validates the tokens kerbridge-client presents; it authenticates nothing outbound, so
# it carries no credential of its own. Its client id is the audience of every
# /ticket token (broker_api_client_id).
resource "azuread_application" "broker_api" {
  display_name     = "${var.name_prefix} broker API"
  sign_in_audience = "AzureADMyOrg"

  api {
    # Defaults to 1 (the attribute is null unless set). The broker accepts only
    # v2 access tokens, so this is required, not cosmetic -- it is the single
    # most common cause of a validator that rejects every otherwise-valid token.
    requested_access_token_version = 2

    # admin_* reaches an operator, user_* reaches an end user -- hence two
    # names for one app (GLOSSARY.md @ NAS Access).
    oauth2_permission_scope {
      id                         = random_uuid.broker_scope.result
      value                      = var.scope_name
      type                       = "User"
      enabled                    = true
      admin_consent_display_name = "Access KerBridge as the signed-in user"
      admin_consent_description  = "Allow the KerBridge client to obtain a Kerberos ticket for the signed-in user."
      user_consent_display_name  = "Access KerBridge on your behalf"
      user_consent_description   = "Allow NAS Access to obtain a Kerberos ticket for you."
    }
  }

  # The broker rejects an app-only token by `idtyp == "app"`
  # (crates/kerbridge-broker/src/verify.rs). The claim is optional and absent
  # unless requested here, and the broker's check degrades silently when it is
  # missing -- it then has only `scp` to tell a delegated token from an app-only
  # one. Requesting it is what keeps both halves of that test alive.
  optional_claims {
    access_token {
      name = "idtyp"
    }
  }
}

# The Application ID URI, without which nothing works.
#
# The broker advertises its scope to the client as
# `api://{broker_api_client_id}/{scope}` (crates/kerbridge-broker/src/config.rs),
# so that URI must resolve to this application. The portal hides the need for it:
# *Expose an API* refuses to add a scope until you have saved an Application ID
# URI, pre-filling `api://{client_id}`. Graph has no such interlock -- create the
# app with a scope and `identifierUris` simply stays empty, and every token
# request then fails with AADSTS500011 (resource principal not found) while every
# value in .env looks correct.
#
# A separate resource rather than `identifier_uris` on the application above,
# because the URI contains the client id Entra assigns to that same application:
# referencing it inline would be a self-reference Terraform cannot resolve.
resource "azuread_application_identifier_uri" "broker_api" {
  application_id = azuread_application.broker_api.id
  identifier_uri = "api://${azuread_application.broker_api.client_id}"
}

resource "azuread_service_principal" "broker_api" {
  client_id = azuread_application.broker_api.client_id
}

# --- 2. Public client (kerbridge-client) -------------------------------------------
# The native client that does the browser sign-in. Public (no secret): it holds
# PKCE, not a credential. Its client id is public_client_id, and the broker
# checks it against azp on every token.
resource "azuread_application" "public_client" {
  display_name     = "${var.name_prefix} public client"
  sign_in_audience = "AzureADMyOrg"

  # "Allow public client flows", explicitly off -- the provider default, stated
  # here because it looks like the switch a public client would want. It is not:
  # authorization-code + PKCE against the registered native redirect URIs below
  # needs nothing from it (docs/setup/entra-manual.md @ B.4, and the WAM path was
  # measured working with it off). Turning it on only adds ROPC and device-code
  # to what this app may do.
  fallback_public_client_enabled = false

  required_resource_access {
    resource_app_id = azuread_application.broker_api.client_id

    resource_access {
      id   = random_uuid.broker_scope.result
      type = "Scope"
    }
  }
}

# Both redirect URIs the two sign-in paths need.
#
#   http://127.0.0.1        the browser flow. kerbridge-client binds an ephemeral
#                           loopback port (client/kerbridge-client/src/oidc.rs) and Entra
#                           ignores the port when matching, so no fixed port is
#                           registered -- but the host must match what the client
#                           sends, and it sends 127.0.0.1, not localhost.
#
#   ms-appx-web://...       the WAM path, i.e. "Use Windows" in the tray. Without
#                           it the interactive WAM call fails with a redirect-URI
#                           mismatch on every Entra-joined machine
#                           (client/kerbridge-agent-windows/src/wam.rs, measured).
#
# Managed here rather than in a `public_client` block on the application above:
# the WAM URI embeds the client id Entra assigns to that same application, which
# inline would be a self-reference. The two forms are mutually exclusive -- with
# this resource present, the application must not also declare the block.
resource "azuread_application_redirect_uris" "public_client" {
  application_id = azuread_application.public_client.id
  type           = "PublicClient"

  redirect_uris = concat(
    var.public_client_redirect_uris,
    ["ms-appx-web://microsoft.aad.brokerplugin/${azuread_application.public_client.client_id}"],
  )
}

resource "azuread_service_principal" "public_client" {
  client_id = azuread_application.public_client.client_id
}

# Pre-authorize the client on the broker scope, so the browser sign-in never
# stops on a consent prompt the user could not grant anyway.
resource "azuread_application_pre_authorized" "client_on_broker" {
  application_id       = azuread_application.broker_api.id
  authorized_client_id = azuread_application.public_client.client_id
  permission_ids       = [random_uuid.broker_scope.result]
}

# --- 3. Sync app -------------------------------------------------------------
# Reads users and groups from Graph, app-only. Its client id is
# sync_client_id; its credential is handled separately (see below).
resource "azuread_application" "sync" {
  display_name     = "${var.name_prefix} sync"
  sign_in_audience = "AzureADMyOrg"

  required_resource_access {
    resource_app_id = data.azuread_service_principal.msgraph.client_id

    resource_access {
      id   = data.azuread_service_principal.msgraph.app_role_ids["User.Read.All"]
      type = "Role"
    }
    resource_access {
      id   = data.azuread_service_principal.msgraph.app_role_ids["Group.Read.All"]
      type = "Role"
    }
  }
}

resource "azuread_service_principal" "sync" {
  client_id = azuread_application.sync.client_id
}

# Admin consent for the two app-only roles. This is the grant that lets sync read
# anything -- without it the client-credentials token carries no roles and every
# Graph read is 403. It needs the identity running Terraform to be able to grant
# application permissions (Privileged Role Administrator or Global Administrator).
resource "azuread_app_role_assignment" "sync_user_read" {
  app_role_id         = data.azuread_service_principal.msgraph.app_role_ids["User.Read.All"]
  principal_object_id = azuread_service_principal.sync.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

resource "azuread_app_role_assignment" "sync_group_read" {
  app_role_id         = data.azuread_service_principal.msgraph.app_role_ids["Group.Read.All"]
  principal_object_id = azuread_service_principal.sync.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

# Optional, off by default. Creating the secret here puts a live sync credential
# in Terraform state, which is why the supported default is to create it out of
# band and let Terraform never see it. Behind the flag for the deployments that
# accept a sensitive state file in exchange for one command.
resource "azuread_application_password" "sync" {
  count = var.create_sync_secret ? 1 : 0

  application_id    = azuread_application.sync.id
  display_name      = "${var.name_prefix} sync (terraform)"
  end_date_relative = var.sync_secret_end_date_relative
}

# --- Admission group ---------------------------------------------------------
# The group whose membership admits a user to the realm. Its object id is
# admission_group_id. Sync marks the synchronized Samba copy with the
# realm-admission role marker; this is just the Entra source object.
resource "azuread_group" "admission" {
  display_name     = var.admission_group_name
  security_enabled = true
  mail_enabled     = false
}
