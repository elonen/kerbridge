# The six values the realm's configs/idp_<source>.toml must carry in its
# [provider_config] table, plus the two that exist only when Terraform creates
# the sync secret. print-provider-config.sh reads the six with `terraform output -raw` and
# prints them as a TOML fragment for the operator to paste -- it writes no file;
# you can also read any one by hand, e.g.
# `terraform output -raw entra_public_client_id`.

output "entra_tenant_id" {
  description = "-> [provider_config] tenant_id"
  value       = var.tenant_id
}

output "entra_broker_api_client_id" {
  description = "-> [provider_config] broker_api_client_id (token audience)"
  value       = azuread_application.broker_api.client_id
}

output "entra_public_client_id" {
  description = "-> [provider_config] public_client_id (checked against azp)"
  value       = azuread_application.public_client.client_id
}

output "entra_broker_scope" {
  description = "-> [provider_config] scope"
  value       = var.scope_name
}

output "entra_sync_client_id" {
  description = "-> [provider_config] sync_client_id"
  value       = azuread_application.sync.client_id
}

output "entra_admission_group" {
  description = "display name, for reference; the source file binds by admission_group_id"
  value       = var.admission_group_name
}

output "entra_admission_group_id" {
  description = "-> [provider_config] admission_group_id"
  value       = azuread_group.admission.object_id
}

# Present only under create_sync_secret = true; null otherwise. The secret is a
# file secret, never a config value: write it to
# deploy/secrets/idp/<name>/credential (0600), and set
# sync_credential_expires from the companion output.
output "entra_sync_credential" {
  description = "The sync Graph secret, iff Terraform created it. Write to deploy/secrets/idp/<name>/credential; never into a config file."
  value       = var.create_sync_secret ? azuread_application_password.sync[0].value : null
  sensitive   = true
}

output "entra_sync_credential_expires" {
  description = "-> sync_credential_expires (YYYY-MM-DD), iff Terraform created the secret."
  value       = var.create_sync_secret ? formatdate("YYYY-MM-DD", azuread_application_password.sync[0].end_date) : null
}
