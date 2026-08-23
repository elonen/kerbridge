# Entra app registrations, as Terraform

Creates:

- the three Entra application registrations
- the admission group KerBridge needs
- the admin consent that makes the sync app usable
- the six values the Entra source's `[provider_config]` must carry

**The guide is [`docs/setup/entra-terraform.md`](../../../docs/setup/entra-terraform.md)**
— prerequisites, how to run it, the sync credential, state sensitivity and
teardown. This file is the module reference only.

## Inputs

| Variable | Default | |
|---|---|---|
| `tenant_id` | *(required)* | Entra tenant (directory) ID. Becomes `tenant_id`. |
| `scope_name` | `access_as_user` | The delegated scope the broker API exposes and the helper requests. Becomes `scope`; the broker checks for it in `scp`, so the two must agree. |
| `admission_group_name` | `KerBridge Allowed On-prem Users` | Display name of the admission group in Entra. Not a `[provider_config]` value: sync binds to the group's id, so `print-provider-config.sh` prints `admission_group_id` and no name key. |
| `public_client_redirect_uris` | `["http://127.0.0.1"]` | Browser-flow redirect URIs. The WAM redirect is appended automatically — it embeds the client id Entra assigns, so it cannot be a default here. |
| `name_prefix` | `KerBridge` | Prepended to the three display names, so several deployments in one tenant stay legible. Not part of any `[provider_config]` value. |
| `create_sync_secret` | `false` | Whether Terraform creates the sync app's Graph secret. `true` puts a live credential in state — see the guide. |
| `sync_secret_end_date_relative` | `17520h` | Lifetime of that secret, as a Go duration. Ignored unless `create_sync_secret`. |

## Outputs

The six `[provider_config]` values, which `./print-provider-config.sh` prints as a TOML
fragment to paste into `configs/idp_<source>.toml`:

| Output | `[provider_config]` key |
|---|---|
| `entra_tenant_id` | `tenant_id` |
| `entra_broker_api_client_id` | `broker_api_client_id` (token audience) |
| `entra_public_client_id` | `public_client_id` (checked against `azp`) |
| `entra_broker_scope` | `scope` |
| `entra_sync_client_id` | `sync_client_id` |
| `entra_admission_group` | *(reference only — the id is the binding, so no name key is printed)* |
| `entra_admission_group_id` | `admission_group_id` |

Two more exist only under `create_sync_secret = true`, and are `null` otherwise:

- `entra_sync_credential` — sensitive; a file secret, written to
  `secrets/idp/<name>/credential`, never a config value
- `entra_sync_credential_expires` — `sync_credential_expires`

## Files

| | |
|---|---|
| `main.tf` | The registrations, the pre-authorization, the Graph consent, the group. |
| `variables.tf` / `outputs.tf` | The tables above, with the reasoning on each entry. |
| `versions.tf` | Provider pinning (`azuread ~> 3.0`) and the tenant-scoped provider. |
| `print-provider-config.sh` | Prints the six values as a `[provider_config]` fragment on stdout, and the credential and paste steps on stderr. It writes no file. |
| `terraform.tfvars.example` | Copy to `terraform.tfvars` (gitignored — it holds a real tenant id). |
