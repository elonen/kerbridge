#!/bin/bash
# Print the `[provider_config]` fragment for configs/idp_<source>.toml, from
# `terraform output`.
#
# This is the bridge the whole module exists for: the values that must match
# between Entra and the realm are exactly the ones Terraform generates, so
# they flow one way -- apply, then run this -- and no GUID is ever copied by
# hand. It prints; pasting the six lines into the `[provider_config]` table of
# configs/idp_<source>.toml is the operator's own step, because this script
# has no way to know that file already exists or where its table starts.
#
# Idempotent: run it again after a re-apply and the fragment reflects the new
# outputs. The sync Graph secret is not printed here -- it is a file secret,
# not a config value; see README.md @ The sync credential.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

[ -d "$here/.terraform" ] || {
  echo "No Terraform state here. Run, in $here:" >&2
  echo "  terraform init && terraform apply" >&2
  exit 1
}

tf() { terraform -chdir="$here" output -raw "$1"; }

# .terraform exists after `init` alone, so its presence says nothing about
# whether anything was applied. Ask for an output before printing anything.
tf entra_tenant_id >/dev/null 2>&1 || {
  echo "Terraform is initialized here but has no outputs -- nothing applied yet." >&2
  echo "Run, in $here:" >&2
  echo "  terraform apply" >&2
  exit 1
}

cat <<EOF
[provider_config]
tenant_id = "$(tf entra_tenant_id)"
broker_api_client_id = "$(tf entra_broker_api_client_id)"
public_client_id = "$(tf entra_public_client_id)"
scope = "$(tf entra_broker_scope)"
sync_client_id = "$(tf entra_sync_client_id)"
# The id is the only binding sync takes. The display name stays readable as the
# entra_admission_group output.
admission_group_id = "$(tf entra_admission_group_id)"
EOF

echo "" >&2
echo "Paste the block above into the [provider_config] table of" >&2
echo "configs/idp_<source>.toml, replacing tenant_id, broker_api_client_id," >&2
echo "public_client_id, scope, sync_client_id and admission_group_id there." >&2
echo "Some of those lines are commented out in that file. Paste over each one," >&2
echo "or delete it: a line you leave commented out sets nothing." >&2
echo "Delete any admission_group (name) line already in that file -- that key" >&2
echo "no longer exists, and a file that states it is refused at startup." >&2
echo "" >&2
echo "If the scope line above says \"access_as_user\", delete it. That is already" >&2
echo "the default, and an option you set keeps your value even where a later" >&2
echo "version has a better default." >&2

# The credential step has three states, and the operator should not have to work
# out which one they are in -- print only the one that applies.
#
# -s, not -e: prepare-state creates this file empty so the compose bind mount has
# a source, so existence proves nothing and sync idles on an empty one.
#
# The probe is the *expiry* output, not the secret: it is the non-sensitive half
# of the same pair, so create_sync_secret can be read off it without putting a
# live credential through a subshell here.
deploy="$(cd "$here/../.." && pwd)"
cred="$deploy/secrets/idp/entra/credential"
expires=""

printf '\nDo this next:\n\n'

if [ -s "$cred" ]; then
  printf '  1. Sync Graph credential -- already in place, nothing to do.\n\n'
elif expires="$(tf entra_sync_credential_expires 2>/dev/null)"; then
  cat <<EOF
  1. Sync Graph credential -- Terraform created it (create_sync_secret = true).
     Write it to its own directory, and put the expiry in
     configs/idp_<source>.toml:

       mkdir -p "$(dirname "$cred")"
       (umask 077; terraform -chdir="$here" output -raw entra_sync_credential \\
          > "$cred")

       sync_credential_expires = "$expires"

     The umask is essential: the redirect creates the file at whatever yours
     is, so a chmod on the next line would leave it readable in between.
     \`make check-secrets\` in deploy/ gates on the mode.

EOF
else
  cat <<EOF
  1. Sync Graph credential -- yours to create; Terraform does not create it.
     Take the secret's **Value**, not its Secret ID, and write it to its file:

       (umask 077; az ad app credential reset --id $(tf entra_sync_client_id) \\
          --append --years 2 --query password -o tsv > "$cred")

     Portal instead of az, why a GUID-shaped value is always the wrong one, and
     the optional sync_credential_expires:
     docs/setup/entra-manual.md @ The sync credential

EOF
fi

cat <<EOF
  2. Fill in the rest of configs/*.toml by hand -- realm, DNS, TLS, ticket
     policy, and everything in idp_<source>.toml outside [provider_config].
     The [provider_config] block above is done; nothing else is.

  3. Continue with SETUP.md step 3 (Publish the DNS records).
EOF
