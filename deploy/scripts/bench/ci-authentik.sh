#!/bin/bash
# The server path with a live authentik as the identity provider, from a fresh
# clone to a broker that verifies a real authentik token. What `make
# test-authentik` runs.
#
# This is the authentik counterpart of ci-stack.sh. The two share
# scripts/bench/provision.sh, which brings a realm up from nothing and waits for
# the broker's `/config` over TLS; each supplies its source through the three
# hooks below. Where the Entra tier fakes the IdP twice -- pre-forged tokens and a
# key document off disk -- authentik is real: it runs on the compose network
# behind the same Caddy, and the broker fetches its signing keys over TLS.
#
# What it proves, beyond what provision.sh already does:
#
#   1. The broker's FIRST REAL JWKS FETCH. The startup fetch is fatal on failure
#      (kerbridge-idp/src/jwks.rs), so the broker answers `/config` only if it
#      first fetched the application's keys from authentik, over TLS, trusting the
#      bench CA. provision.sh waiting for `/config` is that proof.
#   2. Sync REFUSES the authentik source, loudly and by name. This build carries
#      authentik's token face and not its directory one, so the sync daemon must
#      stop rather than mirror nobody -- and it must say which source and why.
#
# Not proved here, and not coverable until the directory face lands: a sign-in to
# a TGT and a file over SMB (ci-stack.sh's last leg), which needs sync to have
# written the user the broker then resolves. The blueprint carries the second
# application and the read-only service account those steps will use.
set -euo pipefail

# provision.sh uses this source in the config set and broker routes.
SOURCE=authentik

# Order is significant. compose.ci.yaml removes the bench ports; compose.authentik.yaml
# then adds authentik and wires the broker to it. There is no compose.mockidp.yaml
# here -- authentik is the authority, not a stand-in for one.
export COMPOSE_FILE=compose.yaml:compose.nas.yaml:compose.ci.yaml:compose.authentik.yaml

# Sync never reads this in a build without authentik's directory face -- connect()
# refuses the source first -- but the source file names it and the config set
# loads all files together, so it has to exist. A constant, bench- prefixed like
# the blueprint's.
idp_prepare() {
  say "writing the constant bench sync credential"
  mkdir -p "$ROOT/deploy/secrets/idp/authentik"
  printf '%s' 'bench-authentik-sync-token' > "$ROOT/deploy/secrets/idp/authentik/credential"
}

# IDP_FQDN is the alias Caddy answers for and proxies to authentik on; the broker
# derives every authentik URL from it. CI_APPROVE_SH is compose.ci.yaml's nas1
# mount and is unused here -- the client sign-in leg is the directory phase -- so
# it points at an existing file the tier never invokes.
idp_env_lines() {
  cat <<EOF

IDP_FQDN=$IDP_FQDN
CI_APPROVE_SH=$ROOT/testbench/mock-idp/approve.sh
EOF
}

# One authentik application. url has no port because the broker reaches it on the
# network's :443, and `iss` follows that origin -- issuer, authority and jwks_url
# all derive from url and the slug. client_id is the blueprint's, a chosen string
# rather than a generated id. sync is stated but does not run: its refusal is the
# assertion below.
idp_source_toml() {
  cat <<EOF
name = "$SOURCE"
provider = "authentik"
group_suffix = "none"
bind_dn = "CN=svc-kerbridge-sync-$SOURCE,CN=Users,$BASE_DN"
bind_password_file = "/etc/kerbridge.secrets/generated/idp/$SOURCE/bind_password"

[provider_config]
url = "https://$IDP_FQDN"
application_slug = "kerbridge"
client_id = "kerbridge"
sync_credential_file = "/etc/kerbridge.secrets/idp/$SOURCE/credential"
EOF
}

. "$(dirname "$0")/provision.sh"

# ---------------------------------------------------------------------------
# The shared script returned after the broker answered /config over TLS -- which
# means its startup JWKS fetch from authentik succeeded. Run authentik-specific
# assertions.
# ---------------------------------------------------------------------------
say "the broker answered /config, so its startup JWKS fetch from live authentik over TLS succeeded"
echo "that is the first real JWKS fetch -- not the mock-idp trick of a key document in a shared volume"

# ---------------------------------------------------------------------------
# Sync must refuse the source rather than mirror nobody. This build has the
# token face and not the directory one, so connect() bails at startup. Run the
# daemon once and require it to stop, naming the source and the reason.
# ---------------------------------------------------------------------------
say "sync refuses the authentik source in a build without its directory face"
out=$ROOT/.local-tmp/ci-sync-refusal.log
if docker compose run --rm --no-deps sync > "$out" 2>&1; then
  cat "$out"
  die "sync exited 0 against authentik, but this build carries no authentik directory face"
fi
cat "$out"
grep -q "reads no directory" "$out" ||
  die "sync stopped, but not with the directory-face refusal -- check what actually failed"
grep -q "$SOURCE" "$out" ||
  die "the refusal does not name the source; an operator cannot act on it"
echo "sync refused source \"$SOURCE\" by name and stopped"

say "PASS -- provisioned, authentik behind Caddy, the broker verified its keys, and sync refused the source"
