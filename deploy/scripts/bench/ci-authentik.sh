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
#   2. A SCRIPTED SIGN-IN TO A REAL TGT. approve.sh signs benchuser in through the
#      flow executor with no browser, the client posts the authentik token to
#      /ticket, and a KDC-signed TGT comes back -- for a directory user seed-demo.sh
#      hand-provisions with benchuser's uuid, because sync is off here as it is in
#      ci-stack.sh. Then the neighbouring application mints a cross-application
#      token, refused 401 on the issuer (per-provider issuer mode makes it an
#      issuer negative; its aud is correct).
#   3. Sync REFUSES the authentik source, loudly and by name. This build carries
#      authentik's token face and not its directory one, so the sync daemon must
#      stop rather than mirror nobody -- and it must say which source and why.
#
# Left to the directory phase: the SMB file read (ci-stack.sh's last leg) driven
# by sync writing the user rather than seed-demo.sh, which needs the directory
# face this build does not carry.
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
# mount: the `$BROWSER` the client's sign-in drives -- here the authentik flow
# executor, not mock-idp's one-redirect approval.
idp_env_lines() {
  cat <<EOF

IDP_FQDN=$IDP_FQDN
CI_APPROVE_SH=$ROOT/testbench/authentik/approve.sh
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
# Hand-provision the directory for the signed-in user. Sync is off in this build,
# so the broker resolves a token to a principal only if one is seeded -- exactly
# how ci-stack.sh proves the broker with sync switched off. The one authentik
# difference is the subject: benchuser's uuid is assigned at blueprint time, not
# known in advance, so read it now and give it to seed-demo.sh as the demo user's
# external id.
# ---------------------------------------------------------------------------
say "reading benchuser's uuid from authentik -- the subject a signed-in token carries"
uuid=$(docker compose exec -T authentik-server python3 - <<'PY'
import json, os, urllib.request
req = urllib.request.Request(
    "http://localhost:9000/api/v3/core/users/?username=benchuser",
    headers={"Authorization": "Bearer " + os.environ["AUTHENTIK_BOOTSTRAP_TOKEN"]})
print(json.load(urllib.request.urlopen(req, timeout=10))["results"][0]["uuid"])
PY
)
uuid=$(printf '%s' "$uuid" | tr -d '\r' | tail -1)
case "$uuid" in
  [0-9a-f]*-[0-9a-f]*-[0-9a-f]*-[0-9a-f]*-[0-9a-f]*) : ;;
  *) die "authentik did not return a canonical uuid for benchuser: '$uuid'" ;;
esac
echo "benchuser uuid = $uuid"

say "seeding the demo directory with that uuid as the demo user's external id"
# The last SEED_USER_OID in .env wins; provision.sh wrote an Entra-shaped
# constant. seed-demo.sh otherwise refuses when a sync credential is present,
# because a present credential means sync owns the OU -- but here sync refuses
# the source (asserted below), so nothing writes the OU but this script.
printf '\nSEED_USER_OID=%s\n' "$uuid" >> "$ROOT/deploy/.env"
SEED_DEMO_AGAINST_LIVE_SYNC=1 scripts/bench/seed-demo.sh

# ---------------------------------------------------------------------------
# The real client, signing in through authentik with no browser and no human,
# and turning the token into a KDC-signed TGT. Run inside nas1 so the same
# `kerbridge` an operator runs drives approve.sh as its `$BROWSER`; only the
# environment differs. This proves the client, the broker's token face, and
# approve.sh end to end -- a documented /config field the broker published and
# the client parsed nowhere would fail here.
# ---------------------------------------------------------------------------
say "the real client, signing in through authentik with no human and no browser"
CI_CA_IN_NAS=/etc/kerbridge-ci-ca.crt
CI_CCACHE_IN_NAS=/tmp/kb.ccache
client() {
  docker compose exec -T \
    -e "BROWSER=/usr/local/bin/kb-approve" \
    -e "KB_APPROVE_CA=$CI_CA_IN_NAS" \
    -e "KB_APPROVE_LOG=/tmp/kb-approve.log" \
    -e "SSL_CERT_FILE=$CI_CA_IN_NAS" \
    -e "KRB5CCNAME=FILE:$CI_CCACHE_IN_NAS" \
    nas1 "$@"
}
docker compose exec -T nas1 rm -f "$CI_CCACHE_IN_NAS"
signin=$ROOT/.local-tmp/ci-authentik-signin.log
if ! client kerbridge --broker "https://$FQDN" > "$signin" 2>&1; then
  cat "$signin"
  client cat /tmp/kb-approve.log 2>/dev/null || true
  die "the client could not sign in through authentik and obtain a TGT"
fi
cat "$signin"
# The principal the broker issued, read out of the client's own log. The token
# was benchuser's; the TGT is $USER_NAME's, the directory principal its uuid maps
# to.
grep -qi "$USER_NAME@$REALM" "$signin" ||
  die "the client reported no ticket for $USER_NAME@$REALM"
echo "benchuser signed in through authentik and the client obtained a TGT for $USER_NAME@$REALM"

# ---------------------------------------------------------------------------
# The cross-application negative. The neighbour
# kerbridge-second shares client_id, so its token carries the correct aud and a
# different iss -- an issuer negative no forged single-instance corpus can make.
# Mint it inside nas1, the only place a token with a port-free iss can be minted,
# and hand it to /ticket. No PKCE: the check under test is issuer verification,
# and a public client without a code_challenge needs none.
# ---------------------------------------------------------------------------
say "a cross-application token is refused 401 on its issuer, aud being correct"
cross=$ROOT/.local-tmp/ci-authentik-crosstoken
docker compose exec -T nas1 sh -s > "$cross" <<'SH'
set -eu
base=https://idp.kbci.test
ruri=http://127.0.0.1:9799
authz="$base/application/o/authorize/?response_type=code&client_id=kerbridge&redirect_uri=$ruri&response_mode=query&scope=openid&state=crossapp"
out=$(KB_APPROVE_CA=/etc/kerbridge-ci-ca.crt KB_APPROVE_LOG=/tmp/kb-cross.log \
      KB_APPROVE_USER=benchuser KB_APPROVE_PASSWORD=bench-user-password \
      /usr/local/bin/kb-approve "$authz")
code=$(printf '%s\n' "$out" | sed -n 's/^code=//p')
[ -n "$code" ] || { echo "no code from approve.sh" >&2; cat /tmp/kb-cross.log >&2; exit 1; }
tokresp=$(curl -sS --cacert /etc/kerbridge-ci-ca.crt "$base/application/o/token/" \
  --data-urlencode grant_type=authorization_code \
  --data-urlencode "code=$code" \
  --data-urlencode "redirect_uri=$ruri" \
  --data-urlencode client_id=kerbridge)
at=$(printf '%s' "$tokresp" | perl -0777 -ne 'print $1 if /"access_token"\s*:\s*"([^"]*)"/')
[ -n "$at" ] || { echo "token exchange returned no access_token: $tokresp" >&2; exit 1; }
printf '%s' "$at"
SH
token=$(tr -d '\r\n' < "$cross")
[ -n "$token" ] || { cat "$cross"; die "could not mint a cross-application token in nas1"; }

resp=$ROOT/.local-tmp/ci-authentik-cross.json
code=$(api POST "/$SOURCE/ticket" "$resp" -H "Authorization: Bearer $token")
[ "$code" = 401 ] || { cat "$resp"; echo; die "the cross-application token answered $code, wanted 401"; }
# The 401 body carries only "invalid identity proof"; the issuer-vs-audience
# distinction is in the broker's DENY log line, keyed by this request's id.
rid=$(jget "$resp" request_id)
docker compose logs --no-color broker 2>&1 |
  grep -- "$rid" | grep -q "iss is not the configured issuer" ||
  die "broker refused the cross-application token, but not on the issuer -- check what it caught"
echo "the cross-application token was refused 401 on its issuer, not its audience"

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

say "PASS -- provisioned, signed in through authentik to a TGT, refused a cross-app token, and sync refused the source"
