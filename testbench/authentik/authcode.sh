#!/usr/bin/env bash
#
# Drive Authentik's authorization-code + PKCE flow to a verified token with
# nothing but curl and a cookie jar. No browser, no human, no headless driver.
#
# A standalone proof, kept for manual iteration; the `make test-authentik` tier
# is deploy/scripts/bench/ci-authentik.sh, which stands its own authentik up.
# The sign-in itself -- the flow-executor loop -- is approve.sh, shared with that
# tier; this drives PKCE, the authorize request and the code exchange around it.
#
#   ./authcode.sh                 # cold stack, proof, tear down with volume
#   ./authcode.sh --keep          # run the proof and leave the stack intact
#   ./authcode.sh up              # provision the fixture, leave it running
#   ./authcode.sh flow            # sign in against an already-provisioned stack
#   ./authcode.sh down            # tear down, volume included
#
# MEASURED against ghcr.io/goauthentik/server:2026.8.0. Read the
# comment on each step before changing it -- here and in approve.sh -- because
# the obvious version of that step is what actually failed, reporting something
# other than its cause.
#
# Dependencies: curl, python3 (and approve.sh's curl and perl). Deliberately no
# jq -- python3 is already a testbench dependency (testbench/mock-idp/idp.py) and
# does PKCE too, so this stays a two-tool script.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE=(docker compose -f "$HERE/compose.authentik.yaml")

BASE="${AK_BASE:-http://127.0.0.1:9000}"
APP_SLUG=kerbridge-bench
CLIENT_ID=kerbridge-bench-client
REDIRECT_URI=http://127.0.0.1:8765
REDIRECT_PATTERN='http://127\.0\.0\.1:[0-9]{1,5}'
SCOPE="openid profile offline_access"
USERNAME=benchuser
PASSWORD=bench-user-password
BOOTSTRAP_TOKEN=kerbridge-bench-bootstrap-token

WORK="$(mktemp -d)"
JAR="$WORK/cookies.txt"

say() { printf '\n== %s\n' "$*" >&2; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

KEEP=0
if [ "${1:-}" = --keep ]; then
  KEEP=1
  shift
fi
ACTION="${1:-all}"
[ "$#" -le 1 ] || die "usage: $0 [--keep] [all|up|flow|down]"

cleanup() {
  local rc=$?
  rm -rf "$WORK"
  [ "$ACTION" = all ] || return "$rc"

  if [ "$rc" != 0 ]; then
    say "the stack as it stood when this failed"
    "${COMPOSE[@]}" ps || true
    "${COMPOSE[@]}" logs --no-color --tail 80 || true
  fi
  if [ "$KEEP" = 1 ]; then
    say "leaving the stack up (--keep). Tear it down with:"
    echo "  $0 down" >&2
  else
    say "tearing down"
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  [ "$rc" = 0 ] || echo "${0##*/}: FAILED (exit $rc)" >&2
  return "$rc"
}
trap cleanup EXIT

# --- helpers ---------------------------------------------------------------

urlenc() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.stdin.read(),safe=""),end="")'; }
jget()   { python3 -c 'import sys,json;d=json.load(open(sys.argv[1]));print(d.get(sys.argv[2],""),end="")' "$1" "$2"; }

# ---------------------------------------------------------------------------
# 0. containers
# ---------------------------------------------------------------------------

stack_up() {
  say "starting the stack (postgresql + server + worker; no Redis since 2025.10)"
  "${COMPOSE[@]}" up -d

  # NEITHER server NOR worker ships a healthcheck -- only postgresql does. The
  # harness polls this itself or it races the first boot, which runs migrations
  # and generates the self-signed keypair the blueprint then !Finds.
  say "polling /-/health/ready/ (no credential; it is a Postgres connectivity check)"
  local start; start=$(date +%s)
  for _ in $(seq 1 150); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$BASE/-/health/ready/" || true)" = 200 ]; then
      echo "ready after $(( $(date +%s) - start ))s" >&2
      return 0
    fi
    sleep 2
  done
  die "server never became ready"
}

# MEASURED, AND IT COST A FAILED RUN: /-/health/ready/ IS NOT ENOUGH.
#
# It is a Postgres connectivity check and nothing more. On a cold volume it
# answers 200 while the worker is still applying the blueprints authentik ships
# with itself, and those are what create the default provider-authorization
# flow and the four scope mappings this fixture !Finds. Apply into that window
# and every !Find resolves to the string "None", which surfaces as
#
#   Serializer errors {'authorization_flow': ['This field may not be null.'],
#                      'property_mappings': ['Invalid pk "None" ...']}
#
# -- an error that names the fields but not the cause, on a blueprint that is
# correct. Gate on the objects themselves; not on a health endpoint, not on a
# sleep, and not on a silent retry loop that would hide this.
wait_for_defaults() {
  say "waiting for authentik's own default blueprints (ready/ does not cover them)"
  local i
  for i in $(seq 1 120); do
    if python3 "$HERE/wait_defaults.py" "$BASE" "$BOOTSTRAP_TOKEN" 2>/dev/null; then
      echo "defaults present after ${i}s" >&2
      return 0
    fi
    sleep 1
  done
  python3 "$HERE/wait_defaults.py" "$BASE" "$BOOTSTRAP_TOKEN" >&2 || true
  die "authentik's default flows/scope mappings never appeared"
}

apply_blueprint() {
  # Synchronous and transactional. Do NOT wait for the worker's startup pass,
  # its hourly pass or its filesystem watcher -- but DO wait for the objects
  # that pass creates, above.
  say "applying the blueprint"
  "${COMPOSE[@]}" exec -T worker \
    ak apply_blueprint /blueprints/kerbridge/kerbridge-bench.yaml >"$WORK/blueprint.log" 2>&1 \
    || { tail -40 "$WORK/blueprint.log" >&2; die "ak apply_blueprint failed"; }
}

assert_provider() {
  say "checking the discovery document and provider settings"
  curl -sf "$BASE/application/o/$APP_SLUG/.well-known/openid-configuration" \
    -o "$WORK/discovery.json" || die "no discovery document at the application slug"
  curl -sf -H "Authorization: Bearer $BOOTSTRAP_TOKEN" -G \
    "$BASE/api/v3/providers/oauth2/" --data-urlencode "name=$APP_SLUG" \
    -o "$WORK/provider.json" || die "could not read the OAuth2 provider"
  curl -sf -H "Authorization: Bearer $BOOTSTRAP_TOKEN" -G \
    "$BASE/api/v3/propertymappings/provider/scope/" \
    --data-urlencode "managed=goauthentik.io/providers/oauth2/scope-offline_access" \
    -o "$WORK/offline.json" || die "could not read the offline_access mapping"
  curl -sf "$BASE/application/o/$APP_SLUG/jwks/" \
    -o "$WORK/jwks.json" || die "could not read the provider JWKS"

  python3 - "$WORK/discovery.json" "$WORK/provider.json" "$WORK/offline.json" \
    "$WORK/jwks.json" "$BASE" "$APP_SLUG" "$REDIRECT_PATTERN" <<'PY'
import json, sys

discovery, providers, mappings, jwks = (json.load(open(path)) for path in sys.argv[1:5])
base, slug, redirect_pattern = sys.argv[5:8]
fails = []

def check(name, got, want):
    ok = got == want
    print("  %-28s %s" % (name, "ok" if ok else "MISMATCH got=%r want=%r" % (got, want)))
    if not ok: fails.append(name)

issuer = "%s/application/o/%s/" % (base, slug)
check("discovery issuer", discovery.get("issuer"), issuer)
check("discovery JWKS", discovery.get("jwks_uri"), issuer + "jwks/")
check("discovery signing alg", discovery.get("id_token_signing_alg_values_supported"), ["RS256"])
check("offline scope published", "offline_access" in discovery.get("scopes_supported", []), True)
keys = jwks.get("keys", [])
check("JWKS non-empty", bool(keys), True)
check("JWKS keys use RS256", {key.get("alg") for key in keys}, {"RS256"})

provider_rows = providers.get("results", [])
mapping_rows = mappings.get("results", [])
check("one OAuth2 provider", len(provider_rows), 1)
check("one offline mapping", len(mapping_rows), 1)
provider = provider_rows[0] if len(provider_rows) == 1 else {}
offline_pk = mapping_rows[0].get("pk") if len(mapping_rows) == 1 else None
check("UUID subject mode", provider.get("sub_mode"), "user_uuid")
check("signing key present", bool(provider.get("signing_key")), True)
check("offline mapping attached", offline_pk in provider.get("property_mappings", []), True)
redirects = [(item.get("matching_mode"), item.get("url")) for item in provider.get("redirect_uris", [])]
check("loopback redirect regex", redirects, [("regex", redirect_pattern)])
sys.exit(1 if fails else 0)
PY
}

# ---------------------------------------------------------------------------
# PKCE, sign in through approve.sh, and exchange the code
# ---------------------------------------------------------------------------

flow() {
  say "PKCE"
  # S256 explicitly. The authorize view defaults code_challenge_method to
  # `plain` when the parameter is absent, which is a downgrade nobody reports.
  VERIFIER="$(python3 -c 'import secrets;print(secrets.token_urlsafe(64)[:64],end="")')"
  CHALLENGE="$(python3 -c '
import base64,hashlib,sys
print(base64.urlsafe_b64encode(hashlib.sha256(sys.argv[1].encode()).digest()).rstrip(b"=").decode(),end="")' "$VERIFIER")"
  STATE="state-$(python3 -c 'import secrets;print(secrets.token_hex(8),end="")')"
  NONCE="nonce-$(python3 -c 'import secrets;print(secrets.token_hex(8),end="")')"

  # The executor loop lives in approve.sh -- the same `$BROWSER` the CI tier
  # (deploy/scripts/bench/ci-authentik.sh) drives, so this manual proof and the
  # automated sign-in exercise one implementation. approve.sh takes the whole
  # authorization URL, drives identification and password, and prints the code
  # it read off the terminal redirect. Read approve.sh's own comments for the
  # `query` encoding and the two curl flags that decide whether the flow runs.
  say "sign in through approve.sh"
  rm -f "$JAR"
  # CLIENT_ID, STATE, NONCE and the base64url CHALLENGE are already url-safe;
  # the redirect and the space-separated scope are the two that need encoding.
  local auth_url="$BASE/application/o/authorize/?response_type=code&client_id=$CLIENT_ID"
  auth_url="$auth_url&redirect_uri=$(printf '%s' "$REDIRECT_URI" | urlenc)"
  auth_url="$auth_url&scope=$(printf '%s' "$SCOPE" | urlenc)"
  auth_url="$auth_url&state=$STATE&nonce=$NONCE"
  auth_url="$auth_url&code_challenge=$CHALLENGE&code_challenge_method=S256"

  # No listener on REDIRECT_URI here, so approve.sh's loopback delivery is the
  # one call that misses; its `code=`/`state=` lines are read off stdout instead.
  local approved
  approved="$(KB_APPROVE_LOG=/dev/stderr KB_APPROVE_USER="$USERNAME" \
    KB_APPROVE_PASSWORD="$PASSWORD" "$HERE/approve.sh" "$auth_url")" ||
    die "approve.sh could not complete the sign-in"
  CODE="$(printf '%s\n' "$approved" | sed -n 's/^code=//p')"
  local got_state; got_state="$(printf '%s\n' "$approved" | sed -n 's/^state=//p')"
  [ -n "$CODE" ] || die "approve.sh returned no code"
  [ "$got_state" = "$STATE" ] || die "state mismatch: $got_state != $STATE"
  echo "signed in; state echoed back intact" >&2

  # Exchange the code for tokens.
  say "POST /application/o/token/"
  # Public client: client_id in the body, no secret, code_verifier instead.
  local code; code=$(curl -s -o "$WORK/token.json" -w '%{http_code}' \
    "$BASE/application/o/token/" \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=$CODE" \
    --data-urlencode "redirect_uri=$REDIRECT_URI" \
    --data-urlencode "client_id=$CLIENT_ID" \
    --data-urlencode "code_verifier=$VERIFIER")
  [ "$code" = 200 ] || { cat "$WORK/token.json" >&2; die "token endpoint returned $code"; }
}

# ---------------------------------------------------------------------------
# verify what came back
# ---------------------------------------------------------------------------

verify() {
  say "verifying claims"
  curl -s -H "Authorization: Bearer $BOOTSTRAP_TOKEN" \
    "$BASE/api/v3/core/users/?username=$USERNAME" -o "$WORK/user.json"

  python3 - "$WORK/token.json" "$WORK/user.json" "$CLIENT_ID" "$BASE/application/o/$APP_SLUG/" <<'PY'
import base64, json, sys

tok, users, client_id, issuer = json.load(open(sys.argv[1])), json.load(open(sys.argv[2])), sys.argv[3], sys.argv[4]
def seg(s): return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
def jwt(t):
    h, p, _ = t.split("."); return seg(h), seg(p)

fails = []
def check(name, got, want):
    ok = got == want
    print("  %-28s %s" % (name, "ok" if ok else "MISMATCH got=%r want=%r" % (got, want)))
    if not ok: fails.append(name)

ah, ap = jwt(tok["access_token"])
ih, ip = jwt(tok["id_token"])
uuid = users["results"][0]["uuid"]

check("access alg",            ah["alg"], "RS256")
check("id alg",                ih["alg"], "RS256")
check("access aud",            ap["aud"], client_id)
check("id aud",                ip["aud"], client_id)
# Written at id_token.py:172 after the scope-mapping
# dict.update, so a mapping cannot forge it. But it is written in
# to_access_token() ONLY -- the ID token has no azp at all, and asserting one
# there would refuse every honest authentik token.
check("access azp",            ap["azp"], client_id)
check("id azp absent",         "azp" in ip, False)
check("access iss",            ap["iss"], issuer)
# The subject is the bare, lowercase, hyphenated user UUID. It is identical to
# what /api/v3/core/users/ returns and filterable there, which the default
# hashed_user_id is not.
check("access sub == user.uuid", ap["sub"], uuid)
check("id sub == user.uuid",     ip["sub"], uuid)
check("refresh token present",   bool(tok.get("refresh_token")), True)
check("offline_access granted",  "offline_access" in tok["scope"].split(), True)

print("\n  sub = %s" % ap["sub"])
print("  scope = %s" % tok["scope"])
sys.exit(1 if fails else 0)
PY
}

# ---------------------------------------------------------------------------

case "$ACTION" in
  up)   stack_up; wait_for_defaults; apply_blueprint; assert_provider ;;
  flow) flow; verify ;;
  down) "${COMPOSE[@]}" down -v --remove-orphans ;;
  all)
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    stack_up; wait_for_defaults; apply_blueprint; assert_provider; flow; verify
    say "PASS -- blueprint settings and verified tokens, no browser"
    ;;
  *) die "usage: $0 [--keep] [all|up|flow|down]" ;;
esac
