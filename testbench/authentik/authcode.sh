#!/usr/bin/env bash
#
# Drive Authentik's authorization-code + PKCE flow to a verified token with
# nothing but curl and a cookie jar. No browser, no human, no headless driver.
#
# A standalone proof, kept for manual iteration; the `make test-authentik` tier
# is deploy/scripts/bench/ci-authentik.sh, which stands its own authentik up.
#
#   ./authcode.sh                 # cold stack, proof, tear down with volume
#   ./authcode.sh --keep          # run the proof and leave the stack intact
#   ./authcode.sh up              # provision the fixture, leave it running
#   ./authcode.sh flow            # sign in against an already-provisioned stack
#   ./authcode.sh down            # tear down, volume included
#
# MEASURED against ghcr.io/goauthentik/server:2026.8.0 (kerbridge #17). Read the
# comment on each step before changing it: the long ones are all there because
# the obvious version of that step is what actually failed, and every one of
# those failures reported something other than its cause.
#
# Dependencies: curl, python3. Deliberately no jq -- python3 is already a
# testbench dependency (testbench/mock-idp/idp.py) and does PKCE too, so this
# stays a two-tool script.

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
header() { tr -d '\r' < "$1" | grep -i "^$2:" | tail -1 | cut -d' ' -f2-; }

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
# 1. the authorization request
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

  say "GET /application/o/authorize/"
  rm -f "$JAR"
  curl -s -o /dev/null -D "$WORK/h.authorize" -c "$JAR" \
    -G "$BASE/application/o/authorize/" \
    --data-urlencode "response_type=code" \
    --data-urlencode "client_id=$CLIENT_ID" \
    --data-urlencode "redirect_uri=$REDIRECT_URI" \
    --data-urlencode "scope=$SCOPE" \
    --data-urlencode "state=$STATE" \
    --data-urlencode "nonce=$NONCE" \
    --data-urlencode "code_challenge=$CHALLENGE" \
    --data-urlencode "code_challenge_method=S256"

  local loc; loc="$(header "$WORK/h.authorize" location)"
  [ -n "$loc" ] || die "authorize did not redirect at all"
  case "$loc" in
    */if/flow/*) : ;;
    # A 302 straight back to the redirect_uri carrying error= means the request
    # never reached a flow. `invalid_request` with "The request is otherwise
    # malformed" is what an empty provider `grant_types` looks like from here.
    *error=*) die "authorize refused the request: $loc" ;;
    *) die "unexpected redirect: $loc" ;;
  esac

  # THE `query` ENCODING, which is the thing #17 exists to pin down.
  #
  # At 2026.8.0 the authorize view redirects to
  #     /if/flow/<flow-slug>/?<the original OAuth2 params, verbatim>&next=<encoded re-entry URL>
  # -- there is no `query` parameter in that Location at all. `query` is what
  # the *browser* flow interface then sends to the executor: it takes its own
  # window.location.search and passes the whole thing as one opaque value.
  #
  # So: take everything after the FIRST `?` of the Location, byte for byte, and
  # url-encode it whole as a single parameter value. Do not reassemble it, do
  # not re-encode the parts, do not drop `next` -- `next` is the only thing
  # that gets you back to /application/o/authorize/ at the end of the flow
  # (executor.py reads it out of the session at :407).
  FLOW_SLUG="${loc#*/if/flow/}"; FLOW_SLUG="${FLOW_SLUG%%/*}"
  RAW_QUERY="${loc#*\?}"
  QUERY="$(printf '%s' "$RAW_QUERY" | urlenc)"
  echo "flow slug: $FLOW_SLUG" >&2

  # -------------------------------------------------------------------------
  # 2. the executor loop
  # -------------------------------------------------------------------------
  #
  # Branch on `component`. Never assume a sequence: which stages are in the
  # flow is instance state, not a protocol.
  #
  # Cookie jar is mandatory -- the plan lives in the HTTP session, and without
  # it every call restarts the flow.
  #
  # TWO CURL FLAGS DECIDE WHETHER THIS WORKS, and both failures look like an
  # authentik bug rather than a curl mistake.
  #
  # `-L`, because every successful stage answers **302 back to the executor's
  # own URL** with an empty body (`stage_ok()` -> `redirect_with_qs`, a
  # post/redirect/get). Without -L you read zero bytes and conclude the flow
  # died.
  #
  # And NO `-X POST`. `-d` already selects POST; `-X POST` additionally pins the
  # method across redirect follows, which defeats curl's 302 POST-to-GET
  # downgrade -- so the follow-up re-POSTs the *previous* stage's body into the
  # *next* stage. The result is a 200 challenge carrying a completely plausible
  # `response_errors` for a field you never meant to submit
  # ("password: This field is required", then "non_field_errors: Empty
  # response"), and the loop walks into the authenticator-validate stage and
  # sticks there forever, because that stage skips on GET and only on GET
  # (`authenticator_validate/stage.py:281-283`). Measured: with `-X POST` the
  # flow never terminates; without it, it terminates in three calls.

  say "driving $FLOW_SLUG"
  local body="$WORK/challenge.json" component payload seq=""
  curl -sL -o "$body" -b "$JAR" -c "$JAR" -H 'Accept: application/json' \
    "$BASE/api/v3/flows/executor/$FLOW_SLUG/?query=$QUERY"

  local i
  for i in $(seq 1 12); do
    component="$(jget "$body" component)"
    [ -n "$component" ] || die "empty challenge body at step $i"
    seq="$seq $component"
    echo "  [$i] $component" >&2

    case "$component" in
      xak-flow-redirect) break ;;
      ak-stage-access-denied)
        die "access denied: $(jget "$body" error_message)" ;;

      ak-stage-identification)
        payload="{\"component\":\"$component\",\"uid_field\":\"$USERNAME\"}" ;;
      ak-stage-password)
        # A separate stage: the identification challenge reports
        # password_fields: false, so the password never rides along with the
        # username.
        payload="{\"component\":\"$component\",\"password\":\"$PASSWORD\"}" ;;
      ak-stage-authenticator-validate)
        # The stage research warned about. It IS bound into the shipped
        # default-authentication-flow at order 30 -- but with a device-less user
        # it NEVER SURFACES AS A CHALLENGE: its get() sees no device and the
        # shipped not_configured_action of `skip` calls stage_ok() before any
        # challenge is rendered, so it is consumed inside the redirect chain.
        # Kept as a branch because a user with an enrolled device would stop
        # here for real, and because the branch is what makes the failure
        # legible instead of an infinite loop.
        payload="{\"component\":\"$component\"}" ;;
      ak-stage-consent)
        # Not reached here -- the provider's authorization flow is
        # default-provider-authorization-implicit-consent. Handled so that
        # switching to the explicit-consent flow does not need a code change.
        payload="{\"component\":\"$component\",\"token\":\"$(jget "$body" token)\"}" ;;
      ak-stage-user-login)
        # Also never seen. The User Login stage IS required -- it is bound at
        # order 100 of the default flow and it is what turns the plan into an
        # authenticated session, without which re-entering /application/o/authorize/
        # would just start the flow again -- but it is a non-interactive stage
        # and is likewise consumed inside the redirect chain.
        payload="{\"component\":\"$component\"}" ;;
      *)
        cat "$body" >&2; die "unhandled stage component: $component" ;;
    esac

    curl -sL -o "$body" -b "$JAR" -c "$JAR" \
      -H 'Accept: application/json' -H 'Content-Type: application/json' \
      "$BASE/api/v3/flows/executor/$FLOW_SLUG/?query=$QUERY" \
      -d "$payload"
  done
  [ "$component" = xak-flow-redirect ] || die "flow never terminated (last: $component)"
  echo "component sequence:$seq" >&2

  # -------------------------------------------------------------------------
  # 3. the terminal redirect is NOT the code
  # -------------------------------------------------------------------------
  #
  # `to` is the RELATIVE /application/o/authorize/?<original params> -- the
  # `next` value carried through the flow, not redirect_uri?code=. The code
  # costs one more request: re-enter the authorize view with the now-
  # authenticated session cookie, and it 302s to the callback.

  local to; to="$(jget "$body" to)"
  echo "xak-flow-redirect.to = $to" >&2
  case "$to" in
    "$REDIRECT_URI"*) : ;;                       # a future version might do this
    /*) to="$BASE$to" ;;
    *) die "unexpected redirect target: $to" ;;
  esac
  curl -s -o /dev/null -D "$WORK/h.callback" -b "$JAR" -c "$JAR" "$to"

  local cb; cb="$(header "$WORK/h.callback" location)"
  case "$cb" in
    "$REDIRECT_URI"*code=*) : ;;
    *) die "no authorization code came back: $cb" ;;
  esac
  CODE="$(printf '%s' "$cb" | sed -E 's/.*[?&]code=([^&]*).*/\1/')"
  local got_state; got_state="$(printf '%s' "$cb" | sed -E 's/.*[?&]state=([^&]*).*/\1/')"
  [ "$got_state" = "$STATE" ] || die "state mismatch: $got_state != $STATE"
  echo "code: ${CODE:0:8}...  state echoed back intact" >&2

  # -------------------------------------------------------------------------
  # 4. exchange
  # -------------------------------------------------------------------------
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
# 5. verify what came back
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
# #21's strong claim: written at id_token.py:172, AFTER the scope-mapping
# dict.update, so a mapping cannot forge it. But it is written in
# to_access_token() ONLY -- the ID token has no azp at all, and asserting one
# there would refuse every honest authentik token.
check("access azp",            ap["azp"], client_id)
check("id azp absent",         "azp" in ip, False)
check("access iss",            ap["iss"], issuer)
# #6's proposal: the bare, lowercase, hyphenated user UUID -- byte-identical to
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
