#!/bin/bash
# The whole server path, from a fresh clone to a file read over SMB, with no
# Entra tenant and no secret. What `make test-stack` runs, and the one test here
# that exercises the things a unit test cannot reach: provisioning, the bootstrap
# scripts, the LDAPS bind, the issuer socket, the KDC, and a member's PAC.
#
# It proves, in order:
#
#   1. A fresh realm provisions. The entrypoint provisions with a throwaway
#      administrator password and replaces it over stdin; anywhere else those two
#      only run together on somebody's first real `up`. Here that happens on
#      every run.
#   2. `kbsetup directory` creates the OUs, the three service accounts and the
#      delegated write, against a domain it has never seen before.
#   3. The public endpoint terminates TLS on a certificate this script creates, and
#      the broker answers GET /config behind it.
#   4. POST /ticket with a freshly issued token returns a real KDC-signed TGT:
#      verify -> resolve the external identity in the realm directory -> issue.
#   5. One engineer's sign-in authorizes a machine to obtain tickets as a service
#      account they hold no credential for, and the ticket that machine gets is
#      the service account's. An admitted user outside the delegate group cannot
#      do the same.
#   6. That TGT reads a file from nas1's Kerberos-only share. No
#      password is used anywhere in steps 4 to 6.
#   7. The real `kerbridge` client does the whole of that last leg by itself,
#      against a stand-in authority, with no human and no browser: sign in with
#      authorization-code + PKCE, exchange the token, write the ticket cache --
#      and the stock `smbclient` then reads the share from what it wrote. Steps
#      4 to 6 prove the server with curl; this proves the client.
#
# Not covered, and not coverable here: Entra itself (Graph, delta, real token
# issuance), the acme TLS strategies, and the client's platform arms -- LSA
# ticket submission, Heimdal's `API:` cache, WAM, CNG device keys and realm
# registration, which are Windows and macOS bench subjects.
# `client/kerbridge-client/src/linux/os.rs` says the same from the other side.
#
# scripts/bench/provision.sh creates the isolated stack and waits for `/config`.
# This Entra stack tier provides the token corpus, authority configuration, and
# assertions. Its Entra-specific setup stays in the three hooks below. `make
# test` enforces this boundary.
set -euo pipefail

# provision.sh uses this source in the config set and broker routes.
SOURCE=entra

# make_fixtures.py signs tokens for this synthetic tenant. The .env fragment and
# source config must use the same value because it determines the accepted `iss`.
TENANT=aaaabbbb-0000-cccc-1111-dddd2222eeee

# Order is significant. compose.ci.yaml removes the bench ports from earlier
# overlays. compose.ci-entra.yaml then adds only Entra-specific settings. Keep
# the complete order visible in this stack tier.
export COMPOSE_FILE=compose.yaml:compose.nas.yaml:compose.mockidp.yaml:compose.ci.yaml:compose.ci-entra.yaml


# Generate the corpus in a scratch directory so positive tokens are current.
# The committed corpus is intentionally expired, and tests pin its time window.
# make_fixtures.py defaults to the corpus it lives in, so --out is not optional.
idp_prepare() {
  local fixtures=testbench/fixtures/entra-token
  say "generating a token corpus"
  FIXDIR=$ROOT/.local-tmp/ci-fixtures
  rm -rf "$FIXDIR"; mkdir -p "$FIXDIR"
  # Cache the virtual environment in the source checkout. The disposable copy is
  # replaced for each run, and reinstalling dependencies adds a network dependency.
  local venv=${KB_CI_SRC:-$ROOT}/.local-tmp/ci-venv
  if [ ! -x "$venv/bin/python" ]; then
    python3 -m venv "$venv"
    "$venv/bin/pip" install --quiet --disable-pip-version-check pyjwt cryptography
  fi
  "$venv/bin/python" "$ROOT/$fixtures/make_fixtures.py" --out "$FIXDIR" >/dev/null
  [ -s "$FIXDIR/jwks.json" ] && [ -s "$FIXDIR/positive_delegated.jwt" ] &&
    [ -s "$FIXDIR/positive_other_user.jwt" ] ||
    die "fixture generation produced nothing"
  echo "generated $(ls "$FIXDIR"/*.jwt | wc -l | tr -d ' ') tokens and a key document"
}

# compose.ci-entra.yaml mounts files from CI_FIXTURE_DIR. CI_APPROVE_SH replaces
# the browser for sign-in. OIDC_AUTHORITY must equal the authority in the source
# config. The tenant ID must match the generated corpus because it determines the
# token issuer.
idp_env_lines() {
  cat <<EOF

CI_FIXTURE_DIR=$FIXDIR
CI_APPROVE_SH=$ROOT/testbench/mock-idp/approve.sh
OIDC_AUTHORITY=https://$IDP_FQDN:8443
MOCK_IDP_TENANT_ID=$TENANT
MOCK_IDP_USER=$USER_NAME
EOF
}

# This run has no Graph tenant or sync app. The broker verifies fixture tokens
# with the mounted jwks.json.
idp_source_toml() {
  cat <<EOF
name = "$SOURCE"
provider = "entra"
group_suffix = "none"
bind_dn = "CN=svc-kerbridge-sync-$SOURCE,CN=Users,$BASE_DN"
bind_password_file = "/etc/kerbridge.secrets/generated/idp/$SOURCE/bind_password"

[provider_config]
tenant_id = "$TENANT"
broker_api_client_id = "11112222-bbbb-3333-cccc-4444dddd5555"
public_client_id = "22223333-cccc-4444-dddd-5555eeee6666"
jwks_file = "/etc/kerbridge-ci-jwks/entra.json"
# Where a client is sent to sign in. Without this the client is told to go to
# login.microsoftonline.com, which this run has no tenant on -- and it is only
# the *address*: the issuer the broker accepts is still derived from tenant_id
# above, so pointing clients at the mock cannot loosen verification.
authority = "https://$IDP_FQDN:8443"
sync_client_id = ""
sync_credential_file = ""
# Sync's, and unreachable from the broker -- which finds the group by its
# marker. Stated anyway because a source file with no admission group admits
# nobody, so the parser refuses one. No tenant answers to either id: sync does
# not run here, and seed-demo.sh stamps the markers itself.
admission_group_id = "77778888-bbbb-9999-cccc-0000dddd1111"
device_grant_group_id = "88889999-cccc-0000-dddd-1111eeee2222"
EOF
}

. "$(dirname "$0")/provision.sh"

# ---------------------------------------------------------------------------
# The shared script returns after provisioning. Run Entra-specific assertions.
# ---------------------------------------------------------------------------
tok() { printf 'Authorization: Bearer %s' "$(cat "$FIXDIR/$1.jwt")"; }

say "seeding the demo realm directory"
scripts/bench/seed-demo.sh

say "POST /ticket with a token issued three minutes ago"
resp=$ROOT/.local-tmp/ci-ticket.json
code=$(api POST /$SOURCE/ticket "$resp" -H "$(tok positive_delegated)")
[ "$code" = 200 ] || { cat "$resp"; echo; die "POST /ticket answered $code, wanted 200"; }
principal=$(jget "$resp" principal)
[ "$principal" = "$USER_NAME@$REALM" ] ||
  die "ticket is for $principal, wanted $USER_NAME@$REALM"
echo "issued a TGT for $principal"

# An expired token from the same corpus, to show the verifier is actually
# deciding rather than admitting whatever it is handed.
code=$(api POST /$SOURCE/ticket /dev/null -H "$(tok neg_expired)")
[ "$code" = 401 ] || die "an expired token answered $code, wanted 401"
echo "an expired token from the same key is refused 401"

# ---------------------------------------------------------------------------
# Device grants do not require TPM attestation. A software key therefore tests
# the assertion format, single-use nonce, grant-group gate, and grant value stored
# in the realm directory.
# The Windows bench tests the CNG client path.
# ---------------------------------------------------------------------------
say "authorizing a device with the same token"
KEY=$ROOT/.local-tmp/ci-device-key.pem
POINT=$(new_device_key "$KEY")

dev=$ROOT/.local-tmp/ci-device.json
code=$(api POST /$SOURCE/devices "$dev" -H "$(tok positive_delegated)" \
  -H 'Content-Type: application/json' \
  -d "{\"alg\":\"es256\",\"key\":\"$POINT\",\"label\":\"CI\\\\runner\"}")
[ "$code" = 201 ] || { cat "$dev"; echo; die "POST /devices answered $code, wanted 201"; }
GRANT_ID=$(jget "$dev" grant_id)
IDENTITY=$(jget "$dev" identity)
echo "authorized device $GRANT_ID"

# Sign an assertion for the specified key and identity with a fresh nonce. The
# replay test reuses the returned assertion; delegated devices call this function
# with a different key and identity.
sign_assertion() {  # key, point, identity
  nonce=$(curl -fsS --noproxy '*' --cacert "$CA/ca.crt" --resolve "$FQDN:$PORT:127.0.0.1" \
    "https://$FQDN:$PORT/$SOURCE/nonce" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])')
  KB_KEY=$1 KB_POINT=$2 KB_IDENTITY=$3 KB_NONCE=$nonce KB_REALM=$REALM \
    python3 - <<'PY'
import base64, json, os, subprocess, time

def b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

payload = {
    "identity": os.environ["KB_IDENTITY"],
    "key": os.environ["KB_POINT"],
    "nonce": os.environ["KB_NONCE"],
    "aud": "kerbridge://" + os.environ["KB_REALM"],
    "exp": int(time.time()) + 60,
}
encoded = b64(json.dumps(payload, separators=(",", ":")).encode())
der = subprocess.run(
    ["openssl", "dgst", "-sha256", "-sign", os.environ["KB_KEY"]],
    input=encoded.encode(), capture_output=True, check=True,
).stdout

# DER SEQUENCE { INTEGER r, INTEGER s } -> the fixed r||s form, 32 bytes each,
# which is what CNG's NCryptSignHash produces and what the broker verifies.
def ints(d):
    i = 2 if d[1] < 0x80 else 2 + (d[1] & 0x7F)
    for _ in range(2):
        assert d[i] == 0x02, "not an INTEGER"
        n = d[i + 1]
        yield int.from_bytes(d[i + 2:i + 2 + n], "big").to_bytes(32, "big")
        i += 2 + n

print(f"{encoded}.{b64(b''.join(ints(der)))}")
PY
}

say "POST /ticket with a device assertion and no token"
assertion=$(sign_assertion "$KEY" "$POINT" "$IDENTITY")
code=$(api POST /$SOURCE/ticket "$resp" -H "Authorization: DeviceGrant $assertion")
[ "$code" = 200 ] || { cat "$resp"; echo; die "device-grant /ticket answered $code, wanted 200"; }
principal=$(jget "$resp" principal)
[ "$principal" = "$USER_NAME@$REALM" ] ||
  die "device-grant ticket is for $principal, wanted $USER_NAME@$REALM"
echo "issued a TGT for $principal with no browser and no token"

# Reuse the exact assertion to test single-use nonces.
code=$(api POST /$SOURCE/ticket /dev/null -H "Authorization: DeviceGrant $assertion")
[ "$code" = 401 ] || die "a replayed assertion answered $code, wanted 401"
echo "the same assertion replayed is refused 401"

# Revocation must reject the next exchange.
say "revoking the device"
code=$(api DELETE "/$SOURCE/devices/$GRANT_ID" /dev/null -H "$(tok positive_delegated)")
[ "$code" = 204 ] || die "DELETE /devices/$GRANT_ID answered $code, wanted 204"
assertion=$(sign_assertion "$KEY" "$POINT" "$IDENTITY")
code=$(api POST /$SOURCE/ticket /dev/null -H "Authorization: DeviceGrant $assertion")
[ "$code" = 401 ] || die "a revoked device answered $code, wanted 401"
echo "a revoked device is refused at its very next exchange"

# ---------------------------------------------------------------------------
# Delegation: an engineer, signing in as themselves, authorizing this machine to
# obtain tickets as a *service account* nobody has the credentials of.
#
# Assert the ticket principal. A 200 response with the engineer's principal would
# work but assign artifacts to the wrong account.
#
# An admitted user outside the delegate group must be refused. First obtain that
# user's own ticket so the refusal cannot pass because the user is not admitted.
# ---------------------------------------------------------------------------
say "authorizing a device for $SERVICE_NAME, as one of its delegates"
DKEY=$ROOT/.local-tmp/ci-delegated-key.pem
DPOINT=$(new_device_key "$DKEY")

deleg=$ROOT/.local-tmp/ci-delegated.json
code=$(api POST /$SOURCE/devices "$deleg" -H "$(tok positive_delegated)" \
  -H 'Content-Type: application/json' \
  -d "{\"alg\":\"es256\",\"key\":\"$DPOINT\",\"label\":\"CI build box\",\"for\":\"$SERVICE_NAME\"}")
[ "$code" = 201 ] || { cat "$deleg"; echo; die "delegated POST /devices answered $code, wanted 201"; }
DGRANT=$(jget "$deleg" grant_id)
DIDENTITY=$(jget "$deleg" identity)
# The identity handed back is the target's, which the caller never spelled and
# which is the only thing the machine has to claim from here on.
want="kb1|$SOURCE|$SERVICE_OID"
[ "$DIDENTITY" = "$want" ] || die "the grant names $DIDENTITY, wanted $want"
echo "authorized device $DGRANT for $SERVICE_NAME"

# The audit log is the only durable record of who authorized a grant. The
# departing-delegate procedure searches this line by account name, so it must
# identify both accounts.
docker compose logs --no-color broker 2>/dev/null |
  grep -qE "GRANT [0-9a-f]+ $SERVICE_NAME $DGRANT by=$USER_NAME" ||
  die "the GRANT line does not name both parties; the audit trail is the only place it is recorded"
echo "the audit trail names $USER_NAME as the authorizer"

say "the ticket that device gets must be $SERVICE_NAME's, not $USER_NAME's"
assertion=$(sign_assertion "$DKEY" "$DPOINT" "$DIDENTITY")
code=$(api POST /$SOURCE/ticket "$resp" -H "Authorization: DeviceGrant $assertion")
[ "$code" = 200 ] || { cat "$resp"; echo; die "delegated /ticket answered $code, wanted 200"; }
principal=$(jget "$resp" principal)
[ "$principal" = "$SERVICE_NAME@$REALM" ] ||
  die "the delegated ticket is for $principal, wanted $SERVICE_NAME@$REALM"
echo "issued a TGT for $principal from a machine $USER_NAME authorized"

say "listing another account's devices, as its delegate"
lst=$ROOT/.local-tmp/ci-delegated-list.json
code=$(api GET "/$SOURCE/devices?for=$SERVICE_NAME" "$lst" -H "$(tok positive_delegated)")
[ "$code" = 200 ] || { cat "$lst"; echo; die "delegated GET /devices answered $code, wanted 200"; }
python3 - "$lst" "$DGRANT" "$want" <<'PY' || die "the delegated list does not show that grant"
import json, sys
devices = json.load(open(sys.argv[1]))["devices"]
sys.exit(0 if any(d["grant_id"] == sys.argv[2] and d["identity"] == sys.argv[3]
                  for d in devices) else 1)
PY
echo "GET /devices?for=$SERVICE_NAME shows $DGRANT"

say "someone who is admitted but is not a delegate"
code=$(api POST /$SOURCE/ticket "$resp" -H "$(tok positive_other_user)")
[ "$code" = 200 ] || { cat "$resp"; echo; die "$OTHER_NAME's own ticket answered $code, wanted 200 \
-- without it the refusal below proves nothing about delegation"; }
[ "$(jget "$resp" principal)" = "$OTHER_NAME@$REALM" ] ||
  die "$OTHER_NAME's ticket is for someone else"
bad=$ROOT/.local-tmp/ci-not-delegate.json
code=$(api POST /$SOURCE/devices "$bad" -H "$(tok positive_other_user)" \
  -H 'Content-Type: application/json' \
  -d "{\"alg\":\"es256\",\"key\":\"$DPOINT\",\"label\":\"CI\",\"for\":\"$SERVICE_NAME\"}")
[ "$code" = 403 ] || { cat "$bad"; echo; die "a non-delegate answered $code, wanted 403"; }
# Which 403 it is, because "not admitted" and "not a delegate" are both 403 and
# only one of them is this test.
case "$(jget "$bad" error)" in
  *"not authorize a device for that account"*) ;;
  *) cat "$bad"; echo; die "refused, but not for not being a delegate" ;;
esac
echo "$OTHER_NAME holds a ticket of their own and is still refused 403 for $SERVICE_NAME"

# A UPN resolves perfectly well and is refused anyway: on the wire a second
# mutable spelling is attack surface, so the target is a login name or a kb1|.
code=$(api POST /$SOURCE/devices /dev/null -H "$(tok positive_delegated)" \
  -H 'Content-Type: application/json' \
  -d "{\"alg\":\"es256\",\"key\":\"$DPOINT\",\"label\":\"CI\",\"for\":\"$SERVICE_NAME@$DOMAIN\"}")
[ "$code" = 400 ] || die "a UPN target answered $code, wanted 400"
echo "a UPN target is refused 400"

say "revoking the delegated device from the delegate's side"
code=$(api DELETE "/$SOURCE/devices/$DGRANT?for=$SERVICE_NAME" /dev/null -H "$(tok positive_delegated)")
[ "$code" = 204 ] || die "delegated DELETE /devices/$DGRANT answered $code, wanted 204"
assertion=$(sign_assertion "$DKEY" "$DPOINT" "$DIDENTITY")
code=$(api POST /$SOURCE/ticket /dev/null -H "Authorization: DeviceGrant $assertion")
[ "$code" = 401 ] || die "a revoked delegated device answered $code, wanted 401"
echo "a remote revocation rejects the next exchange"

# ---------------------------------------------------------------------------
# The last leg, driven by the real client.
#
# Everything above proves the *server* with curl: a fixture token in, a ccache
# out. This proves the client -- it signs in, obtains a ticket, and the stock SMB
# client uses what it wrote. A script that assembles a ccache itself tests the
# script: a documented /config field the broker published and the client parsed
# nowhere passed three green tiers that way.
#
# The client runs *inside nas1* rather than on this host so the ticket lands in
# the cache the SMB client reads by construction rather than by a copy. It is the
# same `kerbridge` binary an operator runs; only the environment differs.
# ---------------------------------------------------------------------------
say "the real client, signing in with no human and no browser"

# What the sign-in needs, and nothing more:
#
#   BROWSER          `oidc::login` opens the system browser, and on Linux
#                    `webbrowser` tries $BROWSER first. Here that is a script
#                    that follows mock-idp's approval redirect back to the
#                    loopback port the client itself chose. The bench replaces
#                    the browser, not the client: oidc.rs has no test-only branch
#                    and reads no environment variable.
#   SSL_CERT_FILE    the client links native-tls, which is OpenSSL here, and
#                    OpenSSL takes its trust store from this. The certificate is
#                    verified, not waved through: `require_https` and the
#                    validated chain are half of what /config is trusted for.
#   KRB5CCNAME       the cache both halves use. Named rather than left to the
#                    default so that what the client wrote and what smbclient
#                    reads cannot be two files -- the client logs which one it
#                    chose either way.
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

# A cache that is not there yet, so nothing below can pass on a leftover.
docker compose exec -T nas1 rm -f "$CI_CCACHE_IN_NAS"

out=$ROOT/.local-tmp/ci-client-signin.log
if ! client kerbridge --broker "https://$FQDN" > "$out" 2>&1; then
  cat "$out"
  client cat /tmp/kb-approve.log 2>/dev/null || true
  die "the client could not sign in and obtain a ticket"
fi
cat "$out"
# The principal the client landed, read out of the cache it wrote by the client
# itself -- `klist` is not installed in nas1 and this is the ticket that matters.
grep -qi "$USER_NAME@$REALM" "$out" ||
  die "the client reported no ticket for $USER_NAME@$REALM"
echo "$USER_NAME signed in through the stand-in authority and the client wrote $CI_CCACHE_IN_NAS"

# Written by the client inside the container, so it is already this reader's own
# and already 0600. A ccache carried in from the host is neither.
mode=$(client stat -c '%a %U' "$CI_CCACHE_IN_NAS")
[ "$mode" = "600 root" ] || die "the client wrote the cache as \"$mode\", wanted \"600 root\""

say "reading a file over SMB with that ticket and no password"
# The invocation the joined-nas-authorization spike proved on the bench, kept
# byte for byte: --use-kerberos=required, and neither -U nor -N. The ccache's own
# principal is what authenticates; naming a user makes smbclient look for that
# one instead.
got=$(client sh -c "smbclient '//nas1.$DOMAIN/share' \
     --use-kerberos=required -c 'get README.txt -'" 2>&1) || true
case "$got" in
  *KerBridge*) echo "read README.txt from //nas1.$DOMAIN/share as $USER_NAME@$REALM" ;;
  *) die "SMB read returned: ${got:-<nothing>}" ;;
esac

say "PASS -- provisioned, bootstrapped, issued, signed in, and read over SMB"
