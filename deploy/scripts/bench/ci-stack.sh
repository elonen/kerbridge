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
#      verify -> resolve the external identity in the directory -> issue.
#   5. One engineer's sign-in authorizes a machine to obtain tickets as a service
#      account they hold no credential for, and the ticket that machine gets is
#      the service account's. An admitted user outside the delegate group cannot
#      do the same.
#   6. That TGT reads a file from nas1's Kerberos-only share. No
#      password is used anywhere in steps 4 to 6.
#
# Not covered, and not coverable here: Entra itself (Graph, delta, real token
# issuance), the acme TLS strategies, and everything the Windows client does with
# the ticket.
#
# ---- isolation -------------------------------------------------------------
#
# This runs on developer machines that have a bench with a realm in it, so it
# touches nothing outside .local-tmp/:
#
#   * It copies the repository's *tracked* files to .local-tmp/ci-tree and works
#     there. `git ls-files` is what makes that safe -- .env, secrets/ and the
#     volumes' contents are gitignored and therefore absent, so the copy is a
#     fresh clone with your uncommitted edits in it. The bench's .env and
#     secrets/generated/ are never read and never written.
#   * COMPOSE_PROJECT_NAME, the container names (compose.ci.yaml), the subnet and
#     the one published port are all distinct from a deployment's.
#
# So it can run while the bench is up. It removes its volumes at the end, and
# `--keep` leaves them for inspection.
set -euo pipefail

FIXTURES=testbench/fixtures/entra-token
PROJECT=kerbridge-ci
REALM=KBCI.TEST
DOMAIN=kbci.test
NETBIOS=KBCI
FQDN=kerbridge.$DOMAIN
# The same derivation check-env.sh asserts .env agrees with. Written out rather
# than restated, so changing DOMAIN above cannot leave the three DNs behind.
BASE_DN=DC=${DOMAIN//./,DC=}
SUBNET=172.29.0.0/24
REALM_IP=172.29.0.10
NAS_IP=172.29.0.20
PORT=${CI_HTTPS_PORT:-8443}
USER_NAME=alice
GRANT_GROUP=onprem-device-grants
# seed-demo.sh's own default, restated because the config set has to name it.
ADMISSION_GROUP=onprem-realm-users
# The synthetic tenant and object ids make_fixtures.py generates its two positive
# tokens with. seed-demo.sh writes the matching kb1| identities, which is the
# whole join between a token and the directory.
TENANT=aaaabbbb-0000-cccc-1111-dddd2222eeee
OID=33334444-dddd-5555-eeee-6666ffff7777
# The delegation cast: OTHER is admitted and delegates for nobody, SERVICE is the
# unattended account a grant is created *for* and never signs in at all.
OTHER_NAME=bob
OTHER_OID=44445555-eeee-6666-ffff-7777aaaa8888
SERVICE_NAME=svc-builder
SERVICE_OID=55556666-ffff-7777-aaaa-8888bbbb9999
DELEGATE_GROUP=$SERVICE_NAME-delegates
# The one source this realm serves -- configs/main.toml's sources list and
# configs/idp_entra.toml's name, both written below. Every broker API call
# below carries it as the route's first segment.
SOURCE=entra

KEEP=0
[ "${1:-}" != "--keep" ] || KEEP=1

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { echo "ci-stack: $*" >&2; exit 1; }

# Every request below wants the same three flags and the status code rather than
# the exit status, because the codes are what is under test. $CA, $FQDN and $PORT
# are resolved at call time; nothing here runs before they are set.
api() {
  local method=$1 path=$2 out=$3
  shift 3
  curl -sS -o "$out" -w '%{http_code}' -X "$method" \
    --cacert "$CA/ca.crt" --resolve "$FQDN:$PORT:127.0.0.1" \
    "$@" "https://$FQDN:$PORT$path"
}
tok() { printf 'Authorization: Bearer %s' "$(cat "$FIXDIR/$1.jwt")"; }
jget() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }
# The raw uncompressed point (0x04 || X || Y) is the trailing 65 bytes of the
# SPKI DER, which is what both CNG hands out and `ring` verifies against -- no
# SPKI encoding sits between the two ends to disagree about.
new_device_key() {
  openssl ecparam -name prime256v1 -genkey -noout -out "$1" 2>/dev/null
  openssl ec -in "$1" -pubout -outform DER 2>/dev/null |
    python3 -c 'import base64,sys; print(base64.urlsafe_b64encode(sys.stdin.buffer.read()[-65:]).decode().rstrip("="))'
}

# Before anything, including the copy -- rsync is the first thing used, and a
# missing one should say so rather than fail as a bare command-not-found.
for t in git docker rsync openssl curl python3; do
  command -v "$t" >/dev/null || die "$t is required"
done

# The one resource the disposable project does not get a private copy of: this
# and compose.mockidp.yaml both default to 8443. Checked before the copy and the
# build, because the clash otherwise surfaces from inside `make up` minutes
# later, naming the broker container rather than the port.
python3 - "$PORT" <<'EOF' || die "port $PORT is already published (the bench's mockidp takes 8443) -- rerun with CI_HTTPS_PORT=<free port>"
import socket, sys
s = socket.socket()
try:
    s.bind(("0.0.0.0", int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    s.close()
EOF

# ---------------------------------------------------------------------------
# Outer half: build the disposable tree, then re-enter it. KB_CI_TREE is how the
# inner run knows it is already inside one.
# ---------------------------------------------------------------------------
if [ -z "${KB_CI_TREE:-}" ]; then
  # Assigned before the cd rather than `cd "$(git ...)"`: bash treats `cd ""` as
  # a successful no-op, so a git that failed would leave the `rm -rf` below
  # pointed at whatever directory the script happened to be invoked from.
  toplevel=$(git -C "$(dirname "$0")" rev-parse --show-toplevel) ||
    die "not inside a git checkout"
  cd "$toplevel"
  TREE=$PWD/.local-tmp/ci-tree
  say "staging a disposable tree at $TREE"
  rm -rf "$TREE"
  mkdir -p "$TREE"
  # Tracked *and* new-but-not-ignored files, at their working-tree contents: this
  # is a test of what you have, not of what you pushed, and a test that could not
  # see a file until it was committed would be the wrong way round. What it does
  # not see is anything gitignored -- .env, secrets/, target/, dist/,
  # .local-tmp/ -- which is exactly what makes the copy a fresh clone.
  git ls-files -z --cached --others --exclude-standard |
    rsync -0a --files-from=- ./ "$TREE"/
  # Derived here and not in the tree: the copy has no .git, and the `debs`
  # service's image build cannot derive a version either. This is the only
  # place in the run that can still see the tags.
  export KB_VERSION=${KB_VERSION:-$(debian/make-changelog --print-version)}
  # The source .local-tmp survives between runs; the tree's does not, since the
  # tree is deleted and rebuilt. The venv below is the one thing worth keeping.
  KB_CI_SRC=$PWD KB_CI_TREE=$TREE exec "$TREE/deploy/scripts/bench/ci-stack.sh" "$@"
fi

cd "$KB_CI_TREE"
ROOT=$PWD
export COMPOSE_PROJECT_NAME=$PROJECT
export COMPOSE_FILE=compose.yaml:compose.nas.yaml:compose.ci.yaml
# Commas, unlike COMPOSE_FILE. bench.env is tracked so the disposable tree gets
# it; the .env written below is listed last and wins, which is how this realm's
# throwaway values beat the committed fixtures.
export COMPOSE_ENV_FILES=bench.env,.env

# ---------------------------------------------------------------------------
# The token corpus, generated now so the positive fixture is inside its validity
# window. Never regenerated in place: the committed corpus is expired on purpose
# (crates/kerbridge-idp/src/entra.rs pins its window) and rewriting it would
# dirty the tree and move the constants that suite asserts.
# ---------------------------------------------------------------------------
say "generating a token corpus"
FIXDIR=$ROOT/.local-tmp/ci-fixtures
rm -rf "$FIXDIR"; mkdir -p "$FIXDIR"
cp "$ROOT/$FIXTURES/make_fixtures.py" "$FIXDIR/"
# In the source tree's .local-tmp, not this one's: the disposable tree is deleted
# and rebuilt every run, and re-installing pyjwt from the network each time is a
# network dependency the test does not otherwise have. On a CI runner nothing is
# cached anyway and this is simply the first run.
VENV=${KB_CI_SRC:-$ROOT}/.local-tmp/ci-venv
if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --quiet --disable-pip-version-check pyjwt cryptography
fi
# make_fixtures.py writes beside itself, which is why it was copied first.
(cd "$FIXDIR" && "$VENV/bin/python" make_fixtures.py >/dev/null)
[ -s "$FIXDIR/jwks.json" ] && [ -s "$FIXDIR/positive_delegated.jwt" ] &&
  [ -s "$FIXDIR/positive_other_user.jwt" ] ||
  die "fixture generation produced nothing"
echo "generated $(ls "$FIXDIR"/*.jwt | wc -l | tr -d ' ') tokens and a key document"

cd "$ROOT/deploy"
# kbmanage(), which the readiness probe below runs the operator CLI through.
. scripts/lib.sh

# ---------------------------------------------------------------------------
# .env. A realm identity that is not the documented example (check-env.sh
# refuses that one while nothing is provisioned) and its own subnet.
# ---------------------------------------------------------------------------
say "writing deploy/.env for the throwaway realm"
cat > .env <<EOF
# Written by scripts/bench/ci-stack.sh in a disposable tree. Not a deployment.
AD_REALM=$REALM
AD_DNS_DOMAIN=$DOMAIN
AD_NETBIOS_DOMAIN=$NETBIOS
AD_DC_HOSTNAME=kerbridge
BROKER_FQDN=$FQDN
TLS_STRATEGY=external
CI_FIXTURE_DIR=$FIXDIR
CI_HTTPS_PORT=$PORT

SEED_USER_OID=$OID
SEED_USER_NAME=$USER_NAME
SEED_OTHER_OID=$OTHER_OID
SEED_OTHER_NAME=$OTHER_NAME
SEED_SERVICE_OID=$SERVICE_OID
SEED_SERVICE_NAME=$SERVICE_NAME
SEED_DELEGATE_GROUP=$DELEGATE_GROUP
# The two group names seed-demo.sh hand-provisions are deliberately absent: it
# reads them out of configs/idp_$SOURCE.toml through kbconfig, and the step
# after this one writes that file. Stating them here as well could only drift.

# Its own subnet: Docker refuses a second network overlapping the bench's.
KERBRIDGE_SUBNET=$SUBNET
REALM_IPV4=$REALM_IP
NAS_IPV4=$NAS_IP
EOF

# ---------------------------------------------------------------------------
# configs/. Gitignored like .env, so the disposable tree arrives with only the
# committed *.toml.example set and this writes the real one. issuerd is the only
# reader, at /etc/kerbridge, and the whole set still has to be here and valid:
# the load is one cross-checked whole, not a per-binary slice.
#
# .env keeps its own copy of the realm and the broker's listen address -- compose
# and Caddy cannot read TOML -- and check-env.sh holds the two sides together.
# Both are written from the shell variables at the top of this script.
# ---------------------------------------------------------------------------
say "writing deploy/configs for the throwaway realm"
mkdir -p configs
cat > configs/main.toml <<EOF
sources = ["$SOURCE"]
device_grant_days = 30

# No webhook here -- the file compose mounts is empty, which is log-only. Stated
# because it has no default and an operator's set names it; every key that has
# one is left out, here and in issuerd.toml, so this run proves the default
# state_dir and audit paths are mountable.
[notify]
url_file = "/etc/kerbridge.secrets/notify_url"
EOF
cat > configs/realm.toml <<EOF
realm = "$REALM"
ldap_url = "ldaps://$FQDN:636"
ldap_ca_file = "/run/kerbridge/realm-ca.pem"
EOF
# Every value a default, uid and gid included; empty on purpose, so the run
# exercises them.
: > configs/issuerd.toml
cat > configs/broker.toml <<EOF
bind_dn = "CN=svc-kerbridge-broker,CN=Users,$BASE_DN"
bind_password_file = "/etc/kerbridge.secrets/generated/svc_kerbridge_broker_password"
EOF
# Every value a default; the file exists because the load reads all five.
: > configs/sync.toml
# The Graph half is blank because this run has no tenant and no sync app: the
# fixture identifiers below are the token's, and the broker verifies against the
# mounted jwks.json rather than resolving anything from them.
cat > configs/idp_entra.toml <<EOF
name = "$SOURCE"
provider = "entra"
group_suffix = "none"
bind_dn = "CN=svc-kerbridge-sync-$SOURCE,CN=Users,$BASE_DN"
bind_password_file = "/etc/kerbridge.secrets/generated/idp/$SOURCE/bind_password"

[provider_config]
tenant_id = "$TENANT"
broker_api_client_id = "11112222-bbbb-3333-cccc-4444dddd5555"
public_client_id = "22223333-cccc-4444-dddd-5555eeee6666"
jwks_file = "/etc/jwks/entra.json"
sync_client_id = ""
sync_credential_file = ""
# Sync's, and unreachable from the broker -- which finds the group by its
# marker. Stated anyway because a source file with no admission group admits
# nobody, so the parser refuses one, and seed-demo.sh creates this name.
admission_group = "$ADMISSION_GROUP"
device_grant_group = "$GRANT_GROUP"
EOF

# ---------------------------------------------------------------------------
# A private CA and a leaf for BROKER_FQDN, so TLS_STRATEGY=external has the
# certificate it refuses to start without -- and so the probe below can verify
# the chain rather than pass -k. The acme strategies are not testable here; they
# need a real zone.
# ---------------------------------------------------------------------------
say "creating a CA and a certificate for $FQDN"
mkdir -p secrets/tls
CA=$ROOT/.local-tmp/ci-ca
rm -rf "$CA"; mkdir -p "$CA"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=kerbridge-ci-ca" \
  -keyout "$CA/ca.key" -out "$CA/ca.crt" 2>/dev/null
# The endpoint probe runs in a container (scripts/lib.sh @ kbmanage()), so the
# CA it judges the chain against has to be reachable from inside one. Read by
# the helper rather than by anything here, hence the directive.
# shellcheck disable=SC2034
KBMANAGE_RUN_ARGS=(-v "$CA/ca.crt:/ca.crt:ro")
openssl req -newkey rsa:2048 -nodes -subj "/CN=$FQDN" \
  -keyout secrets/tls/broker.key -out "$CA/leaf.csr" 2>/dev/null
openssl x509 -req -in "$CA/leaf.csr" -CA "$CA/ca.crt" -CAkey "$CA/ca.key" \
  -CAcreateserial -days 2 -out secrets/tls/broker.crt \
  -extfile <(printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\n' "$FQDN") 2>/dev/null
chmod 0600 secrets/tls/broker.key

# ---------------------------------------------------------------------------
# Secret ownership, which on Linux *is* the access control.
#
# A compose secret is a bind mount, so the host file's owner and mode are what
# the container gets -- and every container that reads one runs with cap_drop:
# ALL. Two rules follow, and a deployment satisfies both by construction because
# root is what bootstraps it:
#
#   * realm, nas1 and caddy run as root, which without DAC_OVERRIDE can read
#     only what it owns. Their files must be owned by uid 0.
#   * broker and sync run as unprivileged uids and reach their files through
#     ${BROKER_GID}, exactly as they reach the issuer socket.
#
# An unprivileged operator satisfies neither, and a CI runner is one. The first
# symptom is the realm container exiting a second after start -- "realm admin
# password file ... is missing" -- of which compose passes on nothing but
# "container kerbridge-ci-realm is unhealthy". Docker Desktop remaps ownership
# into the container, so the macOS bench cannot meet any of this and a Linux
# runner was the first thing that could.
#
# `prepare-state` creates every directory and every generated secret already
# owned as its reader needs, so nothing the deployment itself produces is
# patched up here.
#
# What is left is the TLS key this script generates itself, minutes before the
# tree is prepared, for a bench CA that exists nowhere else. caddy runs as root
# and reads it, so it has to be root's.
#
# Skipped off Linux rather than emulated: there is nothing to fix there, and
# chown would want root for it anyway.
# ---------------------------------------------------------------------------
PRIV=
if [ "$(uname -s)" = Linux ] && [ "$(id -u)" != 0 ]; then
  sudo -n true 2>/dev/null || die "this is running as uid $(id -u), and the TLS key \
this script generates has to be owned by root before caddy can read it. That needs \
root: run this as root, or grant passwordless sudo."
  PRIV="sudo -n"
fi
own_root() { [ "$(uname -s)" = Linux ] || return 0; $PRIV chown 0:0 "$@"; }
teardown() {
  local rc=$?
  # Before `down -v`, because after it there is nothing left to ask. A separate
  # `if: failure()` workflow step cannot do this: the trap has already removed
  # every container it would read, so the failure arrives with the compose event
  # line and nothing else -- never the realm container's own FATAL.
  if [ "$rc" != 0 ]; then
    say "the stack as it stood when this failed"
    docker compose ps || true
    docker compose logs --no-color --tail 80 || true
  fi
  if [ "$KEEP" = 1 ]; then
    say "leaving the stack up (--keep). Tear it down with:"
    echo "  cd $ROOT/deploy && COMPOSE_PROJECT_NAME=$PROJECT \\"
    echo "    COMPOSE_FILE=$COMPOSE_FILE docker compose down -v"
  else
    say "tearing down"
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  [ "$rc" = 0 ] || echo "ci-stack: FAILED (exit $rc)" >&2
  return $rc
}
trap teardown EXIT

# ---------------------------------------------------------------------------
# The deployment's own path, unmodified: the same targets an operator runs.
# ---------------------------------------------------------------------------
say "building images"
docker compose build
# The scripts below read configs/ through it, because shell cannot parse TOML.
# Not a compose service, so `docker compose build` does not reach it.
say "building the kbconfig image"
make kbconfig-image
# And the operator CLI's, which the readiness report below runs the endpoint
# probe through -- the same image `make ready` uses on a real deployment.
say "building the kbmanage image"
make kbmanage-image

say "make up -- provision, bootstrap the directory, start the stack"
# Not `make up`: that also writes ~/.config/kerbridge/configs (a link) and
# configs/kbmanage.toml, which belong to whatever bench the developer actually
# has. The steps it wraps are the ones under test.
scripts/config/check-env.sh
scripts/compose/check-tls.sh
scripts/config/check-config.sh
# The image that carries prepare-state, which the next line runs in a throwaway
# container. `make up` has this as a prerequisite of its own bootstrap step; here
# the steps are called one at a time, so it is named one at a time too.
make realm-image
scripts/compose/bootstrap-secrets.sh
own_root secrets/tls/broker.key
docker compose up -d --wait realm nas1
docker compose run --rm setup directory
# The gate `make stack` runs before the same `up`, now that the files can pass
# it: it is the deployment's own statement of the two rules above, and running
# it here is what keeps this workaround honest. Unprivileged on purpose --
# secrets/generated is this user's, so the glob it walks still sees every file
# root just wrote into it.
scripts/check-secrets.sh
docker compose build caddy
docker compose up -d

say "waiting for the stack to report ready"
# wait-ready.sh inspects fixed container names, which compose.ci.yaml renames, so
# its report is not reachable from here. Its endpoint half is, and is the same
# bytes: `kbmanage endpoint` asks the one question that is not about Docker, and
# tells a broker legitimately refusing an unprefixed /config from a path nothing
# routed. Not a bare curl loop: one that accepts any 200 accepts the edge's own
# 404 page just as happily.
#
# Exit 2 and 3 are "not yet" -- nothing listening, or no TLS session on a stack
# that is still starting; anything else is an answer, right or wrong, and there
# is no point asking sixty times.
ready=0
for _ in $(seq 1 60); do
  msg=$(kbmanage "$PROJECT-broker" endpoint "https://$FQDN" \
          --resolve 127.0.0.1:443 --ca-file /ca.crt) && { ready=1; break; }
  case $? in 2|3|125) sleep 5;; *) break;; esac
done
[ "$ready" = 1 ] || { docker compose ps; die "GET /config never answered: $msg"; }
say "$msg"

say "GET /$SOURCE/config"
curl -fsS --cacert "$CA/ca.crt" --resolve "$FQDN:$PORT:127.0.0.1" "https://$FQDN:$PORT/$SOURCE/config"
echo

# Both halves of the segment at once: caddy's allowlist proxies any source name,
# and the broker is what decides which ones exist. A caddy pattern narrowed to
# one literal source would answer this 404 from the edge and look identical.
say "a source this deployment does not serve"
code=$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CA/ca.crt" \
  --resolve "$FQDN:$PORT:127.0.0.1" "https://$FQDN:$PORT/nosuch/config")
[ "$code" = 404 ] || die "GET /nosuch/config answered $code, wanted 404"

# What a client that found this broker in DNS asks: an SRV record carries a host
# and a port and has nowhere to put a source segment. One source is configured
# here, so the answer names it.
say "the address an SRV record can express"
base=$(curl -fsS --cacert "$CA/ca.crt" --resolve "$FQDN:$PORT:127.0.0.1" \
  "https://$FQDN:$PORT/config" | python3 -c 'import json,sys; print(json.load(sys.stdin)["base_url"])')
[ "$base" = "/$SOURCE" ] || die "GET /config said base_url=$base, wanted /$SOURCE"

say "seeding the demo directory"
scripts/bench/seed-demo.sh

# ---------------------------------------------------------------------------
# The two claims worth making.
# ---------------------------------------------------------------------------
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
# The second identity proof: a device grant. There is no TPM attestation by
# design, which is precisely what lets a software key exercise every server-side
# check here -- the assertion format, the nonce's single use, the grant-group
# gate, and the stored value the broker reads back off the directory. Only the
# CNG half of the client is left to the Windows bench.
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

# Builds and signs one assertion against a fresh nonce, for the key and identity
# it is given. A function because the replay check below needs a second one --
# and the *same* assertion presented twice is what has to fail, not a second,
# differently-nonced one -- and because the delegated device is a different key
# claiming a different identity.
sign_assertion() {  # key, point, identity
  nonce=$(curl -fsS --cacert "$CA/ca.crt" --resolve "$FQDN:$PORT:127.0.0.1" \
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

# The replay window, as something other than a claim: the same assertion again,
# with its nonce already spent.
code=$(api POST /$SOURCE/ticket /dev/null -H "Authorization: DeviceGrant $assertion")
[ "$code" = 401 ] || die "a replayed assertion answered $code, wanted 401"
echo "the same assertion replayed is refused 401"

# Revocation, and that it bites the next exchange rather than some later one.
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
# The claim worth proving is the one with no symptom. If the ticket that key
# later gets were the engineer's rather than the service account's, everything
# would keep working and the build would simply publish its artifacts under the
# wrong owner -- invisible until somebody opened a Security tab. So the principal
# is asserted, not the status code.
#
# The negative below is the other half, and it is the one check here that would
# fail silently if it regressed: an admitted user who is not in the delegate
# group must be refused. It is preceded by that user obtaining an ordinary ticket
# of their own, because a refusal for "not admitted" would otherwise pass this as
# a refusal for "not a delegate".
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

# Nothing durable in the directory says who authorized this, so that line is the
# only record there is -- and the departing-delegate runbook works by grepping it
# for a name. Asserted here because a silently one-sided GRANT line would leave
# that runbook with nothing to find, months later and with no way to reconstruct it.
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
echo "a delegated grant is revocable remotely, and bites at the next exchange"

# Back to the token-obtained ticket for the SMB leg: $resp now holds a
# device-grant one, which is the same ticket by any measure, but the claim under
# test below is the original path's.
code=$(api POST /$SOURCE/ticket "$resp" -H "$(tok positive_delegated)")
[ "$code" = 200 ] || die "POST /ticket answered $code on the re-fetch, wanted 200"
principal=$(jget "$resp" principal)

say "reading a file over SMB with that ticket and no password"
ccache=$ROOT/.local-tmp/ci-ccache
python3 -c 'import base64,json,sys; sys.stdout.buffer.write(base64.b64decode(json.load(open(sys.argv[1]))["ccache_b64"]))' \
  "$resp" > "$ccache"
# 0600, because smbclient here is Heimdal-backed and silently ignores a ccache
# any other user could read.
chmod 600 "$ccache"
docker compose cp "$ccache" nas1:/tmp/kb.ccache
# `docker cp` carries the host file's *ownership* in as well as its mode, so this
# arrives owned by the host uid that wrote it and mode 0600 -- unreadable by the
# root that smbclient runs as, because nas1 is cap_drop: ALL and root without
# CAP_DAC_OVERRIDE is just another user. smbclient then reports no ccache at all:
# it falls back to asking for a password, and says "No password for user
# principal[root@REALM]", which reads like a Kerberos or principal problem and is
# a file permission one. CHOWN is in nas1's cap_add (CAP_FOWNER is not, so chown
# works here and chmod would not).
docker compose exec -T nas1 chown 0:0 /tmp/kb.ccache
# The invocation the joined-nas-authorization spike proved on the bench, kept
# byte for byte: --use-kerberos=required, and neither -U nor -N. The ccache's own
# principal is what authenticates; naming a user makes smbclient look for that
# one instead.
got=$(docker compose exec -T nas1 sh -c \
  "KRB5CCNAME=FILE:/tmp/kb.ccache smbclient '//nas1.$DOMAIN/share' \
     --use-kerberos=required -c 'get README.txt -'" 2>&1) || true
case "$got" in
  *KerBridge*) echo "read README.txt from //nas1.$DOMAIN/share as $principal" ;;
  *) die "SMB read returned: ${got:-<nothing>}" ;;
esac

say "PASS -- provisioned, bootstrapped, issued, and read over SMB"
