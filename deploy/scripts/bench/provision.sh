# Shared provisioning for all stack tiers. Sourcing this file creates an
# isolated realm, bootstraps its directory, and waits for `/config` over TLS.
# The caller performs source-specific setup and assertions.
#
# This file executes when sourced. It has no shebang and is not executable.
# The shellcheck directive below specifies Bash syntax.
#
# Caller contract:
#
#   SOURCE=<name>            source name used in the config set and API routes
#   export COMPOSE_FILE=...  complete overlay list in required order
#   idp_prepare()            prerequisites created before .env
#   idp_env_lines()          source-specific .env lines on stdout
#   idp_source_toml()        idp_$SOURCE.toml body on stdout
#
# The checks below validate this contract before the build. `make test` also
# verifies that this file does not name an identity source.
#
# The script copies tracked and unignored working-tree files to
# .local-tmp/ci-tree. Gitignored deployment data, including .env and secrets/,
# is not copied. The CI project also uses separate container names, volumes, a
# subnet, and a published port. It can run while the development bench is up.
# The default teardown removes its volumes; `--keep` preserves them.

# shellcheck shell=bash

# Apply strict mode even if the caller does not.
set -euo pipefail

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { echo "${0##*/}: $*" >&2; exit 1; }

# Validate the caller contract before copying files or building images.
SOURCE=${SOURCE:?the tier must set it before sourcing provision.sh}
COMPOSE_FILE=${COMPOSE_FILE:?the tier must set it before sourcing provision.sh}
export COMPOSE_FILE
for hook in idp_prepare idp_env_lines idp_source_toml; do
  declare -F "$hook" >/dev/null ||
    die "the tier must define $hook() before sourcing provision.sh"
done

PROJECT=kerbridge-ci
REALM=KBCI.TEST
DOMAIN=kbci.test
NETBIOS=KBCI
# The DC, broker, and authority require different names. Duplicate aliases
# produce two DNS addresses and can route a broker request to the DC.
DC_FQDN=kerbridge.$DOMAIN
FQDN=broker.$DOMAIN
# The authority uses the same certificate and requires its own SAN.
IDP_FQDN=idp.$DOMAIN
# Derive the base DN so it cannot diverge from DOMAIN.
BASE_DN=DC=${DOMAIN//./,DC=}
SUBNET=172.29.0.0/24
REALM_IP=172.29.0.10
NAS_IP=172.29.0.20
PORT=${CI_HTTPS_PORT:-8443}
USER_NAME=alice
# seed-demo.sh maps this token object ID to $USER_NAME in the directory.
OID=33334444-dddd-5555-eeee-6666ffff7777
# OTHER is admitted but cannot delegate. SERVICE receives a delegated grant and
# does not sign in.
OTHER_NAME=bob
OTHER_OID=44445555-eeee-6666-ffff-7777aaaa8888
SERVICE_NAME=svc-builder
SERVICE_OID=55556666-ffff-7777-aaaa-8888bbbb9999
DELEGATE_GROUP=$SERVICE_NAME-delegates

KEEP=0
[ "${1:-}" != "--keep" ] || KEEP=1

# Return the HTTP status because callers test response codes. Resolve CA and
# endpoint variables when called.
#
# --resolve does not bypass proxies because curl selects a proxy from the URL
# host. --noproxy keeps these loopback requests out of an environment proxy.
api() {
  local method=$1 path=$2 out=$3
  shift 3
  curl -sS -o "$out" -w '%{http_code}' -X "$method" --noproxy '*' \
    --cacert "$CA/ca.crt" --resolve "$FQDN:$PORT:127.0.0.1" \
    "$@" "https://$FQDN:$PORT$path"
}
jget() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }
# CNG and `ring` use the raw 65-byte point (0x04 || X || Y), which is the end of
# this SPKI DER value.
new_device_key() {
  openssl ecparam -name prime256v1 -genkey -noout -out "$1" 2>/dev/null
  openssl ec -in "$1" -pubout -outform DER 2>/dev/null |
    python3 -c 'import base64,sys; print(base64.urlsafe_b64encode(sys.stdin.buffer.read()[-65:]).decode().rstrip("="))'
}

# Check tools before the script copies or builds anything.
for t in git docker rsync openssl curl python3; do
  command -v "$t" >/dev/null || die "$t is required"
done

# The published port is the only resource that the Compose project does not
# isolate. Check it before copying files or building images. The development
# bench also uses 8443 by default.
python3 - "$PORT" <<'EOF' || die "port $PORT is already published (the bench's authority overlay takes 8443) -- rerun with CI_HTTPS_PORT=<free port>"
import socket, sys
s = socket.socket()
try:
    s.bind(("0.0.0.0", int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    s.close()
EOF

# KB_CI_TREE distinguishes the source checkout from the disposable copy.
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
  # Copy tracked and unignored files at their working-tree contents. This includes
  # uncommitted files but excludes .env, secrets/, target/, dist/, and .local-tmp/.
  # --ignore-missing-args omits tracked files that are deleted in the working tree.
  git ls-files -z --cached --others --exclude-standard |
    rsync -0a --ignore-missing-args --files-from=- ./ "$TREE"/
  # Derive the version before entering the copy, which has no .git metadata.
  export KB_VERSION=${KB_VERSION:-$(debian/make-changelog --print-version)}
  # Keep tier caches in the source checkout because the disposable copy is
  # replaced for each run.
  #
  # Re-enter through the caller's copied script because this file is sourced.
  script=$(cd -P "$(dirname "$0")" && pwd)/${0##*/}
  rel=${script#"$toplevel"/}
  [ "$rel" != "$script" ] || die "$script is not inside $toplevel"
  KB_CI_SRC=$PWD KB_CI_TREE=$TREE exec "$TREE/$rel" "$@"
fi

cd "$KB_CI_TREE"
ROOT=$PWD
export COMPOSE_PROJECT_NAME=$PROJECT
# Commas, unlike COMPOSE_FILE. bench.env is tracked so the disposable tree gets
# it; the .env written below is listed last and wins, which is how this realm's
# throwaway values beat the committed fixtures.
export COMPOSE_ENV_FILES=bench.env,.env

# Define shared output paths before idp_prepare because .env uses them.
CLIENTDIR=$ROOT/.local-tmp/ci-client
CA=$ROOT/.local-tmp/ci-ca
idp_prepare

cd "$ROOT/deploy"
# kbmanage(), which the readiness probe below runs the operator CLI through.
. scripts/lib.sh

# Use a non-example realm because check-env.sh rejects the documented example.
say "writing deploy/.env for the throwaway realm"
cat > .env <<EOF
# Written by scripts/bench/provision.sh in a disposable tree. Not a deployment.
AD_REALM=$REALM
AD_DNS_DOMAIN=$DOMAIN
AD_NETBIOS_DOMAIN=$NETBIOS
AD_DC_HOSTNAME=kerbridge
BROKER_FQDN=$FQDN
TLS_STRATEGY=external
CI_HTTPS_PORT=$PORT
# compose.ci.yaml mounts the client and CA into nas1. The tier fragment adds its
# sign-in helper.
CI_CLIENT_BIN=$CLIENTDIR/kerbridge
CI_CA_CRT=$CA/ca.crt

SEED_USER_OID=$OID
SEED_USER_NAME=$USER_NAME
SEED_OTHER_OID=$OTHER_OID
SEED_OTHER_NAME=$OTHER_NAME
SEED_SERVICE_OID=$SERVICE_OID
SEED_SERVICE_NAME=$SERVICE_NAME
SEED_DELEGATE_GROUP=$DELEGATE_GROUP
# The two group names seed-demo.sh hand-provisions are deliberately absent: it
# defaults both, and the broker finds either group by the marker the seed stamps
# rather than by its name. Stating them here as well could only drift.

# Its own subnet: Docker refuses a second network overlapping the bench's.
KERBRIDGE_SUBNET=$SUBNET
REALM_IPV4=$REALM_IP
NAS_IPV4=$NAS_IP
EOF

# Append the source-specific Compose values as one block.
idp_env_lines >> .env

# The copied tree contains only the committed *.toml.example files because the
# active config set is gitignored. Write the complete config set; loading checks
# all files together. Compose and Caddy cannot read TOML, so .env duplicates the
# realm and broker values. check-env.sh verifies that the copies agree.
say "writing deploy/configs for the throwaway realm"
mkdir -p configs
cat > configs/main.toml <<EOF
sources = ["$SOURCE"]
device_grant_days = 30

# The empty webhook file selects log-only notifications. Omit keys with defaults
# so this run also tests the default state and audit paths.
[notify]
url_file = "/etc/kerbridge.secrets/notify_url"
EOF
cat > configs/realm.toml <<EOF
realm = "$REALM"
ldap_url = "ldaps://$DC_FQDN:636"
ldap_ca_file = "/run/kerbridge/realm-ca.pem"
EOF
# An empty file exercises all defaults, including uid and gid.
: > configs/issuerd.toml
cat > configs/broker.toml <<EOF
bind_dn = "CN=svc-kerbridge-broker,CN=Users,$BASE_DN"
bind_password_file = "/etc/kerbridge.secrets/generated/svc_kerbridge_broker_password"
EOF
# The loader requires this file; an empty file exercises all defaults.
: > configs/sync.toml
# The stack tier writes the source-specific config file.
idp_source_toml > "configs/idp_$SOURCE.toml"

# TLS_STRATEGY=external requires a certificate. Create a private CA so the probe
# can validate the chain. ACME strategies require a real DNS zone.
say "creating a CA and a certificate for $FQDN (+ $IDP_FQDN)"
mkdir -p secrets/tls
rm -rf "$CA"; mkdir -p "$CA"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=kerbridge-ci-ca" \
  -keyout "$CA/ca.key" -out "$CA/ca.crt" 2>/dev/null
# scripts/lib.sh runs the endpoint probe in a container and reads this mount
# argument indirectly.
# shellcheck disable=SC2034
KBMANAGE_RUN_ARGS=(-v "$CA/ca.crt:/ca.crt:ro")
openssl req -newkey rsa:2048 -nodes -subj "/CN=$FQDN" \
  -keyout secrets/tls/broker.key -out "$CA/leaf.csr" 2>/dev/null
# The broker and authority share this certificate. Include both names in the SAN
# because the client validates the authority name.
openssl x509 -req -in "$CA/leaf.csr" -CA "$CA/ca.crt" -CAkey "$CA/ca.key" \
  -CAcreateserial -days 2 -out secrets/tls/broker.crt \
  -extfile <(printf 'subjectAltName=DNS:%s,DNS:%s\nbasicConstraints=CA:FALSE\n' \
               "$FQDN" "$IDP_FQDN") 2>/dev/null
chmod 0600 secrets/tls/broker.key

# Compose secrets preserve the host file owner and mode. Containers drop
# DAC_OVERRIDE, so root processes can read only files owned by uid 0. prepare-state
# creates generated secrets with the required owners. This script creates the TLS
# key separately, so Linux must change its owner to uid 0 for Caddy.
#
# Docker Desktop remaps ownership. Do not change ownership on non-Linux hosts.
PRIV=
if [ "$(uname -s)" = Linux ] && [ "$(id -u)" != 0 ]; then
  sudo -n true 2>/dev/null || die "this is running as uid $(id -u), and the TLS key \
this script generates has to be owned by root before caddy can read it. That needs \
root: run this as root, or grant passwordless sudo."
  PRIV="sudo -n"
fi
own_root() { [ "$(uname -s)" = Linux ] || return 0; $PRIV chown 0:0 "$@"; }
# A source's sync credential is pasted, never generated: `kbsetup directory`
# writes only what it generates, and the `setup` service mounts
# secrets/generated and deliberately not secrets/idp. Nothing below fixes its
# group, then, and sync -- ${SYNC_UID}:${BROKER_GID}, no DAC_OVERRIDE -- reads
# it through that group alone. The invoking user cannot chgrp into a group they
# are not in, so this takes the privilege the TLS key takes. Off Linux it is a
# no-op for own_root's reason: ownership is remapped at the VM boundary.
own_secret() { [ "$(uname -s)" = Linux ] || return 0; $PRIV chgrp "${BROKER_GID:-10002}" "$@"; }
teardown() {
  local rc=$?
  # Capture diagnostics before `down -v` removes the containers. A later CI
  # failure step cannot recover their logs.
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
  [ "$rc" = 0 ] || echo "${0##*/}: FAILED (exit $rc)" >&2
  return $rc
}
trap teardown EXIT

# Use the same deployment commands that an operator runs.
say "building images"
docker compose build
# The scripts use this image to read TOML. It is not a Compose service.
say "building the kbconfig image"
make kbconfig-image
# The readiness probe uses the same kbmanage image as `make ready`.
say "building the kbmanage image"
make kbmanage-image
# Build a static client for nas1 so it writes the ccache where smbclient reads it.
say "building the kerbridge client"
rm -rf "$CLIENTDIR"; mkdir -p "$CLIENTDIR"
docker build -f "$ROOT/client/kerbridge-client/Dockerfile" --target dist \
  --output "type=local,dest=$CLIENTDIR" "$ROOT"
[ -f "$CLIENTDIR/kerbridge" ] || die "the client build produced no binary"
# nas1 drops DAC_OVERRIDE and does not own this bind-mounted file. Make the
# client world-readable and executable. The ccache remains 0600.
chmod 0755 "$CLIENTDIR/kerbridge"

say "make up -- provision, bootstrap the directory, start the stack"
# Do not run `make up`; it writes host configuration for the development bench.
# Run only its deployment steps in the disposable copy.
scripts/config/check-env.sh
scripts/compose/check-tls.sh
scripts/config/check-config.sh
# bootstrap-secrets.sh runs prepare-state from the realm image.
make realm-image
scripts/compose/bootstrap-secrets.sh
own_root secrets/tls/broker.key
docker compose up -d --wait realm nas1
docker compose run --rm setup directory
# Whatever idp_prepare pasted in, given the group sync reads it through. The
# glob matches nothing on a tier whose source has no credential file.
for credential in secrets/idp/*/credential; do
  [ -s "$credential" ] || continue
  own_secret "$credential"
done
# Run the deployment's secret check without privilege. The current user owns
# secrets/generated, so the check can enumerate files created by root.
scripts/check-secrets.sh
docker compose build caddy
docker compose up -d

say "waiting for the stack to report ready"
# wait-ready.sh uses deployment container names, which this overlay replaces.
# Run its Docker-independent endpoint check directly. This check distinguishes a
# valid multi-source 404 from an unrouted 404.
#
# Exit 2, 3, and 125 are transient connection or container-start failures. Stop
# retrying after any other response.
ready=0
for _ in $(seq 1 60); do
  msg=$(kbmanage "$PROJECT-broker" endpoint "https://$FQDN" \
          --resolve 127.0.0.1:443 --ca-file /ca.crt) && { ready=1; break; }
  case $? in 2|3|125) sleep 5;; *) break;; esac
done
[ "$ready" = 1 ] || { docker compose ps; die "GET /config never answered: $msg"; }
say "$msg"

say "GET /$SOURCE/config"
curl -fsS --noproxy '*' --cacert "$CA/ca.crt" --resolve "$FQDN:$PORT:127.0.0.1" \
  "https://$FQDN:$PORT/$SOURCE/config"
echo

# Caddy must proxy any source segment; the broker decides which sources exist.
# This 404 detects an allowlist narrowed to one literal source.
say "a source this deployment does not serve"
code=$(curl -s -o /dev/null -w '%{http_code}' --noproxy '*' --cacert "$CA/ca.crt" \
  --resolve "$FQDN:$PORT:127.0.0.1" "https://$FQDN:$PORT/nosuch/config")
[ "$code" = 404 ] || die "GET /nosuch/config answered $code, wanted 404"

# An SRV record carries only a host and port. For one configured source, the
# unprefixed response must identify that source.
say "the address an SRV record can express"
base=$(curl -fsS --noproxy '*' --cacert "$CA/ca.crt" --resolve "$FQDN:$PORT:127.0.0.1" \
  "https://$FQDN:$PORT/config" | python3 -c 'import json,sys; print(json.load(sys.stdin)["base_url"])')
[ "$base" = "/$SOURCE" ] || die "GET /config said base_url=$base, wanted /$SOURCE"

# Return control to the stack tier after shared provisioning.
