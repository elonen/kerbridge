#!/bin/bash
# Refuse to provision before the public endpoint's certificate is settled.
#
# Compose bind-mounts secrets/tls as a directory, not as files, so a missing
# certificate raises no bind error the way a missing secret does: caddy would
# start, fail to load it and restart-loop, while `up -d` exited 0 on a stack
# whose public endpoint never comes up.
#
# Checked before the realm is provisioned rather than at the final `up`, because
# provisioning bakes the realm identity into a durable database and the TLS
# strategy is a decision better made first.
set -euo pipefail
cd "$(dirname "$0")/../.."
[ -f .env ] && . ./.env

[ "${TLS_STRATEGY:-external}" = "external" ] || exit 0

if ! { [ -s secrets/tls/broker.crt ] && [ -s secrets/tls/broker.key ]; }; then
  echo "TLS_STRATEGY=external needs secrets/tls/broker.crt and secrets/tls/broker.key,"
  echo "which nothing here can create. Supply them from your CA, or select an acme"
  echo "strategy in .env -- those issue the certificate themselves and need no"
  echo "supplied file. See deploy/README.md section Certificates."
  exit 1
fi

# secrets/tls is bind-mounted as a directory, so a symlink inside it reaches
# caddy unresolved and its target is looked up in *caddy's* filesystem, where a
# host path like /etc/ssl/private/... does not exist. Measured 2026-07-27; the
# host-side tests above pass through the link, so nothing else here catches it.
# A compose `secrets:` entry is a file mount and *is* dereferenced when mounted
# -- which is why a symlinked notify_url works and this does not.
fail=0
for f in secrets/tls/broker.crt secrets/tls/broker.key; do
  [ -L "$f" ] || continue
  echo "  $f -> $(readlink "$f")"
  fail=1
done
[ "$fail" = 0 ] || {
  echo "Refusing to start: caddy cannot follow those. Copy the file into"
  echo "secrets/tls/ instead, and have whatever renews it copy too and then run"
  echo "scripts/compose/reload-caddy.sh -- replacing the file in place is what the"
  echo "directory mount is for."
  exit 1
}
