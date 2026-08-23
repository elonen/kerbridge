#!/bin/bash
# Load an externally-renewed TLS cert without downtime. TLS_STRATEGY=external
# only -- acme and acme-dns renew inside Caddy, with nothing to reload. The
# renewal contract is deploy/README.md, "External certificate renewal".
#
# `caddy reload` finds the admin socket's address in the Caddyfile, so no
# --address is passed. `-T` disables TTY allocation: the caller is typically a
# renewal hook with no terminal, and `docker compose exec` fails without it
# there. Needs docker access on the host; if the renewal identity cannot have
# that, a watcher sidecar reacting to the file change is the decoupled
# alternative.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec docker compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile
