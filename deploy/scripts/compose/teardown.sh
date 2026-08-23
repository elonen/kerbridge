#!/bin/bash
# Stop and remove this deployment, identified by project name rather than by
# compose file.
#
# `docker compose down` run from deploy/ loads compose.yaml, and compose.yaml is
# interpolated from .env. With no .env every ${VAR} resolves empty and the parse
# dies before anything is torn down:
#
#   'services[realm].extra_hosts' bad host name ''
#
# Teardown would then remove nothing, for precisely the operator whose
# configuration is broken or lost. `up` and `stack` are gated by check-env.sh and
# can afford to refuse; teardown cannot, because refusing leaves the stack up.
#
# compose.yaml's `name:` is a literal, and COMPOSE_PROJECT_NAME is deliberately
# absent from .env (.env.example section 3), so the project is identifiable
# without interpolating anything. --project-directory pointed at an empty
# directory is what keeps a compose file from being loaded at all: compose reads
# none there and does not search upward from it -- measured 2026-07-29 against
# compose v5.1.4, with the probe directory a direct child of deploy/ and
# compose.yaml still not found.
#
# Discovery is by the com.docker.compose.project label, which sees strictly more
# than a file-scoped teardown does:
#
#   - `make up NAS=1` creates kerbridge-nas1 from compose.nas.yaml, and NAS=1 is
#     the operator's to remember. A file-scoped `make clean` without it leaves
#     that container running, and the network then refuses to delete.
#   - it reaches services the compose files on disk no longer describe -- the
#     trap README.md records under "Why not a sync compose profile", where a
#     profiled service is invisible to a plain `down`.
#
# Neither flag needs a compose file, both measured the same day: --rmi local
# removes built images by the same label even when the containers are already
# gone (`make down` then `make clean`), and -v removes named volumes. No caller
# passes -v today; it is recorded because the -v documentation describes reading
# the compose file's `volumes:` section, so the next reader has reason to assume
# it would not work here.
set -euo pipefail
cd "$(dirname "$0")/../.."

project=$(sed -n 's/^name:[[:space:]]*\([A-Za-z0-9_-][A-Za-z0-9_-]*\).*/\1/p' compose.yaml | head -1)
[ -n "$project" ] || {
  echo "deploy/compose.yaml has no 'name:' line, which is what identifies the" >&2
  echo "  project to tear down. Teardown cannot parse the file itself -- that is" >&2
  echo "  the dependency on .env this avoids." >&2
  exit 1
}

# Not exec, so this still runs.
empty=$(mktemp -d)
trap 'rmdir "$empty" 2>/dev/null || true' EXIT

docker compose -p "$project" --project-directory "$empty" down "$@"
