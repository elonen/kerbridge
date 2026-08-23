#!/bin/bash
# The Docker half of `make clean`, as three rungs that have to be climbed
# deliberately.
#
#   make clean                 host build output. Reports Docker residue, removes none.
#   make clean-docker-images   the stack and the five built images.
#   make clean-docker-volumes  the data. Irreversible.
#
# Separate rungs because the bottom one is irreversible: destroying the volumes
# takes the domain SID and every filesystem ACL carrying it, which no backup of
# the container images brings back (`kbsetup realm` refuses a mismatched database
# for the same reason). Each rung ends by naming the next rather than taking it,
# so nothing irreversible happens because somebody wanted their disk space back.
#
# None of this reads .env: images are matched by the literal `image:` names in
# the two compose files, volumes by the project label, and the project name by
# compose.yaml's literal `name:`. scripts/compose/teardown.sh explains why
# teardown must not depend on configuration that can be missing.
#
# Images are removed by name and not left to `docker compose down --rmi`,
# because that discovers them by the com.docker.compose.project label and the
# label records whoever built last. compose.yaml pins `image: kerbridge-realm`
# and compose.ci.yaml reuses the same names under COMPOSE_PROJECT_NAME
# kerbridge-ci, so one `make test-stack` relabels all five to kerbridge-ci and a
# label-scoped removal then finds nothing and reports success -- measured
# 2026-07-29, compose v5.1.4, on images the CI stack had last built.
set -euo pipefail
cd "$(dirname "$0")/../.."

mode=${1:-report}
yes=0
[ "${2:-}" = --yes ] && yes=1

die() { echo "$*" >&2; exit 1; }

project=$(sed -n 's/^name:[[:space:]]*\([A-Za-z0-9_-][A-Za-z0-9_-]*\).*/\1/p' compose.yaml | head -1)
[ -n "$project" ] || die "deploy/compose.yaml has no 'name:' line to identify the project by."

# The literal names, both files. Every one is a constant today; an interpolated
# one would arrive here unexpanded and fail loudly at `docker image rm`, which is
# the right way round for a script whose whole point is running without .env.
image_names() {
  grep -h '^[[:space:]]*image:' compose.yaml compose.nas.yaml 2>/dev/null \
    | sed 's/^[[:space:]]*image:[[:space:]]*//' | sort -u
}

present_images() {
  local img
  while IFS= read -r img; do
    [ -n "$img" ] || continue
    docker image inspect "$img" >/dev/null 2>&1 && echo "$img"
  done < <(image_names)
  return 0
}

present_volumes() {
  docker volume ls --filter "label=com.docker.compose.project=$project" \
    --format '{{.Name}}' 2>/dev/null || true
}

running() {
  docker ps -q --filter "label=com.docker.compose.project=$project" 2>/dev/null | grep -c . || true
}

listing() { # heading, items
  local heading=$1 items=$2
  echo "$heading"
  echo "$items" | sed 's/^/    /'
}

report_volumes() {
  local vols
  vols=$(present_volumes)
  [ -n "$vols" ] || return 0
  echo ""
  listing "  $(echo "$vols" | wc -l | tr -d ' ') docker volume(s) remain -- the realm database is among them:" "$vols"
  echo ""
  echo "  make clean-docker-volumes   DESTROYS the realm: the domain SID and every"
  echo "                              filesystem ACL holding it. A rebuilt realm is a"
  echo "                              different realm, and every client re-enrolls."
}

case $mode in
report)
  imgs=$(present_images)
  vols=$(present_volumes)
  up=$(running)

  if [ -z "$imgs" ] && [ -z "$vols" ]; then
    echo "docker: nothing from this project left on the host."
    exit 0
  fi

  echo "docker: left alone by \`make clean\` --"
  [ "$up" = 0 ] || echo "  $up container(s) still running."
  [ -z "$imgs" ] || listing "  $(echo "$imgs" | wc -l | tr -d ' ') built image(s):" "$imgs"
  if [ -n "$imgs" ]; then
    echo ""
    echo "  make clean-docker-images    stops the stack and removes those."
  fi
  report_volumes
  ;;

images)
  # Only tear down if there is something to tear down: compose warns "No resource
  # found to remove" when there is not, and on this path that reads as a problem
  # rather than as the no-op it is.
  if [ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$project" 2>/dev/null)" ] ||
     [ -n "$(docker network ls -q --filter "label=com.docker.compose.project=$project" 2>/dev/null)" ]; then
    scripts/compose/teardown.sh
  fi
  imgs=$(present_images)
  if [ -z "$imgs" ]; then
    echo "no built images from this project on the host."
  else
    # shellcheck disable=SC2086 # names are single tokens by construction
    docker image rm $imgs
  fi
  report_volumes
  ;;

volumes)
  vols=$(present_volumes)
  [ -n "$vols" ] || { echo "no volumes from this project on the host."; exit 0; }

  listing "About to destroy $(echo "$vols" | wc -l | tr -d ' ') volume(s):" "$vols"
  echo ""
  echo "This is the realm itself, not a cache. The domain SID goes with it, so every"
  echo "SID-bearing ACL on every joined file server becomes an orphan, and every"
  echo "enrolled client must be re-enrolled against the realm you provision next."
  echo "deploy/scripts/compose/backup.sh takes a copy; there is no undo here."

  if [ "$yes" = 0 ]; then
    [ -t 0 ] || die "stdin is not a tty; pass --yes to confirm"
    echo ""
    read -r -p "type 'destroy' to proceed: " reply
    [ "$reply" = destroy ] || die "aborted"
  fi

  scripts/compose/teardown.sh -v
  # -v removes what it can see by label; anything left is a volume compose no
  # longer associates with a service, and it is still this project's data.
  left=$(present_volumes)
  if [ -n "$left" ]; then
    # shellcheck disable=SC2086 # names are single tokens by construction
    docker volume rm $left
  fi
  echo "realm destroyed. \`make up\` provisions a new one."
  ;;

*)
  die "usage: clean.sh [report|images|volumes] [--yes]"
  ;;
esac
