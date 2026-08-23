#!/bin/bash
# Put a backup.sh tarball back, onto a host whose stack is down.
#
# Restore is the destructive half, so every check refuses rather than merges: an
# existing config file is not overwritten, a non-empty volume is not written
# into, and a tarball from another realm is not unpacked over this one. --force
# lifts the first two; the realm check has no override, because two deployments
# are never something to reconcile file by file.
#
# The realm container has the last word either way -- its entrypoint refuses to
# start when .env's realm disagrees with the provisioned database -- but a
# refusal here names the mismatch before anything has been written.
#
# Volumes are recreated with the two labels Compose keys on
# (com.docker.compose.project and .volume). Measured: Compose then adopts them
# silently, where an unlabeled volume of the right name draws a "was not
# created by Docker Compose" warning on every up.
#
# On extracting a hostile tarball: the two escapes worth naming are a `../`
# member and a symlink written through, and both tars refuse them already --
# measured 2026-07-28 against a purpose-built tarball. GNU tar 1.35 (the pinned
# debian image, and what a Linux deployment host has) answers `Member name
# contains '..'` and `Cannot open: Not a directory`, exit 2; macOS bsdtar answers
# `Path contains '..'` and `Cannot extract through symlink`, exit 1. Under the
# `set -e` above either one aborts the restore before a single file is copied
# into deploy/. No screening pass is added here on top of that, and it would not
# be the real defense anyway: this tarball carries the KDC keys and every service
# password, and a host that restores one it does not trust has already adopted
# the attacker's realm. The check that matters is where the file came from.
set -euo pipefail
# Resolved before the cd, for the same reason backup.sh does it: this runs from
# deploy/, and a relative input path means the directory the operator typed it in.
origin=$PWD
cd "$(dirname "$0")/../.."

usage() {
  cat >&2 <<'EOF'
usage: restore.sh IN.tgz [--config-only] [--force] [--yes]
       restore.sh -      [--config-only] [--force] --yes    read from stdin

  --config-only  restore .env, configs/, secrets/ and terraform state only,
                 leaving the Docker volumes untouched.
  --force        overwrite config files that already exist, and wipe volumes
                 that already have contents. Named individually before it runs.
  --yes          skip the confirmation prompt. Required when stdin is not a tty.
EOF
}

say() { echo "$@" >&2; }
die() { echo "restore: $*" >&2; exit 1; }

in=
config_only=0
force=0
yes=0
while [ $# -gt 0 ]; do
  case "$1" in
    --config-only) config_only=1 ;;
    --force) force=1 ;;
    --yes) yes=1 ;;
    -h | --help) usage; exit 0 ;;
    -) [ -z "$in" ] || die "one input path only"; in=- ;;
    -*) usage; die "unknown option: $1" ;;
    *) [ -z "$in" ] || die "one input path only"; in=$1 ;;
  esac
  shift
done
[ -n "$in" ] || { usage; exit 1; }
case "$in" in - | /*) ;; *) in="$origin/$in" ;; esac
[ "$in" = - ] || [ -f "$in" ] || die "$in does not exist"

project=$(sed -n 's/^name:[[:space:]]*\([A-Za-z0-9_.-][A-Za-z0-9_.-]*\).*/\1/p' compose.yaml | head -1)
[ -n "$project" ] || die "compose.yaml declares no project name"
image=$(sed -n 's/^FROM \(debian@sha256:[0-9a-f]*\).*/\1/p' realm/Dockerfile | head -1)
[ -n "$image" ] || die "no pinned debian digest in realm/Dockerfile"

# Created and stopped, not just running: a stopped container still pins the
# volume it was created with, and coming back up onto half-restored state is
# exactly what this refuses to allow.
existing=$(docker ps -a --format '{{.Names}}' --filter "label=com.docker.compose.project=$project")
if [ -n "$existing" ]; then
  say "Refusing: the stack's containers still exist here."
  echo "$existing" | sed 's/^/  /' >&2
  say ""
  say "  make down     # then re-run this"
  exit 1
fi

root=$(cd .. && pwd)
mkdir -p "$root/.local-tmp"
stage=$(mktemp -d "$root/.local-tmp/restore.XXXXXX")
trap 'rm -rf "$stage"' EXIT

if [ "$in" = - ]; then tar -xzf - -C "$stage"; else tar -xzf "$in" -C "$stage"; fi
[ -f "$stage/MANIFEST" ] || die "no MANIFEST inside -- not a backup.sh tarball"
mf() { sed -n "s/^$1=//p" "$stage/MANIFEST"; }
[ "$(mf format)" = "kerbridge-backup-1" ] || die "unknown backup format '$(mf format)'"

# A config-only tarball has no volumes/ to restore, whatever the flags say.
if [ "$(mf scope)" != full ]; then
  [ "$config_only" = 1 ] || say "note: this is a config-only backup; volumes are not in it"
  config_only=1
fi

# The one check with no --force. A realm mismatch means the tarball belongs to a
# different deployment, and every password in it names accounts this domain does
# not have.
#
# Sourced, not grepped: backup.sh writes the manifest's realm by sourcing .env,
# so reading it back any other way compares two different parsings of one file.
# `AD_REALM="EXAMPLE.SITE"` is what that costs -- the manifest holds it bare and
# a raw read holds it quoted, a mismatch with no way past it.
if [ -f .env ]; then
  cur=$(. ./.env; printf '%s' "${AD_REALM:-}")
  want=$(mf realm)
  if [ -n "$cur" ] && [ -n "$want" ] && [ "$cur" != "$want" ]; then
    die "this backup is for realm $want, but .env here says $cur"
  fi
fi

# -type l as well as -type f: `cp -pR` recreates a symlink member as a symlink,
# and a listing that only counted regular files would copy one in without ever
# naming it -- including over a path that already exists here, which is the one
# thing this refuses to do silently.
conflicts=
while IFS= read -r p; do
  if [ -e "$p" ] || [ -L "$p" ]; then conflicts="$conflicts $p"; fi
done < <(cd "$stage/config" && find . \( -type f -o -type l \) | sed 's|^\./||')

vols=
volconflicts=
if [ "$config_only" = 0 ]; then
  for tarf in "$stage"/volumes/*.tar; do
    [ -e "$tarf" ] || continue
    short=$(basename "$tarf" .tar)
    vols="$vols $short"
    vol="${project}_${short}"
    docker volume inspect "$vol" > /dev/null 2>&1 || continue
    if [ -n "$(docker run --rm -v "$vol:/v:ro" "$image" sh -c 'ls -A /v | head -1')" ]; then
      volconflicts="$volconflicts $vol"
    fi
  done
fi

say "backup: $(mf realm) from $(mf host), taken $(mf created), git $(mf git_rev)"
say ""
say "will restore into $PWD:"
(cd "$stage/config" && find . \( -type f -o -type l \) | sed 's|^\./|  config  |') >&2
for short in $vols; do say "  volume  ${project}_${short}"; done

if [ -n "$conflicts$volconflicts" ]; then
  say ""
  if [ "$force" = 0 ]; then
    say "Refusing: these already exist here, and restore does not merge."
    for p in $conflicts; do say "  $p"; done
    for v in $volconflicts; do say "  volume $v (not empty)"; done
    say ""
    say "Move them aside, or re-run with --force to overwrite each one."
    exit 1
  fi
  say "--force: overwriting"
  for p in $conflicts; do say "  $p"; done
  for v in $volconflicts; do say "  volume $v -- contents wiped first"; done
fi

if [ "$yes" = 0 ]; then
  [ -t 0 ] || die "stdin is not a tty; pass --yes to confirm"
  say ""
  read -r -p "type 'restore' to proceed: " reply
  [ "$reply" = restore ] || die "aborted"
fi

say ""
cp -pR "$stage/config/." .
say "config restored"

for short in $vols; do
  vol="${project}_${short}"
  if ! docker volume inspect "$vol" > /dev/null 2>&1; then
    docker volume create \
      --label com.docker.compose.project="$project" \
      --label com.docker.compose.volume="$short" "$vol" > /dev/null
  fi
  case " $volconflicts " in
    *" $vol "*) docker run --rm -v "$vol:/v" "$image" \
      sh -c 'rm -rf -- /v/* /v/.[!.]* /v/..?* 2>/dev/null; true' ;;
  esac
  # SYS_ADMIN to write the security.NTACL xattr back; without it Samba's ACLs
  # would land as nothing and SYSVOL would come up unprotected.
  docker run --rm --cap-add SYS_ADMIN \
    -v "$vol:/v" -v "$stage/volumes:/in:ro" "$image" \
    tar -xf "/in/$short.tar" --numeric-owner --xattrs --xattrs-include='*' -p -C /v ||
    die "extracting $short.tar into $vol failed"
  say "volume $vol restored"
done

ns=
case " $vols " in *" m1-samba "*) ns=" NAS=1" ;; esac
say ""
say "Next:"
say "  make check-secrets            # confirm the restored modes are what compose needs"
say "  make up$ns"
say "  make kbmanage-config          # refresh the host-run kbmanage's CA and config"
