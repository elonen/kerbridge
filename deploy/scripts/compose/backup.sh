#!/bin/bash
# One tarball holding everything a deployment cannot regenerate.
#
# Two kinds of state, kept apart inside it:
#
#   config/   host-side files -- .env, configs/, secrets/, terraform's tfvars
#             and state. Small, gitignored, and nothing here can re-derive them:
#             the passwords in secrets/generated/ are the ones the provisioned
#             domain actually has (`kbsetup realm`: generated iff absent, never
#             rotated), the Graph client secret is shown by the portal exactly
#             once, and
#             losing terraform state means terraform no longer owns the Entra
#             objects it created. configs/ is the deployment's own settings, and
#             a realm restored without them is a realm nothing knows how to
#             serve.
#   volumes/  the durable Docker volumes -- domain SID, KDC keys, the
#             directory, SYSVOL, Caddy's issued certificate.
#
# Refuses to run while the stack is up, and does not stop it for you. Samba
# writes its TDB and LDB files continuously, and a tar taken across them is torn
# in a way nothing notices until the restore. `make down` first, deliberately.
# --config-only skips the volumes and is the one mode that may run on a live
# stack, because those files are static.
#
# Volume tars carry --xattrs for a measured reason: Samba keeps NT ACLs in the
# security.NTACL extended attribute, and a tar without that flag stores none of
# them -- SYSVOL would restore with its permissions gone and nothing would say so.
#
# Named volumes only. If a deployment ever bind-mounts Samba state from
# KERBRIDGE_STATE_DIR (deploy/README.md, "Development bench versus production"),
# those paths are not discoverable by label and this backs up none of them.
#
# The result carries the domain administrator password, the KDC keys, the TLS
# private key and the sync credential -- the whole authority of the deployment
# in one file. It is written 0600, and `-` as the output path writes to stdout,
# so piping into age or gpg needs no plaintext copy on disk.
set -euo pipefail
# Before anything is created, not after. A `chmod 0600 "$out"` at the end leaves
# the tarball at the caller's umask -- 0644 on a stock login -- for as long as
# the tar takes to write: minutes of a world-readable file holding the KDC keys,
# on exactly the schedule a cron backup makes predictable. This covers the
# staging tree too.
umask 077
# Every script here works from deploy/, so a relative output path has to be
# resolved against the caller's directory first -- otherwise `backup.sh out.tgz`
# from the repo root writes into deploy/ without saying so.
origin=$PWD
cd "$(dirname "$0")/../.."

usage() {
  cat >&2 <<'EOF'
usage: backup.sh OUT.tgz [--config-only]
       backup.sh -       [--config-only]     write the tarball to stdout

  --config-only  .env, configs/, secrets/ and terraform state only, skipping
                 the Docker volumes. The only mode that may run while the stack
                 is up.
EOF
}

# Everything progress-related goes to stderr, so `backup.sh -` is a clean pipe.
say() { echo "$@" >&2; }
die() { echo "backup: $*" >&2; exit 1; }

out=
config_only=0
while [ $# -gt 0 ]; do
  case "$1" in
    --config-only) config_only=1 ;;
    -h | --help) usage; exit 0 ;;
    -) [ -z "$out" ] || die "one output path only"; out=- ;;
    -*) usage; die "unknown option: $1" ;;
    *) [ -z "$out" ] || die "one output path only"; out=$1 ;;
  esac
  shift
done
[ -n "$out" ] || { usage; exit 1; }
case "$out" in - | /*) ;; *) out="$origin/$out" ;; esac
[ "$out" = - ] || [ ! -e "$out" ] ||
  die "$out exists -- refusing to overwrite a backup. Remove it or name another file."

# Both read from the file that defines them rather than restated here: compose.yaml
# names the project, and its volumes are ${project}_*; realm/Dockerfile pins the
# Debian digest, so the tar reading a volume is from the same build as the Samba
# that wrote it.
project=$(sed -n 's/^name:[[:space:]]*\([A-Za-z0-9_.-][A-Za-z0-9_.-]*\).*/\1/p' compose.yaml | head -1)
[ -n "$project" ] || die "compose.yaml declares no project name"
image=$(sed -n 's/^FROM \(debian@sha256:[0-9a-f]*\).*/\1/p' realm/Dockerfile | head -1)
[ -n "$image" ] || die "no pinned debian digest in realm/Dockerfile"

vols=
if [ "$config_only" = 0 ]; then
  running=$(docker ps --format '{{.Names}}' --filter "label=com.docker.compose.project=$project")
  if [ -n "$running" ]; then
    say "Refusing: a tar over a live Samba database is torn, and these are running:"
    echo "$running" | sed 's/^/  /' >&2
    say ""
    say "  make down                      # then re-run this"
    say "  backup.sh $out --config-only   # or skip the volumes, which is safe while up"
    exit 1
  fi
  # Discovered by label rather than listed here, so the example member's m1-*
  # come along when NAS=1 created them and a volume added later is not silently
  # left out. sock is excluded: both things in it are recreated on every start
  # -- the issuer socket by issuerd, the realm CA by `kbsetup realm`.
  vols=$(docker volume ls -q --filter "label=com.docker.compose.project=$project" |
    grep -v "^${project}_sock$" || true)
  [ -n "$vols" ] || say "note: no ${project}_* volumes exist -- this will be config only"
fi

root=$(cd .. && pwd)
mkdir -p "$root/.local-tmp"
stage=$(mktemp -d "$root/.local-tmp/backup.XXXXXX")
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/config" "$stage/volumes"

# secrets/ wholesale rather than by name: every file under it is either
# non-regenerable or trivially small, and copying the tree means a secret added
# later is not missing from every backup taken after it. The terraform recipes
# are by name, because .terraform/ is provider binaries that `terraform init`
# fetches again.
copy() { # path relative to deploy/
  [ -e "$1" ] || return 0
  mkdir -p "$stage/config/$(dirname "$1")"
  cp -pR "$1" "$stage/config/$1"
  say "  config/$1"
}

say "collecting:"
copy .env
# Every *.toml and no more: the committed *.toml.example set and the .gitignore
# beside them come from the repository, and a restore that laid its own copies
# over a checkout would collide with files git already provides. The glob is
# what keeps a source added later from being missing here.
for f in configs/*.toml; do
  copy "$f"
done
copy secrets
# Two things. The audit trail (state/*-audit), which is the reason this line is
# not optional: it is the only record of who was granted which machine and who
# was given an account, and nothing regenerates it. And the notifier's
# last-notified record, which *is* regenerable and is here anyway because
# restoring without it re-sends every outstanding event -- exactly the flood the
# record exists to prevent, arriving at the moment an operator is already busy.
copy state
# One recipe directory per cloud IdP: a provider added later is backed up
# without editing this list.
for f in terraform/*/terraform.tfvars terraform/*/*.auto.tfvars \
  terraform/*/terraform.tfstate terraform/*/terraform.tfstate.backup \
  terraform/*/.terraform.lock.hcl; do
  copy "$f"
done

for vol in $vols; do
  short=${vol#"${project}_"}
  say "  volumes/$short.tar"
  # SYS_ADMIN to read the security.* xattr namespace, the same capability the
  # realm container needs to write it.
  errs=$(docker run --rm --cap-add SYS_ADMIN \
    -v "$vol:/v:ro" -v "$stage/volumes:/out" "$image" \
    tar -cf "/out/$short.tar" --numeric-owner --xattrs --xattrs-include='*' -C /v . 2>&1) ||
    die "tar of $vol failed: $errs"
  # tar names every socket it skips; those are runtime state by definition.
  errs=$(echo "$errs" | grep -v 'socket ignored$' || true)
  if [ -n "$errs" ]; then echo "$errs" | sed 's/^/    /' >&2; fi
done

[ -f .env ] && . ./.env
{
  echo "format=kerbridge-backup-1"
  echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host=$(hostname)"
  echo "git_rev=$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo "project=$project"
  echo "scope=$([ "$config_only" = 1 ] && echo config-only || echo full)"
  echo "realm=${AD_REALM:-}"
  echo "netbios=${AD_NETBIOS_DOMAIN:-}"
  echo "dns_domain=${AD_DNS_DOMAIN:-}"
  echo "volumes=$(echo "$vols" | tr '\n' ' ')"
} > "$stage/MANIFEST"

# COPYFILE_DISABLE keeps macOS tar from adding ._ AppleDouble members, which the
# GNU tar on the deployment host would restore as stray files.
if [ "$out" = - ]; then
  COPYFILE_DISABLE=1 tar -czf - -C "$stage" .
else
  COPYFILE_DISABLE=1 tar -czf "$out" -C "$stage" .
  # The umask above already did this; kept so the mode is stated where the file
  # is written, and so a caller who sources this with a looser umask set later
  # still ends up at 0600.
  chmod 0600 "$out"
  say ""
  say "wrote $out ($(du -h "$out" | cut -f1)), mode 0600"
fi

say ""
say "This file is the deployment's authority in one place: the realm's account"
say "passwords, the TLS private key, the sync credential -- and in a full backup"
say "the KDC keys themselves. Encrypt it at rest, and delete any copy you no"
say "longer need."
