#!/bin/bash
# Refuse to hand a container a secret whose permissions are wrong.
#
# A compose secret is a bind mount: on Linux the host file's owner and mode
# reach the container unchanged, so these bits are the access control, not
# hygiene. The scripts here already satisfy both rules below -- this exists for
# the files an operator places by hand (a source's credential, acme-dns.env,
# tls/broker.key), where a stray 0644 out of an editor or an scp is invisible
# until something is denied at start.
#
#   1. Nothing under secrets/ may be readable by other, or writable by group.
#      Group *read* is allowed: it is how an unprivileged service reaches its
#      own secret (rule 2), and how an operator shares a host TLS key with the
#      system group that already owns it. Any *.crt is exempt wherever it sits:
#      a certificate is public by construction, and keying the exemption on the
#      property rather than on one path keeps a cert left at an older location
#      from reading as a leak. realm-ca.pem is exempt too, by name:
#      kbmanage-config.sh writes it 0644 on purpose, because a host-run
#      kbmanage reads it as an unprivileged user. It is named rather than
#      covered by a *.pem glob deliberately -- private keys are conventionally
#      .pem as well, so a glob would exempt exactly the file this check exists
#      to catch.
#   2. The secrets an unprivileged container reads must go further and *be*
#      group-readable by BROKER_GID: the broker and sync both run as unprivileged
#      uids and reach their own secret through that group, exactly as they reach
#      the issuer socket. Judged only where the secrets tree carries ownership
#      -- see carries_ownership() below. A bind source that remaps ownership
#      into the container neither needs the group nor can be given it. Off Linux
#      the rule is skipped outright: the remap happens at the VM boundary, where
#      a host-side probe cannot see it, and an unprivileged operator cannot chgrp
#      to a group they are not in.
#
#      A source's credential is judged only once it has content: it arrives from
#      the portal after the deployment is running, and sync skips that source
#      until it does, so refusing the stack over a file not in use yet would fail
#      every fresh deployment. notify_url ships empty too but is judged whatever
#      it holds -- notifying nowhere is a supported deployment, and
#      kerbridge-notify calls EACCES a fault rather than "not configured", so an
#      unreadable empty file is a broker that will not start.
#
# Every mode judged here is the *target's*. A hand-placed secret is often a
# symlink into a path the host already manages, and a symlink is always
# lrwxrwxrwx -- never access control, and never what the container gets. That
# works because a compose `secrets:` entry is a file mount, which dereferences
# when mounted. A *directory* mount does not: the link reaches the container
# unresolved and its target is looked up in the container's filesystem, where a
# host path does not exist. secrets/tls, secrets/idp and secrets/generated/idp
# are all directory mounts, so a symlink under any of them is refused outright --
# check-tls.sh does it for the certificate, rule 3 below for a source's files.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] && . ./.env
GID=${BROKER_GID:-10002}
fail=0

# ls -l's mode string is parsed rather than stat'd: stat's format flags differ
# between GNU and BSD, and this bench is macOS while production is Linux. -L
# dereferences, so a symlinked secret is judged by its target; -d so a directory
# argument reports itself rather than listing what is in it.
mode() { ls -ldL "$1" 2>/dev/null | cut -c1-10; }

# Rule 0, before the globs below, because it decides whether they inspected
# anything: a per-source directory that cannot be listed matches nothing, and
# that is indistinguishable from a source with no files yet -- so without this a
# gate reports success having checked nothing. Listing needs r and x.
# prepare-state creates these 0711 and owned by the operator, because this walk
# is unprivileged; kbsetup's ensure_directory() creates them 0750 root:<daemon
# group> when it gets there first.
for d in secrets/generated/idp/*/ secrets/idp/*/; do
  [ -d "$d" ] || continue
  { [ -r "$d" ] && [ -x "$d" ]; } && continue
  echo "  ${d%/} is $(mode "${d%/}") and uid $(id -u) cannot list it, so nothing"
  echo "    under it was checked -- including the bind password sync starts with."
  echo "    Fix: scripts/compose/bootstrap-secrets.sh, which creates these 0711,"
  echo "    or run this as root."
  fail=1
done

for f in secrets/* secrets/tls/* secrets/generated/* secrets/generated/idp/*/* secrets/idp/*/*; do
  [ -f "$f" ] || continue
  # Rule 3: the two per-source directories reach the container as directories, so
  # a link inside one arrives unresolved and points at nothing there. The mode
  # below would pass, and the failure would be a source that never mirrors.
  case "$f" in
    secrets/idp/* | secrets/generated/idp/*)
      if [ -L "$f" ]; then
        echo "  $f is a symlink (-> $(readlink "$f"))."
        echo "    $(dirname "$(dirname "$f")") is a directory mount, so the link reaches the sync"
        echo "    container unresolved and resolves to nothing there."
        echo "    Fix: copy the file rather than linking it."
        fail=1
        continue
      fi;;
  esac
  case "$f" in *.crt | */realm-ca.pem) continue;; esac
  m=$(mode "$f")
  case "$(echo "$m" | cut -c5-10)" in
    "------" | "r-----") ;;
    *)
      via=""; [ -L "$f" ] && via=" (-> $(readlink "$f"))"
      echo "  $f is $m$via -- readable by other, or writable by group."
      echo "    Fix: chmod 0640 $f"
      fail=1;;
  esac
done

# file:reader, where reader names the container that is denied when this is wrong.
# The per-source pairs are enumerated from disk rather than from configs/: this
# runs before the stack does, and every file under secrets/idp/ and
# secrets/generated/idp/ is one the sync container reads whether or not main.toml
# currently lists that source.
PAIRS="secrets/generated/svc_kerbridge_broker_password:the broker (uid ${BROKER_UID:-10001})
secrets/notify_url:the broker and sync (uids ${BROKER_UID:-10001} and ${SYNC_UID:-10003})"
for f in secrets/generated/idp/*/bind_password secrets/idp/*/credential; do
  [ -f "$f" ] || continue
  PAIRS="$PAIRS
$f:sync (uid ${SYNC_UID:-10003})"
done

# Does this filesystem remember the group a chgrp sets on it? A virtiofs or
# FUSE-backed bind source -- what a Linux VM mounting a host directory gives you
# -- takes the call with exit 0 and leaves the group alone, then remaps ownership
# again on the way into the container, so every accessor sees the file as owned
# by itself and reads it whatever the host-side group says. Measured both ways:
# `chgrp 10002` from the host and from a container each reported success and
# changed nothing, and a container running as 10001:10002 read the 0640 file
# regardless. Rule 2 is then unsatisfiable *and* unnecessary. `kbsetup directory`
# and prepare-state already warn rather than fail on this, and a gate that
# refused what they permit would make the deployment they describe unstartable.
#
# Three outcomes, and only the middle one relaxes anything:
#   exit 0 and the group changed -- ownership is real; judge it.
#   exit 0 and it did not        -- the source is remapping; skip rule 2.
#   non-zero                     -- the kernel refused a chgrp, which only a
#                                   filesystem that stores ownership does; judge it.
# Anything else, a secrets/ this cannot write a probe into included, judges as
# before: refusing a deployment that would have worked is recoverable, starting
# one whose daemons cannot read their credentials is not. The probe is a dotfile,
# so the globs above -- which have already run -- would not match it either way.
carries_ownership() {
  probe=$(mktemp secrets/.owner-probe.XXXXXX 2>/dev/null) || return 0
  chgrp "$GID" "$probe" 2>/dev/null || { rm -f "$probe"; return 0; }
  got=$(ls -lnd "$probe" | awk '{print $4}')
  rm -f "$probe"
  [ "$got" = "$GID" ]
}

# Decided once, and said out loud when it comes out false. A gate that stops
# checking half of what it checks and still prints nothing is the quietest way to
# lose it: a clean run and a half-run have to look different, or the next
# operator reads silence as "the groups were checked and were right".
judge_group=1
if [ "$(uname -s)" != "Linux" ]; then
  judge_group=0
elif ! carries_ownership; then
  judge_group=0
  echo "  Note: secrets/ is on a bind source that does not record the group a chgrp"
  echo "    sets (FUSE, virtiofs, Docker Desktop). Such a source remaps ownership into"
  echo "    the container, so every daemon reads its own secret whatever the group here"
  echo "    says -- the group half of this check was skipped. The modes above still hold."
fi

while IFS= read -r pair; do
  f=${pair%%:*}
  [ "$judge_group" = 1 ] || continue
  # -s, not -f: a source's credential exists empty on a fresh deployment, and its
  # reader skips that source until it has content. notify_url's readers do not --
  # see rule 2.
  case "$f" in
    secrets/notify_url) [ -f "$f" ] || continue;;
    *)                  [ -s "$f" ] || continue;;
  esac
  m=$(mode "$f")
  if [ "$(echo "$m" | cut -c5)" != "r" ] || [ "$(ls -lnL "$f" | awk '{print $4}')" != "$GID" ]; then
    echo "  $f is $m and not owned by group $GID, so ${pair#*:} cannot read it."
    echo "    Fix: chgrp $GID $f && chmod 0640 $f"
    echo "    (or re-run \`docker compose run --rm setup directory\`, which sets this on every run)"
    fail=1
  fi
done <<EOF
$PAIRS
EOF

[ "$fail" = 0 ] || { echo "Refusing to start: fix the secret permissions above."; exit 1; }
