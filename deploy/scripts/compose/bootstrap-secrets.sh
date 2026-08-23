#!/bin/bash
# Prepare the host tree `docker compose up` binds into the containers: the
# directories, and the empty files a compose secret needs a source for.
#
# The work itself is not here. `/usr/libexec/kerbridge/prepare-state` does it,
# shipped by kerbridge-config and run by the Debian deployment's postinst too --
# the same bytes, so the two deployments cannot drift about what a directory is
# for or who may read it. This script is the Compose caller: it decides which
# tree, whose it is, and which sources it holds.
#
# Root does it, in a container that lasts one command. Every path below is a
# bind-mount *source* and an unprivileged operator cannot give one the group its
# reader needs -- while the service containers that could are exactly the ones
# hardened with `cap_drop: ALL`, where root is powerless against a file it does
# not own (measured). A throwaway with default capabilities is the one
# thing that can.
#
# secrets/ is split by who produces the file:
#
#   secrets/generated/  what KerBridge writes: realm_admin_password,
#                       svc_kerbridge_broker_password, idp/<name>/bind_password.
#                       Never edit one; the value is in the directory too.
#   secrets/idp/<name>/ what you supply per source: `credential` from that IdP's
#                       portal. A source is a unit here for the same reason it
#                       is one in configs/ -- adding one must not mean editing
#                       compose.yaml.
#   secrets/            what else you supply: acme-dns.env from your DNS
#                       provider, tls/ from your CA.
#
# Nothing writes into both halves, which is what lets the setup service be
# handed secrets/generated/ alone: it holds KDC authority, and an IdP credential
# is an authority in your cloud tenant rather than in this realm.
#
# No password is generated here. `kbsetup realm` draws the realm
# Administrator's on first provision and `kbsetup directory` draws the service
# accounts' with the accounts themselves -- both generate iff absent, and both
# treat the empty file this leaves as absent (`-s`, never `-e`). One generator
# in kerbridge-core, reached from one program.
set -euo pipefail
. "$(dirname "$0")/../lib.sh"
cd "$(dirname "$0")/../.."
# For BROKER_GID, and it is not optional: every directory and file below is
# given that group, and a tree prepared for 10002 while the containers run as
# something else is a deployment where nothing can read its own secret.
# check-secrets.sh reads it the same way, and judges what this wrote.
if [ -f .env ]; then . ./.env; fi

# The two mount points, created here rather than by the daemon. dockerd
# root-creates a missing bind source, and these two are the roots of everything
# below -- a root-owned deploy/state/ is one an operator cannot clear.
mkdir -p state secrets

# The tag compose.yaml pins for the `realm` service's build. compose.ci.yaml
# reuses it -- a CI run renames the container, never the image -- so this one
# name holds for a bench and a test run alike.
IMAGE=kerbridge-realm
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "the $IMAGE image is missing, and it carries the helper that prepares" >&2
  echo "  this tree. Build it with \`docker compose build realm\` from deploy/," >&2
  echo "  or run \`make up\`, which builds before it prepares." >&2
  exit 1
fi

# The source list comes from the config set, because that is what decides it --
# a directory per source under both halves, which is where sync looks for a
# credential and where kbsetup writes a bind password. No config set yet means
# no sources and no `kbsetup directory` run either, so an empty list leaves
# nothing behind.
#
# --entrypoint, because this image has one: it is the realm's, and a command
# given as arguments would reach `kbsetup realm` instead of replacing it. No
# volume of the realm's is mounted either -- the image is the carrier, and this
# container is not that service.
#
# The source list is deliberately unquoted: it is a list of names.
# shellcheck disable=SC2046
docker run --rm \
  -v "$PWD/state:/state" \
  -v "$PWD/secrets:/secrets" \
  --entrypoint /usr/libexec/kerbridge/prepare-state \
  "$IMAGE" \
  compose /state /secrets "$(id -u)" "${BROKER_GID:-10002}" \
  $(kbconfig sources 2>/dev/null || true)
