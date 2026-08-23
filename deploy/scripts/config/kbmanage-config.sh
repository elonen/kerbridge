#!/bin/bash
# Everything a host-run `kbmanage` needs, derived from the stack that is already
# running. Writes one file and one link:
#
#   secrets/generated/realm-ca.pem      the realm's own CA, copied out of the
#                                       realm container. The realm creates it at
#                                       provisioning, so a rebuilt realm means a
#                                       new one -- re-run this after any rebuild
#                                       or TLS validation fails. Refreshed in
#                                       place on every run.
#   configs/kbmanage.toml               the CLI's own identity and the two paths
#                                       that differ off-container. Written iff
#                                       absent: it is the operator's to edit once
#                                       it exists, and silently rewriting a
#                                       hand-pointed DC is how a tool ends up
#                                       talking to the wrong directory. Delete it
#                                       to have this regenerate it.
#   ~/.config/kerbridge/configs         a link to this deployment's configs/,
#                                       which is how `kbmanage` and `kbconfig`
#                                       find it with no argument. One link, so a
#                                       host administers one deployment by
#                                       default; --config names any other.
#
# Not a secret-generating step: svc_kerbridge_manage_password comes from
# `kbsetup directory`, which generates it with the account.
#
# Idempotent, and safe as a step of `make up`: an existing file or link is
# reported, not an error.
set -euo pipefail
cd "$(dirname "$0")/../.."
set -a; . ./.env; set +a

: "${AD_DNS_DOMAIN:?}" "${AD_DC_HOSTNAME:?}"
BASE="DC=${AD_DNS_DOMAIN//./,DC=}"
FQDN="${AD_DC_HOSTNAME}.${AD_DNS_DOMAIN}"
OUT="secrets/generated"
CONF="configs/kbmanage.toml"
LINK="${XDG_CONFIG_HOME:-$HOME/.config}/kerbridge/configs"
mkdir -p "$OUT" configs

docker compose cp realm:/run/kerbridge/realm-ca.pem "$OUT/realm-ca.pem" >/dev/null 2>&1 || {
  echo "could not copy the realm CA -- is the realm container running? (make up)" >&2
  exit 1
}
chmod 0644 "$OUT/realm-ca.pem"
echo "refreshed $OUT/realm-ca.pem"

if [ -e "$CONF" ]; then
  echo "$CONF exists -- leaving it alone. Delete it and re-run to regenerate."
else
  cat > "$CONF" <<EOF
# Written by deploy/scripts/config/kbmanage-config.sh from deploy/.env. Yours to edit:
# nothing rewrites this file, so a changed .env needs this one deleted and
# regenerated. \`kbmanage config\` prints what it resolved to.
#
# Everything not here comes from realm.toml beside it. These four are here
# because kbmanage is the one component running outside the containers.
bind_dn = "CN=svc-kerbridge-manage,CN=Users,$BASE"
bind_password_file = "$PWD/$OUT/svc_kerbridge_manage_password"

# localhost, because the realm's certificate names it: the SAN carries
# $FQDN, $AD_DC_HOSTNAME, localhost, 127.0.0.1 and ::1, so a host-run
# binary needs no /etc/hosts entry and no name resolution at all. Point this at
# ldaps://$FQDN:636 instead if you have moved LDAPS off loopback
# (LDAPS_BIND) and are reaching the DC over the network.
#
# Only IPv4 loopback is published by default, so ldaps://[::1] is in the
# certificate but has nothing listening behind it.
ldap_url = "ldaps://localhost:636"

# The copy taken out of the realm container above. realm.toml's own
# ldap_ca_file names the path inside it, which nothing on this host can read.
ldap_ca_file = "$PWD/$OUT/realm-ca.pem"
EOF
  # 0644, not 0600 like a secret: compose mounts this directory into the realm
  # container, which is root with cap_drop ALL -- root without DAC_OVERRIDE
  # reads only what its own uid may, and issuerd loads every file here. Nothing
  # in it is secret; the password *file* it names is the 0600 one.
  chmod 0644 "$CONF"
  echo "wrote $CONF"
fi

# The link is what makes `kbmanage` with no argument mean *this* deployment.
# Never replaced silently: pointing it somewhere else is a deliberate act, and a
# script that quietly re-aimed it would be the "why is it talking to that DC"
# bug this whole lookup is shaped to avoid.
mkdir -p "$(dirname "$LINK")"
# Compared as resolved paths: $PWD is logical, and a checkout reached through a
# symlinked home would otherwise never match its own link.
here=$(cd configs && pwd -P)
if [ -e "$LINK" ] || [ -L "$LINK" ]; then
  current=$(cd "$LINK" 2>/dev/null && pwd -P) || current="(unreadable)"
  if [ "$current" = "$here" ]; then
    echo "$LINK already points here"
  else
    echo "$LINK points at $current, not $here -- leaving it alone." >&2
    echo "  Remove it and re-run to switch, or use: kbmanage --config $PWD/configs" >&2
  fi
else
  ln -s "$PWD/configs" "$LINK"
  echo "linked $LINK -> $PWD/configs"
fi

[ -s "$OUT/svc_kerbridge_manage_password" ] ||
  echo "note: $OUT/svc_kerbridge_manage_password is missing -- run \`make directory\`" >&2

