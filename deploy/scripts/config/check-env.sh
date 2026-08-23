#!/bin/bash
# .env must exist, and must agree with itself and with the config set.
#
# What is left in .env is the deployment shape: what compose interpolates, and
# what the scripts here source as shell. The settings the services read are in
# configs/*.toml, and `dist/kbconfig check` is what judges those -- shell has no
# business parsing TOML.
#
# So this file is about the handful of values that exist on BOTH sides, where
# each side has its own copy and a disagreement is silent. AD_DNS_DOMAIN is
# AD_REALM lowercased, because provisioning is given the realm and derives the
# zone from it. AD_REALM is realm.toml's `realm`, because compose passes the
# first to the entrypoint and every binary reads the second. Change one alone and
# the bootstrap creates accounts under a base the broker never searches; every
# login then fails with nothing in either file looking wrong.
#
# It also decides, once, that the realm identity is the operator's own -- before
# the first `make up` bakes it into a database that only a volume delete can
# change.
#
# Not here: the shape of a single value. Whether the flat name is flat and fits
# in fifteen characters, whether dc_hostname is short, and whether ldap_url names
# a host the realm's certificate covers are all decidable from
# configs/realm.toml alone, so they belong to `kbconfig check` -- which the
# Debian path runs and this Compose-only file never could. See
# crates/kerbridge-core/src/config/mod.rs @ realm_shape.
set -euo pipefail
. "$(dirname "$0")/../lib.sh"
cd "$(dirname "$0")/../.."

[ -f .env ] || {
  echo "deploy/.env is missing: cp .env.example .env, then review the realm identity --"
  echo "it is baked into the database at provisioning and cannot be changed afterwards."
  exit 1
}

# The config set, which compose mounts into every container at /etc/kerbridge.
# Existence only: whether the files are *right* is `dist/kbconfig check`'s
# question, and only the two-sided values below are this one's. Caught here
# rather than at `up` because a missing mount source is a container that exits a
# second after start, reported as "container kerbridge-realm is unhealthy".
[ -f configs/main.toml ] || {
  echo "deploy/configs/main.toml is missing. Copy the template set and edit it:"
  echo "  for f in configs/*.toml.example; do cp \"\$f\" \"\${f%.example}\"; done"
  echo "Then check it with: dist/kbconfig --config deploy/configs check"
  exit 1
}

# .env alone, unlike the scripts that read bench.env first: nothing this file
# judges is a bench fixture, and KB_ALLOW_EXAMPLE_REALM must never come from a
# tracked file that loads unconditionally -- a `1` in bench.env would disarm the
# gate for an operator who never opened it.
. ./.env
: "${AD_REALM:?AD_REALM is unset in deploy/.env}"
: "${AD_DNS_DOMAIN:?AD_DNS_DOMAIN is unset in deploy/.env}"
: "${AD_NETBIOS_DOMAIN:?AD_NETBIOS_DOMAIN is unset in deploy/.env}"
: "${AD_DC_HOSTNAME:?AD_DC_HOSTNAME is unset in deploy/.env}"

# `tr` rather than ${x,,}: this one runs on the operator's host, and macOS ships
# bash 3.2, where the substitution is a parse error rather than a fallback.
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# The realm identity .env.example ships is the documented example, and it is the
# one group of values a later edit cannot correct: the first `make up` bakes them
# into the Samba database, and the entrypoint then refuses to start on any
# configuration that disagrees with what it provisioned. Fixing a forgotten edit
# means deleting the realm volume, and with it the domain SID and every
# filesystem ACL that carries it.
#
# So this fires only while there is nothing to lose. example.site is not merely a
# placeholder -- it is what this repo's own bench runs on (CLAUDE.md
# @ Conventions) -- and once a database exists the identity is settled and the
# entrypoint's durable-state guard owns it. Gating past that point would block
# `make stack` on a deployment that is working as provisioned.
#
# The volume name is project + volume, and COMPOSE_PROJECT_NAME is deliberately
# absent from .env (see .env.example), so `kerbridge_samba` is not a guess. A
# host with no reachable Docker answers the same as a fresh clone, which is the
# safe way round: the gate stays on.
provisioned() { docker volume inspect kerbridge_samba >/dev/null 2>&1; }

# The one way past it, for a bench that means example.site -- this repo's own
# docs, its certificates and its DNS are all written against that realm, so
# development wants the value the gate is there to catch. Read from the
# environment as well as from .env, which is both forms at once: a line in .env
# is a bench's standing decision, and `KB_ALLOW_EXAMPLE_REALM=1 make up` (or
# `make up KB_ALLOW_EXAMPLE_REALM=1` -- make exports command-line variables) is
# one deployment's. .env.example leaves it commented out, so setting it in the
# environment of a deployment that never edited that line still works.
#
# It announces itself rather than passing quietly, and only when it actually let
# something through: the gate exists because the identity cannot be corrected
# afterwards, and a silent skip would leave that reasoning nowhere the next time
# this realm is provisioned. Once the volume exists there is nothing to skip, so
# a bench that keeps the line in .env stops being told.
#
# Set and non-empty is yes, and `0` is not special. compose.yaml interpolates the
# same variable into `kbsetup realm`'s argv with `${KB_ALLOW_EXAMPLE_REALM:+...}`,
# which has no way to treat a `0` as no -- and one decision judged by two gates
# has to mean the same thing to both, or `docker compose up` run around make does
# the opposite of what the operator wrote.
allow_example() {
  [ -n "${KB_ALLOW_EXAMPLE_REALM:-}" ]
}

example=0
found=""
still() {  # name  value
  case "$(lower "$2")" in
    *example.site*|example) found="$found  $1=$2
"; example=1 ;;
  esac
}
if ! provisioned; then
  still AD_REALM          "$AD_REALM"
  still AD_DNS_DOMAIN     "$AD_DNS_DOMAIN"
  still AD_NETBIOS_DOMAIN "${AD_NETBIOS_DOMAIN:-}"
  still BROKER_FQDN       "${BROKER_FQDN:-}"
fi

if [ "$example" = 1 ] && allow_example; then
  echo "note: KB_ALLOW_EXAMPLE_REALM=$KB_ALLOW_EXAMPLE_REALM -- provisioning the documented"
  echo "      example realm on purpose:"
  printf '%s' "$found"
  echo "      It is baked in by this \`make up\` and unchangeable: a different realm later"
  echo "      means deleting the realm volume, its domain SID and every filesystem ACL"
  echo "      carrying it."
  example=0
fi

[ "$example" = 0 ] || {
  printf '%s' "$found"
  echo "deploy/.env still names the documented example realm, and nothing is provisioned yet."
  echo "  These get baked into the Samba database by this \`make up\` and cannot be changed"
  echo "  afterwards -- correcting one later destroys the domain SID and every filesystem"
  echo "  ACL holding it. SETUP.md section 1 is the decision."
  echo "  A development bench that means example.site: KB_ALLOW_EXAMPLE_REALM=1 make up,"
  echo "  or set it in deploy/.env section 4. deploy/README.md section The example-realm gate."
  exit 1
}

# AD_DNS_DOMAIN is not a second setting either. Provisioning is given --realm and
# derives the zone from it, so the zone the DC serves is AD_REALM lowercased,
# always. Everything else is built from AD_DNS_DOMAIN instead -- the DC's FQDN
# and its LDAPS SAN, the compose network aliases and extra_hosts, the three DNs
# below, sync's KB_AD_DNS_DOMAIN -- so a disagreement points the whole stack at a
# zone nothing serves. The entrypoint's durable-state guard compares realm,
# workgroup and netbios name only; AD_DNS_DOMAIN is not in it, and no later step
# looks either.
zone="$(lower "$AD_REALM")"
[ "$AD_DNS_DOMAIN" = "$zone" ] || {
  echo "AD_DNS_DOMAIN=$AD_DNS_DOMAIN is not AD_REALM=$AD_REALM lowercased."
  echo "  Samba derives the DNS zone from the realm at provisioning, so the zone will be"
  echo "  $zone whatever this says."
  echo "  Set AD_DNS_DOMAIN=$zone, or change AD_REALM if it is the domain that is wrong."
  exit 1
}

# The realm identity, stated on both sides. `kbsetup realm` provisions from
# realm.toml alone, so .env is no longer what the database is built from -- but
# compose.yaml's hostname and network aliases, the scripts here, and the member's
# /etc/hosts are all still built from it. A pair that drifts points the stack at a
# name the DC does not answer to, with each side reading correctly on its own.
config_realm=$(kbconfig get realm.realm)
[ "$AD_REALM" = "$config_realm" ] || {
  echo "AD_REALM=$AD_REALM but configs/realm.toml says realm = \"$config_realm\"."
  echo "  The database is provisioned from the second and this deployment's names are"
  echo "  built from the first, so the stack would look for a realm the KDC does not"
  echo "  serve. Make them the same."
  exit 1
}

# The flat name, on both sides for the same reason -- and this one is baked in.
# realm.toml need not state it: absent, it derives as the realm's first label,
# which is what makes the shipped pair agree without either side saying so.
config_netbios=$(kbconfig get realm.netbios_domain)
[ "$AD_NETBIOS_DOMAIN" = "$config_netbios" ] || {
  echo "AD_NETBIOS_DOMAIN=$AD_NETBIOS_DOMAIN but the config set resolves"
  echo "  realm.netbios_domain to \"$config_netbios\"."
  echo "  The second is what provisioning bakes into the database, and it cannot be"
  echo "  corrected afterwards. State netbios_domain in configs/realm.toml, or make"
  echo "  .env agree with what it derives from the realm."
  exit 1
}

# The DC's short name, on both sides. compose.yaml's hostname and network
# aliases, the member's /etc/hosts and BROKER_FQDN are built from .env's copy;
# the config set's is what `kbsetup realm` names the host and what the LDAPS
# certificate is issued for. A pair that drifts points the stack at a name the
# DC does not answer to, and the certificate does not cover.
#
# realm.toml need not state it: absent, it derives as ldap_url's first label,
# which is what makes the shipped pair agree without either side saying so. An
# ldap_url naming an address rather than a name is the case where it has to be
# stated -- realm.toml says so where the key is.
config_dc_hostname=$(kbconfig get realm.dc_hostname)
[ "$AD_DC_HOSTNAME" = "$config_dc_hostname" ] || {
  echo "AD_DC_HOSTNAME=$AD_DC_HOSTNAME but the config set resolves realm.dc_hostname"
  echo "  to \"$config_dc_hostname\"."
  echo "  The second is the name provisioning gives the DC and issues its LDAPS"
  echo "  certificate for; the first is what compose calls the container and what the"
  echo "  member resolves. State dc_hostname in configs/realm.toml, or make .env agree"
  echo "  with what it derives from ldap_url."
  exit 1
}

# Two settings that moved into realm.toml's [provision] group when the entrypoint
# became `kbsetup realm`. A value left behind in .env is now read by nothing, and
# the symptom is a realm that forwards no DNS, or an RPC range a firewall was
# opened for and Samba never uses -- neither of which points back at this file.
# Compared rather than merely refused, so the shipped defaults stay silent and
# only a real disagreement stops the deployment.
for moved in AD_DNS_FORWARDER:dns_forwarder AD_RPC_PORT_RANGE:rpc_port_range; do
  var=${moved%%:*}
  key=${moved#*:}
  # Unset or empty is the migrated state and says nothing; only a value that
  # disagrees with the config set is a deployment about to lose a setting.
  [ -n "${!var:-}" ] || continue
  [ "${!var}" = "$(kbconfig get "realm.provision.$key")" ] || {
    echo "$var=${!var} in deploy/.env, but nothing reads it any more."
    echo "  It moved to configs/realm.toml, under [provision], as $key -- the realm is"
    echo "  provisioned from the config set now. Set it there and remove it here."
    exit 1
  }
done

# Caddy cannot read TOML: BROKER_UPSTREAM is compose's own copy of the address
# the broker binds. A disagreement is a 502 on every ticket, with both files
# looking right. The loopback rule itself lives in the broker's parser.
upstream=${BROKER_LISTEN:-127.0.0.1:8080}
config_listen=$(kbconfig get broker.listen)
[ "$upstream" = "$config_listen" ] || {
  echo "BROKER_LISTEN=$upstream but the broker's effective listen is \"$config_listen\"."
  echo "  .env's copy is what Caddy proxies to and the file's is what the broker binds,"
  echo "  so this is a 502 on every ticket exchange. Make them the same."
  exit 1
}

# acme-dns is what .env.example ships, because it is the strategy a real
# deployment behind a LAN address actually uses -- but it needs two values nothing
# can default for you, and an unset one does not fail where you are looking. Caddy
# with no provider block has no DNS-01 solver at all, so the certificate simply
# never issues: `make up` waits out READY_TIMEOUT and reports an endpoint that is
# not serving, with nothing in .env looking wrong. Refuse here and name the
# settings instead.
if [ "${TLS_STRATEGY:-}" = "acme-dns" ] && [ -z "${ACME_DNS_PROVIDER:-}" ]; then
  echo "TLS_STRATEGY=acme-dns but ACME_DNS_PROVIDER is empty."
  echo "  Caddy would have no DNS-01 solver, and the certificate would never issue."
  echo "  Set ACME_DNS_PROVIDER to your DNS module's block (.env.example shows the"
  echo "  route53 form), put its credentials in secrets/acme-dns.env, and check that"
  echo "  CADDY_DNS_MODULE names your provider -- it is a build arg, so changing it"
  echo "  needs \`docker compose build caddy\`."
  echo "  Supplying your own certificate instead? TLS_STRATEGY=external."
  exit 1
fi
