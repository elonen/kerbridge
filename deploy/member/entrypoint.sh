#!/bin/bash
# Member (NAS) entrypoint: render config from the realm identity, join the
# domain once, then supervise smbd + winbindd.
#
# The share ACL is NOT applied here. It is keyed by the domain-local group's
# gid, which winbind can only resolve once that group exists -- and the group is
# directory state seeded after this container is up. seed-demo.sh applies it.
# Until then smbd serves the share but `valid users` denies everyone, which is
# the correct closed default.
set -euo pipefail

: "${AD_REALM:?AD_REALM is required}"
: "${AD_DNS_DOMAIN:?AD_DNS_DOMAIN is required}"
: "${AD_NETBIOS_DOMAIN:?AD_NETBIOS_DOMAIN is required}"
: "${NAS_HOSTNAME:?NAS_HOSTNAME is required}"
REALM_ADMIN_PASSWORD_FILE=${REALM_ADMIN_PASSWORD_FILE:-/etc/kerbridge.secrets/generated/realm_admin_password}
NETBIOS_NAME=${NAS_HOSTNAME^^}

log() { echo "[nas] $*"; }
die() { echo "[nas] FATAL: $*" >&2; exit 1; }

# krb5.conf: realm plus SRV-based KDC discovery through the AD DNS this member's
# resolver points at (the DC).
cat > /etc/krb5.conf <<EOF
[libdefaults]
    default_realm = ${AD_REALM}
    dns_lookup_realm = false
    dns_lookup_kdc = true
EOF

# smb.conf: a security=ADS member with deterministic RID id mapping and a single
# share reachable only through the domain-local group. `secrets and keytab` is
# the join config the joined-nas spike measured; the keytab lands in /etc on the
# writable rootfs (read-only rootfs hardening is deferred).
cat > /etc/samba/smb.conf <<EOF
[global]
    netbios name = ${NETBIOS_NAME}
    security = ADS
    realm = ${AD_REALM}
    workgroup = ${AD_NETBIOS_DOMAIN}

    kerberos method = secrets and keytab

    # Default backend for BUILTIN and any non-realm SIDs (member-local).
    idmap config * : backend = tdb
    idmap config * : range = 100000-199999
    # Deterministic, stateless RID mapping for the realm. Must be identical on
    # every member that needs to agree on numeric ids.
    idmap config ${AD_NETBIOS_DOMAIN} : backend = rid
    idmap config ${AD_NETBIOS_DOMAIN} : range = 1000000-1999999

    template shell = /sbin/nologin

    disable netbios = yes
    smb ports = 445

[share]
    path = /srv/share
    read only = no
    valid users = @"${AD_NETBIOS_DOMAIN}\\nas-share-rw"
EOF

# NSS: resolve domain users and groups through winbind, so `id EXAMPLE\alice`
# and the share ACL's group -> gid both work.
sed -i -E 's/^(passwd:.*files)( .*)?$/\1 winbind/; s/^(group:.*files)( .*)?$/\1 winbind/' /etc/nsswitch.conf

# Join once. The machine account in secrets.tdb (durable volume) is what lets a
# restart skip the rejoin; testjoin is the cheap idempotency check.
if net ads testjoin >/dev/null 2>&1; then
  log "already joined to ${AD_REALM}"
else
  # Present is not the same as readable: a compose secret is a bind mount, so on
  # Linux the host file's owner and mode reach the container unchanged, and this
  # container is root with cap_drop: ALL -- root without DAC_OVERRIDE, which can
  # read only what it owns. Docker Desktop remaps ownership, so a macOS bench
  # never meets it.
  [ -e "$REALM_ADMIN_PASSWORD_FILE" ] ||
    die "realm admin password file ${REALM_ADMIN_PASSWORD_FILE} is missing"
  [ -r "$REALM_ADMIN_PASSWORD_FILE" ] ||
    die "realm admin password file ${REALM_ADMIN_PASSWORD_FILE} is owned by uid \
$(stat -c %u "$REALM_ADMIN_PASSWORD_FILE") mode $(stat -c %a "$REALM_ADMIN_PASSWORD_FILE"), \
and this container is root without DAC_OVERRIDE, so it cannot read it. A deployment's \
secrets must be owned by root."
  log "joining ${AD_REALM} as ${NETBIOS_NAME}"
  # PASSWD_FILE rather than `-U administrator%<password>`: container argv is in
  # the host's process table, so the argv form publishes the domain
  # administrator password to every local `ps` for the length of the join.
  # Measured on the bench (2026-07-28): with PASSWD_FILE set,
  # `net` reads the password from the file and goes straight to preauth; without
  # it and without argv, it prompts. The env var is readable only by this uid and
  # root through /proc, which argv is not.
  PASSWD_FILE="$REALM_ADMIN_PASSWORD_FILE" net ads join -U administrator
fi

# The share exists before its ACL is seeded; 0770 root:root denies everyone
# until seed-demo.sh grants the domain-local group.
install -d -m 0770 -o root -g root /srv/share

term() {
  log "caught TERM/INT, stopping children"
  kill -TERM "${SMBD_PID:-}" "${WINBIND_PID:-}" 2>/dev/null || true
  wait
  exit 0
}
trap term TERM INT

winbindd -F --no-process-group &
WINBIND_PID=$!
smbd -F --no-process-group &
SMBD_PID=$!
log "winbindd pid ${WINBIND_PID}, smbd pid ${SMBD_PID}"

# Either dying takes the pair down so Compose restarts a coherent whole: smbd
# without winbind cannot map PAC SIDs, winbind without smbd serves nothing.
wait -n
rc=$?
log "a supervised process exited rc=${rc}: terminating its peer"
kill -TERM "$SMBD_PID" "$WINBIND_PID" 2>/dev/null || true
wait
exit "$rc"
