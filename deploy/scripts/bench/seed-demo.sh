#!/bin/bash
# Bench only -- NEVER run against a production deployment. Hand-provisions the
# source-OU content that kerbridge-sync owns in production (the realm-admission
# group and a demo user with its external identity), plus the resource-group
# authorization policy, so the broker's end-to-end path can be proven WITHOUT
# sync running. In production sync creates the admission group and users from
# Entra, and the operator owns the resource groups and share ACL -- none of this
# script runs.
#
# Prerequisite: `make directory` (the two OUs, svc accounts, delegation).
#
# Creates:
#   $IDP_SPECIFIC_OU       <ADMISSION_GROUP> the admission group, carrying the
#                                   realm-admission marker sync would stamp
#                                   (planner ROLE_ADMISSION)
#                 <GRANT_GROUP>     the device-grant group, carrying the marker
#                                   sync would stamp (planner ROLE_DEVICE_GRANT).
#                                   Inert unless device_grant_days is non-zero
#                 <SEED_USER_NAME>  one user with its external identity, UAC 66048,
#                                   in both groups
#                 <SEED_OTHER_NAME> a second person, admitted and nothing else:
#                                   what an unauthorized caller looks like when
#                                   the reason is not "not admitted"
#                 <SEED_SERVICE_NAME> the unattended build account -- an Entra
#                                   user like any other, in both groups
#                 build-engineers   a global group holding SEED_USER_NAME, and
#                                   the thing nested into the delegate group
#                 proj-x            a global authorization group the user belongs to
#   OU=Resources  nas-share-rw      a domain-local group proj-x nests into
#                 <DELEGATE_GROUP>  managedBy -> SEED_SERVICE_NAME and carrying
#                                   the delegates marker: who may authorize a
#                                   device on that account's behalf. Inert on the
#                                   same condition the grant group is
#   nas1          the share ACL granting nas-share-rw (if nas1 is up)
#
# Two distinct chains, deliberately: the admission group (realm admission) is
# what the broker checks before issuing a TGT; proj-x -> nas-share-rw (share
# authorization) is what the file server checks from the injected ticket's PAC. They are
# independent -- a realm-admitted identity still reaches nothing it is not
# separately authorized for.
#
# The delegate chain is a third: build-engineers -> DELEGATE_GROUP -> managedBy
# -> SEED_SERVICE_NAME. It authorizes a *key*, never a ticket, so it grants
# nothing on its own and gates only who may create a device grant on that
# account.
#
# Idempotent: re-running against a seeded directory is a no-op.
set -euo pipefail
. "$(dirname "$0")/../lib.sh"
cd "$(dirname "$0")/../.."
# bench.env then .env, the order compose reads them in: the tracked fixtures
# first, the operator's own file last so it wins.
set -a; . ./bench.env; . ./.env; set +a

# Every one of these is stated in bench.env, which is tracked -- so an unset one
# means that file was edited or bypassed, not that this bench predates a
# feature. Nothing is defaulted here: a fixture's value belongs in one file.
: "${AD_NETBIOS_DOMAIN:?}" "${SEED_USER_OID:?}" "${SEED_USER_NAME:?}" \
  "${SEED_OTHER_OID:?}" "${SEED_OTHER_NAME:?}" \
  "${SEED_SERVICE_OID:?}" "${SEED_SERVICE_NAME:?}"
BASE=$(kbconfig get realm.base_dn)
# The name in every identity this script writes, and the OU that name owns --
# both from the config set, so the objects land where the broker looks. The first
# listed source unless told otherwise: a bench proving one path wants the one it
# has, and a realm with several says which.
SOURCE_NAME=${SEED_SOURCE:-$(kbconfig sources | head -1)}
[ -n "$SOURCE_NAME" ] || { echo "configs/main.toml lists no sources; nothing to seed" >&2; exit 1; }
IDP_SPECIFIC_OU=$(kbconfig get "sources.$SOURCE_NAME.ou")
# The two group names this seed creates. Names only, and this script's own: the
# broker finds a role group by its marker, which the LDIF below stamps, and the
# source file binds by object id -- so neither name has to agree with anything
# in the config set.
ADMISSION_GROUP=${SEED_ADMISSION_GROUP:-onprem-realm-users}
GRANT_GROUP=${SEED_GRANT_GROUP:-onprem-device-grants}
# Derived, not a fixture: a function of SEED_SERVICE_NAME, which bench.env
# states. Overridable for a bench that already has a delegate group by another
# name.
DELEGATE_GROUP=${SEED_DELEGATE_GROUP:-${SEED_SERVICE_NAME}-delegates}
ENGINEER_GROUP=build-engineers

# kerbridge-core owns this encoding and escapes `%` and `|`. Canonical Entra
# values contain neither -- its `canonical_entra_values_need_no_escaping` test
# asserts exactly that -- so plain interpolation here is identical to what the
# crate produces. Refuse anything that would make that untrue rather than write
# a value the broker would decode differently.
case "${SOURCE_NAME}${SEED_USER_OID}${SEED_OTHER_OID}${SEED_SERVICE_OID}" in
  *%*|*\|*) echo "source name or oid contains % or | -- encode with kerbridge-core, not this script" >&2; exit 1;;
esac
identity_of() { printf 'kb1|%s|%s' "$SOURCE_NAME" "$1"; }
IDENTITY=$(identity_of "$SEED_USER_OID")

# The admission group's name reaches an LDIF DN, an LDAP filter and a `grep`
# pattern below, and it is an operator's value, not something `safe_name`
# has been through. Escaping it correctly in all three contexts is more shell than this
# bench script should carry, so refuse the characters instead -- the same trade
# the identity guard above makes. Production names come from `safe_name`, which
# already excludes every one of these.
for g in "SEED_ADMISSION_GROUP=$ADMISSION_GROUP" \
         "SEED_GRANT_GROUP=$GRANT_GROUP" \
         "SEED_DELEGATE_GROUP=$DELEGATE_GROUP" "SEED_SERVICE_NAME=$SEED_SERVICE_NAME"; do
  case "${g#*=}" in
    *[,+\"\\\<\>\;=*\(\)]* | \#* | " "* | *" ")
      echo "$g holds a character that is reserved in a DN" >&2
      echo "  or an LDAP filter. This bench script interpolates the name into both." >&2
      exit 1;;
  esac
done

r() { docker compose exec -T realm "$@"; }
# -F: the name is a literal, not a basic regular expression. `Sales.Team` would
# otherwise match an existing `SalesXTeam` and the caller would skip creating it.
have() { r samba-tool "$1" list 2>/dev/null | grep -qxF "$2"; }

have user svc-kerbridge-broker || { echo "run \`make directory\` first -- the OUs + svc accounts are missing" >&2; exit 1; }

# The "bench only" at the top of this file, as something other than a comment.
#
# There is one honest signal for the difference, and it is the sync credential:
# this source's `credential` file is absent or empty until an operator pastes the
# portal value in, at which point sync starts owning every object
# under its IdP-specific OU. Everything this script writes is then a hand-made object in
# sync's container with no cloud source -- an ambiguous identity value away from
# the broker refusing the real user it collides with. The role marker is not a
# signal, because this script stamps one itself.
if [ -s "secrets/idp/$SOURCE_NAME/credential" ] && [ -z "${SEED_DEMO_AGAINST_LIVE_SYNC:-}" ]; then
  cat >&2 <<'EOF'
seed-demo: refusing -- this source's credential file has content, so kerbridge-sync
  owns the IdP-specific OU here and this script hand-writes objects into it.

  This script exists to prove the broker's path with sync switched off. On a
  deployment where sync is configured, the admission group and the users are
  Entra's, and seeding a second set of them is how you get an ambiguous identity
  value and a real user who can no longer log in.

  If this really is a bench that happens to have a credential in place:
    SEED_DEMO_AGAINST_LIVE_SYNC=1 scripts/bench/seed-demo.sh
EOF
  exit 1
fi

# Random undisclosed password, drawn by samba-tool itself: the account's key is
# what issuance uses, and nothing anywhere needs to know the password that
# created it. That is the whole reason this can use `--random-password` while
# every other creator in the tree draws from `kerbridge_core::password` -- those
# hand the value to someone, and this one has no reader at all.
#
# It also keeps the value out of the host's process table, which
# crates/kerbridge-setup/src/dc.rs spells out. Measured against the pinned baseline (Samba 4.22.10, in
# `kerbridge-realm`): one line of output and no prompt, complexity satisfied by
# samba's own generator, and the account lands at UAC 512 exactly as the stdin
# path left it -- which the LDIF below replaces with 66048 either way.
make_user() {
  have user "$1" && return 0
  # --userou is relative to the base DN, so strip the DC components.
  r samba-tool user create "$1" --userou="${IDP_SPECIFIC_OU%%,DC=*}" \
    --use-username-as-cn --random-password
}
make_group() {  # name, OU relative to the base DN, scope
  have group "$1" || r samba-tool group add "$1" \
    --groupou="$2" --group-scope="$3" --group-type=Security
}
join() { r samba-tool group addmembers "$1" "$2" 2>/dev/null || true; }

make_user "$SEED_USER_NAME"
make_group "$ADMISSION_GROUP" "${IDP_SPECIFIC_OU%%,DC=*}" Global
join "$ADMISSION_GROUP" "$SEED_USER_NAME"

# The device-grant group, seeded unconditionally: it does nothing at all unless
# main.toml's device_grant_days is non-zero, and having it here is what lets a
# bench turn the feature on with one edit. Additional to the admission group, never an
# alternative -- the same user is in both, which is what a real holder looks like.
make_group "$GRANT_GROUP" "${IDP_SPECIFIC_OU%%,DC=*}" Global
join "$GRANT_GROUP" "$SEED_USER_NAME"

# Share-authorization chain: user -> proj-x (global, in the TGT PAC at AS time)
# -> nas-share-rw (domain-local, added to the cifs/nas1 ticket at TGS time). The
# member reads nas-share-rw from the PAC and matches it against the share ACL.
make_group proj-x "${IDP_SPECIFIC_OU%%,DC=*}" Global
make_group nas-share-rw OU=Resources Domain  # samba-tool spelling of domain-local
join proj-x "$SEED_USER_NAME"
join nas-share-rw proj-x

# Delegation. The service account is an Entra user like any other -- that is what
# leaves issuerd, sync and the ticket path untouched -- so it is in both groups
# for the same reasons SEED_USER_NAME is. SEED_OTHER_NAME is admitted and in
# neither: a caller refused for *not being a delegate* has to be distinguishable
# from one refused for not being admitted, and one who is not admitted proves
# nothing about the delegate check.
make_user "$SEED_SERVICE_NAME"
make_user "$SEED_OTHER_NAME"
join "$ADMISSION_GROUP" "$SEED_SERVICE_NAME"
join "$GRANT_GROUP" "$SEED_SERVICE_NAME"
join "$ADMISSION_GROUP" "$SEED_OTHER_NAME"
# The service account needs the share too, and it is the only account that does:
# the engineer authorizes the machine, but every file the machine writes is
# written as this account. Without it the delegation demo reaches a real cifs
# ticket for the service account and then cannot connect, which reads on Windows
# as "the password is invalid" -- a tree-connect refusal wearing an
# authentication error's clothes.
join nas-share-rw "$SEED_SERVICE_NAME"
# Engineers reach the delegate group by nesting their synced Entra group into it,
# which is the ordinary authorization model and not a special case -- and the
# nesting is why the broker evaluates membership with LDAP_MATCHING_RULE_IN_CHAIN
# rather than reading `member`.
make_group "$ENGINEER_GROUP" "${IDP_SPECIFIC_OU%%,DC=*}" Global
make_group "$DELEGATE_GROUP" OU=Resources Domain
join "$ENGINEER_GROUP" "$SEED_USER_NAME"
join "$DELEGATE_GROUP" "$ENGINEER_GROUP"

# UAC 66048 on each user (DONT_EXPIRE_PASSWORD -- an expired password breaks
# keytab issuance), the external identity the broker matches the token against,
# and the role markers sync's planner stamps in production.
#
# The delegate group carries both halves of the link: `managedBy` naming the
# account, and the marker saying the link was meant as a delegation. `managedBy`
# alone is not enough -- it has a live conventional meaning, and a group an admin
# marked managed-by this account for ADUC reasons must not thereby hand every
# member of it the right to authorize devices.
r sh -c "cat > /tmp/demo.ldif <<'EOF'
dn: CN=${SEED_USER_NAME},$IDP_SPECIFIC_OU
changetype: modify
replace: msDS-ExternalDirectoryObjectId
msDS-ExternalDirectoryObjectId: ${IDENTITY}
-
replace: userAccountControl
userAccountControl: 66048
-

dn: CN=${SEED_OTHER_NAME},$IDP_SPECIFIC_OU
changetype: modify
replace: msDS-ExternalDirectoryObjectId
msDS-ExternalDirectoryObjectId: $(identity_of "$SEED_OTHER_OID")
-
replace: userAccountControl
userAccountControl: 66048
-

dn: CN=${SEED_SERVICE_NAME},$IDP_SPECIFIC_OU
changetype: modify
replace: msDS-ExternalDirectoryObjectId
msDS-ExternalDirectoryObjectId: $(identity_of "$SEED_SERVICE_OID")
-
replace: userAccountControl
userAccountControl: 66048
-

dn: CN=${ADMISSION_GROUP},$IDP_SPECIFIC_OU
changetype: modify
replace: extensionName
extensionName: kbrole1|realm-admission
-

dn: CN=${GRANT_GROUP},$IDP_SPECIFIC_OU
changetype: modify
replace: extensionName
extensionName: kbrole1|device-grant
-

dn: CN=${DELEGATE_GROUP},OU=Resources,$BASE
changetype: modify
replace: managedBy
managedBy: CN=${SEED_SERVICE_NAME},$IDP_SPECIFIC_OU
-
replace: extensionName
extensionName: kbrole1|delegates
-
EOF
ldbmodify -H /var/lib/samba/private/sam.ldb /tmp/demo.ldif; rm -f /tmp/demo.ldif"

echo "--- seeded demo directory ---"
r ldbsearch -H /var/lib/samba/private/sam.ldb "(sAMAccountName=${SEED_USER_NAME})" \
  sAMAccountName userAccountControl msDS-ExternalDirectoryObjectId objectSid memberOf \
  | grep -vE '^(#|$|ref:)'
r ldbsearch -H /var/lib/samba/private/sam.ldb "(sAMAccountName=${ADMISSION_GROUP})" extensionName objectSid \
  | grep -vE '^(#|$|ref:)'
r ldbsearch -H /var/lib/samba/private/sam.ldb "(sAMAccountName=nas-share-rw)" groupType member objectSid \
  | grep -vE '^(#|$|ref:)'
# Both ends of the delegate link, because a link with only one end reads as
# working right up until the broker refuses.
r ldbsearch -H /var/lib/samba/private/sam.ldb "(sAMAccountName=${DELEGATE_GROUP})" \
  groupType managedBy extensionName member | grep -vE '^(#|$|ref:)'
r ldbsearch -H /var/lib/samba/private/sam.ldb "(sAMAccountName=${SEED_SERVICE_NAME})" \
  sAMAccountName msDS-ExternalDirectoryObjectId managedObjects memberOf \
  | grep -vE '^(#|$|ref:)'

# Share ACL on nas1: keyed by nas-share-rw's gid, which winbind resolves
# only now that the group exists. This is file-server admin, not directory state sync
# will own -- bundled here so one command takes the bench from up to testable.
NAS=nas1
if docker compose ps --status running --services 2>/dev/null | grep -qx "$NAS"; then
  n() { docker compose exec -T "$NAS" "$@"; }
  # Drop any negative cache from a lookup made before the group existed.
  n net cache flush
  n setfacl -m "g:${AD_NETBIOS_DOMAIN}\\nas-share-rw:rwx" \
            -m "d:g:${AD_NETBIOS_DOMAIN}\\nas-share-rw:rwx" /srv/share
  n sh -c 'printf "KerBridge: reached over SMB with a cloud identity, no password.\n" > /srv/share/README.txt && chmod 664 /srv/share/README.txt'
  echo "--- share ACL on ${NAS} ---"
  n id "${AD_NETBIOS_DOMAIN}\\${SEED_USER_NAME}"
  n getfacl -n /srv/share 2>/dev/null | grep -vE '^#|^$' || true
else
  echo "note: ${NAS} is not running -- start it and re-run to apply the share ACL"
fi
