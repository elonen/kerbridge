#!/bin/bash
# The server path with a live authentik as the identity provider, from a fresh
# clone to a file read over SMB with a TGT and no password. What `make
# test-authentik` runs.
#
# This tier shares realm provisioning with ci-stack.sh. Authentik runs behind
# Caddy. The broker fetches its signing keys over TLS, and sync reads its live
# directory (IdP).
#
# Authentik-specific assertions:
#
#   1. The broker's live JWKS fetch. The startup fetch is fatal on failure
#      (kerbridge-idp/src/jwks.rs), so the broker answers `/config` only if it
#      first fetched the application's keys from authentik, over TLS, trusting the
#      bench CA. provision.sh waiting for `/config` is that proof.
#   2. Sync mirrors the directory (IdP). Pointed at the admission group's live pk, one
#      cycle turns the blueprint's one user and one group into a realm account and
#      a marked admission group. Asserted by OUTCOME, never an exit code: one user,
#      one group, and the account's external identity byte-equal to the REST uuid.
#   3. A scripted sign-in to a real TGT. approve.sh signs benchuser in through the
#      flow executor with no browser, the client posts the authentik token to
#      /ticket, and a KDC-signed TGT comes back -- for the very account sync wrote.
#      The issuer negative (correct aud, foreign iss) is not driven here: authentik
#      keys client_id uniquely, so it cannot mint that token; it is forged in the
#      token corpus and checked under test instead. See the note above the sign-in.
#   4. The TGT reads a file over SMB, with no password after sign-in.
#      It is the only proof that sync wrote a user the KDC issues a usable PAC
#      for -- the same end state ci-stack.sh reaches, driven by sync rather than by
#      seed-demo.sh.
set -euo pipefail

# provision.sh uses this source in the config set and broker routes.
SOURCE=authentik

# Order is significant. compose.ci.yaml removes the bench ports; compose.authentik.yaml
# then adds authentik and wires the broker to it. There is no compose.mockidp.yaml
# here -- authentik is the authority, not a stand-in for one.
export COMPOSE_FILE=compose.yaml:compose.nas.yaml:compose.ci.yaml:compose.authentik.yaml

# The constant bench sync credential -- the API token sync reads the directory
# with. It is the token the blueprint sets on the read-only service account, so
# the two are one value. authentik makes an API token unreadable after creation,
# so a constant is the only way both ends can hold it. bench- prefixed like the
# blueprint's.
idp_prepare() {
  say "writing the constant bench sync credential"
  mkdir -p "$ROOT/deploy/secrets/idp/authentik"
  printf '%s' 'bench-authentik-sync-token' > "$ROOT/deploy/secrets/idp/authentik/credential"
  # The broker refuses a secret that other can read; a fresh file inherits the
  # umask (0644), so tighten it to the 0640 the permission check demands.
  chmod 0640 "$ROOT/deploy/secrets/idp/authentik/credential"
}

# IDP_FQDN is the alias Caddy answers for and proxies to authentik on; the broker
# derives every authentik URL from it. CI_APPROVE_SH is compose.ci.yaml's nas1
# mount: the `$BROWSER` the client's sign-in drives -- here the authentik flow
# executor, not mock-idp's one-redirect approval.
idp_env_lines() {
  cat <<EOF

IDP_FQDN=$IDP_FQDN
CI_APPROVE_SH=$ROOT/testbench/authentik/approve.sh
EOF
}

# One authentik application. url has no port because the broker reaches it on the
# network's :443, and `iss` follows that origin -- issuer, authority and jwks_url
# all derive from url and the slug. client_id is the blueprint's, a chosen string
# rather than a generated id.
#
# admission_group_id is the group's pk (a uuid), which authentik generates when
# the blueprint creates the group and this script does not know when it writes
# this file. The placeholder here is a syntactically valid uuid so the broker,
# which parses the whole block at startup and never uses this key, can start; the
# tail below re-runs this hook with ADMISSION_GROUP_ID set to the pk it read back
# from the live instance, before sync is recreated against it.
idp_source_toml() {
  cat <<EOF
name = "$SOURCE"
provider = "authentik"
group_suffix = "none"
bind_dn = "CN=svc-kerbridge-sync-$SOURCE,CN=Users,$BASE_DN"
bind_password_file = "/etc/kerbridge.secrets/generated/idp/$SOURCE/bind_password"

[provider_config]
url = "https://$IDP_FQDN"
application_slug = "kerbridge"
client_id = "kerbridge"
sync_credential_file = "/etc/kerbridge.secrets/idp/$SOURCE/credential"
admission_group_id = "${ADMISSION_GROUP_ID:-00000000-0000-0000-0000-000000000000}"
EOF
}

. "$(dirname "$0")/provision.sh"

# ---------------------------------------------------------------------------
# The shared script returned after the broker answered /config over TLS -- which
# means its startup JWKS fetch from authentik succeeded. Run authentik-specific
# assertions.
# ---------------------------------------------------------------------------
say "the broker answered /config, so its startup JWKS fetch from live authentik over TLS succeeded"
echo "that is the first real JWKS fetch -- not the mock-idp trick of a key document in a shared volume"

# The realm login name of the account sync will mirror. It is benchuser's authentik
# `username`, which is `name_candidates`' first choice and needs no reduction, so
# the sAMAccountName is `benchuser` verbatim. Everything below asserts against it
# rather than provision.sh's alice, who this tier never seeds.
LOGIN=benchuser

r() { docker compose exec -T realm "$@"; }
lsearch() { r ldbsearch -H /var/lib/samba/private/sam.ldb "$@"; }
# The first value of one attribute, out of ldbsearch's LDIF on stdin. ldbsearch
# folds a line past ~78 columns onto a continuation line beginning with a space,
# and the external identity is long enough to fold, so unfold before matching or
# the value comes back truncated.
attr1() {  # attribute-name
  python3 - "$1" <<'PY'
import base64, sys
want = sys.argv[1].lower()
lines = []
for raw in sys.stdin.read().splitlines():
    if raw[:1] == " " and lines:
        lines[-1] += raw[1:]
    else:
        lines.append(raw)
for line in lines:
    if ":" not in line:
        continue
    key, _, rest = line.partition(":")
    if key.strip().lower() != want:
        continue
    if rest.startswith(":"):  # `attr:: value` is base64
        print(base64.b64decode(rest[1:].strip()).decode())
    else:
        print(rest.strip())
    break
PY
}

# The UUID a signed-in token carries and the value sync must write. Read it
# from authentik so the assertions compare sync's output against the
# authority rather than against a constant this script chose.
say "reading benchuser's uuid and the admission group's pk from authentik"
read_ak() {  # path -> stdout, via the bootstrap token inside authentik-server
  docker compose exec -T authentik-server python3 - "$1" <<'PY'
import json, os, sys, urllib.request
req = urllib.request.Request(
    "http://localhost:9000" + sys.argv[1],
    headers={"Authorization": "Bearer " + os.environ["AUTHENTIK_BOOTSTRAP_TOKEN"]})
print(json.dumps(json.load(urllib.request.urlopen(req, timeout=10))["results"]))
PY
}
uuid=$(read_ak "/api/v3/core/users/?username=benchuser" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["uuid"])')
case "$uuid" in
  [0-9a-f]*-[0-9a-f]*-[0-9a-f]*-[0-9a-f]*-[0-9a-f]*) : ;;
  *) die "authentik did not return a canonical uuid for benchuser: '$uuid'" ;;
esac
gid=$(read_ak "/api/v3/core/groups/?name=KerBridge%20Allowed%20On-prem%20Users" |
  python3 -c 'import json,sys
rs=[g for g in json.load(sys.stdin) if g["name"]=="KerBridge Allowed On-prem Users"]
print(rs[0]["pk"] if rs else "")')
case "$gid" in
  [0-9a-f]*-[0-9a-f]*-[0-9a-f]*-[0-9a-f]*-[0-9a-f]*) : ;;
  *) die "authentik did not return a pk for the admission group: '$gid'" ;;
esac
echo "benchuser uuid = $uuid; admission group pk = $gid"

# ---------------------------------------------------------------------------
# Point sync at that pk and let it mirror. The config the broker parsed at startup
# carried the placeholder pk; re-run the source hook with the real one and recreate
# sync so it reads the new file. The broker keeps running -- it never uses this key.
# ---------------------------------------------------------------------------
say "pointing sync at the admission group and mirroring the directory"
ADMISSION_GROUP_ID=$gid idp_source_toml > "configs/idp_$SOURCE.toml"
docker compose up -d --force-recreate --no-deps sync

# Asserted by OUTCOME: poll the realm until sync has written benchuser with the
# right external identity, rather than reading sync's exit code -- it is a daemon
# and does not exit. IDP_OU is the OU sync owns, derived from the source name.
IDP_OU=$(kbconfig get "sources.$SOURCE.ou")
IDENTITY="kb1|$SOURCE|$uuid"
say "waiting for sync to mirror benchuser into $IDP_OU"
mirrored=0
for _ in $(seq 1 30); do
  got=$(lsearch -b "$IDP_OU" "(sAMAccountName=$LOGIN)" msDS-ExternalDirectoryObjectId 2>/dev/null |
    attr1 msDS-ExternalDirectoryObjectId) || true
  [ -z "$got" ] || { mirrored=1; break; }
  sleep 3
done
if [ "$mirrored" != 1 ]; then
  docker compose logs --no-color --tail 40 sync || true
  die "sync did not write $LOGIN under $IDP_OU"
fi
[ "$got" = "$IDENTITY" ] ||
  die "sync wrote $LOGIN with external id '$got', wanted '$IDENTITY' (byte-equal to the REST uuid)"
echo "sync wrote $LOGIN, external id byte-equal to the REST uuid"

# One user and one group: the blueprint seeds exactly one of each, so a second of
# either would mean sync mirrored something it should not have.
users=$(lsearch -b "$IDP_OU" "(&(objectClass=user)(objectCategory=person))" sAMAccountName |
  grep -c '^sAMAccountName:') || true
[ "$users" = 1 ] || die "sync wrote $users users under $IDP_OU, wanted exactly one"
groups=$(lsearch -b "$IDP_OU" "(objectClass=group)" sAMAccountName | grep -c '^sAMAccountName:') || true
[ "$groups" = 1 ] || die "sync wrote $groups groups under $IDP_OU, wanted exactly one"

# The one group is the admission group, carrying the marker the broker gates on.
# Read its realm sAMAccountName by that marker, the way the broker finds it.
admgrp=$(lsearch -b "$IDP_OU" "(objectClass=group)" sAMAccountName extensionName | attr1 sAMAccountName)
marker=$(lsearch -b "$IDP_OU" "(objectClass=group)" extensionName | attr1 extensionName)
[ "$marker" = "kbrole1|realm-admission" ] ||
  die "the mirrored group carries extensionName '$marker', wanted the realm-admission marker"
echo "sync mirrored one user and one group ($admgrp), the admission group carrying the marker"

# ---------------------------------------------------------------------------
# Share authorization: file-server admin the operator owns, not directory state
# sync writes. sync mirrors the admission group; the operator nests THAT group
# into a domain-local resource group and grants it the share. The resource group
# lives in OU=Resources, outside sync's OU, so no cycle retires it. This is the
# resource half of seed-demo.sh, pointed at the synced group instead of a
# hand-made user -- benchuser reaches the share through
# benchuser -> admission group (synced) -> nas-share-rw (operator's).
# ---------------------------------------------------------------------------
say "granting the share to the synced admission group"
have_group() { r samba-tool group list 2>/dev/null | grep -qxF "$1"; }
have_group nas-share-rw ||
  r samba-tool group add nas-share-rw --groupou=OU=Resources \
    --group-scope=Domain --group-type=Security  # samba-tool spelling of domain-local
r samba-tool group addmembers nas-share-rw "$admgrp" 2>/dev/null || true

# The ACL on nas1, keyed by nas-share-rw's gid, which winbind resolves only now
# that the group exists. README.txt is the file the SMB read returns.
n() { docker compose exec -T nas1 "$@"; }
n net cache flush
n setfacl -m "g:${NETBIOS}\\nas-share-rw:rwx" \
          -m "d:g:${NETBIOS}\\nas-share-rw:rwx" /srv/share
n sh -c 'printf "KerBridge: reached over SMB with a cloud identity, no password.\n" > /srv/share/README.txt && chmod 664 /srv/share/README.txt'

# The cross-application issuer negative -- a token with the correct audience but
# a foreign issuer, refused on `iss` -- is not driven here: a real authentik
# cannot mint it. The authorize and token endpoints resolve a provider by
# `client_id`, which is unique per instance, so no second application can share
# it to differ only on the slug-keyed issuer. That token is forged in the token
# corpus (testbench/fixtures/authentik-token/neg_wrong_issuer.jwt) and the
# adapter rejects it under test with "iss is not the configured issuer"
# (kerbridge-idp/src/authentik/auth.rs).

# ---------------------------------------------------------------------------
# The real client, signing in through authentik with no browser and no human, and
# turning the token into a KDC-signed TGT for the account sync wrote. Run inside
# nas1 so the ticket lands in the cache the SMB client reads by construction, and
# so the same `kerbridge` an operator runs drives approve.sh as its `$BROWSER`.
# ---------------------------------------------------------------------------
say "the real client, signing in through authentik with no human and no browser"
CI_CA_IN_NAS=/etc/kerbridge-ci-ca.crt
CI_CCACHE_IN_NAS=/tmp/kb.ccache
client() {
  docker compose exec -T \
    -e "BROWSER=/usr/local/bin/kb-approve" \
    -e "KB_APPROVE_CA=$CI_CA_IN_NAS" \
    -e "KB_APPROVE_LOG=/tmp/kb-approve.log" \
    -e "SSL_CERT_FILE=$CI_CA_IN_NAS" \
    -e "KRB5CCNAME=FILE:$CI_CCACHE_IN_NAS" \
    nas1 "$@"
}
docker compose exec -T nas1 rm -f "$CI_CCACHE_IN_NAS"
signin=$ROOT/.local-tmp/ci-authentik-signin.log
if ! client kerbridge --broker "https://$FQDN" > "$signin" 2>&1; then
  cat "$signin"
  client cat /tmp/kb-approve.log 2>/dev/null || true
  die "the client could not sign in through authentik and obtain a TGT"
fi
cat "$signin"
# The principal the broker issued, read out of the client's own log. The token was
# benchuser's, the account sync wrote, so the TGT is benchuser's too.
grep -qi "$LOGIN@$REALM" "$signin" ||
  die "the client reported no ticket for $LOGIN@$REALM"
echo "benchuser signed in through authentik and the client obtained a TGT for $LOGIN@$REALM"

# ---------------------------------------------------------------------------
# The last leg: that TGT reads a file over SMB. No password from the sign-in on.
# The invocation ci-stack.sh proved on the bench, byte for byte:
# --use-kerberos=required and neither -U nor -N, so the ccache's own principal is
# what authenticates.
# ---------------------------------------------------------------------------
say "reading a file over SMB with that ticket and no password"
got=$(client sh -c "smbclient '//nas1.$DOMAIN/share' \
     --use-kerberos=required -c 'get README.txt -'" 2>&1) || true
case "$got" in
  *KerBridge*) echo "read README.txt from //nas1.$DOMAIN/share as $LOGIN@$REALM" ;;
  *) die "SMB read returned: ${got:-<nothing>}" ;;
esac

say "PASS -- provisioned, mirrored the directory with sync, signed in through authentik, and read over SMB"
