# `nas1`, the bench file server. `security = ADS`, `idmap_rid`, one Kerberos
# share. A member, not a DC: no samba-ad-dc, no provisioning, no issuerd. It
# joins the realm the realm container provisions and serves SMB over Kerberos
# only. Base pinned by the same digest as the realm image (both are trixie).
FROM debian@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd

ENV DEBIAN_FRONTEND=noninteractive

# samba:          smbd, and `net` (samba-common-bin) for the domain join
# winbind:        winbindd, wbinfo -- the machine's channel to the DC
# libnss-winbind: resolves domain users/groups (id EXAMPLE\alice, and the
#                 share ACL's group -> gid)
# acl:            setfacl/getfacl for the share's domain-local-group grant
# procps:         supervision checks
# smbclient:      the client half, its own package -- `samba` ships the server
#                 only. scripts/bench/ci-stack.sh reads a share file through it
#                 with the TGT the broker issued, and an operator uses it to
#                 tell a broken share from a broken client.
# curl:           the *other* client half. ci-stack.sh runs the real `kerbridge`
#                 in this container, and its browser sign-in is completed by
#                 testbench/mock-idp/approve.sh -- a `$BROWSER` that is a curl
#                 following one redirect. Nothing else in this image can speak
#                 HTTP: perl is the only interpreter here, and there is no
#                 wget, python3 or busybox to fall back to.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      samba \
      winbind \
      libnss-winbind \
      acl \
      procps \
      smbclient \
      curl \
 && rm -rf /var/lib/apt/lists/*

COPY deploy/member/entrypoint.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
