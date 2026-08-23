# The realm image: Samba AD DC and `issuerd`. Compose runs it twice, as `realm`
# and `issuer` (docs/design/components.md @ `realm`).
#
# It installs the shipped .deb files, like the broker and sync images, but does
# not build `FROM debs`: that stage is trixie-slim and this base is full debian.

# Base pinned by digest, never a floating tag. This is the digest the
# samba-tgt-issuance spike measured every issuance property against.
FROM debian@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd

ENV DEBIAN_FRONTEND=noninteractive

# The shared group, numbered before the packages create it. No daemon account:
# this image runs both processes as root. The gid must be 10002 -- issuerd
# chowns the socket directory to it, and the broker's and sync's `user:` lines
# name it.
#
# Widening LAST_SYSTEM_GID makes kerbridge-config's postinst accept the group:
# `addgroup --system` exits 13 on an existing group outside
# FIRST/LAST_SYSTEM_GID, and 10002 is outside Debian's 100-999. Same as
# debian/Dockerfile's `runtime` stage.
RUN apt-get update \
 && apt-get install -y --no-install-recommends adduser \
 && rm -rf /var/lib/apt/lists/* \
 && printf '%s\n' 'LAST_SYSTEM_GID=10100' >> /etc/adduser.conf \
 && addgroup --system --gid 10002 _kerbridge

# kerbridge-issuerd carries `issuerd` and `kbsetup` and Depends on the whole
# Samba side, so apt resolves it from the package's own list and a dependency
# missing from debian/control fails this build.
#
# The two named packages are nothing's Depends: samba-ad-provision holds the
# LDIF `samba-tool domain provision` reads, and openssl creates the LDAPS CA and
# the SAN certificate Samba's own lacks.
#
# kerbridge-config arrives as a dependency and brings `prepare-state`
# (/usr/libexec/kerbridge/prepare-state). On Compose only this image can run it:
# the host tree it prepares needs a root with DAC_OVERRIDE, which the hardened
# service containers have dropped, and `make up` already builds this one first.
COPY --from=debs /debs/ /tmp/debs/
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      /tmp/debs/kerbridge-config_*.deb /tmp/debs/kerbridge-issuerd_*.deb \
      samba-ad-provision openssl ca-certificates \
 && rm -rf /tmp/debs /var/lib/apt/lists/*

COPY deploy/realm/entrypoint.sh deploy/realm/healthcheck.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
