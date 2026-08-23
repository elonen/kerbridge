# Broker container: the shipped .deb, installed on the release it is cut for.
# It installs the same two packages a Debian host installs -- kerbridge-config
# for the tooling and the state tree, kerbridge-broker for the daemon -- so one
# set of bytes is tested, not two.
#
# The base is debian/Dockerfile's `runtime` stage, exposed as the `debs` build
# context: the .deb files at /debs, plus the numbered accounts the postinsts
# would otherwise allocate. compose.yaml's `debs` service builds it and is the
# only entry point -- a bare `docker build -f deploy/broker/Dockerfile ..` has
# no such context and fails.
FROM debs

# `ca-certificates` named, Recommends refused. The one outbound path needs it:
# validating login.microsoftonline.com when the broker fetches the signing keys.
# These roots refresh with `apt` and need no recompile; `webpki-roots` stays
# compiled in for a host with no bundle, and both sets merge (DESIGN.md @
# kerbridge-broker, "Trust anchors").
#
# The other Recommends is logrotate, useless here -- compose bounds these logs
# with the json-file driver. Measured: taking Recommends installs 140 packages
# instead of 83, because logrotate wants cron, cron wants an MTA, and exim4
# brings 31 MB of perl.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      /debs/kerbridge-config_*.deb /debs/kerbridge-broker_*.deb \
 && rm -rf /debs /var/lib/apt/lists/*

# No USER: Compose sets the uid/gid, because the socket group belongs to the
# deployment, not the image.
#
# /usr/sbin/kerbridge-broker is the package's path and
# kerbridge-broker.service's ExecStart=; compose.yaml's `entrypoint:` restates
# it, and that copy is what debian/check-manifests reads.
ENTRYPOINT ["/usr/sbin/kerbridge-broker"]
