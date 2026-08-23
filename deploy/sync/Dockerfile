# Sync container: the shipped .deb, installed on the release it is cut for.
# Same shape as deploy/broker/Dockerfile -- read it there. It installs
# kerbridge-config and kerbridge-sync onto that file's `debs` base, which
# compose.yaml's `debs` service builds and is the only entry point.
FROM debs

# `ca-certificates` named, Recommends refused -- see the broker's copy for the
# cost. Graph validates login.microsoftonline.com and graph.microsoft.com
# against these roots, which refresh with the base; `webpki-roots` stays
# compiled in as the fallback for a host with no bundle (DESIGN.md @
# kerbridge-broker). The realm CA that LDAPS is verified against is mounted at
# runtime, never baked here.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      /debs/kerbridge-config_*.deb /debs/kerbridge-sync_*.deb \
 && rm -rf /debs /var/lib/apt/lists/*

# No USER: Compose sets the uid/gid, since the identity that reads the realm CA
# and the sync credential belongs to the deployment.
#
# /usr/sbin/kerbridge-sync is the package's path and kerbridge-sync.service's
# ExecStart=; compose.yaml's `entrypoint:` restates it, and that copy is what
# debian/check-manifests reads.
ENTRYPOINT ["/usr/sbin/kerbridge-sync"]
