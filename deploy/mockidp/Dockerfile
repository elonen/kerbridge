# The bench's stand-in OIDC authority, packaged. What it serves and why is
# testbench/mock-idp/README.md; this file is only how it is shipped.
#
# Base pinned by the same digest as the realm and member images -- all three are
# the one trixie this repository builds on.
FROM debian@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd

ENV DEBIAN_FRONTEND=noninteractive

# python3-jwt is PyJWT and python3-cryptography is its RSA backend -- the only
# two imports idp.py makes beyond the standard library. From Debian rather than
# pip so the image carries no build toolchain and the build reaches no index but
# the distribution's own.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-jwt python3-cryptography \
 && rm -rf /var/lib/apt/lists/*

COPY testbench/mock-idp/idp.py /opt/mock-idp/idp.py

# The source of truth for both halves of the handoff: idp.py writes `jwks.json`
# here at every start, and the broker mounts this same volume read-only to load
# it. A directory rather than a file, which is what makes the volume possible --
# a bind-mounted *file* that does not exist yet becomes a directory, and the
# broker then fails to parse it.
ENV IDP_STATE_DIR=/state
VOLUME /state

# The image runs read-only apart from that volume, so bytecode has nowhere to go
# and Python would retry the write on every start.
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8443
CMD ["python3", "-u", "/opt/mock-idp/idp.py"]
