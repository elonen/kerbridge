# Debian packages, end to end. `make debian-docker` runs it.
#
# `debian/rules` stages, it does not compile. Something has to fill
# `debian/prebuilt/` before `dpkg-buildpackage` starts: this, or
# `debian/stage-prebuilt` by hand.
#
# Two bases. The programs are static musl from the same digest-pinned
# rust:alpine as the service images, which is what makes one deb install
# unchanged across every supported release; the packaging is cut on trixie.
#
# The build context is `debian/Dockerfile.dockerignore`, not the repository
# root's -- this is the one image that needs `debian/` in it. It needs no
# `.git`; the version arrives as KB_VERSION.

# Same digest as deploy/broker/Dockerfile and the realm image.
FROM rust@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900 AS build
RUN apk add --no-cache musl-dev gcc file

# Licence notices for the static binaries, from the lockfile that built them.
# Version-pinned: unpinned, the text a release ships depends on the build date.
RUN cargo install cargo-about --locked --version 0.8.4

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Three files, not `COPY debian ./debian`: that puts this Dockerfile and every
# manifest into the cargo cache key, so editing one recompiles all six crates.
COPY debian/stage-prebuilt debian/about.toml debian/about.hbs ./debian/

# One `-p` per crate, never `--workspace`: a cold workspace build of this tree
# fails in issuerd with "crate `base64` required to be available in rlib
# format", and every build in a container is cold. The service images take the
# same path.
#
# Then the assertion the broker image makes, for all six: a dynamically linked
# binary installs only on the release it was built on.
RUN for p in kerbridge-config kerbridge-manage kerbridge-setup \
             kerbridge-broker kerbridge-sync kerbridge-issuerd; do \
      cargo build --release -p "$p" || exit 1; \
    done \
 && for b in kbconfig kbmanage kbsetup kerbridge-broker kerbridge-sync issuerd; do \
      file "target/release/$b" | grep -q "dynamically linked" \
        && { echo "$b is not statically linked" >&2; exit 1; }; \
      true; \
    done

RUN cargo about generate --config debian/about.toml debian/about.hbs \
      > target/release/THIRD-PARTY-NOTICES

# Fills debian/prebuilt/, taking the notices from the target directory.
RUN debian/stage-prebuilt target/release


FROM debian:trixie AS deb

# Required: the context carries no `.git` and this image installs no git.
# `make debian-docker` fills it from `debian/make-changelog --print-version`,
# the one copy of the derivation; a tree with no tags passes its own string.
ARG KB_VERSION=

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential debhelper po-debconf fakeroot dpkg-dev lintian \
 && rm -rf /var/lib/apt/lists/*

# dpkg-buildpackage writes the .debs to the parent directory.
WORKDIR /build/kerbridge
COPY . .
COPY --from=build /src/debian/prebuilt ./debian/prebuilt

# lintian in the build layer, so a package that does not lint is a build
# failure rather than an artifact somebody has to remember to check.
RUN [ -n "$KB_VERSION" ] || { \
      echo "KB_VERSION is required: this context carries no .git, so no version" >&2; \
      echo "    can be derived here. \`make debian-docker\` derives it on the host." >&2; \
      exit 1; } \
 && KB_VERSION="$KB_VERSION" debian/make-changelog \
 && dpkg-buildpackage -us -uc -b \
 && lintian --fail-on error,warning ../*.changes \
 && mkdir /out \
 && cp ../*.deb /out/


# The base the two unprivileged service images build on: it carries the
# packages they install and the accounts those packages would otherwise let
# adduser number. `deploy/broker/Dockerfile` and `deploy/sync/Dockerfile` name
# it as a build context and `FROM` it; compose builds it first.
#
# Not the realm image's base -- that one is full `debian`, pinned to the digest
# the samba-tgt-issuance spike measured every issuance property against.
FROM debian:trixie-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# adduser alone and first: the next layer edits its conffile, which has to be
# dpkg's copy rather than a file left lying around for dpkg to find later.
RUN apt-get update \
 && apt-get install -y --no-install-recommends adduser \
 && rm -rf /var/lib/apt/lists/*

# Fixed numbers, seeded before any postinst runs. `adduser --system` allocates
# from the system range, so these IDs would differ in every build -- while
# compose states 10001, 10002 and 10003 in `user:` and issuerd.toml states
# 10002 as the socket group. Each postinst looks the name up before creating
# it, so seeding the names here makes the packages agree with the deployment.
#
# The range has to be widened first, and this is measured: `addgroup --system`
# refuses an existing group outside FIRST/LAST_SYSTEM_GID with exit 13, which
# fails kerbridge-config's postinst and the whole install. 10002 sits outside
# Debian's 100-999. Allocation still starts at the bottom of the range, so
# packages installed alongside take their usual low numbers.
#
# Appended, never substituted: trixie ships both keys commented out, so an
# in-place edit anchored on `^LAST_SYSTEM_GID=` matches nothing and exits 0.
# adduser takes the last assignment it reads.
#
# `adduser` and not `useradd`, with the flags the postinsts use, so only the
# numbers are chosen here.
RUN printf '%s\n' 'LAST_SYSTEM_UID=10100' 'LAST_SYSTEM_GID=10100' \
      >> /etc/adduser.conf \
 && addgroup --system --gid 10002 _kerbridge \
 && adduser --system --uid 10001 --ingroup _kerbridge --home /nonexistent \
            --no-create-home --disabled-password _kerbridge-broker \
 && adduser --system --uid 10003 --ingroup _kerbridge --home /nonexistent \
            --no-create-home --disabled-password _kerbridge-sync

COPY --from=deb /out/ /debs/


FROM scratch AS dist
COPY --from=deb /out/ /
