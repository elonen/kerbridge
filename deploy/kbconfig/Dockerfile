# The configuration CLI, built to a static musl binary and exported to the host.
# Same shape as deploy/kbmanage/Dockerfile and for the same reasons -- read the
# comments there; only the crate and the binary name differ.
#
# It is a second image rather than a second target in that one because the two
# binaries are deliberately separate: kbconfig links no LDAP client, and an
# operator runs it during bootstrap, before kbmanage has a directory to talk to.
FROM rust@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900 AS build
RUN apk add --no-cache musl-dev gcc file
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) want="x86-64";; \
      arm64) want="aarch64";; \
      "")    want="";; \
      *)     echo "unsupported TARGETARCH=$TARGETARCH"; exit 1;; \
    esac; \
    cargo build --release -p kerbridge-config \
 && { [ -z "$want" ] || file target/release/kbconfig | grep -q "$want"; } \
 && ! file target/release/kbconfig | grep -q "dynamically linked" \
 || { echo "kbconfig is not a static $TARGETARCH binary:"; file target/release/kbconfig; exit 1; }

FROM scratch AS dist
COPY --from=build /src/target/release/kbconfig /kbconfig
