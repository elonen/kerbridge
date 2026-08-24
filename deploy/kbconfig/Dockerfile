# The configuration CLI, built to a static musl binary and exported to the host.
# Same shape as deploy/kbmanage/Dockerfile and for the same reasons -- read the
# comments there; only the crate and the binary name differ.
#
# It is a second image rather than a second target in that one because the two
# binaries are deliberately separate: kbconfig links no LDAP client, and an
# operator runs it during bootstrap, before kbmanage has a directory to talk to.
FROM rust@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900 AS build
RUN apk add --no-cache musl-dev gcc file binutils
# See deploy/kbmanage/Dockerfile for why `cargo auditable` and why pinned.
RUN cargo install cargo-auditable --locked --version 0.7.0
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
ARG TARGETARCH
# Same build and same assertion as deploy/kbmanage/Dockerfile, which explains
# why `--target` is named and why the binary is copied back.
RUN case "$TARGETARCH" in \
      amd64) want="x86-64";  triple="x86_64-unknown-linux-musl";; \
      arm64) want="aarch64"; triple="aarch64-unknown-linux-musl";; \
      "")    want="";        triple="$(rustc -vV | sed -n 's/^host: //p')";; \
      *)     echo "unsupported TARGETARCH=$TARGETARCH"; exit 1;; \
    esac; \
    RUSTFLAGS="-C relocation-model=pic -C link-self-contained=yes -C link-arg=-static-pie" \
    cargo auditable build --release --target "$triple" -p kerbridge-config \
 && mkdir -p target/release \
 && cp "target/$triple/release/kbconfig" target/release/kbconfig \
 && { [ -z "$want" ] || file target/release/kbconfig | grep -q "$want"; } \
 && file target/release/kbconfig | grep -q "static-pie" \
 || { echo "kbconfig is not a static-pie $TARGETARCH binary:"; file target/release/kbconfig; exit 1; }

# See deploy/kbmanage/Dockerfile for why this is asserted rather than assumed.
RUN readelf -S target/release/kbconfig | grep -q "\.dep-v0" \
 || { echo "kbconfig carries no audit data" >&2; exit 1; }

FROM scratch AS dist
COPY --from=build /src/target/release/kbconfig /kbconfig
