# The operator CLI, built to a static musl binary and exported to the host. The
# only directory under deploy/ that is not a compose service: `docker compose
# build` never exports to the host and this must. The root Makefile builds it
# with --output type=local and the repository root as the context, so a Linux
# host with only Docker can build everything, with no Rust toolchain.
#
# The Makefile owns the architecture: it passes --platform, defaulting to the
# build host's. No cross-compilation -- the builder image *is* the target
# platform, emulated when it differs -- because neither Alpine nor Debian
# packages a musl cross-C toolchain and `ring` compiles C and assembly.
# BuildKit lints a constant platform here and suggests $BUILDPLATFORM, so the
# value stays in the Makefile.
FROM rust@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900 AS build
RUN apk add --no-cache musl-dev gcc file
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Assert what was asked for is what came out. On x86_64 a musl release build is
# static-PIE, which `file` calls "static-pie linked" and `ldd` reports with a
# loader line, not the "Not a valid dynamic program" the non-PIE aarch64 form
# emits -- so test for "not dynamically linked", which is phrasing-stable across
# targets. TARGETARCH comes from buildx via --platform; checking the binary
# against it catches a base image that ignored the request.
#
# An empty TARGETARCH means a plain `docker build` with no buildx: the build
# still runs, it just cannot assert.
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) want="x86-64";; \
      arm64) want="aarch64";; \
      "")    want="";; \
      *)     echo "unsupported TARGETARCH=$TARGETARCH"; exit 1;; \
    esac; \
    cargo build --release -p kerbridge-manage \
 && { [ -z "$want" ] || file target/release/kbmanage | grep -q "$want"; } \
 && ! file target/release/kbmanage | grep -q "dynamically linked" \
 || { echo "kbmanage is not a static $TARGETARCH binary:"; file target/release/kbmanage; exit 1; }

FROM scratch AS dist
COPY --from=build /src/target/release/kbmanage /kbmanage
