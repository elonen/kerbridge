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
# binutils is for the `readelf` the audit-section assertion below runs.
RUN apk add --no-cache musl-dev gcc file binutils
# `cargo auditable` writes the dependency list into a `.dep-v0` ELF section, so
# `cargo audit bin` and the usual scanners can read a static binary they would
# otherwise report as having no dependencies at all. Costs ~2 KB. Version-pinned
# for the reason cargo-about is in debian/Dockerfile.
RUN cargo install cargo-auditable --locked --version 0.7.0
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Assert what was asked for is what came out: a static-PIE binary of the
# requested architecture. TARGETARCH comes from buildx via --platform; checking
# the binary against it catches a base image that ignored the request. An empty
# TARGETARCH means a plain `docker build` with no buildx -- the build still runs,
# it just cannot assert the architecture.
#
# `--target` is required, not cosmetic. Without it cargo applies RUSTFLAGS to the
# proc-macro crates too, and async-trait then fails with "cannot produce
# proc-macro ... does not support these crate types". Naming the target splits
# host flags from target flags, and moves the binary to target/<triple>/release/
# -- hence the copy back to the path the export stage reads.
#
# x86_64-musl is static-PIE on its own and the flags change nothing there.
# aarch64-musl is a plain ET_EXEC without them: fixed load address, no ASLR on
# the main image. `-C relocation-model=pic` alone does not fix it; the link
# argument is the part that does.
#
# `-C link-self-contained=no` is load-bearing on aarch64, and a binary built
# without it segfaults before main. rustc otherwise passes its own crt1.o,
# musl's non-PIE startup object; a static-PIE ET_DYN has no interpreter, so
# nothing self-relocates it and it jumps into unrelocated code. rustc chooses
# that object without seeing `-C link-arg=-static-pie`, and `-nostartfiles`
# cannot displace it -- it is an explicit object on the link line. Left to gcc,
# the startfile spec picks rcrt1.o, which self-relocates. `-L` then supplies
# the one file the system lacks, rustc's own libunwind.a.
#
# The last assertion runs the binary. `file` reads the ELF header, which said
# static-pie of the crt1.o build too.
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) want="x86-64";  triple="x86_64-unknown-linux-musl";; \
      arm64) want="aarch64"; triple="aarch64-unknown-linux-musl";; \
      "")    want="";        triple="$(rustc -vV | sed -n 's/^host: //p')";; \
      *)     echo "unsupported TARGETARCH=$TARGETARCH"; exit 1;; \
    esac; \
    sc="$(rustc --print sysroot)/lib/rustlib/$triple/lib/self-contained"; \
    RUSTFLAGS="-C relocation-model=pic -C link-self-contained=no -C link-arg=-static-pie -C link-arg=-L$sc" \
    cargo auditable build --release --target "$triple" -p kerbridge-manage \
 && mkdir -p target/release \
 && cp "target/$triple/release/kbmanage" target/release/kbmanage \
 && { [ -z "$want" ] || file target/release/kbmanage | grep -q "$want"; } \
 && file target/release/kbmanage | grep -q "static-pie" \
 && target/release/kbmanage --version >/dev/null \
 || { echo "kbmanage is not a static-pie $TARGETARCH binary that runs:"; file target/release/kbmanage; exit 1; }

# A binary with no `.dep-v0` reads to every scanner as one with no dependencies,
# which is worse than not scanning it. `cargo auditable` failing open is silent.
RUN readelf -S target/release/kbmanage | grep -q "\.dep-v0" \
 || { echo "kbmanage carries no audit data" >&2; exit 1; }

FROM scratch AS dist
COPY --from=build /src/target/release/kbmanage /kbmanage
