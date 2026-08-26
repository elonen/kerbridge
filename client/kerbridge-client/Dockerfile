# The `kerbridge` CLI, as a binary the bench containers can run.
#
# `scripts/bench/ci-stack.sh` is the only caller. It exists so the stack test can
# drive the *real* client through the last leg -- sign in, exchange, inject, read
# a file over SMB -- instead of re-implementing those steps in shell, which is a
# test of the shell.
#
# **Not a release artifact, and not a supported Linux client.** What the Linux
# arm is and is not is written out in `src/linux/os.rs`; this file only says how
# it is built. The Windows and macOS clients ship from
# `kerbridge-agent-windows/Dockerfile` and the macOS agent's Makefile.
#
# Static musl, from the same digest-pinned rust:alpine as the service images and
# the debs. That is what makes the one binary runnable in *any* bench container
# whatever its libc -- nas1 is trixie, this image is alpine -- so the leg can move
# to wherever the ticket has to land rather than the ticket being carried to it.

# Same digest as debian/Dockerfile, deploy/broker/Dockerfile and the realm image.
FROM rust@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900 AS build

# openssl-libs-static is the one addition over the server crates' build: the
# client links native-tls rather than rustls, deliberately -- on Windows and
# macOS that is SChannel and Security.framework, which validate against the OS
# certificate store an operator installs their CA into. On Linux it is OpenSSL,
# which honours SSL_CERT_FILE, and that is how the bench hands it the bench CA.
# `file` is for the assertion below.
RUN apk add --no-cache musl-dev gcc openssl-dev openssl-libs-static pkgconf perl make file

WORKDIR /src
COPY client ./client

# OPENSSL_STATIC, so the trust decisions and the crypto travel inside the binary
# and no shared object has to exist in the container it is dropped into.
ENV OPENSSL_STATIC=1

# `--target` even for the host triple: it keeps the static-musl link off the
# proc-macros, exactly as deploy/kbmanage/Dockerfile explains for the servers.
#
# Then the assertion. A dynamically linked binary here would run in the alpine
# image it was built in and nowhere else -- and the failure is not a link error,
# it is `docker compose exec nas1 kerbridge` printing "not found" for a file that
# is plainly there, which reads like a mount problem and is not one.
RUN case "$(rustc -vV | sed -n 's/^host: //p')" in \
      x86_64-*)  triple="x86_64-unknown-linux-musl";; \
      aarch64-*) triple="aarch64-unknown-linux-musl";; \
      *)         echo "unsupported build host" >&2; exit 1;; \
    esac; \
    cd client && cargo build --release --target "$triple" -p kerbridge-client --bin kerbridge; \
    cp "target/$triple/release/kerbridge" /kerbridge; \
    file /kerbridge | grep -q 'statically linked' || { \
      echo "FAIL: the client is not statically linked:"; file /kerbridge; exit 1; }; \
    /kerbridge --help > /dev/null

# What `--output type=local` writes out: the binary and nothing else.
FROM scratch AS dist
COPY --from=build /kerbridge /kerbridge
