# The Caddy image, one per TLS strategy but only one of them expensive.
#
# TLS_STRATEGY=acme-dns needs a DNS provider module inside Caddy, and no module
# can be added at runtime: Caddy plugins are Go packages linked into the binary,
# and the official image ships none. That strategy relinks Caddy with
# CADDY_DNS_MODULE; the other two take the stock binary untouched.
#
# TLS_STRATEGY selects the final stage, so only a DNS-01 deployment pulls the Go
# builder -- external and acme retag the pinned image. Changing either build arg
# needs an explicit `docker compose build caddy`; Compose does not rebuild.

ARG TLS_STRATEGY=external

# Caddy 2.11.4, digest-pinned, and the base of every strategy. The builder below
# is pinned to the same version on purpose: a plugin is linked into Caddy itself,
# so the two halves must agree.
FROM caddy@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648 AS stock

# The operator supplies the certificate, or Caddy fetches it over an inbound
# challenge. Either way the stock binary is enough.
FROM stock AS caddy-external
FROM stock AS caddy-acme

# DNS-01: rebuild Caddy with the provider module, e.g.
# github.com/caddy-dns/cloudflare -- the list is at https://github.com/caddy-dns.
# Needs network at build time for the Go module fetch. `:?` fails the build with
# that message rather than producing a Caddy that cannot serve this strategy.
FROM caddy:2.11.4-builder@sha256:198d47eaee306d4d0c38a9960c89ff2c959aa29ad51d3e2dafa3e93ac961782a AS build
ARG CADDY_DNS_MODULE
RUN xcaddy build \
      --with "${CADDY_DNS_MODULE:?set CADDY_DNS_MODULE in .env for TLS_STRATEGY=acme-dns}" \
      --output /out/caddy

FROM stock AS caddy-acme-dns
# Replaces the stock binary in place, so everything else about the image -- entry
# point, layout, the /data and /config paths Compose mounts -- is unchanged.
COPY --from=build /out/caddy /usr/bin/caddy

FROM caddy-${TLS_STRATEGY}
