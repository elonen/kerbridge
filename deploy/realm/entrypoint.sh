#!/bin/bash
# Realm container entrypoint: bring the realm into existence, then become Samba.
#
# `kbsetup realm` is the whole realm half. It reads the config set at
# /etc/kerbridge, creates the LDAPS CA and SAN certificate, publishes the CA
# where the broker can read it, and provisions when no database exists. Against
# an existing database it compares durable state to the config set and refuses on
# a conflict: silently reprovisioning a populated bind mount destroys the domain
# SID, and with it every SID sitting in a filesystem ACL.
#
# ONE PROCESS, NOT TWO, and nothing here supervises anything: issuerd is the
# `issuer` service, the same image with its own `command:`
# (docs/design/components.md @ `realm`).
#
# The realm identity, the RPC port range and the DNS forwarder come from
# realm.toml, not from AD_* in .env, so Compose and a native DC are configured
# the same way. compose.yaml still interpolates AD_DC_HOSTNAME and AD_DNS_DOMAIN
# for its hostname and network aliases; scripts/config/check-env.sh holds those
# to what the config set says.
set -euo pipefail

# "$@" is compose's `command:`: --allow-example-realm, or nothing.
#
# kbsetup refuses to bake the documented example realm into a database unless
# told to on purpose. The realm service interpolates KB_ALLOW_EXAMPLE_REALM into
# argv, so the flag a native DC's operator types is the flag this container gets.
# argv and not environment: a KB_* key in an `environment:` block is what
# scripts/compose/check-compose-env.py exists to refuse.
#
# Two gates judge this one decision, from different files.
# scripts/config/check-env.sh fires first, on `make up`, and judges .env --
# including BROKER_FQDN, which kbsetup cannot see. This gate judges the config
# set, and catches a `docker compose up` run around make.
kbsetup realm "$@"

# `exec`, so a TERM from `docker compose stop` reaches Samba itself and the 30s
# stop_grace_period is Samba's to use.
#
# No `-d`: as argv it overrides smb.conf's `log level` wholesale, including the
# `auth_audit:3` class provisioning sets -- the KDC's record of every AS
# exchange. `-d 1` and the configured `1 auth_audit:3` look alike and are not:
# measured 2026-08-03 on 4.22.10, a failed AS-REQ under `-d 1` produced no
# `Auth:` line anywhere, and the same request without it produced one.
#
# `-i`, not the `--foreground` a systemd unit uses. Both stay in the foreground;
# only `-i` also puts the log on stdout, where `docker compose logs realm` reads
# it. `--foreground` sends the stream to smb.conf's `log file`, a tmpfs nothing
# reads. Forked children inherit the stdout; only smbd and winbindd write files.
#
# Two lines per Kerberos authentication, which is why compose.yaml bounds the log
# driver.
exec samba -i --no-process-group
