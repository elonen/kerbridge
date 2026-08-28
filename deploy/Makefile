# Compose resolves build contexts and bind mounts relative to this directory.
# The root Makefile forwards Compose targets here. Recipes use scripts that also
# run directly. Targets are idempotent and resume after a failed step.

# Bootstrap prerequisites are ordered steps. Do not run them in parallel.
.NOTPARALLEL:

# `NAS=1` adds nas1 from compose.nas.yaml. Use it on each later target for that
# deployment. nas1 uses the DC's port 445, so no external file server can join.
# `MOCKIDP=1` adds the stand-in OIDC authority for sign-in without a tenant.
# Both fixtures can run together.
#
# Export COMPOSE_FILE because scripts call plain `docker compose` and must use
# the same overlays. Teardown finds fixtures by project label and does not need
# these variables.
COMPOSE_FILES = compose.yaml
ifdef NAS
COMPOSE_FILES := $(COMPOSE_FILES):compose.nas.yaml
endif
ifdef MOCKIDP
COMPOSE_FILES := $(COMPOSE_FILES):compose.mockidp.yaml
endif
# Leave COMPOSE_FILE unset when no fixture is selected.
ifneq ($(COMPOSE_FILES),compose.yaml)
export COMPOSE_FILE = $(COMPOSE_FILES)
endif

.PHONY: build up stack broker secrets directory seed down ready kbmanage-config kbconfig-image \
        kbmanage-image realm-image test-notification clean-report clean-docker-images \
        clean-docker-volumes check-env check-tls check-config check-secrets

# COMPOSE_ENV_FILES uses commas; COMPOSE_FILE uses colons. Export it because
# scripts call plain `docker compose`. Later files override earlier files, so the
# operator's .env must follow tracked bench.env. An explicit list
# replaces Compose's implicit .env.
#
# Compose rejects a missing listed file and validates interpolated fields before
# a build. Use .env.example only when .env is absent, so a fresh clone can build
# without a deployment identity. check-env.sh validates an existing .env.
COMMA := ,
export COMPOSE_ENV_FILES = bench.env$(COMMA)$(if $(wildcard .env),.env,.env.example)

# debian/Dockerfile has no .git metadata. Recursive expansion derives the package
# version only for targets that build the `debs` service.
export KB_VERSION ?= $(shell ../debian/make-changelog --print-version)

# Compose builds the six packages before images that use `debs` as a build context.
build:
	@[ -f .env ] || echo "note: no deploy/.env -- building with .env.example; only caddy's build args read it"
	docker compose build

# `NAS=1` adds the example file server. Without it, join an external file server
# as described in docs/setup/file-server.md.
up: kbconfig-image check-env check-tls check-config secrets
	# Wait for realm provisioning before the next step accesses sam.ldb. nas1 is
	# optional, so its dependency does not provide this barrier.
	docker compose up -d --wait realm $(if $(NAS),nas1)
	docker compose run --rm setup directory
	$(MAKE) stack
	$(MAKE) kbmanage-config

# `up -d` returns when containers exist. wait-ready.sh detects later startup
# failures after directory bootstrap.
stack: kbconfig-image kbmanage-image check-env check-tls check-config check-secrets
	# Rebuild Caddy because TLS_STRATEGY and CADDY_DNS_MODULE are build arguments.
	# Compose does not detect a stale image after these .env values change. A cached
	# Caddy build takes approximately 0.3 seconds; a full build takes 75 seconds.
	docker compose build caddy
	docker compose up -d
	@scripts/compose/wait-ready.sh

# Recreate Caddy after the broker. Caddy joins the broker's network namespace by
# container ID (`network_mode: service:broker`). Recreating only the broker leaves
# Caddy attached to a deleted namespace, so port 443 stops listening while all
# containers report running. Recreating Caddy takes approximately one second.
# wait-ready.sh detects this stale namespace by container identity.
broker: check-env kbmanage-image
	docker compose build broker
	docker compose up -d broker
	docker compose up -d --force-recreate caddy
	@scripts/compose/wait-ready.sh

# Check secrets before readiness because the operator writes the Entra credential
# after `make up`. A wrong mode otherwise appears only as "sync idle".
ready: check-secrets kbmanage-image
	@scripts/compose/wait-ready.sh

# Refresh the realm CA for host-run kbmanage after each realm rebuild.
# configs/kbmanage.toml and its link are created only when absent.
kbmanage-config:
	@scripts/config/kbmanage-config.sh

# Scripts use this image to parse deploy/configs/. The exported host binary uses
# the server architecture and cannot run on a macOS bench. Workspace layers make
# later image builds inexpensive.
kbconfig-image:
	docker build -q -f kbconfig/Dockerfile --target dist -t kerbridge-kbconfig .. >/dev/null

# Run kbmanage in a container because the exported binary uses the server
# architecture. scripts/lib.sh uses this image for the readiness endpoint probe.
kbmanage-image:
	docker build -q -f kbmanage/Dockerfile --target dist -t kerbridge-kbmanage .. >/dev/null

# Build the realm image before the host tree. `secrets` runs its
# /usr/libexec/kerbridge/prepare-state helper in a temporary container.
realm-image:
	docker compose build realm

# Prepare gitignored state/ and secrets/ on the host. Docker rejects a missing
# bind source before a service starts, and hardened services cannot set the
# required owners. Run the shipped helper in a temporary root container from the
# realm image. A cached realm build takes approximately 0.3 seconds.
secrets: kbconfig-image realm-image
	scripts/compose/bootstrap-secrets.sh

# Requires a provisioned realm. kbsetup reads the config set directly, so this
# target does not need kbconfig.
directory:
	docker compose run --rm setup directory

# Bench only. Production uses kerbridge-sync to manage source OU content.
seed: kbconfig-image
	scripts/bench/seed-demo.sh

# Send a synthetic event and verify that the receiver accepts it. Use `run --rm`
# because setup can test the channel before any service runs. Arguments after the
# service name pass to the binary.
test-notification:
	docker compose run --rm --no-deps sync --test-notification

# Teardown finds the project by name, so it works with a missing or invalid .env.
down:
	scripts/compose/teardown.sh

clean-report:
	@scripts/compose/clean.sh report

clean-docker-images:
	@scripts/compose/clean.sh images

clean-docker-volumes:
	@scripts/compose/clean.sh volumes $(if $(YES),--yes)

check-env:
	@scripts/config/check-env.sh

check-tls:
	@scripts/compose/check-tls.sh

# The gate parses TOML with kbconfig in a container. Keep the image as an ordered
# prerequisite because sibling prerequisites have no build order.
check-config: kbconfig-image
	@scripts/config/check-config.sh

check-secrets:
	@scripts/check-secrets.sh
