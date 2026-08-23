# The Compose stack: build it, bootstrap it, run it. The root Makefile forwards
# every compose-related target here, and each one is equally runnable from
# deploy/ directly.
#
# This file exists because compose has to be invoked from this directory --
# compose.yaml's build contexts and its secret and Caddyfile bind mounts are all
# resolved relative to it. It holds targets only; the shell lives in scripts/,
# which every target calls and which are all runnable by hand.
#
# Every target is idempotent: re-running is a no-op, and re-running after a
# failure resumes where it stopped.

# Prerequisites are ordered steps here, not independent work -- `make -j` must
# not reorder a bootstrap into its own preconditions.
.NOTPARALLEL:

# `nas1` in compose.nas.yaml is opt-in: `make up NAS=1`, and
# then NAS=1 on every later target in that deployment. Production leaves it
# unset and never creates the container.
#
# COMPOSE_FILE rather than -f, because the scripts in scripts/ all call plain
# `docker compose` and this is the one form that reaches them too -- one
# definition, and seeding sees the same file list the `up` did.
#
# Teardown needs none of it: scripts/compose/teardown.sh works by project label,
# so it sees the fixture whether or not the operator remembered NAS=1 here.
#
# It also takes the DC's :445 for itself -- see compose.nas.yaml -- so a
# deployment running the fixture is one no external file server can join.
#
# MOCKIDP=1 adds the bench's stand-in OIDC authority, for a client sign-in
# without a tenant. The two are independent and compose, which is why this
# accumulates rather than assigning: `make up NAS=1 MOCKIDP=1` is the whole
# path -- cloud sign-in to a file over SMB -- on one machine and no tenant.
COMPOSE_FILES = compose.yaml
ifdef NAS
COMPOSE_FILES := $(COMPOSE_FILES):compose.nas.yaml
endif
ifdef MOCKIDP
COMPOSE_FILES := $(COMPOSE_FILES):compose.mockidp.yaml
endif
# Left unset when neither is asked for, so a production deployment's environment
# looks exactly as it did before either fixture existed.
ifneq ($(COMPOSE_FILES),compose.yaml)
export COMPOSE_FILE = $(COMPOSE_FILES)
endif

.PHONY: build up stack broker secrets directory seed down ready kbmanage-config kbconfig-image \
        kbmanage-image realm-image test-notification clean-report clean-docker-images \
        clean-docker-volumes check-env check-tls check-config check-secrets

# NOTE: commas. COMPOSE_FILE above uses colons; COMPOSE_ENV_FILES does not.
#
# Exported for the reason COMPOSE_FILE is: the scripts in scripts/ all call
# plain `docker compose`, and this is the one form that reaches them too.
# bench.env holds the tracked fixtures, .env the operator's own values, and the
# order matters -- the last file listed wins, so .env must be last or an
# operator's edit is silently ignored. Setting this at all replaces compose's
# implicit ./.env rather than adding to it, which is why .env is named.
#
# A file listed here that does not exist is a hard error, not a skip, and .env
# is gitignored -- so a fresh clone falls back to the example. `docker compose
# build` parses the whole file and validates fields it has interpolated into
# (extra_hosts rejects the empty string), so without that fallback a clone with
# no .env fails before reaching a single Dockerfile, naming a host name nobody
# wrote. Building is not deploying and must not need a deployment's identity.
# An .env that exists is used as it is, wrong values and all: that one belongs
# to the operator, and check-env.sh is where it is judged.
COMMA := ,
export COMPOSE_ENV_FILES = bench.env$(COMMA)$(if $(wildcard .env),.env,.env.example)

# The package version, for the `debs` service's build arg. Derived here because
# debian/Dockerfile carries no `.git` and can derive nothing itself; recursively
# expanded, so `git describe` runs only for a target that actually builds.
export KB_VERSION ?= $(shell ../debian/make-changelog --print-version)

# The six .deb files first, then the images that install them; compose orders
# that itself, because each names the `debs` service as a build context.
build:
	@[ -f .env ] || echo "note: no deploy/.env -- building with .env.example; only caddy's build args read it"
	docker compose build

# A fresh clone to a running stack. `make up NAS=1` also brings up the example
# file server; without it the realm comes up alone and you join your own
# (docs/setup/file-server.md), which is what a real deployment does.
up: kbconfig-image check-env check-tls check-config secrets
	# --wait, because the next step talks to sam.ldb and `up -d` returns as soon
	# as the container exists -- provisioning a fresh domain takes far longer than
	# that. Without it a fresh volume fails on "could not open sam.ldb". Nothing
	# else here waits: nas1 is opt-in, so its depends_on is not a barrier.
	docker compose up -d --wait realm $(if $(NAS),nas1)
	docker compose run --rm setup directory
	$(MAKE) stack
	$(MAKE) kbmanage-config

# The rest of the stack, once the directory is bootstrapped. `up -d` returns as
# soon as the containers exist, so the report is what decides whether this
# worked -- see scripts/compose/wait-ready.sh for what it would otherwise take a log
# read to notice.
stack: kbconfig-image kbmanage-image check-env check-tls check-config check-secrets
	# caddy only, and not as a dependency on `build`. Its image is the one whose
	# correctness follows a .env value rather than source you edited --
	# TLS_STRATEGY and CADDY_DNS_MODULE are build args, so switching strategy
	# leaves an image that silently does not match, and compose will not notice.
	# Cached this is ~0.3s; a full `docker compose build` is 75s, which is the
	# wrong tax for catching stale Rust you knew you were writing.
	docker compose build caddy
	docker compose up -d
	@scripts/compose/wait-ready.sh

# Rebuild just the broker, which is the dev loop for server-side Rust and the one
# service that cannot be recreated on its own. `docker compose up -d broker` is
# the reflex and it silently breaks TLS ingress: caddy joined *that* container's
# network namespace by ID when it started (compose.yaml: network_mode:
# service:broker), so the recreate leaves caddy attached to a namespace that no
# longer exists. Nothing then listens on :443, caddy logs nothing, and all five
# containers still read running. Recreating caddy is the whole fix and costs ~1s.
#
# Every other service is safe to `up -d` by hand; only this one is a namespace
# parent. wait-ready.sh detects the stale state by container identity and names
# it, for the times this target was not the path taken.
broker: check-env kbmanage-image
	docker compose build broker
	docker compose up -d broker
	docker compose up -d --force-recreate caddy
	@scripts/compose/wait-ready.sh

# The same report on its own, against whatever is running.
#
# check-secrets first, and that is the point rather than a tidy-up: the Entra
# credential is written by hand *after* `make up` has already run the check, so
# nothing judges the one file whose mode an operator actually chooses. This is the
# command SETUP.md tells them to re-run, so it is where the answer belongs. It
# fails the target instead of reporting into it, because "sync idle" is the
# misleading symptom a wrong mode produces.
ready: check-secrets kbmanage-image
	@scripts/compose/wait-ready.sh

# The realm CA, the CLI's own identity, and the link that makes a host-run
# kbmanage mean this deployment. Run by `up`, and on its own after a realm
# rebuild -- which creates a new CA. The CA is refreshed every run;
# configs/kbmanage.toml and the link are written only if absent.
kbmanage-config:
	@scripts/config/kbmanage-config.sh

# What the scripts here read deploy/configs/ through, because shell cannot parse
# TOML. An image rather than the host binary `make kbconfig` exports: that one is
# built for the server's architecture and a macOS bench cannot run it. Cheap
# after the first build -- the layers are the workspace's, shared with the
# service images.
kbconfig-image:
	docker build -q -f kbconfig/Dockerfile --target dist -t kerbridge-kbconfig .. >/dev/null

# The other one the scripts here run in a container, and for the same reason:
# the host binary is built for the server's architecture. This one is what the
# readiness report asks the endpoint with -- see scripts/lib.sh @ kbmanage().
kbmanage-image:
	docker build -q -f kbmanage/Dockerfile --target dist -t kerbridge-kbmanage .. >/dev/null

# The realm image, on its own and before `up` needs it running. It carries
# /usr/libexec/kerbridge/prepare-state, which `secrets` runs in a throwaway
# container -- so this is the one build that has to happen before the host tree
# exists rather than after.
realm-image:
	docker compose build realm

# The host tree every container binds a piece of: the directories, and the empty
# files a compose secret needs a source for. It cannot be done from inside a
# service container -- the daemon refuses a missing bind source before anything
# in one runs, and the hardened ones could not set the ownership anyway -- so a
# throwaway root container prepares it, from the shipped helper. state/ and
# secrets/ are both gitignored, so a fresh clone has neither.
#
# realm-image because it carries the helper. Cached that build is ~0.3s, and it
# is the one `up` needs two steps later anyway.
secrets: kbconfig-image realm-image
	scripts/compose/bootstrap-secrets.sh

# the OUs, the svc-kerbridge-broker account and one svc-kerbridge-sync-<source>
# per source with freshly generated passwords, and each delegated source-OU
# write. Needs a provisioned realm; needs no kbconfig, because `kbsetup` reads
# the config set in process rather than a subprocess per value.
directory:
	docker compose run --rm setup directory

# Bench only: demo user, groups, share ACL. Production never runs this --
# kerbridge-sync owns its IdP-specific OU's content.
seed: kbconfig-image
	scripts/bench/seed-demo.sh

# Send one synthetic event and report whether the receiver took it. A
# notification channel can fail as silently as the conditions it reports, so an
# installation is not finished until this has been seen to arrive in the channel.
#
# `run --rm` rather than `exec`: it needs no running service -- the point is to
# prove the channel on a deployment that is still being set up -- and the
# arguments after the service name reach the binary as its own.
test-notification:
	docker compose run --rm --no-deps sync --test-notification

# Teardown identifies the project by name instead of parsing compose.yaml, so a
# missing or broken .env cannot leave an operator unable to stop their own stack.
# scripts/compose/teardown.sh has the reasoning and what it measured.
down:
	scripts/compose/teardown.sh

# The two Docker rungs of `make clean`. The root Makefile owns `clean` itself --
# host build output there, nothing from Docker -- and each rung here names the
# next rather than climbing it. scripts/compose/clean.sh explains why.
clean-report:
	@scripts/compose/clean.sh report

clean-docker-images:
	@scripts/compose/clean.sh images

clean-docker-volumes:
	@scripts/compose/clean.sh volumes $(if $(YES),--yes)

# All four gates refuse rather than warn, and each explains the fix -- see the
# header comment in each script for why the failure it catches is otherwise
# silent.
check-env:
	@scripts/config/check-env.sh

check-tls:
	@scripts/compose/check-tls.sh

# The image is a prerequisite rather than an assumption: shell cannot read TOML,
# so this gate runs the binary in a container, and `make -j` gives no order to a
# sibling in the same list.
check-config: kbconfig-image
	@scripts/config/check-config.sh

check-secrets:
	@scripts/check-secrets.sh
