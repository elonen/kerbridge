# Top-level build. The default target builds the product in Docker and requires
# no host Rust or MinGW toolchain.
#
# `docker` builds the server images. `windows` cross-compiles the CLI and tray
# agent into dist/. `installer` packages them as an unsigned MSI. `macos` and
# `macos-zip` build the arm64 app and release archive natively on macOS.
# `kbmanage` and `kbconfig` export static CLIs for KBMANAGE_PLATFORM. The default
# is the Docker host platform. `debian-docker` exports six packages to
# dist/debian/. Release-only targets are not part of the default build.
#
# deploy/Makefile owns Compose operations because Compose resolves paths from
# that directory.

DIST := dist
DEPLOY := $(MAKE) -C deploy
# Windows packaging must run from the agent directory.
CLIENT_WIN := $(MAKE) -C client/kerbridge-agent-windows

.DEFAULT_GOAL := build-docker
.PHONY: all build-docker build-local docker windows macos macos-zip installer kbmanage kbconfig cli-dist debian-docker up down \
        clean clean-docker-images clean-docker-volumes \
        setup setup-rustfmt setup-clippy setup-tools \
        test test-fast test-win test-mac test-build test-authentik test-stack test-deb test-all

# Compatibility alias for the containerized build.
all: build-docker
build-docker: docker windows kbmanage kbconfig

# Host-native development build. Production uses the container builds. Windows
# cross-compilation stays in Docker, so MinGW is not a host dependency.
build-local:
	cargo build --release --workspace

docker:
	$(DEPLOY) build

# Cross-compile both Windows executables without host Rust or MinGW.
windows:
	docker build -f client/kerbridge-agent-windows/Dockerfile --target dist --output type=local,dest=$(DIST) .
	ls -l $(DIST)

# Build the unsigned MSI in Docker with wixl and msitools. This target compiles
# both executables and does not use `windows` output. See docs/setup/rough-edges.md.
installer:
	$(CLIENT_WIN) installer
	ls -l $(DIST)

# Assemble the macOS app natively. Refuse unsupported hosts.
macos:
	@[ "$$(uname -s)" = Darwin ] || { echo "macos: needs a Mac" >&2; exit 1; }
	$(MAKE) -C client/kerbridge-agent-macos app
	ls -l $(DIST)

# Package the macOS app as a release archive without changing `macos` output.
macos-zip:
	@[ "$$(uname -s)" = Darwin ] || { echo "macos-zip: needs a Mac" >&2; exit 1; }
	$(MAKE) -C client/kerbridge-agent-macos zip
	ls -l $(DIST)

# Defaults to the Docker host platform. Override for another server:
# KBMANAGE_PLATFORM=linux/amd64.
KBMANAGE_PLATFORM ?= $(shell docker version --format '{{.Server.Os}}/{{.Server.Arch}}' 2>/dev/null)

# Either CLI target exports both files from debian/Dockerfile. In `build-docker`,
# the preceding `docker` target makes the build stage available in the cache.
kbmanage kbconfig: cli-dist
cli-dist:
	docker buildx build -f debian/Dockerfile --platform=$(KBMANAGE_PLATFORM) \
	  --target cli-dist --output type=local,dest=$(DIST) .
	@file $(DIST)/kbmanage $(DIST)/kbconfig 2>/dev/null | sed 's/^/built /' || true

# Build six Debian packages in Docker with the pinned musl toolchain, trixie,
# dpkg-buildpackage, and lintian. GNU/Debian scripts do not run on the host.
#
# Derive the version before the image build, which receives no .git directory.
# Recursive expansion limits this command to targets that need it. Override when
# tags are unavailable: `make debian-docker KB_VERSION=0.10.0`.
#
# Build one native architecture per run. Do not reuse KBMANAGE_PLATFORM because
# emulating six crate builds is slow. Release CI builds each architecture on a
# runner of that architecture for the same reason. DEB_PLATFORM overrides it for
# a one-off cross build: `make debian-docker DEB_PLATFORM=linux/amd64`.
DEB_PLATFORM ?=
KB_VERSION ?= $(shell debian/make-changelog --print-version)

# CI sets optional BuildKit cache flags because a fresh runner has no builder
# cache. Example: `DOCKER_CACHE='--cache-from type=local,... --cache-to
# type=local,...'`. An empty value does not change the build.
#
# Use buildx because the default Docker builder cannot export a cache. CI selects
# a docker-container builder with docker/setup-buildx-action.
DOCKER_CACHE ?=
# Simply expanded, so the derivation runs once rather than once per reference.
debian-docker: KB_VERSION := $(KB_VERSION)
debian-docker:
	@# A variable set from a shell command keeps no exit status, so a checkout
	@# with no tags -- `git clone --depth 1` -- leaves KB_VERSION empty and the
	@# build starts anyway. debian/Dockerfile refuses an empty one, but only
	@# past the compile stages.
	@[ -n "$(KB_VERSION)" ] || { \
		echo "no version: see the message above, or pass KB_VERSION=<version>" >&2; \
		exit 1; \
	}
	@# Remove old packages because versioned filenames accumulate and make
	@# `apt-get install ./*.deb` select multiple versions.
	rm -rf $(DIST)/debian
	docker buildx build -f debian/Dockerfile --build-arg KB_VERSION=$(KB_VERSION) \
	  $(if $(DEB_PLATFORM),--platform=$(DEB_PLATFORM)) \
	  $(DOCKER_CACHE) --target dist --output type=local,dest=$(DIST)/debian .
	@ls -l $(DIST)/debian

# Forward stack creation to deploy/Makefile. NAS=1 adds nas1, which takes the
# published port 445 and prevents an external file server from joining. See
# docs/setup/file-server.md.
up:
	$(DEPLOY) up

# Stop the stack before backup. See docs/setup/broker-host.md and backup.sh.
down:
	$(DEPLOY) down

# Remove host build output only. Report Docker resources without changing them.
# Use `rm` so a Docker-only host can clean the tree without Cargo. Keep
# .local-tmp/ because `make test-stack ARGS=--keep` can run a stack from it;
# removing that tree would leave its containers without their source files.
clean:
	rm -rf $(DIST) target client/target
	@$(DEPLOY) clean-report

# Docker cleanup is explicit. See deploy/scripts/compose/clean.sh.
# `make clean-docker-volumes YES=1` skips interactive confirmation.
clean-docker-images:
	$(DEPLOY) clean-docker-images

clean-docker-volumes:
	$(DEPLOY) clean-docker-volumes

# Install test dependencies explicitly with `make setup`. Test and build targets
# do not invoke package managers. Cargo, rustc, and python3 must already exist.
# Prefer rustup for components when it owns the Rust toolchain.

setup: setup-rustfmt setup-clippy setup-tools

# Arguments: cargo subcommand, rustup component, Debian package. Verify the
# command after installation because Cargo searches $$CARGO_HOME/bin first. An
# obsolete crates.io rustfmt can shadow the toolchain component and accepts
# `--check` without checking files.
define install_rust_component
	@if cargo $(1) --version >/dev/null 2>&1; then \
		echo "cargo $(1): already present ($$(cargo $(1) --version))"; \
	elif command -v rustup >/dev/null 2>&1; then \
		rustup component add $(2); \
	elif command -v apt-get >/dev/null 2>&1; then \
		sudo apt-get install -y $(3); \
	else \
		echo "setup: no rustup and no apt-get here -- install $(2) the way this host does it" >&2; \
		exit 1; \
	fi
	@cargo $(1) --version >/dev/null 2>&1 || { \
		echo "FAIL: $(2) is installed, but \`cargo $(1)\` still cannot run it." >&2; \
		echo "      If \`ls \$$HOME/.cargo/bin\` lists it, that copy shadows the toolchain's" >&2; \
		echo "      -- \`cargo uninstall $(2)\` drops it." >&2; \
		exit 1; }
	@echo "cargo $(1): ready ($$(cargo $(1) --version))"
endef

# rustfmt is a separate rustup component or distribution package. test-fast
# fails when Cargo cannot find it.
setup-rustfmt:
	$(call install_rust_component,fmt,rustfmt,rustfmt)

setup-clippy:
	$(call install_rust_component,clippy,clippy,rust-clippy)

# test-fast uses shellcheck for scripts and zstd for compressed research data.
# Install zstd explicitly so a missing tool does not look like a corrupt archive.
setup-tools:
	@for t in shellcheck zstd; do \
		if command -v $$t >/dev/null 2>&1; then echo "$$t: already present"; continue; fi; \
		if command -v apt-get >/dev/null 2>&1; then sudo apt-get install -y $$t; \
		elif command -v brew >/dev/null 2>&1; then brew install $$t; \
		else echo "setup-tools: no apt-get and no brew here -- install $$t the way this host does it" >&2; exit 1; fi; \
	done
	@for t in shellcheck zstd python3; do \
		command -v $$t >/dev/null 2>&1 || { echo "FAIL: $$t is still not on PATH" >&2; exit 1; }; \
	done
	@echo "shellcheck, zstd, python3: ready"

# Test tiers add a cross-compiler, Docker, a provisioned realm, and four
# distribution releases in that order. `make test` runs the fast tier. CI runs
# each tier separately in .github/workflows/ci.yml.
#
# Manual tests cover a live Entra tenant, ACME TLS, and Windows ticket use.

test: test-fast

# Cargo tests print one character per test. KB_TEST_VERBOSE=1 restores the
# per-test name list, for a failure that needs the names around it.
CARGO_TEST_Q := $(if $(KB_TEST_VERBOSE),,--quiet)

# The report shape for test-fast. `section` heads a group. `check` runs a short
# command, marks every line it prints with `ok`, and names a silent one by its
# label; it buffers, so a non-zero exit prints the whole output under FAIL and
# stops the tier. `step` streams instead, for the commands that compile --
# their progress has to arrive while they run.
#
# A gate reached through `check` states only what is wrong. The macro supplies
# the marker and the label, so no gate repeats them.
define section
@printf '\n=== %s ===\n' "$(1)"
endef

define check
@out=$$($(2) 2>&1); st=$$?; \
if [ $$st -ne 0 ]; then \
	printf 'FAIL %s\n' "$(1)"; printf '%s\n' "$$out" | sed 's/^/     /' >&2; exit $$st; \
fi; \
if [ -n "$$out" ]; then printf '%s\n' "$$out" | sed 's/^/ok   /'; \
else printf 'ok   %s\n' "$(1)"; fi
endef

define step
@printf '\n-- %s\n' "$(1)"; \
$(2) \
	&& printf 'ok   %s\n' "$(1)" \
	|| { printf 'FAIL %s\n' "$(1)" >&2; exit 1; }
endef

# The root rustfmt.toml applies to all three workspaces. Formatting parses
# platform-specific crates without building them.
define gate_rustfmt
cargo fmt --all --check \
	&& (cd client && cargo fmt --all --check) \
	&& (cd website && cargo fmt --all --check)
endef

define gate_graph_fixtures
stage=$$(mktemp -d); trap 'rm -rf "$$stage"' EXIT; \
python3 testbench/fixtures/graph-sync/make_fixtures.py --out "$$stage" >/dev/null; \
diff -ru --exclude=make_fixtures.py --exclude=__pycache__ testbench/fixtures/graph-sync "$$stage"
endef

# Run the client core on Darwin or Linux. Darwin links Kerberos.framework;
# Linux writes a FILE ccache. test-win covers Windows compilation. An
# unsupported host is reported as skipped, not passed.
UNAME_S := $(shell uname -s)
define step_client_core
(cd client/kerbridge-client \
	&& cargo test $(CARGO_TEST_Q) \
	&& cargo clippy --all-targets -- -D warnings)
endef

# rustls can select aws-lc-rs, which requires CMake and causes musl build
# problems. KerBridge uses ring; reject an additional provider before the
# musl cross-build.
define gate_tls_provider
if cargo tree --workspace -e normal 2>/dev/null | grep -q aws-lc; then \
	echo "aws-lc-rs entered the tree; rustls must stay on ring" >&2; exit 1; \
fi
endef

# Permit one major version of each TLS crate. Multiple majors retain an older
# line that cannot receive fixes released only on the current line.
define gate_tls_majors
for c in rustls ring rustls-webpki; do \
	n=$$(cargo tree --workspace -e normal 2>/dev/null \
	     | grep -oE "(^|[^-a-z])$$c v[0-9]+\.[0-9]+" | grep -oE "[0-9]+\.[0-9]+" | sort -u | wc -l); \
	if [ "$$n" -gt 1 ]; then \
		echo "$$n majors of $$c in the tree; expected 1" >&2; exit 1; \
	fi; \
done
endef

# kbconfig runs before the realm exists and must not access the directory.
# Reject ldap3 so this boundary is structural, not only untested.
define gate_kbconfig_ldap
if cargo tree -p kerbridge-config -e normal 2>/dev/null | grep -q ldap3; then \
	echo "ldap3 entered kerbridge-config's tree; the config tool must not be able to reach the directory" >&2; \
	exit 1; \
fi
endef

# Only kbconfig renders templates from schema metadata. Reject schemars from
# services, especially issuerd, to keep their dependency surfaces narrow.
define gate_schemars
for p in kerbridge-issuerd kerbridge-broker kerbridge-sync kerbridge-manage kerbridge-setup; do \
	if cargo tree -p $$p -e normal 2>/dev/null | grep -q schemars; then \
		echo "schemars entered $$p's tree; only kbconfig renders templates" >&2; exit 1; \
	fi; \
done
endef

# The password feature pulls ring and belongs only in kerbridge-sync and
# kbsetup, which create directory accounts. Check issuerd separately because
# Cargo features are additive across a workspace build.
define gate_issuerd_ring
if cargo tree -p kerbridge-issuerd -e normal 2>/dev/null | grep -qE '(^|[^-a-z])ring v[0-9]'; then \
	echo "ring entered issuerd's tree; only the crates that generate passwords take it" >&2; exit 1; \
fi
endef

# Caddy proxies an allowlist. A missing broker route returns 404 through the
# public endpoint while direct broker tests pass. Replace each route parameter
# with one segment and require the Caddy expression to match it. Keep the
# expression in the syntax shared by RE2 and POSIX ERE. Also reject an empty
# route search, which would make the loop pass without checking a route.
define gate_caddy_routes
re=$$(sed -n 's/^@api path_regexp //p' deploy/caddy/routes.caddyfile); \
[ -n "$$re" ] || { echo "deploy/caddy/routes.caddyfile has no @api path_regexp" >&2; exit 1; }; \
routes=$$(grep -rhoE '\.route\("[^"]+"' crates/kerbridge-broker/src \
          | grep -oE '"/[^"]*"' | tr -d '"' | sed 's/{[^}]*}/x/g'); \
[ -n "$$routes" ] || { echo "no .route(\"...\") under crates/kerbridge-broker/src; this gate greps for them" >&2; exit 1; }; \
for r in $$routes; do \
	printf '%s\n' "$$r" | grep -Eq -- "$$re" || { \
		echo "the broker serves $$r; deploy/caddy/routes.caddyfile does not proxy it" >&2; \
		exit 1; }; \
done
endef

# The tray maps broker 403 reasons to translated messages. The client and
# broker share no crate, so require exact strings in both sources and in
# docs/design/api-and-network.md.
define gate_403_reasons
for s in "account may not authorize a device" "device grants are not enabled" \
         "you may not authorize a device for that account"; do \
	for f in crates/kerbridge-broker/src client/kerbridge-client/src/broker.rs docs/design/api-and-network.md; do \
		grep -rFq -- "$$s" "$$f" || { \
			echo "403 reason \"$$s\" is not in $$f; the tray picks its message from it" >&2; \
			exit 1; }; \
	done; \
done
endef

# provision.sh writes .env and the config set from unquoted heredocs. An
# unquoted heredoc expands three things and only $VAR is wanted, so the other
# two are refused between an unquoted <<EOF and its terminator. shellcheck
# does not see them: a backtick that runs leaves the tier green, printing
# "command not found" and writing the line with a hole in it. A backslash is
# the quiet one -- it eats the character after it, and one before a newline
# joins two lines.
define gate_provision_heredocs
if sed -n '/<<EOF$$/,/^EOF$$/p' deploy/scripts/bench/provision.sh | grep -nE '`|\$$\(|\\'; then \
	echo "the lines above are inside an unquoted heredoc in provision.sh" >&2; \
	echo "a backtick or a \$$( there runs as a command, and a backslash" >&2; \
	echo "rewrites the line -- write it without one, or quote the heredoc" >&2; \
	echo "if it needs no \$$VAR expansion" >&2; \
	exit 1; \
fi
endef

# provision.sh must not depend on one identity source. Otherwise, one tier can
# pass while the shared provisioning code is no longer reusable. Every source
# any tier uses belongs in the pattern, not only the first one.
define gate_provision_source
if grep -inE 'mock-?idp|entra|authentik' deploy/scripts/bench/provision.sh; then \
	echo "the lines above are in deploy/scripts/bench/provision.sh" >&2; \
	echo "shared provisioning code must not name an identity source" >&2; \
	exit 1; \
fi
endef

# In ci-stack.sh, source-specific terms are valid only in comments, SOURCE and
# TENANT declarations, COMPOSE_FILE, and the three idp_* hook bodies. There is
# no counterpart for ci-authentik.sh: that tier states its own source in the
# assertions it prints, so the same gate would refuse prose it is right to
# have. The guard that matters is the one above, on the shared file.
define gate_ci_stack_hooks
body=$$(sed -e '/^idp_prepare()/,/^}$$/d' -e '/^idp_env_lines()/,/^}$$/d' \
	-e '/^idp_source_toml()/,/^}$$/d' -e '/^[[:space:]]*#/d' \
	-e '/^SOURCE=/d' -e '/^TENANT=/d' -e '/^export COMPOSE_FILE=/d' \
	deploy/scripts/bench/ci-stack.sh); \
for line in 'seed-demo.sh' 'PASS -- provisioned'; do \
	printf '%s\n' "$$body" | grep -qF "$$line" || { \
		echo "the idp_* hook ranges include ci-stack.sh's \"$$line\" line" >&2; \
		echo "this check no longer covers the complete tier body; check the closing braces" >&2; \
		exit 1; }; \
done; \
if printf '%s\n' "$$body" | grep -inE 'mock-?idp|entra'; then \
	echo "the lines above are source-specific and sit outside ci-stack.sh's idp_* hooks" >&2; \
	echo "move each one into the applicable hook" >&2; \
	exit 1; \
fi
endef

# Enumerate .sh files from Git so moved scripts remain covered. List scripts
# without a .sh suffix explicitly. Exclude SC1091 for intentional sources of
# .env and /usr/share/debconf/confmodule, which shellcheck cannot follow.
define gate_shellcheck
git ls-files -z '*.sh' | xargs -0 shellcheck -S warning -e SC1091 \
	docs/research/read-result crates/kerbridge-config/libexec/prepare-state \
	debian/make-changelog debian/stage-prebuilt debian/check-install \
	debian/check-manifests \
	debian/kerbridge-config.config \
	debian/kerbridge-config.postinst debian/kerbridge-config.postrm \
	debian/kerbridge-issuerd.postinst debian/kerbridge-issuerd.postrm \
	debian/kerbridge-broker.postinst debian/kerbridge-broker.postrm \
	debian/kerbridge-sync.postinst debian/kerbridge-sync.postrm
endef

# These directives skip a unit with no config and stop restart loops after a
# configuration failure. Daemon tests do not exercise this unit behavior.
define gate_unit_directives
for unit in debian/kerbridge-issuerd.service debian/kerbridge-broker.service \
            debian/kerbridge-sync.service; do \
	for directive in ConditionPathExists StartLimitIntervalSec StartLimitBurst; do \
		grep -q "^$$directive=" "$$unit" || { \
			echo "$$unit has no $$directive=; without all three a failing" >&2; \
			echo "ExecStartPre= restarts every RestartSec= for ever" >&2; \
			exit 1; }; \
	done; \
done
endef

# The three daemons parse arguments without command metadata, so their man
# pages are hand-written. Permit only `--help`; generated pages own current
# flag lists. Remove roff backslashes before searching for escaped hyphens.
define gate_man_flags
for page in debian/man/issuerd.8 debian/man/kerbridge-broker.8 debian/man/kerbridge-sync.8; do \
	[ -f "$$page" ] || { echo "$$page is missing; the package manifest ships it" >&2; exit 1; }; \
	found=$$(tr -d '\\\\' < "$$page" | grep -oE -- '--[a-zA-Z][a-zA-Z0-9-]*' | grep -vx -- '--help' | sort -u); \
	if [ -n "$$found" ]; then \
		echo "$$page names flags a hand-written page cannot keep current: $$found" >&2; \
		echo "Say what the daemon does and point at --help; the generated pages carry the flags." >&2; \
		exit 1; \
	fi; \
	grep -q -- '--help' "$$page" || { echo "$$page does not point the reader at --help" >&2; exit 1; }; \
done
endef

# Require each hand-written parser to keep the `--help` flag named by its man
# page.
define gate_help_parsers
for c in kerbridge-issuerd kerbridge-broker kerbridge-sync; do \
	grep -rq -- '"--help" .*=> return Ok(None)' "crates/$$c/src" || { \
		echo "$$c no longer answers --help, and its man page points at it" >&2; \
		exit 1; }; \
done
endef

# Fast, host-native checks with no Docker or network. Requires rustfmt, clippy,
# shellcheck, zstd, and python3; `make setup` installs the missing test tools.
test-fast:
	$(call section,formatting)
	$(call check,rustfmt in all three workspaces,$(gate_rustfmt))
	$(call section,fixtures)
	$(call check,graph-sync fixtures regenerate identically,$(gate_graph_fixtures))
	@# The authentik corpus has no generator -- it is hand-derived from the
	@# recordings, so it is held to the derivation instead of regenerated.
	$(call check,authentik corpus,python3 testbench/fixtures/authentik-directory/check_derivation.py)
	$(call section,rust)
	$(call step,workspace tests,cargo test --workspace $(CARGO_TEST_Q))
	$(call step,workspace clippy,cargo clippy --workspace --all-targets -- -D warnings)
ifneq ($(filter Darwin Linux,$(UNAME_S)),)
	$(call step,client core,$(step_client_core))
else
	@printf 'skip  client core -- no arm for $(UNAME_S)\n'
endif
	$(call section,dependencies)
	$(call check,tls provider is ring,$(gate_tls_provider))
	$(call check,one major of each tls crate,$(gate_tls_majors))
	$(call check,kbconfig cannot reach the directory,$(gate_kbconfig_ldap))
	$(call check,only kbconfig renders templates,$(gate_schemars))
	$(call check,issuerd takes no password crate,$(gate_issuerd_ring))
	$(call section,cross-source contracts)
	$(call check,caddy proxies every broker route,$(gate_caddy_routes))
	$(call check,403 reasons reach broker client and design,$(gate_403_reasons))
	$(call section,scripts)
	$(call check,provision.sh heredocs stay literal,$(gate_provision_heredocs))
	$(call check,provision.sh names no identity source,$(gate_provision_source))
	$(call check,ci tree preparation,python3 deploy/scripts/bench/test_prepare_ci_tree.py)
	$(call check,entra conformance,python3 testbench/entra-tenant/test_conformance.py)
	$(call check,ci-stack.sh keeps its source in the idp hooks,$(gate_ci_stack_hooks))
	$(call check,shellcheck,$(gate_shellcheck))
	$(call section,docs)
	$(call check,research,python3 docs/scripts/check-research.py)
	$(call check,doc links,python3 docs/scripts/check-doc-links.py)
	$(call check,signing key,python3 docs/scripts/check-signing-key.py)
	@# The reverse proxies allow a route list and 404 the rest, so a route the
	@# broker gained and a proxy did not is a 404 nothing reaching the broker
	@# directly can see.
	$(call check,broker routes,python3 docs/scripts/check-broker-routes.py)
	@# Render every help-site language in memory to detect invalid templates,
	@# renamed fields, and missing translation keys before publication.
	$(call check,website,$(MAKE) -s --no-print-directory -C website check)
	$(call section,deployment)
	@# compose.yaml maps the two environment namespaces. A wrong default starts a
	@# daemon with the wrong limit. Check the mapping without Docker because
	@# `docker compose config` resolves interpolation before inspection.
	$(call check,compose env,python3 deploy/scripts/compose/check-compose-env.py)
	$(call section,packaging)
	$(call check,systemd units carry all three restart directives,$(gate_unit_directives))
	$(call check,man pages name only --help,$(gate_man_flags))
	$(call check,each daemon answers --help,$(gate_help_parsers))
	@# Check duplicated binary names, package names, debhelper compatibility,
	@# version, and latest changelog section without the Docker-based test-deb.
	$(call check,package manifests,debian/check-manifests)
	@printf '\ntest-fast: all checks passed\n'

# Cross-build and lint the Windows client against Win32 FFI. test-fast runs its
# unit tests on the host. Test LSA, ccache injection, and the message loop on a
# Windows client. This target requires MinGW-w64 and the rustup target; `make
# windows` provides the equivalent build in Docker.
test-win:
	$(CLIENT_WIN) check

# Run macOS agent and client-core tests against Kerberos.framework.
test-mac:
	@[ "$$(uname -s)" = Darwin ] || { echo "test-mac: needs a Mac" >&2; exit 1; }
	$(MAKE) -C client/kerbridge-agent-macos check

# Build all shipping artifacts to detect unresolved image digests and musl link
# failures. This is a compile and packaging check, not a runtime test.
# deploy/.env is not required; deploy/Makefile uses .env.example for Compose
# parsing when the deployment file is absent.
test-build: build-docker installer

# Test authentik sign-in and a IdP directory read through an SMB file read.
# This tier uses a disposable project, subnet, port and tree of its own under
# .local-tmp/ -- distinct from test-stack's, so the two can run at once -- and
# pulls pinned external images. `ARGS=--keep` preserves the stack.
test-authentik:
	deploy/scripts/bench/ci-authentik.sh $(ARGS)

# Test sign-in through an SMB file read against a new realm without a tenant or
# secret. The disposable stack uses a separate project, container names, subnet
# and tree under .local-tmp/, so it runs beside a bench and beside the other
# tier. Its HTTPS port defaults to 8443; CI_HTTPS_PORT overrides it, as
# CI_PROJECT, CI_SUBNET and CI_TREE override the rest. ARGS=--keep preserves
# the stack.
test-stack:
	deploy/scripts/bench/ci-stack.sh $(ARGS)

# Build, lint, and install all six Debian packages on each documented release.
# Docker makes this target host-independent. Containers do not run an init
# system, so systemd-analyze verifies units without starting them. Each release
# resolves samba-ad-dc from its own archive, which makes this the slowest and
# most network-dependent tier.
test-deb: debian-docker
	debian/check-install $(DIST)/debian

test-all: test-fast test-win test-build test-authentik test-stack test-deb
