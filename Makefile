# Top-level build. `make` (the default rule) builds the whole product in Docker,
# so a clean Linux host with only Docker installed can build everything -- no
# local Rust or MinGW toolchain. Developers can still run cargo directly in each
# crate; that path is unchanged and unaffected.
#
#   docker   -- the KerBridge server stack images (realm, broker, member, sync),
#               each compiling its Rust binary inside the image.
#   windows  -- the Windows client bits (CLI kerbridge.exe + tray
#               kerbridge-agent.exe), cross-compiled in a container to
#               x86_64-pc-windows-gnu and written to dist/.
#   installer-- the same two exes packaged as
#               dist/windows-kerbridge-nas-access-gui-amd64.msi. Not part of
#               the default build: it is what a release ships, and it is
#               unsigned until the publisher signs it.
#   macos    -- dist/NAS Access.app, the menu-bar agent. Not part of the default
#               build and not containerized: an .app is assembled on a Mac.
#               `macos-zip` is the same bundle as the single file a release
#               attaches. Both are arm64, and unsigned beyond the ad-hoc
#               signature Notification Center needs.
#   kbmanage -- the operator CLI, a static musl binary in dist/, built for the
#               build host's architecture by default. Not a service, so it has no
#               compose entry: `docker compose build` never exports to the host,
#               and this must. Cross-build with
#               `make kbmanage KBMANAGE_PLATFORM=linux/amd64`, which is emulated
#               and therefore slow -- see deploy/kbmanage/Dockerfile for why
#               there is no cross-compilation. Exported with kbconfig in one
#               step, off the stage that builds the debs.
#   kbconfig -- the configuration CLI, same platform variable, same export.
#               A separate binary on purpose: it links no LDAP client, and it is
#               what bootstrap reads the config set with, before kbmanage has a
#               directory to talk to.
#   debian-docker
#            -- the six .deb files in dist/debian/, for the other deployment.
#               Not part of the default build, for the same reason `installer`
#               is not: it is what a release ships. Nothing about it runs on the
#               host -- see debian/Dockerfile.
#
# Everything about the Compose stack -- building its images, bootstrapping its
# secrets and directory, running it -- lives in deploy/Makefile and is delegated
# to from here, because compose must be invoked from that directory.

DIST := dist
DEPLOY := $(MAKE) -C deploy
# The Windows agent's Makefile owns the packaging; targets here delegate to it
# for the same reason deploy/ does -- both must run from their own directory.
CLIENT_WIN := $(MAKE) -C client/kerbridge-agent-windows

.DEFAULT_GOAL := build-docker
.PHONY: all build-docker build-local docker windows macos macos-zip installer kbmanage kbconfig cli-dist debian-docker up down \
        clean clean-docker-images clean-docker-volumes \
        setup setup-rustfmt setup-clippy setup-tools \
        test test-fast test-win test-mac test-build test-stack test-deb test-all

# `all` is the old name for the containerized build; keep it working.
all: build-docker
build-docker: docker windows kbmanage kbconfig

# Host-native build of the server crates, for the development loop -- a macOS or
# arm64 host building a kbmanage it can run against the bench over the LDAPS port
# compose now publishes. DEVELOPMENT ONLY: production binaries are the
# x86_64-musl rebuilds above. The Windows cross-compile
# stays in Docker either way; MinGW is not a host dependency this repo takes on.
build-local:
	cargo build --release --workspace

docker:
	$(DEPLOY) build

# Cross-compile both exes in a container (the Windows agent's Dockerfile) and copy
# just the .exes out to $(DIST)/. No local Rust or MinGW needed.
windows:
	docker build -f client/kerbridge-agent-windows/Dockerfile --target dist --output type=local,dest=$(DIST) .
	ls -l $(DIST)

# The MSI, also in Docker (wixl + msitools, never a Windows machine). It compiles
# both exes itself, so it does not depend on `windows` and does not reuse its
# output. UNSIGNED -- see docs/setup/rough-edges.md.
installer:
	$(CLIENT_WIN) installer
	ls -l $(DIST)

# The macOS agent bundle. Native, not containerized: an .app is assembled on a
# Mac. Refuses elsewhere rather than producing something that cannot run.
macos:
	@[ "$$(uname -s)" = Darwin ] || { echo "macos: needs a Mac" >&2; exit 1; }
	$(MAKE) -C client/kerbridge-agent-macos app
	ls -l $(DIST)

# The same bundle as one file, which is what a release ships. Separate from
# `macos`: a developer wants an .app to launch, not an archive to unpack.
macos-zip:
	@[ "$$(uname -s)" = Darwin ] || { echo "macos-zip: needs a Mac" >&2; exit 1; }
	$(MAKE) -C client/kerbridge-agent-macos zip
	ls -l $(DIST)

# Defaults to the build host's platform, matching the four service images and the
# reasoning that a native stack is right for a cloned-repo deployment. Override to
# build for a different server: KBMANAGE_PLATFORM=linux/amd64.
KBMANAGE_PLATFORM ?= $(shell docker version --format '{{.Server.Os}}/{{.Server.Arch}}' 2>/dev/null)

# Both CLIs come out of debian/Dockerfile's `build` stage in one export, so
# either target name writes both files. `docker` runs before them in
# `build-docker`, which leaves that stage in the layer cache -- this copies from
# it rather than compiling again.
kbmanage kbconfig: cli-dist
cli-dist:
	docker buildx build -f debian/Dockerfile --platform=$(KBMANAGE_PLATFORM) \
	  --target cli-dist --output type=local,dest=$(DIST) .
	@file $(DIST)/kbmanage $(DIST)/kbconfig 2>/dev/null | sed 's/^/built /' || true

# The six debs, in Docker from end to end: the static musl binaries in the
# pinned toolchain that ships them, then dpkg-buildpackage and lintian on
# trixie. Nothing here runs on the host, which is why it works on a Mac --
# debian/stage-prebuilt, debian/make-changelog and the maintainer scripts are
# all GNU/Debian shell and are never asked to be anything else.
#
# The version is derived on the host and passed in, so the image build needs no
# `.git` in its context -- 22 MB of it, and a cache miss on every commit.
# `--print-version` is make-changelog's own derivation, so there is one copy of
# it. Recursively expanded, so `git describe` runs only for the targets that
# use it. Override for a tree whose tags are not reachable:
# `make debian-docker KB_VERSION=0.10.0`.
#
# One architecture per run, the build host's. KBMANAGE_PLATFORM is deliberately
# not reused here: emulating six crate compiles is slow enough that
# cross-building wants an answer of its own.
KB_VERSION ?= $(shell debian/make-changelog --print-version)

# Extra flags for the `docker buildx build` call below, empty on a developer's
# machine and set by CI. BuildKit keeps a layer cache per builder, which a fresh
# runner does not have, so every CI run recompiles the six crates from cold
# unless it is handed one: `make debian-docker DOCKER_CACHE='--cache-from
# type=local,... --cache-to type=local,...'`, with actions/cache carrying the
# directory between runs. Nothing here depends on it -- an unset value builds
# exactly as before.
#
# `buildx build`, not `build`: `docker build` pins the default builder, whose
# docker driver cannot export a cache. buildx uses the selected builder, which
# docker/setup-buildx-action makes a docker-container one in CI.
DOCKER_CACHE ?=
debian-docker:
	@# Emptied first. The version is part of every filename, so a second run
	@# adds a generation rather than replacing one, and `apt-get install
	@# ./*.deb` then names two versions of all six packages.
	rm -rf $(DIST)/debian
	docker buildx build -f debian/Dockerfile --build-arg KB_VERSION=$(KB_VERSION) \
	  $(DOCKER_CACHE) --target dist --output type=local,dest=$(DIST)/debian .
	@ls -l $(DIST)/debian

# A fresh clone to a running stack: generate the host-side secrets, provision the
# DC, bootstrap the directory, start the rest. See deploy/Makefile.
#
# NAS=1 reaches deploy/ from here too, and adds `nas1` -- which
# takes the DC's published :445 with it, so no file server elsewhere can join a
# realm running it. docs/setup/file-server.md is the real thing.
up:
	$(DEPLOY) up

# The counterpart to `up`, and what docs/setup/broker-host.md and backup.sh both
# tell you to run before taking a backup -- neither from deploy/.
down:
	$(DEPLOY) down

# Host build output only: the three cargo target directories and dist/. Docker is
# reported, never touched -- `clean` used to run `docker compose down --rmi
# local`, so reclaiming disk space also stopped a running realm.
#
# `rm -rf` rather than `cargo clean`, for the reason at the top of this file: a
# host with only Docker can build everything here, and it must be able to clean
# up after itself too. .local-tmp/ is deliberately left -- `make test-stack
# ARGS=--keep` leaves a stack running out of a tree under it, and removing the
# tree would strand those containers exactly as the old `clean` stranded nas1.
clean:
	rm -rf $(DIST) target client/target
	@$(DEPLOY) clean-report

# The two Docker rungs, each reached deliberately. See deploy/scripts/compose/clean.sh.
# `make clean-docker-volumes YES=1` skips the typed confirmation, for scripts.
clean-docker-images:
	$(DEPLOY) clean-docker-images

clean-docker-volumes:
	$(DEPLOY) clean-docker-volumes

# ---- developer setup -------------------------------------------------------
# What `make test` needs on the host beyond `cargo` itself, and what nothing
# else installs for you. Deliberately not a prerequisite of `test` or of any
# build target: this installs software, and a test run that reaches for the
# package manager on its own is a test run that does something different on the
# machine it has already been run on. Call it by hand, once per host:
#
#   make setup
#
# Assumes cargo, rustc and python3 are already here. rustup is used when it is
# present -- it owns the toolchain on a machine that has it, so a component
# belongs to it rather than to the distribution's packages.

setup: setup-rustfmt setup-clippy setup-tools

# $(1) the cargo subcommand it provides, $(2) the rustup component name,
# $(3) the Debian package. Verifying afterwards is not a formality: cargo
# resolves a subcommand from $$CARGO_HOME/bin before $$PATH, so an old
# `cargo install` of the same name goes on shadowing the toolchain's copy after
# any install here succeeds -- and the abandoned crates.io `rustfmt` answers
# `--check` by printing its usage and exiting 0. A gate that passes without
# reading a single file is worse than no gate.
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

# `make test-fast` opens with `cargo fmt --check`, and rustfmt is not part of a
# bare Rust install: rustup keeps it as a separate component, distributions
# split it into its own package. So a host with cargo and rustc can still have
# no formatter -- a failing `make test`, not a skipped check, because cargo-fmt
# exits non-zero when it cannot find rustfmt.
setup-rustfmt:
	$(call install_rust_component,fmt,rustfmt,rustfmt)

# The line after it, and split off the same way.
setup-clippy:
	$(call install_rust_component,clippy,clippy,rust-clippy)

# The two non-Rust tools test-fast runs: shellcheck lints every script the
# repository ships, and the research check reads the compressed spike archives
# with zstd -- it reports a missing zstd as an archive error, which reads like a
# broken archive rather than a missing tool.
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

# ---- tests -----------------------------------------------------------------
# Five tiers, cheapest first, because they need progressively more of the world:
# nothing, a cross-compiler, Docker, a provisioned realm, four distro releases.
# `make test` is the one to run constantly; CI runs each tier as its own job
# (.github/workflows/ci.yml).
#
# What none of them reach, and what therefore still has to be checked by hand:
# the live Entra tenant (Graph, delta, real tokens), the acme TLS strategies, and
# everything the Windows client does with a ticket once it has one.

test: test-fast

# No Docker, no network, nothing this host cannot already do -- but more than a
# bare Rust install: rustfmt, clippy, shellcheck, zstd, python3. `make setup`
# puts them there, and no other target does. Seconds.
test-fast:
	@# All three workspaces: rustfmt.toml sits at the repo root and both nested
	@# workspaces are under it, so one config governs three `cargo fmt` runs.
	@# Parses only, so it holds on any host -- including the Windows and macOS
	@# agent crates, which this host cannot build.
	cargo fmt --all --check
	cd client && cargo fmt --all --check
	cd website && cargo fmt --all --check
	cargo test --workspace
	cargo clippy --workspace --all-targets -- -D warnings
	@# The client core, for whatever host this is. Darwin and Linux both have an
	@# arm at every #[cfg] seam, so these tests link Kerberos.framework on a Mac
	@# and write a real FILE: ccache on Linux. The Linux arm proves the
	@# platform-neutral majority; client/kerbridge-client/src/linux/os.rs says
	@# what a green run there does *not* prove. `make test-win` owns everything
	@# Windows-observable either way.
	@#
	@# A host with no arm -- FreeBSD, Windows -- is skipped out loud: a tier that
	@# cannot run says so rather than passing quietly.
	@case "$$(uname -s)" in \
		Darwin|Linux) cd client/kerbridge-client && cargo test \
		              && cargo clippy --all-targets -- -D warnings ;; \
		*) echo "skipped: the client core has no arm for $$(uname -s)" ;; \
	esac
	@# The crypto provider is a property of the build, not of the source, and
	@# rustls selects aws-lc-rs unless told otherwise -- it needs cmake and
	@# fights musl. kerbridge-core::tls names ring at the call, so a stray
	@# provider costs build weight rather than correctness; still cheaper to
	@# refuse it here than to discover it in a musl cross-build.
	@if cargo tree --workspace -e normal 2>/dev/null | grep -q aws-lc; then \
		echo "FAIL: aws-lc-rs entered the tree; rustls must stay on ring" >&2; exit 1; \
	fi
	@# One rustls, one ring, one webpki. Two majors of a TLS crate means one of
	@# them is the older line, and the older line reaches end-of-life with
	@# advisories whose fixes ship only on the newer one -- leaving nothing to
	@# update to. Cheap to assert, expensive to notice late.
	@for c in rustls ring rustls-webpki; do \
		n=$$(cargo tree --workspace -e normal 2>/dev/null \
		     | grep -oE "(^|[^-a-z])$$c v[0-9]+\.[0-9]+" | grep -oE "[0-9]+\.[0-9]+" | sort -u | wc -l); \
		if [ "$$n" -gt 1 ]; then \
			echo "FAIL: $$n majors of $$c in the tree; expected 1" >&2; exit 1; \
		fi; \
	done
	@# kbconfig runs during bootstrap, before the realm exists, and has no
	@# directory rights and no way to acquire any. What enforces that is the
	@# absence of an LDAP client rather than a rule someone remembers: with no
	@# ldap3 in its tree, directory reach is unavailable rather than merely
	@# unexercised. A structural boundary nothing checks will not hold.
	@if cargo tree -p kerbridge-config -e normal 2>/dev/null | grep -q ldap3; then \
		echo "FAIL: ldap3 entered kerbridge-config's tree; the config tool must not be able to reach the directory" >&2; exit 1; \
	fi
	@# The `schema` feature of kerbridge-core and kerbridge-idp is what renders a
	@# template from the parser's own description of itself. Only kbconfig asks
	@# that question. issuerd holds KDC authority and must not widen its
	@# dependency surface for a question it never asks, and the services that run
	@# beside it have no reason to either. Same rule as ldap3 above: a boundary
	@# nothing checks will not hold.
	@for p in kerbridge-issuerd kerbridge-broker kerbridge-sync kerbridge-manage kerbridge-setup; do \
		if cargo tree -p $$p -e normal 2>/dev/null | grep -q schemars; then \
			echo "FAIL: schemars entered $$p's tree; only kbconfig renders templates" >&2; exit 1; \
		fi; \
	done
	@# The `password` feature of kerbridge-core is the third of these, and the one
	@# that pulls `ring`. Only the two programs that create directory accounts --
	@# kerbridge-sync and kbsetup -- turn it on. issuerd creates none, holds KDC
	@# authority, and is the crate DESIGN.md's rule about kerbridge-core's
	@# dependency surface exists to protect. A feature is additive across a
	@# workspace build, so the boundary is a per-crate resolution and this is what
	@# checks it.
	@if cargo tree -p kerbridge-issuerd -e normal 2>/dev/null | grep -qE '(^|[^-a-z])ring v[0-9]'; then \
		echo "FAIL: ring entered issuerd's tree; only the crates that generate passwords take it" >&2; exit 1; \
	fi
	@# Caddy is the only public entrypoint and proxies an allowlist, so a route
	@# the broker serves and that list omits is a 404 in every deployment while
	@# every test that reaches the broker directly still passes. Each route is
	@# turned into a sample path -- every `{param}` becomes one segment -- and the
	@# allowlist has to match it. Caddy is RE2 and this is POSIX ERE; the
	@# expression stays inside what both read the same way.
	@# The whole crate is searched, and finding no route at all is a failure: this
	@# gate is a loop over what the grep returns, so a router that moved or a
	@# spelling it stopped matching would otherwise pass it by checking nothing.
	@re=$$(sed -n 's/^@api path_regexp //p' deploy/caddy/routes.caddyfile); \
	[ -n "$$re" ] || { echo "FAIL: deploy/caddy/routes.caddyfile has no @api path_regexp" >&2; exit 1; }; \
	routes=$$(grep -rhoE '\.route\("[^"]+"' crates/kerbridge-broker/src \
	          | grep -oE '"/[^"]*"' | tr -d '"' | sed 's/{[^}]*}/x/g'); \
	[ -n "$$routes" ] || { echo "FAIL: no .route(\"...\") under crates/kerbridge-broker/src; this gate greps for them" >&2; exit 1; }; \
	for r in $$routes; do \
		printf '%s\n' "$$r" | grep -Eq -- "$$re" || { \
			echo "FAIL: the broker serves $$r; deploy/caddy/routes.caddyfile does not proxy it" >&2; \
			exit 1; }; \
	done
	@# The tray branches on the broker's 403 reasons to decide which of eleven
	@# translated sentences a user sees, and the client shares no crate with the
	@# broker to spell them once. A reword on one side would silently start
	@# telling people to solve the wrong problem, so both sources and the table
	@# in docs/design/api-and-network.md have to carry the same string.
	@for s in "account may not authorize a device" "device grants are not enabled" \
	          "you may not authorize a device for that account"; do \
		for f in crates/kerbridge-broker/src client/kerbridge-client/src/broker.rs docs/design/api-and-network.md; do \
			grep -rFq -- "$$s" "$$f" || { \
				echo "FAIL: 403 reason \"$$s\" is not in $$f; the tray picks its message from it" >&2; \
				exit 1; }; \
		done; \
	done
	@# Every shell script the repository ships. Enumerated from git, not globbed:
	@# a glob silently stops covering a script that moves into a subdirectory.
	@# read-result, prepare-state and everything under debian/ are listed by
	@# hand because none of them has a .sh -- one is a research helper, one is a
	@# program installed to /usr/libexec/kerbridge/, and the rest are
	@# maintainer scripts and packaging helpers whose names dpkg and debhelper
	@# fix. SC1091 is `. ./.env` and `. /usr/share/debconf/confmodule`, neither
	@# of which shellcheck can follow and both of which are done on purpose.
	git ls-files -z '*.sh' | xargs -0 shellcheck -S warning -e SC1091 \
		docs/research/read-result crates/kerbridge-config/libexec/prepare-state \
		debian/make-changelog debian/stage-prebuilt debian/check-install \
		debian/check-manifests \
		debian/kerbridge-config.config \
		debian/kerbridge-config.postinst debian/kerbridge-config.postrm \
		debian/kerbridge-issuerd.postinst debian/kerbridge-issuerd.postrm \
		debian/kerbridge-broker.postinst debian/kerbridge-broker.postrm \
		debian/kerbridge-sync.postinst debian/kerbridge-sync.postrm
	python3 docs/scripts/check-research.py
	python3 docs/scripts/check-doc-links.py
	python3 docs/scripts/check-signing-key.py
	@# The help site renders every language from the client's own string tables,
	@# so a renamed field, a template that no longer compiles, or a translation
	@# missing a key all fail here rather than at publish time. Renders to memory
	@# and writes nothing.
	$(MAKE) -C website check
	@# `compose.yaml` is the only translation between the two environment
	@# namespaces, and a wrong default in it does not fail -- the daemon starts
	@# with the wrong ceiling. Docker-free on purpose: `docker compose config`
	@# would do the interpolation, and a check that runs only where Docker does
	@# is a check that does not run here.
	python3 deploy/scripts/compose/check-compose-env.py
	@# Three directives keep a unit from looping, and no test that runs a daemon
	@# can see them: with no config set the unit is meant to be skipped, and with
	@# a broken one to reach `failed` and stay there.
	@for unit in debian/kerbridge-issuerd.service debian/kerbridge-broker.service \
	             debian/kerbridge-sync.service; do \
		for directive in ConditionPathExists StartLimitIntervalSec StartLimitBurst; do \
			grep -q "^$$directive=" "$$unit" || { \
				echo "FAIL: $$unit has no $$directive=; without all three a failing" >&2; \
				echo "      ExecStartPre= restarts every RestartSec= for ever" >&2; \
				exit 1; }; \
		done; \
	done
	@# Three of the eighteen man pages are hand-written, because the three
	@# daemons parse their arguments by hand and there is no command definition
	@# to render one from. The other fifteen are generated at build time and
	@# cannot go stale; these can, and the way they would is by naming a flag
	@# that later changes. So they name exactly one: `--help`, which is where a
	@# reader goes for the current set.
	@#
	@# Backslashes are stripped first, because roff writes a hyphen as `\-` and
	@# a page could otherwise smuggle one past a plain grep.
	@for page in debian/man/issuerd.8 debian/man/kerbridge-broker.8 debian/man/kerbridge-sync.8; do \
		[ -f "$$page" ] || { echo "FAIL: $$page is missing; the package manifest ships it" >&2; exit 1; }; \
		found=$$(tr -d '\\\\' < "$$page" | grep -oE -- '--[a-zA-Z][a-zA-Z0-9-]*' | grep -vx -- '--help' | sort -u); \
		if [ -n "$$found" ]; then \
			echo "FAIL: $$page names flags a hand-written page cannot keep current: $$found" >&2; \
			echo "      Say what the daemon does and point at --help; the generated pages carry the flags." >&2; \
			exit 1; \
		fi; \
		grep -q -- '--help' "$$page" || { echo "FAIL: $$page does not point the reader at --help" >&2; exit 1; }; \
	done
	@# And the premise those pointers rest on: that each daemon answers --help.
	@# These three parse their arguments by hand, so nothing but this stops the
	@# flag being dropped from under the pages that name it.
	@for c in kerbridge-issuerd kerbridge-broker kerbridge-sync; do \
		grep -rq -- '"--help" .*=> return Ok(None)' "crates/$$c/src" || { \
			echo "FAIL: $$c no longer answers --help, and its man page points at it" >&2; \
			exit 1; }; \
	done
	@# Five values that two files each must agree about, and that nothing
	@# derives: the binaries, the package names, the debhelper compat level, the
	@# version, and the newest CHANGELOG.md section. `make test-deb` finds the
	@# same defects, but it needs Docker and ten minutes to reach them.
	debian/check-manifests

# The Windows client, as a Windows artifact: a clean cross-build plus clippy. What
# it covers that `test-fast` cannot is the link -- that the real x86_64-pc-windows-gnu
# binary builds against the Win32 FFI, which no host target exercises. The unit
# tests themselves are run by `test-fast`, on the host; LSA, ccache injection and
# the message loop remain untestable anywhere and have to be checked on a real
# client by hand. Needs MinGW-w64
# (`brew install mingw-w64` / `apt-get install mingw-w64`) and the rustup target;
# `make windows` does the same build in Docker if you would rather not have them.
test-win:
	$(CLIENT_WIN) check

# The macOS half, on a Mac. Includes the client core's own tests, which link the
# real Kerberos.framework there rather than compiling against a stub.
test-mac:
	@[ "$$(uname -s)" = Darwin ] || { echo "test-mac: needs a Mac" >&2; exit 1; }
	$(MAKE) -C client/kerbridge-agent-macos check

# Every shipping artifact still builds: the four service images, both .exes, the
# operator CLI and the MSI. A compile and packaging gate, not a test -- but it is
# the only thing that notices a pinned digest that no longer resolves, or a
# dependency that stopped linking against musl.
#
# Needs no deploy/.env: nothing in it affects what is compiled, and deploy's
# COMPOSE_ENV_FILES falls back to .env.example for the parse compose insists on
# -- see the comment there for why compose cannot be handed an absent file.
test-build: build-docker installer

# The whole server path against a realm provisioned from nothing: sign-in proof
# to a file read over SMB, with no tenant and no secret. Minutes.
#
# Runs beside your bench: a disposable copy of the tree under .local-tmp/, with
# its own compose project, container names and subnet. The HTTPS port is shared
# -- this and compose.mockidp.yaml both default to 8443; CI_HTTPS_PORT overrides.
# `make test-stack ARGS=--keep` leaves the stack running afterwards.
test-stack:
	deploy/scripts/bench/ci-stack.sh $(ARGS)

# The other deployment: the six .deb files, on every release the docs make a
# claim about. `debian-docker` is half the tier -- lintian runs inside that
# image, so a package that does not lint never reaches here -- and
# `debian/check-install` is the other half, which installs what it built.
#
# Docker from end to end, so it runs on a Mac, and no init runs inside any of
# the four containers. `systemd-analyze verify` is therefore the whole of what
# this says about the units; starting one is a surface no tier reaches.
#
# Slowest of the five, and the one that needs the network most: four releases,
# each resolving samba-ad-dc from its own archive.
test-deb: debian-docker
	debian/check-install $(DIST)/debian

test-all: test-fast test-win test-build test-stack test-deb
