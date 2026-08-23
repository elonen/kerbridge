# kerbridge-agent-windows -- the NAS Access systray agent.
# Cross-compiled to Windows with MinGW-w64 (linker in ../.cargo/config.toml); no
# MSVC. Every cargo line names $(TARGET): the core builds for the host too now,
# so the target is no longer implied by a per-crate pin.
#
# `deploy` ships BOTH binaries: the tray is the product, and the CLI next to it is
# the escape hatch for when the tray is what you suspect. They link the same
# `kerbridge-client` library, so they cannot disagree about the protocol.

# The binary name is not the crate name -- see the [[bin]] block in Cargo.toml.
BIN        := kerbridge-agent
CLI        := kerbridge
MSI        := kerbridge-nas-access.msi
TARGET     := x86_64-pc-windows-gnu
# One target directory for the whole client workspace (../Cargo.toml), so the
# agent links a core the CLI build already compiled.
EXE        := ../target/$(TARGET)/release/$(BIN).exe
CLI_EXE    := ../target/$(TARGET)/release/$(CLI).exe
# The logo is shared with every other platform's packaging; the .ico it is
# rasterized into is a Windows artifact and stays here.
SVG        := ../assets/app-icon.svg
ICO        := ui/icons/app-icon.ico
ICON_SIZES := 16 32 48 64 128 256
TMP        := .local-tmp/icon
# Where the top-level Makefile already puts the shipping Windows bits.
DIST       := ../../dist
# The MSI's ProductVersion is the crate version -- one version number for the
# product, not a second one maintained in the installer.
VERSION    := $(shell sed -n '/^\[package\]/,/^\[/ s/^version = "\([^"]*\)".*/\1/p' Cargo.toml | head -1)

.PHONY: all build cli check icon installer clean

all: build

# The Windows exe. Uses the committed $(ICO) as an embedded resource; it does NOT
# regenerate the icon, so a normal build needs only the Rust/MinGW toolchain.
build:
	cargo build --release --target $(TARGET)

cli:
	cd ../kerbridge-client && cargo build --release --target $(TARGET)

# What CI should run for the Windows half. There is nothing to `cargo test` here
# -- the crate is Win32 FFI and a message loop, neither of which a host test can
# exercise -- so the gate is a clean cross-build plus clippy on both crates.
#
# `kerbridge-client` gets --all-targets, which also typechecks its unit tests
# against the Windows arms. They cannot be *run* by this target: there is no wine
# in CI. Compiling them is what stops the Windows side rotting silently, and the
# host `cargo test` in the root Makefile is what actually runs them.
check: build cli
	cargo clippy --release --target $(TARGET) -- -D warnings
	cd ../kerbridge-client && cargo clippy --release --target $(TARGET) --all-targets -- -D warnings

# Regenerate the embedded app icon from the SVG. Separate from `build` on purpose:
# only needed when the logo changes, and it pulls in rsvg-convert + ImageMagick.
# Commit the resulting $(ICO); build.rs re-embeds it (rerun-if-changed).
icon: $(ICO)

$(ICO): $(SVG)
	@mkdir -p $(TMP)
	@for n in $(ICON_SIZES); do rsvg-convert -w $$n -h $$n $(SVG) -o $(TMP)/ico-$$n.png; done
	magick $(foreach n,$(ICON_SIZES),$(TMP)/ico-$(n).png) $(ICO)
	@echo "wrote $(ICO) ($(ICON_SIZES))"

# The shipping MSI. Unlike every other target here
# this one goes through Docker: it needs wixl and msitools, which are not host
# dependencies this repo takes on -- and building it the same way CI does is the
# point, since the whole chain is meant to run on a Linux runner. It compiles both
# exes itself (the Dockerfile's `build` stage), so it does not use `make build`.
#
# The result is UNSIGNED. Signing is a release-time act by the publisher, with a
# CI secret. Note the exes are packaged in the same Docker build, so signing them
# (not just the .msi) needs the stages split -- see docs/setup/rough-edges.md.
installer:
	docker build -f Dockerfile --target msi-dist \
	  --build-arg VERSION=$(VERSION) \
	  --output type=local,dest=$(DIST) ../..
	@# abspath, because the root Makefile forwards here and "../../dist" would
	@# be read relative to wherever `make` was invoked.
	@echo "wrote $(abspath $(DIST))/$(MSI) (version $(VERSION), unsigned)"

clean:
	cargo clean
	rm -rf $(TMP)
