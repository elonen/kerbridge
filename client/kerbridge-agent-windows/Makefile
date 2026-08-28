# Cross-compile the NAS Access systray agent with MinGW-w64. Each Cargo command
# specifies $(TARGET) because the client workspace also builds for the host.
#
# Ship the tray and CLI together. Both use the same `kerbridge-client` library;
# the CLI remains available when troubleshooting the tray.

BIN        := kerbridge-agent
CLI        := kerbridge
MSI        := windows-kerbridge-nas-access-gui-amd64.msi
TARGET     := x86_64-pc-windows-gnu
# Both binaries share the client workspace target directory.
EXE        := ../target/$(TARGET)/release/$(BIN).exe
CLI_EXE    := ../target/$(TARGET)/release/$(CLI).exe
# Keep the generated Windows icon beside its packaging files.
SVG        := ../assets/app-icon.svg
ICO        := ui/icons/app-icon.ico
ICON_SIZES := 16 32 48 64 128 256
TMP        := .local-tmp/icon
DIST       := ../../dist
# Use the crate version as the MSI ProductVersion.
VERSION    := $(shell sed -n '/^\[package\]/,/^\[/ s/^version = "\([^"]*\)".*/\1/p' Cargo.toml | head -1)

.PHONY: all build cli check icon installer clean

all: build

# Use the committed icon so a normal build does not require graphics tools.
build:
	cargo build --release --target $(TARGET)

cli:
	cd ../kerbridge-client && cargo build --release --target $(TARGET)

# Cross-build and lint both crates. The agent has Win32 FFI and a message loop,
# which host tests cannot exercise. `--all-targets` type-checks the client tests
# for Windows; CI has no Wine to run them. The root test target runs them on its
# host platform.
check: build cli
	cargo clippy --release --target $(TARGET) -- -D warnings
	cd ../kerbridge-client && cargo clippy --release --target $(TARGET) --all-targets -- -D warnings

# Regenerate and commit the icon only when the logo changes. This target requires
# rsvg-convert and ImageMagick; normal builds do not.
icon: $(ICO)

$(ICO): $(SVG)
	@mkdir -p $(TMP)
	@for n in $(ICON_SIZES); do rsvg-convert -w $$n -h $$n $(SVG) -o $(TMP)/ico-$$n.png; done
	magick $(foreach n,$(ICON_SIZES),$(TMP)/ico-$(n).png) $(ICO)
	@echo "wrote $(ICO) ($(ICON_SIZES))"

# Build the MSI in Docker so wixl and msitools are not host dependencies. The
# Docker build compiles both executables and does not use the local `build` target.
#
# The publisher signs the MSI during release. Signing its executables separately
# requires split Docker stages; see docs/setup/rough-edges.md.
installer:
	docker build -f Dockerfile --target msi-dist \
	  --build-arg VERSION=$(VERSION) \
	  --output type=local,dest=$(DIST) ../..
	@# Print an absolute path because the root Makefile invokes this target.
	@echo "wrote $(abspath $(DIST))/$(MSI) (version $(VERSION), unsigned)"

clean:
	cargo clean
	rm -rf $(TMP)
