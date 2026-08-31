# Build the NAS Access menu-bar agent on macOS. `make check` is the CI target;
# `make app` creates the application bundle.

BIN     := kerbridge-agent
APP     := NAS Access.app
# The bundle is arm64-only, so the release asset name includes the architecture.
ZIP     := macos-kerbridge-nas-access-gui-arm64.app.zip
DIST    := ../../dist
# Use the crate version in Info.plist.
VERSION := $(shell sed -n '/^\[package\]/,/^\[/ s/^version = "\([^"]*\)".*/\1/p' Cargo.toml | head -1)
# Keep the generated macOS icon beside its packaging files.
SVG     := ../assets/app-icon.svg
ICNS    := installer/app-icon.icns
ICON_SIZES := 16 32 64 128 256 512 1024
TMP     := .local-tmp/icon

# An empty name makes `rm -rf` target ../../dist/. Reject empty path components
# before a recipe can remove all release artifacts.
$(if $(strip $(DIST)),,$(error DIST is empty))
$(if $(strip $(APP)),,$(error APP is empty))
$(if $(strip $(ZIP)),,$(error ZIP is empty))

.PHONY: all build check app zip icon clean

all: build

build:
	cargo build --release

# Cargo tests print one character per test. KB_TEST_VERBOSE=1 restores the
# per-test name list.
CARGO_TEST_Q := $(if $(KB_TEST_VERBOSE),,--quiet)

# Run core tests against Kerberos.framework and libresolv, not platform stubs.
check: build
	cargo clippy --release --all-targets -- -D warnings
	cargo test $(CARGO_TEST_Q)
	cd ../kerbridge-client && cargo test $(CARGO_TEST_Q)

# Apply an ad-hoc signature because Notification Center rejects unsigned
# binaries. The publisher applies the Developer ID signature during release.
app: build $(ICNS)
	rm -rf "$(DIST)/$(APP)"
	mkdir -p "$(DIST)/$(APP)/Contents/MacOS" "$(DIST)/$(APP)/Contents/Resources"
	sed 's/@VERSION@/$(VERSION)/g' installer/Info.plist > "$(DIST)/$(APP)/Contents/Info.plist"
	cp ../target/release/$(BIN) "$(DIST)/$(APP)/Contents/MacOS/"
	cp $(ICNS) "$(DIST)/$(APP)/Contents/Resources/app-icon.icns"
	codesign --force --deep --sign - "$(DIST)/$(APP)"
	@echo "wrote $(abspath $(DIST))/$(APP) (version $(VERSION), ad-hoc signed)"

# Use `ditto` because `zip -r` does not preserve a verifiable bundle signature.
zip: app
	rm -f "$(DIST)/$(ZIP)"
	ditto -c -k --keepParent "$(DIST)/$(APP)" "$(DIST)/$(ZIP)"
	@echo "wrote $(abspath $(DIST))/$(ZIP)"

# Regenerate and commit the icon only when the logo changes. This target requires
# rsvg-convert; normal application builds do not.
icon: $(ICNS)

$(ICNS): $(SVG)
	@rm -rf $(TMP) && mkdir -p $(TMP)/app-icon.iconset
	@for n in $(ICON_SIZES); do \
		rsvg-convert -w $$n -h $$n $(SVG) -o $(TMP)/app-icon.iconset/icon_$${n}x$${n}.png; \
		rsvg-convert -w $$(($$n * 2)) -h $$(($$n * 2)) $(SVG) \
			-o $(TMP)/app-icon.iconset/icon_$${n}x$${n}@2x.png; \
	done
	@# iconutil rejects these generated sizes.
	@rm -f $(TMP)/app-icon.iconset/icon_1024x1024@2x.png $(TMP)/app-icon.iconset/icon_64x64@2x.png
	iconutil -c icns -o $(ICNS) $(TMP)/app-icon.iconset
	@echo "wrote $(ICNS)"

clean:
	cargo clean
	rm -rf $(TMP) "$(DIST)/$(APP)" "$(DIST)/$(ZIP)"
