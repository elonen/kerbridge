# kerbridge-agent-macos -- the NAS Access menu-bar agent.
#
# Built natively: an .app has to be assembled on a Mac, and unlike the Windows
# half there is no container that can stand in. `make check` is what CI on a Mac
# runner should run; `make app` produces the bundle a person can actually launch.

BIN     := kerbridge-agent
APP     := NAS Access.app
DIST    := ../../dist
# One version number for the product: the crate's, substituted into Info.plist.
VERSION := $(shell sed -n '/^\[package\]/,/^\[/ s/^version = "\([^"]*\)".*/\1/p' Cargo.toml | head -1)
# The logo is shared with every other platform's packaging; the .icns it is
# rasterized into is a macOS artifact and stays here.
SVG     := ../assets/app-icon.svg
ICNS    := installer/app-icon.icns
ICON_SIZES := 16 32 64 128 256 512 1024
TMP     := .local-tmp/icon

# `app` and `clean` below run `rm -rf "$(DIST)/$(APP)"`, and Make expands an
# unset variable to the empty string without a word: an APP that lost its
# definition makes that `rm -rf ../../dist/`, which is every shipping artifact
# including the MSI. Checked at parse time, so it fails before a recipe runs.
$(if $(strip $(DIST)),,$(error DIST is empty))
$(if $(strip $(APP)),,$(error APP is empty))

.PHONY: all build check app icon clean

all: build

build:
	cargo build --release

# What CI should run for the macOS half. The core's own tests run here too:
# unlike the Windows arms, these link against the real Kerberos.framework and
# libresolv, so they are the thing rather than a compile check.
check: build
	cargo clippy --release --all-targets -- -D warnings
	cargo test
	cd ../kerbridge-client && cargo test

# The bundle. Ad-hoc signed (`-`), because an unsigned binary cannot use
# Notification Center at all and a real Developer ID signature is a release-time
# act by the publisher with a CI secret -- the same split as the unsigned MSI.
app: build $(ICNS)
	rm -rf "$(DIST)/$(APP)"
	mkdir -p "$(DIST)/$(APP)/Contents/MacOS" "$(DIST)/$(APP)/Contents/Resources"
	sed 's/@VERSION@/$(VERSION)/g' installer/Info.plist > "$(DIST)/$(APP)/Contents/Info.plist"
	cp ../target/release/$(BIN) "$(DIST)/$(APP)/Contents/MacOS/"
	cp $(ICNS) "$(DIST)/$(APP)/Contents/Resources/app-icon.icns"
	codesign --force --deep --sign - "$(DIST)/$(APP)"
	@echo "wrote $(abspath $(DIST))/$(APP) (version $(VERSION), ad-hoc signed)"

# Regenerate bundle icon from SVG. Separate from `app` on purpose: only
# needed when the logo changes, and it pulls in rsvg-convert. Commit the result.
icon: $(ICNS)

$(ICNS): $(SVG)
	@rm -rf $(TMP) && mkdir -p $(TMP)/app-icon.iconset
	@for n in $(ICON_SIZES); do \
		rsvg-convert -w $$n -h $$n $(SVG) -o $(TMP)/app-icon.iconset/icon_$${n}x$${n}.png; \
		rsvg-convert -w $$(($$n * 2)) -h $$(($$n * 2)) $(SVG) \
			-o $(TMP)/app-icon.iconset/icon_$${n}x$${n}@2x.png; \
	done
	@# iconutil rejects sizes outside the set it knows, so drop the two the
	@# loop above produces that it does not want.
	@rm -f $(TMP)/app-icon.iconset/icon_1024x1024@2x.png $(TMP)/app-icon.iconset/icon_64x64@2x.png
	iconutil -c icns -o $(ICNS) $(TMP)/app-icon.iconset
	@echo "wrote $(ICNS)"

clean:
	cargo clean
	rm -rf $(TMP) "$(DIST)/$(APP)"
