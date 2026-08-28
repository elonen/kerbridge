# Build help.kerbridge.org into the untracked `dist/` tree. Source icons from
# agent drawing constants, labels from client string tables, screenshots from
# ../docs, and prose from content/*.toml.

ifeq ($(strip $(CURDIR)),)
$(error CURDIR must not be empty)
endif

ROOT  := $(CURDIR)/..
ICONS := $(CURDIR)/.build/icons

.PHONY: all icons check serve clean

all: icons
	cargo run --quiet --manifest-path $(CURDIR)/Cargo.toml

# Generate icons from `icon.rs` and both agent compositors to keep them equal to
# the product output.
icons:
	python3 $(ROOT)/docs/scripts/make-state-icons.py --out $(ICONS)

# Render all eleven languages without writing files. Fail on invalid templates,
# missing translation keys, or unknown client string fields.
check: icons
	cargo run --quiet --manifest-path $(CURDIR)/Cargo.toml -- --check

serve: all
	@echo "http://localhost:8000/  (Ctrl-C to stop)"
	cd $(CURDIR)/dist && python3 -m http.server 8000

clean:
	rm -rf $(CURDIR)/dist $(CURDIR)/.build $(CURDIR)/target
