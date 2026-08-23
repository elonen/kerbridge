# The user help site: help.kerbridge.org.
#
# `dist/` is the deployable tree and is not committed. Nothing in it is authored
# by hand -- the icons come from the agent's own drawing constants, the labels
# from the client's string tables, the screenshots from ../docs, and the prose
# from content/*.toml.

ifeq ($(strip $(CURDIR)),)
$(error CURDIR must not be empty)
endif

ROOT  := $(CURDIR)/..
ICONS := $(CURDIR)/.build/icons

.PHONY: all icons check serve clean

all: icons
	cargo run --quiet --manifest-path $(CURDIR)/Cargo.toml

# Regenerated on every build rather than committed: they are a projection of
# `icon.rs` and two agents' compositors, so a committed copy is a copy that can
# disagree with what the product draws.
icons:
	python3 $(ROOT)/docs/scripts/make-state-icons.py --out $(ICONS)

# What `make test` at the repo root runs. Renders all eleven languages without
# writing anything: catches a template that no longer compiles, a key a
# translation is missing, and a `{{ s.* }}` naming a field the client renamed.
check: icons
	cargo run --quiet --manifest-path $(CURDIR)/Cargo.toml -- --check

serve: all
	@echo "http://localhost:8000/  (Ctrl-C to stop)"
	cd $(CURDIR)/dist && python3 -m http.server 8000

clean:
	rm -rf $(CURDIR)/dist $(CURDIR)/.build $(CURDIR)/target
