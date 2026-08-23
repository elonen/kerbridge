# Sourced, not run: what more than one of the scripts here needs and must not
# disagree about. Definitions only, no side effects. No shebang and not
# executable, on purpose -- the directive below is what tells shellcheck the
# dialect, since `make test` globs this directory.
# shellcheck shell=bash

# One value or one list out of deploy/configs/, for the scripts that need what
# only a TOML parser can tell them. Shell cannot read TOML, which is the whole
# reason kbconfig has `get` and `sources` at all.
#
# In a container, not from dist/: the binary there is a static musl one for the
# *server's* architecture, which a macOS bench cannot execute. The image is
# scratch plus that binary, so the run costs a process start and nothing else,
# and /etc/kerbridge is where it looks by default.
#
# Callers all `cd` to deploy/ first.
KBCONFIG_IMAGE=kerbridge-kbconfig
kbconfig() {
  if ! docker image inspect "$KBCONFIG_IMAGE" >/dev/null 2>&1; then
    echo "the $KBCONFIG_IMAGE image is missing, and the scripts here read" >&2
    echo "  deploy/configs/ through it. Build it with \`make kbconfig-image\` from deploy/." >&2
    return 1
  fi
  docker run --rm -v "$PWD/configs:/etc/kerbridge:ro" "$KBCONFIG_IMAGE" /kbconfig "$@"
}

# The operator CLI, run against a container of this deployment. The one caller
# today is the endpoint probe, `kbmanage endpoint <url>`.
#
# $1 is the container whose *network namespace* the probe runs in; the rest are
# the command's own arguments. That namespace does not reach the published port:
# caddy shares the broker's namespace, so :443 is answered there directly and the
# caller passes `--resolve 127.0.0.1` instead of a name only the site's own
# resolver knows. What that gives up is the port publish itself -- and a port
# compose could not publish is a container that never started, which the
# per-container checks already name.
#
# In a container for the reason kbconfig() gives. The image is scratch plus that
# binary; the public roots it judges an ACME certificate against are compiled in,
# so the empty filesystem around it needs nothing.
#
# TODO: no image installs kerbridge-manage yet. When one does, this becomes
# `docker compose exec broker kbmanage ...` and the image goes away: same bytes,
# one fewer build.
#
# Extra `docker run` arguments -- a bind mount for a CA file, say -- go in
# KBMANAGE_RUN_ARGS, which is an array because a string would word-split.
KBMANAGE_IMAGE=kerbridge-kbmanage
KBMANAGE_RUN_ARGS=()
kbmanage() {
  local netns=$1; shift
  if ! docker image inspect "$KBMANAGE_IMAGE" >/dev/null 2>&1; then
    echo "the $KBMANAGE_IMAGE image is missing, and the endpoint check runs the" >&2
    echo "  operator CLI through it. Build it with \`make kbmanage-image\` from deploy/." >&2
    return 125
  fi
  docker run --rm --network "container:$netns" \
    ${KBMANAGE_RUN_ARGS[@]+"${KBMANAGE_RUN_ARGS[@]}"} "$KBMANAGE_IMAGE" /kbmanage "$@"
}
