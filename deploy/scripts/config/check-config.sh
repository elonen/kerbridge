#!/bin/bash
# Refuse to start the stack on a config set that no daemon would accept.
#
# Every validation in `kerbridge_core::config` is fatal, which is only safe
# because this runs first: otherwise a typo surfaces as one container
# crash-looping minutes later, in a log nobody is watching, and
# `docker compose up -d` exits 0 either way.
#
# `[provider_config]` is the half that most needs the pre-flight.
# `kerbridge-core` hands that table to the adapter without looking inside it, so
# a misspelled Entra key stays invisible until the adapter is built -- after the
# process has committed to running.
#
# Offline, deliberately. `kbconfig check --online` also probes the IdP and
# belongs to the operator: a transient IdP outage must not become a local
# refusal to start.
set -euo pipefail
cd "$(dirname "$0")/../.."
. "$(dirname "$0")/../lib.sh"

kbconfig check
