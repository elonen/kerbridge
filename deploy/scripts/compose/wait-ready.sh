#!/bin/bash
# Report whether the stack actually came up, rather than leaving it to be noticed.
#
# `docker compose up -d` exits 0 once the containers are *created*, which is
# well before any of them works. The failures that follow are invisible at that
# point and surface only to whoever thinks to read the logs:
#
#   1. Caddy under an acme strategy never obtains a certificate -- a DNS
#      credential that cannot edit the zone, a propagation check pointed at a
#      split-horizon resolver, a provider module missing from the image. Caddy
#      stays up and retries forever; :443 simply never completes a handshake.
#   2. The broker starts but cannot bind LDAPS or reach the issuer socket, so
#      caddy answers 502 on a route that looks configured.
#   3. A container crash-loops. `up -d` created it, and it has been restarting
#      ever since.
#   4. Caddy is attached to a network namespace that no longer exists, because
#      the broker was recreated on its own and caddy joined the *old* container
#      (compose.yaml: network_mode: service:broker, resolved by container ID when
#      caddy starts). From outside this is indistinguishable from 1 -- :443
#      accepts and resets -- so it is tested by identity instead, below.
#
# So this polls each service until it settles, prints a line per service as it
# does, and exits non-zero on anything still broken at the deadline. Unlike
# check-*.sh it is a report, not a gate: everything it looks at has already
# been started, and it changes nothing.
#
# READY_TIMEOUT bounds the wait, defaulting to 180s under external and 300s
# under the acme strategies -- DNS-01 is the slow one, since issuance waits out
# a propagation delay before a propagation check.
set -euo pipefail
# Two levels: this is one of the Compose-only scripts, and every path below --
# .env, secrets/, the compose project itself -- is relative to deploy/.
cd "$(dirname "$0")/../.."
. ./scripts/lib.sh
# Not the `[ -f .env ] && . ./.env` one-liner the check-*.sh gates use: under
# `set -e` a false test ends the script, which for a status report would mean
# exiting 0 having reported nothing.
if [ -f .env ]; then . ./.env; fi

FQDN=${BROKER_FQDN:-}
STRATEGY=${TLS_STRATEGY:-external}
# The default is strategy-dependent because the two wait for different things.
# External has already succeeded or failed by the time anything is polled. The
# acme strategies have to complete an issuance first: with Caddyfile.acme-dns's
# 60s propagation_delay, a first-time DNS-01 that works takes ~90s, and Caddy's
# first retry backoff is another 60s on top of that. 180s reported a healthy
# stack as broken.
case "$STRATEGY" in
  acme|acme-dns) TIMEOUT=${READY_TIMEOUT:-300};;
  *)             TIMEOUT=${READY_TIMEOUT:-180};;
esac
START=$(date +%s)
# A staging directory issues from an untrusted root on purpose, so judging the
# certificate against the public roots would report a correct setup as broken.
case "${ACME_CA:-}" in *staging*) STAGING=1;; *) STAGING=0;; esac

# Whose question the certificate is. Under the acme strategies public trust is
# the entire point of having asked for issuance, and a certificate only `-k`
# accepts is one the client -- which validates against the Windows store --
# would reject exactly as this would; so it is judged, and a failure is a
# failure. Under external the supplied certificate's trust is the operator's
# business (the bench signs its own), and against a staging directory it is
# untrusted by design, so both ask for the verdict without acting on it.
if [ "$STRATEGY" != external ] && [ "$STAGING" = 0 ]; then
  TRUST=()
else
  TRUST=(--any-cert)
fi

# status|health|restarts, or missing|-|0 when the container was never created.
# Health is "-" for services that declare no healthcheck: running is all we know
# about those, and all we claim.
#
# The emptiness test, not the exit status: `docker inspect` on an absent object
# writes a blank line to stdout as well as erroring, and a `|| echo` fallback
# then yields two lines whose first one parses as three empty fields.
cstate() {
  local out
  out=$(docker inspect --type container -f \
    '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}-{{end}}|{{.RestartCount}}' \
    "$1" 2>/dev/null) || true
  [ -n "$out" ] || out='missing|-|0'
  echo "$out"
}

# Each check_* echoes "state|message": ok, fail, or wait (still settling).
container_check() {
  local s h r
  IFS='|' read -r s h r <<EOF
$(cstate "$1")
EOF
  case "$s" in
    missing) echo "fail|no such container -- compose never created it";  return;;
    exited)  echo "fail|exited -- docker compose logs $2";               return;;
  esac
  # Two restarts is past coincidence: something fails every time it starts.
  if [ "$r" -gt 2 ]; then
    echo "fail|crash-looping ($r restarts) -- docker compose logs $2"; return
  fi
  [ "$s" = running ] || { echo "wait|$s"; return; }
  case "$h" in
    healthy|-) echo "ok|" ;;
    unhealthy) echo "wait|running but unhealthy" ;;
    *)         echo "wait|health $h" ;;
  esac
}

check_realm()  { container_check kerbridge-realm realm; }
check_issuer() { container_check kerbridge-issuer issuer; }
check_nas1()   { container_check kerbridge-nas1 nas1; }
check_broker() { container_check kerbridge-broker broker; }
# Running is not the same as working here: a source with no credential is skipped
# by design, and reporting that as a plain ok would hide a stack that never
# synchronizes. The files are the same ones each cycle reads.
check_sync() {
  local r waiting=""
  r=$(container_check kerbridge-sync sync)
  case "$r" in
    ok\|*)
      for c in secrets/idp/*/credential; do
        [ -s "$c" ] || waiting="$waiting ${c%/credential}"
      done
      [ -z "$waiting" ] ||
        r="ok|idle --$waiting has no credential yet, so that source does not sync";;
  esac
  echo "$r"
}

# A certificate problem means something different per strategy, so the diagnosis
# and the log that answers it are both strategy-dependent. Kept apart because
# only one of the two call sites below means "no certificate at all".
no_cert() {
  case "$STRATEGY" in
    acme|acme-dns) echo "TLS_STRATEGY=$STRATEGY never obtained a certificate";;
    *)             echo 'caddy could not load secrets/tls/broker.crt and .key';;
  esac
}

tls_hint() {
  case "$STRATEGY" in
    acme|acme-dns) echo 'read: docker compose logs caddy | grep -i -e acme -e certificate';;
    *)             echo 'read: docker compose logs caddy';;
  esac
}

# True when caddy holds the network namespace of a broker container that is gone
# -- header case 4. Recreating the broker alone (`docker compose up -d broker`
# rather than `make broker` or `make stack`) leaves caddy running and healthy with
# nothing listening on the live broker's :443, so the published port accepts the
# connection and resets it. Under external that reads as a missing certificate
# file and under the acme strategies as an issuance still in flight, and both
# send the operator somewhere the fault is not; hence comparing the IDs rather
# than interpreting the symptom. Silent when either container is absent -- the
# per-container checks already name that, and this must not shadow it.
caddy_netns_stale() {
  local joined live
  joined=$(docker inspect --type container -f '{{.HostConfig.NetworkMode}}' \
    kerbridge-caddy 2>/dev/null) || return 1
  case "$joined" in container:*) ;; *) return 1;; esac
  live=$(docker inspect --type container -f '{{.Id}}' kerbridge-broker 2>/dev/null) || return 1
  [ -n "$live" ] && [ "${joined#container:}" != "$live" ]
}

# The one check that exercises the public path end to end: TLS terminates, the
# route matches, and the broker answers behind it. Everything specific to *this*
# path is here; the question itself -- and the 404 discrimination that is the
# whole of it -- is `kbmanage endpoint`, which a Debian deployment runs with no
# Compose around it. See scripts/lib.sh @ kbmanage() for where it runs and why.
#
# Its exit codes are the report: 0 serving, 2 still settling, 3 the port is open
# and no TLS session came of it, 1 answering wrongly. Only the third is
# strategy-dependent, and that is the one branch below.
check_endpoint() {
  [ -n "$FQDN" ] || { echo 'fail|BROKER_FQDN is unset'; return; }
  local msg rc=0
  msg=$(kbmanage kerbridge-broker endpoint "https://$FQDN" \
          --resolve 127.0.0.1:443 ${TRUST[@]+"${TRUST[@]}"} 2>&1) || rc=$?
  # Before attributing anything to TLS or to a slow start: a stale namespace
  # produces both of those symptoms and neither of their diagnoses would be
  # true. The probe runs inside the *live* broker's namespace, where a caddy
  # left behind in the old one is not listening at all.
  if [ "$rc" != 0 ] && caddy_netns_stale; then
    echo 'fail|caddy holds a network namespace the broker no longer has -- it was recreated without caddy. Fix: docker compose up -d --force-recreate caddy'
    return
  fi
  case "$rc" in
    0)   echo "ok|$msg$([ "$STAGING" = 1 ] && echo ' -- an untrusted root is what an ACME_CA staging directory issues')";;
    2)   echo "wait|$msg";;
    # Terminal under external -- the certificate is a file, it either loaded or
    # it did not, and waiting cannot change that. Under the acme strategies it
    # is the *expected* state while issuance is in flight: caddy listens on :443
    # from the start and simply refuses the handshake until it has one, so this
    # is the only symptom a working-but-slow DNS-01 produces. Reported as fail,
    # the check could never wait for the one thing this script exists to wait
    # for. The message is carried into the wait so a TIMEOUT line still says
    # what went wrong.
    3)   case "$STRATEGY" in
           acme|acme-dns) echo "wait|$msg -- $(no_cert). $(tls_hint)";;
           *)             echo "fail|$msg -- $(no_cert). $(tls_hint)";;
         esac;;
    # The probe itself could not be run. Two causes and opposite verdicts: a
    # broker container that has not started yet has no namespace to join, and
    # is exactly what this loop is for; anything else -- a missing image, most
    # likely -- waiting cannot fix.
    125) if [ "$(docker inspect --type container -f '{{.State.Running}}' kerbridge-broker 2>/dev/null)" = true ]; then
           echo "fail|$msg"
         else
           echo "wait|the broker container is not running yet, so there is no namespace to probe from"
         fi;;
    *)   echo "fail|$msg";;
  esac
}

# realm, issuer, broker and endpoint are the product and are always required: a
# missing one is the failure this report exists to name. nas1 and sync are checked only
# when they exist -- sync so a partial `up -d` still reports usefully, nas1
# because it is a bench fixture. A real deployment's file server is somebody
# else's machine, joined by hand (docs/setup/file-server.md), and its absence here is
# not a fault to report. --type container because `docker inspect` resolves
# images by name too, and the image outlives every `down`.
CHECKS='realm issuer'
if docker inspect --type container kerbridge-nas1 >/dev/null 2>&1; then CHECKS="$CHECKS nas1"; fi
CHECKS="$CHECKS broker endpoint"
if docker inspect --type container kerbridge-sync >/dev/null 2>&1; then CHECKS="$CHECKS sync"; fi

echo "Waiting for the stack to settle (up to ${TIMEOUT}s; READY_TIMEOUT overrides)."
pending=$CHECKS
failed=0
last_msg=
announced=0

while [ -n "$pending" ]; do
  now=$(( $(date +%s) - START ))
  expired=0
  if [ "$now" -ge "$TIMEOUT" ]; then expired=1; fi
  next=
  for c in $pending; do
    r=$("check_$c")
    state=${r%%|*}
    msg=${r#*|}
    case "$state" in
      ok)   if [ -n "$msg" ]; then printf '  %-9s ok      %s\n' "$c" "$msg"
            else printf '  %-9s ok\n' "$c"; fi ;;
      fail) printf '  %-9s FAILED  %s\n' "$c" "$msg"; failed=1 ;;
      *)
        if [ "$expired" = 1 ]; then
          printf '  %-9s TIMEOUT %s\n' "$c" "${msg:-still not ready}"
          failed=1
        else
          next="$next $c"
          last_msg="$last_msg $c"
        fi
        ;;
    esac
  done
  pending=${next# }
  [ -n "$pending" ] || break
  # A progress line every 15s, so a slow ACME issuance does not look like a hang.
  if [ $(( now / 15 )) -gt "$announced" ]; then
    announced=$(( now / 15 ))
    printf '  ... still waiting on:%s (%ss)\n' "$last_msg" "$now"
  fi
  last_msg=
  sleep 2
done

if [ "$failed" != 0 ]; then
  echo
  echo "The stack is not fully up. Logs for one service:  docker compose logs <service>"
  exit 1
fi
echo "Stack is up."
