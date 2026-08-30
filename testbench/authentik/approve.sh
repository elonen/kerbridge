#!/bin/sh
# A `$BROWSER` for an unattended authentik sign-in: take the authorization URL
# the client generated and drive authentik's flow executor to the code, so
# `oidc::login` runs exactly as it ships. The authentik counterpart of
# testbench/mock-idp/approve.sh -- mock-idp approves on a single redirect, but
# authentik has a credential prompt, so this drives the prompt itself.
#
# nas1 is where the CI tier signs in (deploy/scripts/bench/ci-authentik.sh mounts
# this as the `${CI_APPROVE_SH}` browser), and nas1 has curl and no python3
# (deploy/member/Dockerfile), so this is POSIX sh, curl and perl -- never the
# python3 loop of testbench/authentik/authcode.sh, which keeps this as its
# sign-in step and holds nothing of the executor itself.
#
# Three executor calls, branching on `component` and never on a sequence:
#   ak-stage-identification -> ak-stage-password -> xak-flow-redirect
# MFA-validate and User Login are bound in the default flow but non-interactive,
# so neither surfaces. Read the long comments in authcode.sh's original loop for
# why each curl flag below is the one that works.
#
# Two consumers, one flow. As a `$BROWSER` it follows the final hop to the
# client's loopback listener, which is what hands over the code; run by hand it
# prints `code=<code>` and `state=<state>` on stdout for a caller with no
# listener (authcode.sh, and the cross-application mint in ci-authentik.sh). The
# loopback delivery is best effort for exactly that second case.
#
# Usage:  BROWSER=/path/to/approve.sh kerbridge --broker https://...
#         approve.sh <authorization-url>        # prints `code=` / `state=`
#
# Environment:
#   KB_APPROVE_CA        CA bundle for authentik's certificate (--cacert). Unset,
#                        the system trust store is used.
#   KB_APPROVE_LOG       a file to append the transcript to; the caller's stdout
#                        carries only the two result lines.
#   KB_APPROVE_USER      who to sign in as (default benchuser).
#   KB_APPROVE_PASSWORD  their password (default bench-user-password).
set -eu

url=${1:?usage: approve.sh <authorization-url>}
log=${KB_APPROVE_LOG:-/dev/null}
user=${KB_APPROVE_USER:-benchuser}
password=${KB_APPROVE_PASSWORD:-bench-user-password}

# scheme://host of the authorization URL: every executor and callback URL below
# is relative to it, and the authorization endpoint is the only address this
# script is told rather than assuming.
base=$(printf '%s' "$url" | perl -ne 'print $1 if m{^(https?://[^/]+)}')
[ -n "$base" ] || { echo "approve.sh: no scheme://host in $url" >&2; exit 1; }

jar=$(mktemp)
work=$(mktemp -d)
trap 'rm -rf "$jar" "$work"' EXIT

# Two curl definitions rather than an optional flag, so nothing is left unquoted.
# --max-time bounds every call, so a wedged authentik surfaces as a failed
# sign-in and not a hung test.
if [ -n "${KB_APPROVE_CA:-}" ]; then
  akcurl() {
    curl --silent --show-error --max-time 30 \
      --cookie-jar "$jar" --cookie "$jar" --cacert "$KB_APPROVE_CA" "$@"
  }
else
  akcurl() {
    curl --silent --show-error --max-time 30 --cookie-jar "$jar" --cookie "$jar" "$@"
  }
fi

# The transcript goes to the log; only the two result lines reach the caller's
# stdout, on the descriptor saved here.
exec 3>&1
exec >>"$log" 2>&1

echo "approve.sh: $url"

# 1. The authorization request. authentik 302s an unauthenticated authorize to
#    /if/flow/<slug>/?<original params>&next=<re-entry> -- the flow interface a
#    browser would render. No -L: the Location is what carries the flow slug and
#    the query the executor needs.
akcurl -o /dev/null -D "$work/h.authorize" "$url"
loc=$(perl -ne 'print "$1\n" if /^location:\s*(\S+)/i' "$work/h.authorize" | tail -1)
case "$loc" in
  */if/flow/*) : ;;
  # A 302 straight back to redirect_uri carrying error= means the request never
  # reached a flow: an empty provider `grant_types` looks like this.
  *) echo "approve.sh: authorize did not redirect to a flow: ${loc:-<none>}" >&2; exit 1 ;;
esac
slug=${loc#*/if/flow/}; slug=${slug%%/*}
raw_query=${loc#*\?}
# Url-encode the whole query as one opaque `query` value: the executor
# takes what the browser's window.location.search would carry, `next` included.
query=$(printf '%s' "$raw_query" | perl -pe 's/([^A-Za-z0-9_.~-])/sprintf("%%%02X",ord($1))/ge')
exec_url="$base/api/v3/flows/executor/$slug/?query=$query"
echo "approve.sh: flow $slug"

# 2. The executor loop. Branch on `component`; -L to follow each stage's 302 back
#    to the executor's own URL, and never -X POST -- -d already selects POST, and
#    -X POST additionally pins the method across the follow, re-POSTing the
#    previous stage's body into the next stage until the flow wedges.
akcurl -L -H 'Accept: application/json' -o "$work/challenge.json" "$exec_url"
i=0
component=
while [ "$i" -lt 12 ]; do
  i=$((i + 1))
  component=$(perl -0777 -ne 'print $1 if /"component"\s*:\s*"([^"]*)"/' "$work/challenge.json")
  [ -n "$component" ] || { echo "approve.sh: empty challenge body at step $i" >&2; exit 1; }
  echo "approve.sh: [$i] $component"
  case "$component" in
    xak-flow-redirect) break ;;
    ak-stage-identification)
      payload="{\"component\":\"$component\",\"uid_field\":\"$user\"}" ;;
    # A separate stage: identification reports password_fields false, so the
    # password never rides along with the username.
    ak-stage-password)
      payload="{\"component\":\"$component\",\"password\":\"$password\"}" ;;
    *)
      cat "$work/challenge.json" >&2
      echo "approve.sh: unhandled stage component: $component" >&2
      exit 1 ;;
  esac
  akcurl -L -H 'Accept: application/json' -H 'Content-Type: application/json' \
    -o "$work/challenge.json" "$exec_url" -d "$payload"
done
[ "$component" = xak-flow-redirect ] ||
  { echo "approve.sh: flow never terminated (last: ${component:-<none>})" >&2; exit 1; }

# 3. `to` is the relative re-entry into /application/o/authorize/, carried as
#    `next` through the flow -- not the code. Re-entering it with the now-
#    authenticated session cookie 302s to the client's loopback redirect_uri
#    carrying code=. No -L here: the Location is read out so a listener-less
#    caller gets the code too.
to=$(perl -0777 -ne 'print $1 if /"to"\s*:\s*"([^"]*)"/' "$work/challenge.json")
case "$to" in
  http*) : ;;
  /*)    to="$base$to" ;;
  *)     echo "approve.sh: unexpected redirect target: ${to:-<none>}" >&2; exit 1 ;;
esac
akcurl -o /dev/null -D "$work/h.callback" "$to"
cb=$(perl -ne 'print "$1\n" if /^location:\s*(\S+)/i' "$work/h.callback" | tail -1)
case "$cb" in
  *code=*) : ;;
  *) echo "approve.sh: no authorization code came back: ${cb:-<none>}" >&2; exit 1 ;;
esac
code=$(printf '%s' "$cb" | perl -ne 'print $1 if /[?&]code=([^&]+)/')
state=$(printf '%s' "$cb" | perl -ne 'print $1 if /[?&]state=([^&]+)/')
echo "approve.sh: got a code, state $state"

# The result, on the caller's stdout. Discarded when this is the client's
# `$BROWSER`; read by a scripted caller.
printf 'code=%s\nstate=%s\n' "$code" "$state" >&3

# Deliver the code to the loopback redirect_uri, which is the whole of the
# `$BROWSER` contract -- the client's listener reads code and state off this
# request. Best effort: a scripted caller has read `code=` above and has nothing
# listening there.
akcurl -o /dev/null "$cb" || echo "approve.sh: no loopback listener at $cb (scripted caller)"
