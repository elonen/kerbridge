#!/bin/sh
# A `$BROWSER` for an unattended sign-in: take the authorization URL the client
# generated and drive this authority's approval, so `oidc::login` runs exactly
# as it ships.
#
# `webbrowser::open` on Linux tries `$BROWSER` before anything else and appends
# the URL as an argument (webbrowser-1.2.x, src/unix.rs @ try_with_browser_env),
# so setting BROWSER to this file is the whole of the mechanism. **That is the
# point**: there is no `cfg(test)`, no environment escape hatch and no branch in
# `oidc.rs` -- the client opens a browser, and on this bench the browser is a
# shell script. Anything a test-only branch would have hidden -- a mis-built
# authorization URL, a wrong `redirect_uri`, a state check that does not fire --
# is still under test here.
#
# What it relies on, and nothing else: mock-idp's `/authorize` approves whoever
# is selected immediately and answers with a 302 to `redirect_uri`, so following
# redirects once is the entire "sign-in". A real authority with a credential
# prompt needs a different script, one that drives the prompt itself.
#
# The URL is *taken from the client*, never assumed. `oidc::login` binds
# 127.0.0.1:0, so the redirect carries an ephemeral port that changes every run
# and only the client knows -- which is also why an authority that matches
# redirect URIs exactly has to admit the whole loopback range.
#
# Usage:  BROWSER=/path/to/approve.sh kerbridge --broker https://...
#
# Environment:
#   KB_APPROVE_CA    a CA bundle for the authority's certificate. Unset, the
#                    system trust store is used, which is right against a real
#                    authority and wrong against a bench one.
#   KB_APPROVE_LOG   a file to append a transcript to. The client spawns this in
#                    the background with its output discarded, so a failure here
#                    is otherwise invisible and presents as the sign-in timing
#                    out -- which says nothing about which half was wrong.
set -eu

url=${1:?usage: approve.sh <authorization-url>}
log=${KB_APPROVE_LOG:-/dev/null}

set -- --silent --show-error --location --max-time 30 --output /dev/null \
       --write-out '%{http_code} %{url_effective}'
[ -z "${KB_APPROVE_CA:-}" ] || set -- "$@" --cacert "$KB_APPROVE_CA"

{
  echo "approve.sh: $url"
  # `--location`, so the 302 back to the client's loopback listener is followed
  # and the code is delivered by this process rather than by a person.
  if out=$(curl "$@" "$url" 2>&1); then
    echo "approve.sh: $out"
  else
    rc=$?
    echo "approve.sh: curl exited $rc: $out"
    exit $rc
  fi
} >> "$log" 2>&1
