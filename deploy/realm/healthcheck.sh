#!/bin/bash
# Samba's LDAP listener accepts a connection. That is the whole of this
# container's health: the issuer is the `issuer` service, and it answers its own
# probe with `issuerd ping`.
set -eu
timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/389'
