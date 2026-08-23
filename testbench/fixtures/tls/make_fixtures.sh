#!/bin/sh
# Regenerate the certificate corpus that `kerbridge-client`'s X.509 reader parses.
#
# Only the certificates are kept -- the keys are generated into `.local-tmp/` and
# deleted on the way out, because nothing under `testbench/` may hold a key.
# Nothing here is ever presented by a server or trusted by anything; these are
# bytes to parse.
#
# The dates are literal rather than `-days N`, so the tests can assert them.
set -eu

OUT="$(cd "$(dirname "$0")" && pwd)"
WORK="$(cd "$OUT/../../.." && pwd)/.local-tmp/tls-fixtures"
mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT

# The shape every broker certificate has: issued by a private CA, and carrying
# the names it is valid for in the subjectAltName rather than only in the CN.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
	-keyout "$WORK/ca.key" -out "$WORK/ca.pem" \
	-subj "/O=Example Org/CN=Example LAN CA" \
	-not_before 20260101000000Z -not_after 20360101000000Z

openssl req -x509 -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
	-newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
	-keyout "$WORK/leaf.key" -outform DER -out "$OUT/lan-ca-leaf.der" \
	-subj "/O=Example Org/CN=kerbridge.example.site" \
	-addext "subjectAltName=DNS:kerbridge.example.site,DNS:nas1.example.site" \
	-not_before 20260102030400Z -not_after 20270102030400Z

# Valid past 2049, which forces the validity into GeneralizedTime, and with a
# non-ASCII organization, which forces the DN into UTF8String. Self-signed and
# without a subjectAltName -- the other arm of each branch.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -utf8 \
	-keyout "$WORK/far.key" -outform DER -out "$OUT/far-future.der" \
	-subj "/O=Ekämpel Öy/CN=kerbridge.example.site" \
	-not_before 20250102030400Z -not_after 20550102030400Z

openssl x509 -in "$OUT/lan-ca-leaf.der" -inform DER -noout -subject -issuer -dates -ext subjectAltName
openssl x509 -in "$OUT/far-future.der" -inform DER -noout -subject -dates
