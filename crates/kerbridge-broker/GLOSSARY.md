# kerbridge-broker glossary

The HTTP service that turns an identity proof into a ticket: token verification,
the `/ticket` and `/devices` routes, and what a client is told at `/config`.

Part of the repo-wide vocabulary in [`GLOSSARY.md`](../../GLOSSARY.md) — a term
means the same thing there and here. It lives in this file, closest to where
it's used, rather than in the root file, because the root file would be
unreadably long if it carried every term at once.

### access token

The IdP-issued bearer credential, audience the broker, that proves one caller's
cloud identity for one exchange: an Entra v2 delegated token, presented as
`Authorization: Bearer`. Never written to disk, logged or passed as a
command-line argument, and the only proof that may create or list a device
grant.
<!-- refs: `grant_holder` in `crates/kerbridge-broker/src/devices.rs` -->
<!-- avoid: token, bearer, bearer token, entra token, the browser proof -->

### audience

What a [device assertion](#device-assertion)'s `aud` must name to be accepted:
`kerbridge://<REALM>`, derived from the realm by the broker and copied by the
client out of the [discovery document](#discovery-document) rather than
re-derived, so the two ends cannot disagree about spelling. Opaque and compared
byte for byte; its only job is to stop an assertion captured against one
deployment being presented to another.
<!-- refs: `kerbridge_broker::config` -->
<!-- avoid: scope, resource -->

### broker API app

The Entra app registration whose client id is the audience an access token must
carry. Distinct from the [public client](#public-client), which is what the same
token's `azp` must name.
<!-- avoid: this broker, the api app, the resource -->

### caller

Whoever presented the identity proof on a request. On the `/devices` routes the
caller is resolved before the target and for admission alone, so someone not
admitted learns nothing about which accounts exist; caller and target are
different accounts whenever a delegate is acting.
<!-- refs: `kerbridge_broker::directory::Directory::authorize_device_request` -->
<!-- avoid: requester, the presenter -->

### delegated token

An Entra access token issued on behalf of a signed-in user, evidenced by a `scp`
claim carrying the [required scope](#required-scope) and by the absence of
`idtyp: app`. Telling it from an app-only token is the real access control, not
defense in depth: Entra will issue an app-only token with this broker's audience
to any confidential client in the tenant, with no app role, consent or grant
required.
<!-- avoid: user token, on-behalf-of token -->

### device

The machine holding the private key a device grant names. In the broker's
`/devices` API it is that grant seen from the client's side — handle, identity,
label, and the deadlines.
<!-- avoid: machine, key, the key, endpoint -->

### device assertion

The second identity proof `POST /ticket` accepts:
`base64url(payload).base64url(signature)`, ECDSA P-256 over the encoded payload,
presented as `Authorization: DeviceGrant`. Two parts and no JOSE header on
purpose, so `alg` is never the client's to choose; the payload binds the raw
public key, the claimed `kb1|` identity, a single-use [nonce](#nonce), the
[device-grant audience](#device-grant-audience) and a short expiry. The broker
verifies it and decides nothing about admission, which the directory still
answers on every exchange.
<!-- refs: `kerbridge_broker::device` -->
<!-- avoid: assertion (bare), device-grant assertion, signed assertion, DeviceGrant token, DeviceGrant credential, signed nonce -->

### device registration

Creating a device grant: `POST /devices`, on an Entra access token the broker
has just validated. A token by design — a [device assertion](#device-assertion)
is refused on this route, so a machine cannot enroll more machines. With a
target named, the caller is a delegate authorizing the device *for* that
account, and the ticket the key later obtains is the target's, never the
delegate's.
<!-- avoid: grant device, enrolment, enrol, authorizing a device, registering a key -->

### device-grant audience

The `kerbridge://<REALM>` string a [device assertion](#device-assertion) must
name, derived from the realm rather than configured. Opaque to both ends and
compared byte for byte; its only job is to stop an assertion captured against
one deployment being presented to another.
<!-- refs: `device_grant_audience` in `crates/kerbridge-broker/src/config.rs` -->
<!-- avoid: aud, audience, deployment id -->

### discovery document

The `GET /config` body: OIDC authority, client id and scopes, realm, KDC list,
out-of-zone service hosts, `ticket format`, and the device-grant
knobs. A client bootstraps from a broker URL and this document alone.
<!-- refs: `kerbridge_broker::config::Discovery` -->
<!-- avoid: config document -->

### in-flight cap

The broker's ceiling on concurrent ticket exchanges, refused with 429 before any
directory traffic happens: a valid token is not a budget. issuerd holds its own,
lower cap.
<!-- refs: `configs/broker.toml` `max_inflight`, `configs/issuerd.toml` `max_inflight` -->
<!-- avoid: max inflight, in-flight slots, `KB_MAX_INFLIGHT`, `BROKER_MAX_INFLIGHT` -->

### nonce

A single-use random value the broker issues from `GET /nonce` and holds in
memory until it is spent or expires; it is the replay defense for a [device
assertion](#device-assertion), which is bound to a value only that broker
process handed out. Not the OAuth `state` value, which the browser leg uses for
a different purpose.
<!-- avoid: challenge, salt, one-shot token -->

### not admitted

The broker's 403 and the client error it maps to: a valid identity that is not
provisioned or is `ambiguous`, is disabled, is outside the admission group or
outside the device-grant group, is not a delegate of the account it named, or
asked for a device grant where the feature is off. One status carrying the
verbatim reasons above, which the client tells apart by string because their fixes
differ and none of them is "sign in again".
<!-- avoid: refused, denied, forbidden, notadmitted -->

### public client

The app registration a token's `azp` must name: the only client this broker
accepts tokens from, and the `client_id` it publishes in the [discovery
document](#discovery-document) for the client to sign in with.
<!-- avoid: authorized public client, the client app -->

### required scope

The delegated scope a token must carry to reach the ticket path,
`access_as_user` by default. The broker publishes it to clients as
`api://<broker API app>/<scope>`.
<!-- avoid: delegated scope, the scope -->

### token issuer

The exact tenant-specific `iss` an access token must carry,
`https://login.microsoftonline.com/<tenant>/v2.0`, derived from the configured
tenant. The multi-tenant `/common` and `/organizations` forms are a different
tenant's tokens as far as this broker is concerned.
<!-- refs: `issuer` in `kerbridge_idp::entra::Settings` -->

### validation policy

The tenant, broker API client id, public client id, required scope and clock
leeway an Entra access token is checked against. Fixed configuration: nothing in
a token selects it, and the expected issuer is derived from the configured
tenant rather than configured beside it.
<!-- refs: `kerbridge_idp::entra::Policy` -->
<!-- avoid: the token policy -->
