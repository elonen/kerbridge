# mock-idp — a stand-in OIDC authority for bench runs

`ci-stack.sh` proves the broker with pre-issued fixture JWTs posted straight at
it with `curl`. That leaves one thing untested by anything: **the client's own
sign-in**. `kerbridge-client` does authorization-code + PKCE against whatever
`/config` advertises, and no test drives it.

This serves the endpoints that flow needs, and issues tokens the broker's
verifier accepts unmodified. It exists so a Windows or macOS client can be taken
through a real sign-in without a tenant.

It is **not** an authorization server. `/authorize` approves everyone who asks,
immediately, with no credential of any kind. Bench networks only.

## Running it

As part of the stack, which is the way to want:

```sh
make up MOCKIDP=1          # add NAS=1 for the file server too
```

That builds [`deploy/mockidp/Dockerfile`](../../deploy/mockidp/Dockerfile), runs it
on `:8443` beside the broker, and wires both halves below for you. The broker
waits for it to be healthy, so the JWKS is on disk before anything reads it.

<details>
<summary>On the host instead, without a container</summary>

```sh
python3 -m venv .local-tmp/mock-idp/venv
.local-tmp/mock-idp/venv/bin/pip install pyjwt cryptography

TLS=deploy/secrets/tls/kerbridge.example.site
IDP_TLS_CERT=$TLS/kerbridge.example.site.crt \
IDP_TLS_KEY=$TLS/kerbridge.example.site.key \
  .local-tmp/mock-idp/venv/bin/python testbench/mock-idp/idp.py
```

Then hand the broker the JWKS it writes, yourself. Worth knowing: a foreground
process dies with the shell that started it, and a dead authority presents as a
failed *sign-in* while the broker keeps answering `/config` — so it looks like a
broken stack rather than a missing one.

</details>

TLS is required, not optional: the client refuses a non-HTTPS authority and
verifies the certificate, so there is no plaintext shortcut worth having. The
container reuses the broker's own leaf, because it answers on the broker's name
and a client that trusts one trusts the other.

## Wiring it to a broker

Two things have to agree. `MOCKIDP=1` does both; this is what it does.

**The keys.** The broker must trust what this signs with. The container generates
a key per start and writes the matching JWKS into a volume the broker mounts
read-only — no file to create first, and a restart is picked up when the broker
meets a `kid` it does not know.

To adopt the corpus key a `ci-stack.sh` run left behind instead, so a stack
already mounting that `jwks.json` accepts these tokens with no further wiring:

```sh
IDP_SIGNING_KEY=<disposable-tree>/.local-tmp/ci-fixtures/signing-key.pem
```

**The address.** Set `OIDC_AUTHORITY` to the URL this advertises, so `/config`
sends clients here instead of to the tenant:

```sh
OIDC_AUTHORITY=https://kerbridge.example.site:8443
```

The overlay serves that address; it does not advertise it. Without this in `.env`
the mock runs and no client is ever told to use it.

That variable only changes what clients are *told*. It does not affect
verification — the issuer the broker accepts is built from `provider_config.tenant_id`
in `verify.rs`, and nothing here can move it. Which is why the tokens keep the
`login.microsoftonline.com/<tenant>/v2.0` form in `iss` no matter what host they
were served from: the address and the issuer are separate strings.

## Choosing who signs in

The users default to the ones `seed-demo.sh` creates, with the same object ids,
so the identities line up with the directory:

| name | role in the bench |
|---|---|
| `alice` | admitted, in the grant group, and a delegate for `svc-builder` |
| `bob` | admitted and nothing else — the negative |
| `svc-builder` | the unattended build account |

`/authorize` issues for whoever is currently selected. Two ways to change it:

```sh
curl -X POST "https://<idp>/select?user=bob"   # sticky, for the next sign-in
```

or pass `login_hint=bob` on the authorization request, which wins for that one
exchange. `GET /whoami` says who is selected. `IDP_DEFAULT_USER` sets it at
startup, and `IDP_EXTRA_USERS=name=oid,...` adds more.

## What it does not do

No credential prompt, no consent, no `id_token`, no client authentication, no
`nonce` validation, no token revocation, and no attempt at Entra's claim set
beyond what `verify.rs` reads. PKCE *is* verified, because that is the part the
client actually implements and waving it through would mean the bench was not
testing the client.
