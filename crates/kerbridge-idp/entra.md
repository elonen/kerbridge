# Entra tokens

What an Entra access token carries, and what the broker does with each claim.
The verifier is [`src/entra/auth.rs`](src/entra/auth.rs). The signed corpus that holds it
to this shape is [`testbench/fixtures/entra-token/`](../../testbench/fixtures/entra-token/),
and `make_fixtures.py` there is the same claim set in executable form.

The values below are the corpus placeholders. `docs/setup/entra.md` states which
Entra object produces each one.

## The token

The agent sends this to `POST /ticket` as a bearer token.

```json
{ "typ": "JWT", "alg": "RS256", "kid": "<key id>" }
```

```json
{
  "aud": "11112222-bbbb-3333-cccc-4444dddd5555",
  "iss": "https://login.microsoftonline.com/aaaabbbb-0000-cccc-1111-dddd2222eeee/v2.0",
  "iat": 1756200000,
  "nbf": 1756200000,
  "exp": 1756203600,
  "aio": "<opaque>",
  "azp": "22223333-cccc-4444-dddd-5555eeee6666",
  "azpacr": "0",
  "name": "Alice Example",
  "oid": "33334444-dddd-5555-eeee-6666ffff7777",
  "preferred_username": "alice@example.site",
  "rh": "I",
  "scp": "access_as_user",
  "sub": "<pairwise, per application>",
  "tid": "aaaabbbb-0000-cccc-1111-dddd2222eeee",
  "uti": "<request id>",
  "ver": "2.0"
}
```

`aud` names the broker API app. `azp` names the public client. They are
different Entra apps, and the difference is what the verifier depends on.

## What the broker reads

| Claim | What Entra puts there | What the broker does |
|---|---|---|
| `aud` | The resource the client asked for. The client requests `api://<broker API app>/access_as_user`, so Entra sets the broker API app. | Must equal the configured `broker_api_client_id`. A string or an array; both are accepted. |
| `iss` | The tenant-specific v2 issuer. | Compares it to the configured `issuer`, byte for byte. |
| `tid` | The tenant the user signed in to. | Must be a GUID in canonical lowercase form, and must equal the configured `tenant_id`. |
| `exp`, `nbf` | The validity window. | Both required. 300 s of clock skew, which is Microsoft's own `DefaultClockSkew`. |
| `iat` | Time of issue. | Required to be present. The value is not compared. |
| `ver` | `"2.0"`, but only if the broker API app sets `requestedAccessTokenVersion: 2`. | Must be `"2.0"`. This catches the null default, which gives v1 tokens with a different `aud` and `iss`. |
| `idtyp` | `"user"` or `"app"`. An optional claim that the broker API app must request. | Refuses `"app"`. |
| `scp` | The delegated scopes, separated by spaces. Absent on an app-only token. | Must be present, and must contain the required scope. |
| `azp` | The client that received the token. | Must equal the configured `public_client_id`. |
| `oid` | The user's object id. Immutable, and unique in the tenant. | Must be a GUID in canonical lowercase form. Becomes the stored subject. |

## What the broker ignores

`aio`, `rh`, `uti` and `azpacr` are Entra internals. `name` and
`preferred_username` are mutable, so they are never identity; the agent shows
`preferred_username` as the default label on a delegated device grant, and no
check consults it.

**`sub` is ignored, and that is deliberate.** Entra makes it pairwise: the value
differs for each application. A new app registration would issue a different
`sub` for the same person, and every synchronized account keyed to the old one
would be orphaned. `oid` is the same value for the whole tenant, so the stored
subject is the bare `oid`.

**Case is part of the `oid` rule.** The stored subject is compared byte for
byte against what sync writes from Graph, so `690222BE-…` and `690222be-…`
would be two accounts for one person. The rule therefore lives in
`entra::identity`, the one function both the broker and sync build a subject
with. `tid` is held to the same form, which changes nothing: the comparison
against the configured `tenant_id` is exact either way.

## The order of the checks

The order is the one the research spike `entra-token-validation` measured.

1. The token splits into exactly three parts.
2. `alg` resolves against the allowlist, and the header carries a `kid`. This
   happens before any key is loaded.
3. The signature verifies over the exact bytes that arrived. Nothing is
   re-encoded. A key that publishes its own `alg` refuses a token that names a
   different one.
4. The claims above, in the order of the table.

The algorithm allowlist is asymmetric-only and is compiled in. The reasons are
in [`README.md`](README.md).

## Why `scp` and `idtyp` are access control

Entra issues an app-only token with the broker API app as its `aud` to **any**
confidential client in the tenant. It needs no app role, no consent and no
grant. This is how Entra works, and a tenant cannot turn it off.

So `aud` alone does not show that a person signed in. The presence of `scp`,
together with `idtyp != "app"`, is the only mark that separates a user's
delegated token from any service principal's token. These two checks are the
access control itself, and not defence in depth.

`idtyp` is an optional claim. If an operator removes it from the broker API app,
the token carries no `idtyp` at all, and only the `scp` check remains.

## Known gap

The header parser reads `alg` and `kid` only, so the JOSE header `typ` is not
checked. No attack is known through this: `iss`, `aud`, `azp`, `scp` and `idtyp`
together pin the token to one purpose. The standard still expects the check.
