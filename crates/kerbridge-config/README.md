# kerbridge-config — `kbconfig`, the tool that runs before the realm does

One binary, and a boundary held by a missing dependency.

```
kbconfig check [--online]     validate the config set; --online also probes the IdP
kbconfig get <path>           one value, by dotted path
kbconfig sources              the active source names, one per line
kbconfig decisions            every option the set states, against its default
kbconfig upgrade [--dry-run]  carry the set to this version's shape
kbconfig init <dir> [--source <name>[=<provider>]]... [--set <path>=<value>]...
                              write a config set from this version's templates,
                              with those sources and answers already in it
kbconfig schema <dir>         write the config schema into <dir>/schema/, one
                              document per file, plus the .taplo.toml mapping them
```

`--config <path>` names `main.toml`; the rest of the set is found beside it.
Without it the compiled-in `/etc/kerbridge/main.toml` is used.

## `init`, and the three rules a maintainer script does not retype

`init` is what a Debian `postinst` calls with the debconf answers. It refuses to
overwrite a file that is already there unless `--force`; `--source` is the only
thing that writes which sources exist, and a `--set` naming one of those three
values is refused rather than silently overruled; and if a *required* answer
arrives empty it writes nothing at all — not that file, not the rest of
the set — says which answer it was, and exits 0. An empty answer cannot be told
from a question nobody answered, so an unattended install with no preseed ends
with no config set rather than one naming a realm nobody chose, and the install
still succeeds.

An empty answer for an option that is *not* required is left at its default, so
the template's commented line survives — "no opinion" is not the same decision as
`key = ""`.

An answer is `--set <file>.<option>=<value>`, and the option path is the one
`kbconfig decisions` prints under that file. **These are not `get`'s paths**:
`get` addresses the loaded configuration, where a source answers under its own
name (`sources.entra.issuer`), while `--set` addresses the file it is written
into (`idp_entra.provider_config.tenant_id`).

```sh
kbconfig init /etc/kerbridge --source entra \
  --set realm.realm=EXAMPLE.SITE \
  --set realm.ldap_url=ldaps://kerbridge.example.site:636 \
  --set idp_entra.provider_config.tenant_id="$tenant_id"
```

`--source <name>[=<provider>]` is repeatable, and is the only thing that writes
`main.sources` and a source file's `name` and `provider` — so the list and the
files beside it cannot disagree. With no `--source` the set names none, which is
a realm mid-bootstrap and is what an administrator's own machine wants.

With no `--set` the files are this version's templates unchanged, which is what
`deploy/configs/*.toml.example` holds under the reference names. That set does
not load: every option the parser requires is a *line to complete*, commented
out under its example and a `# REQUIRED.` note, and `kbconfig check` names every
one still waiting before serde is asked -- serde reports one missing field per
file and stops.

A value is taken as the type the option holds, which the template names: a
string option takes its answer as written, so a `group_suffix` of `42` is the
text `42`. Every other type parses its answer as TOML, which is what makes
`main.sources=["entra"]` a list, and text that will not parse is refused rather
than written for the parser to reject later.

## What `check` says before the parser does

Every option the parser requires is a *line to complete*. `check` walks each
file as a **document** first -- through `config::decisions`, which exists
because the set that most needs reading is the one the parser refuses -- and
names every line the set has not completed, in one report, before serde is
asked. Serde reports one missing field per file and stops, so completing a
fresh `idp_<name>.toml` any other way is nine runs.

The report covers the source files `main.sources` lists. On a set whose
`main.toml` has not completed `sources` at all -- every freshly copied template
set -- it reads whatever `idp_*.toml` is beside it instead, so one report is
still the whole answer.

## Why it is not a `kbmanage` subcommand

`deploy/scripts/config/check-env.sh` runs *before the realm exists* and needs
both values and the source list out of the config set, and shell cannot read
TOML. `kbmanage` is useless at that point: every one of its verbs wants a live
directory, it finds its own configuration before it can run, and it binds as an
account holding delete-child ACEs on the parent OU. A config tool inside it
would have to be configured before it could read the configuration, and would
hand an operator the directory-deleting binary as part of setup.

**This crate does not depend on `ldap3`, and that absence is the boundary** —
directory reach is unavailable rather than merely unexercised. `make test`
asserts it, because a structural boundary that nothing checks will not hold.
`kerbridge-core` is taken without its `tls` feature for the same shape of
reason, though that one is dead-code elimination and not a boundary: `reqwest`
brings rustls regardless.

## What `get` answers

Every option of the set, as its *effective value* — the operator's decision
where there is one, the derivation or the default where there is not. It
joins three sources: `kerbridge-core` generates one path per plain field,
`src/paths.rs` adds the paths read back through an accessor (`realm.base_dn`, `sources.<name>.ou`,
the rest), and each source's adapter answers for its own `[provider_config]`.

**A provider path answers with the adapter's resolved setting, never with the
line in the file.** `kbconfig get sources.entra.issuer` prints the derived v2
endpoint on a set that states no `issuer`, and the stated one on a set that
does — the same contract `realm.base_dn` has. The adapter stays the only thing
that interprets its own block; `get` is its mouthpiece rather than a competitor,
and *withholding* it is what would create the second interpreter, by sending a
deploy script to `cat` and `grep` and letting it rebuild
`https://login.microsoftonline.com/$TENANT/v2.0` by hand. Not a secret boundary
either way: every secret in the set is named as a *path*, so there is no
credential here to print.

`decisions` and `get` do not overlap. `decisions` reports the
[configuration decisions](GLOSSARY.md#configuration-decision) — what the
operator wrote, read out of the documents. `get` reports the
[effective value](GLOSSARY.md#effective-value) — what is in force.

`paths.txt` is the committed list of every path `get` answers. It is the ratchet
on a promised interface: a field added to a config struct fails the build until
somebody regenerates it, with
`KB_WRITE_PATH_SNAPSHOT=1 cargo test -p kerbridge-config`.

## `get` is a program interface, and the two things it will never become

**There will never be a `kbconfig env` verb, and no `eval "$(kbconfig env)"`
idiom.** Such a verb has to invent a TOML-path → shell-name mapping, and that
mapping is exactly the second environment namespace
`deploy/scripts/compose/check-compose-env.py:4-18` exists to keep dead: one
namespace classifying by where the operator got the value, another by which
component consumes it, and a translation layer between them that nothing
validates.

**Parsing the config set's TOML directly is banned for every consumer outside
this workspace.** Not hypothetical — `check-compose-env.py` is already Python
and `tomllib` has been in the standard library since 3.11. A reader doing that
gets *nothing* for `realm.base_dn`, `realm.idp_parent_ou`,
`realm.ad_dns_domain`, `realm.netbios_domain` or `realm.dc_hostname`: every one
of them is commented out in the file it lives in, and supplied by the parser.
Measured — `kbconfig get realm.base_dn` prints `DC=example,DC=site` from a file
that never states it.

A source's `[provider_config]` is in that same class, and worse: `issuer`,
`authority` and the JWKS URL are all derived from `tenant_id` unless the file
states them, so a reader that greps gets the right answer on every bench and the
wrong one on the first sovereign cloud. `kbconfig get sources.<name>.issuer`
hands back what that source actually verifies against.

> The file holds decisions; the binary holds defaults and derivations. Only the
> binary knows the effective value.

The cost objection does not apply. In both deployments `kbconfig` is a local
binary beside its caller, so one call is a process start, not the `docker run`
that `deploy/scripts/lib.sh:24`'s *host-side* wrapper pays for. Which package
or image puts it there is #46's to say, and nothing here assumes an answer. A
consumer needing more than a handful of values is the argument for a structured
dump, never for a second parser.

## What `upgrade --dry-run` exits with

One question, asked after the command has done whatever it does: **is the config
set already this version's shape?**

```
0   it is
2   it is not
1   error -- the set could not be read, or a file could not be written
```

A wet `kbconfig upgrade` therefore exits `0`: it just made it so. The predicate
is the same in both modes and never means "something would change". `2` rather
than `1` because `1` is spent on errors, and `diff` and `grep` both put an
informational state above the error code.

A Debian maintainer script probes a set with this and never writes to it, which
makes it a promised interface rather than a detail of the report — the same
status `get` has. **There is no third code** for an option this version cannot
carry: the report names those where the operator will read them, and the
instruction is identical either way — run `--dry-run`, read it, then run it for
real.

## The `--online` probes

One question per source, asked in the adapter because which document to fetch
and which claim to compare are provider facts. The one that earns the feature is
the middle one: the issuer the tenant publishes against the issuer the adapter
derived, since both that and every stored subject come from `tenant_id`, and a
wrong one misfiles every account rather than failing loudly.

A 4xx, an unreadable document or a mismatched claim is a hard fail — the
configuration. A refused connection, a DNS failure, a timeout or a 5xx is a
warning — the world. **`--online` never runs at startup or on the bootstrap
path**, and `check` defaults to offline so a transient IdP outage cannot become
a local one.
