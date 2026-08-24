# kbconfig glossary

The words for what an operator sets, what a binary uses when the operator sets
nothing, and how the two move to a new version.

Part of the repo-wide vocabulary in [`GLOSSARY.md`](../../GLOSSARY.md) — a term
means the same thing there and here. The [config set](../../deploy/GLOSSARY.md#config-set)
itself is a deployment term and stays in [`deploy/GLOSSARY.md`](../../deploy/GLOSSARY.md).
This file holds the terms for its *contents* and its *lifetime*, together in one
place, because they are one subject and are hard to read apart.

### configuration decision

A [configuration option](#configuration-option) that the operator set: its line
is present in a live `*.toml` file and is not commented out.

A configuration decision is the only thing in a config file that KerBridge did
not put there. This is why a [template](#template-config) comments out every
option that has a [default](#default): a file that stated its defaults would
make each one look like a decision the operator made, and no reader — operator
or tool — could tell the two apart.

Never the bare word *decision* in prose, which says nothing about what was
decided. `kbconfig decisions` and `config::decisions` keep the short name
because the tool and the module are themselves the scope.
<!-- refs: `kbconfig decisions`, `config::decisions`, `deploy/configs/*.toml` -->
<!-- avoid: decision, override, custom value, user setting, non-default -->
<!-- different than: default (what an option uses when nobody decided) -->

### configuration option

One setting in the [config set](../../deploy/GLOSSARY.md#config-set), written as
one line: a **key**, `=`, and a value.

The key is the option's *name* and nothing more — `min_severity`, or
`notify.min_severity` where the table is needed to tell two apart. The option is
the key together with what it controls and what it may hold. So a line sets an
option, a key names one, and neither word stands in for the other.

Every option is in exactly one of two states. Either the operator set it — a
[configuration decision](#configuration-decision) — or its line is commented out
and the binary uses the [default](#default).
<!-- refs: `deploy/configs/*.toml`, `kbconfig get <path>`, `render` in `config/template.rs` -->
<!-- avoid: variable, config key, knob, parameter, directive -->
<!-- different than: `.env` key (compose-level, and a shell variable — deploy/GLOSSARY.md#env) -->

### default

The value a binary uses for a [configuration option](#configuration-option) the
operator did not set.

The parser holds every default, in `kerbridge_core::config`. A
[template](#template-config) shows a default on a commented-out line, and a test
compares the shown value against the parser. A template that shows a value the
code does not use fails the build.

A default can change in a new version. An operator who decided nothing about
that option then gets the new value. This is deliberate: it is how an improved
default reaches a deployment at all.
<!-- refs: `#[serde(default)]` in `crates/kerbridge-core/src/config/mod.rs`, `every_template_shows_the_defaults_it_claims` -->
<!-- avoid: fallback, built-in value, standard value -->

### effective value

The value a binary uses for a [configuration option](#configuration-option): the
[configuration decision](#configuration-decision) if the operator made one, the
[default](#default) if not.

`kbconfig get <path>` prints one effective value. A config file does not always
show it, because an option nobody set is a commented-out line.

A source's `[provider_config]` is included, and there the adapter is what
resolves it: `sources.<name>.issuer` is the endpoint that source verifies
against, derived from `tenant_id` unless the file states one. This is the other
half of what `kbconfig decisions` reports — that verb answers *what did the
operator write*, read out of the documents, and this one answers *what is in
force*. Two questions, so the two verbs never say the same thing about a line.
<!-- refs: `kbconfig get`, `crates/kerbridge-config/src/paths.rs`, `IdpSettings::paths` -->
<!-- avoid: actual value, resolved value, current value -->

### example value

The value that an `# Example:` line shows above a
[configuration option](#configuration-option) with no [default](#default). It
gives the shape of a legal value and nothing more.

The option's own line stays bare, with nothing after the `=`:

```toml
# Example: "DC=example,DC=site"
#base_dn =
```

The bare line is what keeps the two forms apart. `#key = value` always means
that the value shown is the one KerBridge uses. `#key =` always means that there
is no fixed value to show: KerBridge either derives the value from another
option or leaves it unset, and the comment above says which. A file that showed
an example on the option's own line would read as though the example were in
use. To set such an option the operator must remove the `#` *and* supply a
value — `base_dn =` alone is not valid TOML.
<!-- refs: `Realm::base_dn`, `Notify::url_file`, `SourceFile::ou` -->
<!-- avoid: sample, placeholder, illustration -->
<!-- different than: default (a value the code really uses) -->

### template (config)

The commented document that `kbconfig init <dir>` writes for one file of the
[config set](../../deploy/GLOSSARY.md#config-set). It holds the prose that
documents each [configuration option](#configuration-option), the required
options as lines to complete, and every other option commented out.

A template is documentation as much as a starting point. Nobody writes one: it
is rendered from a [template source](#template-source), and the committed
`deploy/configs/*.toml.example` set is that rendering, held to it by a test.

A template is also where an answer is *placed*: `init --set` and `upgrade` both
rewrite the one line that names the option and leave every other line alone. So
a template names each option exactly once, in one of these forms, and each form
shows a value of the option's own type — the example a required option is
written with, the default a commented one names, or the `# Example:` above a
line that shows neither.
<!-- refs: `templates()`, `render`, `decisions::lines`, `deploy/configs/*.toml.example` -->
<!-- avoid: sample config, skeleton, boilerplate, the example files -->

### template source

What an author writes: a [template](#template-config) with its prose and its
layout, but with a `{{key}}` line in place of each
[configuration option](#configuration-option). `render` turns one into a
template.

The point is that no value is written twice. A `{{key}}` line becomes
`key = <example>` for a required option, `#key = <default>` where the parser has
a [default](#default), and a bare `#key =` under an `# Example:` line where it
has neither — all read from the [config schema](#config-schema). A source
therefore cannot show a value the code does not use, name a key the parser
dropped, or miss a key the parser gained.

Prose has two homes, and the source decides which. A comment block above the
line is the template's own, and is used as written: this is what carries the
section banners, the aligned option tables and the blank lines that group, none
of which a per-field attribute can express. One block covers the run of keys
below it. A `{{key}}` line with nothing above it takes the field's `///` doc
instead, which suits a key that needs one line rather than a block.
<!-- refs: `TEMPLATE_SOURCES`, `MAIN_SRC` and the rest, `render` in `config/template.rs` -->
<!-- avoid: template template, raw template, unrendered template, skeleton -->

### config schema

The description of the [config set](../../deploy/GLOSSARY.md#config-set) that
the parser makes from its own structs, as JSON Schema. It names each
[configuration option](#configuration-option) and gives its type, whether the
parser requires it, its [default](#default) and its
[example value](#example-value).

It is generated and never written by hand, so it cannot disagree with the
parser. `render` reads it to make a [template](#template-config), the tests read
it to prove that a template states every required option and comments out every
other one, and `kbconfig schema <dir>` writes it out as one document per file
for an editor to validate a live file against.

A source file's document is the only one that is assembled. `kerbridge-core`
leaves `provider_config` out of the envelope's schema, so `kerbridge-idp` puts
the adapter's own description in that place; only that crate holds both halves.
<!-- refs: `kbconfig schema`, `schemas()`, `Provider::source_schema`, feature `schema` in `kerbridge-core` and `kerbridge-idp` -->
<!-- avoid: config spec, the JSON schema files, key list -->

### migration

One recorded change to the shape of the
[config set](../../deploy/GLOSSARY.md#config-set): a
[configuration option](#configuration-option) renamed, moved to another file,
retired, or one of the values it takes renamed.

A migration states a precondition and a consequence, never a version range — *if
`sync.toml` sets `sam_attribute`*, not *if this set was written before 0.4*.
Nothing records which version wrote a config set, and nothing needs to: the
whole list is replayed from the top every time, and a migration whose
precondition does not hold does nothing. A deployment that skipped four versions
meets four migrations in one pass. This is what removes the version stamp, the
reconstruction of historical defaults, and the three-way merge — each of them a
thing that can be wrong about a deployment it has never seen.

The list is cheap to replay only because a file holds
[configuration decisions](#configuration-decision) and nothing else. A file that
stated its defaults would give every migration the whole set to reason about.

**A rename ships with its migration, in the same commit.** A migration is not a
record of what happened. It is the only thing that turns `unknown field` into an
instruction, and the only thing a tool can replay.
<!-- refs: `MIGRATIONS` and `explain` in `crates/kerbridge-core/src/config/migrations.rs` -->
<!-- avoid: upgrade step, config version, schema version, patch, fixup -->

### upgrade (config)

To carry a [config set](../../deploy/GLOSSARY.md#config-set) to the shape a new
version expects. `kbconfig upgrade` does it, and `--dry-run` says what it would
do first.

Two steps. Every [migration](#migration) is replayed over the whole set at once,
because an option that moved to another file must leave one document and reach
another before either is written. Then each file is written again from this
version's [template](#template-config) with the operator's
[configuration decisions](#configuration-decision) put back into it. So the
prose, the newly added options and the commented [defaults](#default) all become
this version's, and the decisions are the only thing carried over.

**An upgrade changes no [effective value](#effective-value).** It changes the
shape of the files and nothing about what any option evaluates to, which is what
makes it safe to run before reading the result. A line writing a value that is
already the default goes back exactly as it was: naming those is what
`kbconfig decisions` is for, and acting on them is the operator's call.

An option the operator set that this version has no migration for is dropped and
named. A file holding it does not load, so an upgrade that left it would achieve
nothing. The file it replaced is beside it as `*.toml.bak`, which is also where
any comment the operator wrote themselves stays.
<!-- refs: `kbconfig upgrade`, `decisions::apply`, `migrations::replay` -->
<!-- avoid: migrate the config, config update, convert, port -->
<!-- different than: migration (one recorded change; an upgrade replays them all) -->
