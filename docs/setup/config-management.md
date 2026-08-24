# Configuration, and how to carry it to a new version

How KerBridge configuration works, what you write in it, and what happens when
you install a new version.

Read this once, before you change a configuration file. The rules are short,
and they are what make an upgrade safe.

- [What you have](#what-you-have)
- [The one rule](#the-one-rule)
- [Change an option](#change-an-option)
- [See what you decided](#see-what-you-decided)
- [Check before you start the services](#check-before-you-start-the-services)
- [Install a new version](#install-a-new-version)
- [When a new version removes an option](#when-a-new-version-removes-an-option)
- [Where the files come from](#where-the-files-come-from)

## What you have

Your configuration is a directory, not a file. It is the
config set<sup>[?](../../deploy/GLOSSARY.md#config-set)</sup>.

| File | What it configures |
|---|---|
| `main.toml` | The entry point. It names your sources, and holds `[notify]`. |
| `realm.toml` | The realm, and the directory the services read. |
| `issuerd.toml` | The ticket issuer. |
| `broker.toml` | The broker. |
| `sync.toml` | The directory mirror. |
| `kbmanage.toml` | The operator CLI. Optional. |
| `idp_<source>.toml` | One file for each identity source. |

Every service reads the directory. No service reads one file. Therefore you
give a program the directory, and it takes the files that it needs.

## The one rule

**A configuration file holds your decisions, and everything else is commented out.**

Each file starts as a
template<sup>[?](../../crates/kerbridge-config/GLOSSARY.md#template-config)</sup>.
A template sets only the options that KerBridge cannot supply for you. Every
other option is on a commented-out line, with its
default<sup>[?](../../crates/kerbridge-config/GLOSSARY.md#default)</sup> shown.

A commented-out line sets nothing. Two forms tell you two different things:

```toml
#interval_seconds = 300     # KerBridge uses 300 by default.
#url_file =                 # KerBridge has no value for this option.
```

For options that have no default, a comment above the line says what KerBridge
does instead, and usually shows an
example value<sup>[?](../../crates/kerbridge-config/GLOSSARY.md#example-value)</sup>.

An option that you set is a
configuration decision<sup>[?](../../crates/kerbridge-config/GLOSSARY.md#configuration-decision)</sup>.
KerBridge keeps your decision through every version.

**Do not write a value that is already the default.** The line then looks the
same as a decision, but you decided nothing. Worse, a later version cannot
improve that default for you: your value wins, because KerBridge cannot tell
the difference between a value you chose and a value you copied.

If you want the default, leave the line commented out.

## Change an option

1. Find the commented-out line for the option.
2. Remove the `#`.
3. Write your value.
4. Run `kbconfig check`.
5. Restart the services that read the file.

To go back to the default, put the `#` back. Do not write the default value.

Example. `sync.toml` ships this:

```toml
# Log the plan every cycle and apply nothing. The safe way to watch a new
# deployment before letting it write the directory.
#dry_run = false
```

To watch the deployment first, make it this:

```toml
dry_run = true
```

To let sync write the directory later, comment the line out again.

## See what you decided

`kbconfig decisions` reads the configuration set and shows every option that differs from defaults:

```
configs: 21 options set, 52 at their default.

main.toml
  sources = ["entra"]

sync.toml
  dry_run = true          default false
= interval_seconds = 300  same as the default
! sam_attribute = "upn"   rename `sam_attribute` to `sam_source`
```

The first column marks the lines that need your attention:

| Mark | What it means | What to do |
|---|---|---|
| (blank) | A configuration decision. | Nothing. |
| `=` | The value is already the default. | Comment the line out. |
| `!` | Validation error. | Correct it, as the note says. |

Run this command before an upgrade, and after one.

## Check before you start the services

```sh
kbconfig check            # offline.
kbconfig check --online   # also probes the IdP.
```

`check` refuses a set that no service would accept. The stack runs the offline
check before it starts, because a typo must not become a container that
restarts in a loop ten minutes later.

Use `--online` yourself, when you want it. The stack does not, because an IdP
outage must not stop your services from starting.

## Install a new version

A new version can add options, improve a default, or rename an option. Your
decisions carry across all of them. The command that does it is
`kbconfig upgrade`<sup>[?](../../crates/kerbridge-config/GLOSSARY.md#upgrade-config)</sup>.

Step 1 differs by deployment method. Steps 2 to 5 are the same either way.

**Docker Compose deployment:**

1. Install the new version, but do not start the services.

**Debian deployment:** starting the services is not yours to control — dpkg
starts them — so step 1 becomes:

1. `apt install` the new packages. `kerbridge-config`'s postinst probes the set
   and prints one line if it is not this version's shape. A daemon then refuses
   to start at `ExecStartPre=kbconfig check`, but **only if a migration
   matched** — a renamed key fails the parse, while a set that is merely older
   in shape parses and starts normally.

Then, either way:

2. Run `kbconfig upgrade --dry-run`. Read what it says.
3. Run `kbconfig upgrade`.
4. Run `kbconfig check`.
5. Start the services — `systemctl restart kerbridge-issuerd kerbridge-broker
   kerbridge-sync` in a Debian deployment.

`--dry-run` writes nothing. It tells you which options this version adds, which
lines it must correct, and which files it must write again.

The command keeps the file that it replaced, beside it, as `*.toml.bak`.

A comment that you wrote yourself is not carried across. The new file is this
version's template, with your values copied in it. Your old file is the `.bak`.

## When a new version removes an option

A service refuses to start on an option that it does not know.

If the option was renamed, KerBridge says so:

```
kbconfig: in configs/sync.toml: TOML parse error at line 73, column 1
   |
73 | sam_attribute = "upn"
   | ^^^^^^^^^^^^^
unknown field `sam_attribute`, expected one of `interval_seconds`, ...

  this version of KerBridge moved it -- rename `sam_attribute` to `sam_source`

== How to fix this?

Try the `kbconfig upgrade` command. Use --dry-run first to see what would
change.
```

Each of these is a recorded
migration<sup>[?](../../crates/kerbridge-config/GLOSSARY.md#migration)</sup>.
The `upgrade` command replays them every time, so you do not have to install
versions in order. A deployment that is four versions behind is carried forward
in one step. You do not record which version wrote your files, and neither does
KerBridge.

Where the option was removed and not renamed, `upgrade` deletes the line and
names it in the report. A file that keeps the line does not start, so an
upgrade that left it would help nobody. The line is still in the `.bak` file.

## Where the files come from

You do not write a template by hand. KerBridge generates each one from the same code
that reads it. So the comments, the defaults, and the example values in your files are always
what this version has.

```sh
kbconfig init configs       # write the config set itself
kbconfig schema configs     # write a config schema, for your editor (optional)
```

`kbconfig init` writes a file only if it is not there: if any file in the set
already exists it writes nothing and names it. Pass `--force` only when you mean
to throw away what you edited.

`init` also takes the answers, one option at a time, so that a set does not have
to be written and then edited:

```sh
kbconfig init configs --set realm.realm=EXAMPLE.SITE \
                      --set realm.ldap_url=ldaps://kerbridge.example.site:636
```

The path is `<file>.<option>`, and the `<option>` part is what `kbconfig decisions`
prints under that file. An answer goes into the line that names the option and
changes nothing else on the page, so the file you get is this version's template
with your value in it. Two rules make it safe to call from a package's install
script, which is why they are in the command rather than in a shell script:

- a file that already exists is never overwritten — and if any one of them
  exists, nothing at all is written;
- if a *required* option is answered with an empty value, **nothing at all is
  written** — not that file and not the rest of the set — and the command says
  which answer it was. An install that asked nobody anything then leaves you with
  no config set, rather than one naming a realm nobody chose.

An empty answer for an option that is *not* required is left at its default
instead, and the commented line stays as it was.

`kbconfig schema` writes the
config schema<sup>[?](../../crates/kerbridge-config/GLOSSARY.md#config-schema)</sup>
into `configs/schema/`, and a `configs/.taplo.toml` that points each file at its
document. A compatible text editor can then complete option names, show each default, and
mark a misspelled option as you type. This needs the taplo language server.
Helix, Neovim, and the VS Code TOML extension all run it. Both outputs are
generated: do not edit them.

## See also

- [`kbconfig` README](../../crates/kerbridge-config/README.md) — every
  subcommand.
- [config glossary](../../crates/kerbridge-config/GLOSSARY.md) — the words on
  this page, and what each one is pinned to.
- [compose-deployment.md](compose-deployment.md) and
  [debian-deployment.md](debian-deployment.md) — the settings that a deployment
  decides, in the order that you meet them, one page per method.
