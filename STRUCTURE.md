# Repository structure

```text
.
├── README.md               what it is, why it exists, where everything is
├── SETUP.md                how to deploy it, for an operator
├── DESIGN.md               design index: goal, architecture, security boundaries
├── SECURITY.md             risks, what limits each one, worst case
├── STRUCTURE.md            this file
├── GLOSSARY.md             repo-wide terms; links to a GLOSSARY.md per subdir
├── CHANGELOG.md            release notes; the debs' changelog is built from it
├── crates/                 server components (Rust)
├── debian/                 the Debian packages, for the other deployment
├── deploy/                 Docker Compose project that runs them
├── client/                 workstation client (Rust, its own workspace)
├── docs/                   cross-topic synthesis + operator guides
│   ├── design/             the design, one page per topic; DESIGN.md indexes it
│   ├── setup/              depth behind each SETUP.md step
│   └── research/           index plus compressed evidence from completed spikes
├── testbench/              test fixtures, live-tenant tooling, a capture decoder
└── website/                copy for kerbridge.org, written for end users
```

- Server (`crates/`, `deploy/`) and client share no code.
- `kerbridge-client` is library plus CLI binary. The library holds the entire
  protocol: discovery, OIDC, the broker call, ccache→KRB-CRED, LSA injection,
  realm enrollment, config, logging. The binary (`kerbridge`) is a thin console
  front end. The `client/kerbridge-agent-windows` and `client/kerbridge-agent-macos` 
  packages build on top of it.
- `SETUP.md` is the route; `docs/setup/` is the details. The split is by *who reads it*, not by topic.
  If every operator needs it, it is in `SETUP.md`; if only some do, or only later, it is a page.
  - Step 4 is the one step with two procedures behind it:
    [`compose-deployment.md`](docs/setup/compose-deployment.md) and
    [`debian-deployment.md`](docs/setup/debian-deployment.md) are one per method,
    and [`broker-host.md`](docs/setup/broker-host.md) is what is true either way.
    Neither method is the default, so neither page is reached from the step table --
    step 4 names both.
  - [`deploy/README.md`](deploy/README.md) is technical details and instructions off the paved road. For most
    deployments, following SETUP.md and the sub-documents should be enough.
- `DESIGN.md` is the index; [`docs/design/`](docs/design/) is the topics. The split is by
  *the question a reader arrives with*, not by component. `DESIGN.md` keeps what a
  reader needs before they can select a topic: the goal, the non-goals, the
  deployment assumptions, the architecture diagram and the security boundaries.
  A topic page never restates them.

## `crates/` - the server components

| Crate | What |
|---|---|
| `kerbridge-broker`, `kerbridge-sync`, `kerbridge-issuerd` | **Broker** offers HTTP API to clients, **sync** reads users and groups from IdP, **issuerd** creates TGTs for the Samba AD. More in `DESIGN.md` |
| `kerbridge-core` | Anything common to all server components: protocols that cross a process boundary. |
| `kerbridge-idp` | Every provider-specific fact, behind one interface. Linked by **both** the broker and sync, because the two build the same stored identity from opposite sides and must not disagree. This is where a second cloud IdP is added. |
| `kerbridge-notify` | Operator-notification channel: persists lists of open problems as files, and sends notifications about them through a configurable webhook. Meant for Slack, Telegram, Mattermost etc. You can also read the problem files with Zabbix agent scripts for example. |
| `kerbridge-manage` | The operator CLI, and one of the crates that are not services. |
| `kerbridge-setup` | The setup CLI, `kbsetup`: provisions the realm, bootstraps the directory, and answers whether durable state still matches the config set. Runs as root on the domain controller and drives the Samba command-line tools; the one crate that creates things which cannot be uncreated. |
| `kerbridge-config` | The configuration CLI: validates the config set, and prints one value or the source list for the shell scripts, which cannot read TOML. Links no LDAP client, because it runs before the realm exists -- directory reach is unavailable to it rather than merely unexercised. Also ships `libexec/prepare-state`, the helper that creates the package directories: not Rust, because both deployments have to run the same bytes and one of them runs them from a container. |

## `deploy/` - deployment and build containers

- Mainly: `kerbridge` Docker Compose project. Subfolders of `deploy/`:
  - Compose project containers
    - `caddy/` : TLS termination (and ACME renewal if needed) for `broker`
    - `realm/` : one image, two services -- `realm` runs Samba AD DC, `issuer` runs `issuerd`
    - `broker/` : HTTP API
    - `sync/` : IdP to AD sync daemon
  - Individual containers
    - `kbmanage/`: build operator's management CLI tool
    - `kbconfig/`: build the configuration CLI
  - Deployment state, gitignored except its templates
    - `configs/`: the config set the binaries read, mounted at `/etc/kerbridge`
    - `member/`: separate Samba file server (`nas1`) for integration tests
    - `mockidp/`: fake OIDC IdP for testing without live Entra
  - Non-container folders
    - `scripts/`: for bootstrapping, testing, verification, backup etc. Sorted by
      what a script would still mean off Compose:
      - `compose/`: no Debian counterpart exists or should -- dpkg and systemd do
        these jobs. Teardown, image and volume removal, Caddy, the deployment's
        durable state out and back in, and the host tree the bind mounts need,
        because `backup.sh` discovers Docker volumes by compose-project label, a
        Debian deployment backs the domain up with `samba-tool` and no script at
        all, and `bootstrap-secrets.sh` is a caller of a shipped helper rather
        than the work itself.
      - `bench/`: testing and development only; production runs none of it.
      - `config/`: the gates and generators over `.env` and `configs/`.
      - directly in `scripts/`: the residue -- each of these has a Compose half
        and a Debian half tangled in one file, and moving it settles neither.
    - `terraform/entra/`: recipe for automatic Entra setup & app registrations;
      one directory per cloud IdP
  - Runtime folders. These are created on demand.
    - `secrets/`: your deployment secrets, referenced by `.env`
    - `state/`: runtime logs, persisted problem reports 

## `debian/` - the packages

The Debian deployment, where the Docker Compose deployment's counterpart is
`deploy/`. One source
package builds these binary packages: `kerbridge-config` (which owns
`/etc/kerbridge`, the `_kerbridge` group and the install-time questions),
`kerbridge-issuerd`, `kerbridge-broker`, `kerbridge-sync`, `kerbridge-manage`,
and a `kerbridge` metapackage that ships no files.

Know these things before you read the directory.

**It packages, it does not build.** The programs are static musl artifacts
from the digest-pinned toolchain the images use, and a Debian builder cannot
make the same bytes. So `debian/rules` stages a tree somebody else filled --
`debian/prebuilt/`, whose layout is the paths the packages install to.
`make debian-docker` fills it and cuts the debs, both in Docker;
`debian/stage-prebuilt` is the same step by hand, from a cargo target directory.

**Some files in here are generated and not committed.** `debian/changelog` is
what dpkg reads the version from, so whatever writes it is the release process:
`debian/make-changelog` writes it from `CHANGELOG.md` and `git describe`, and
stamps the version into `kerbridge-config.NEWS` from the committed
`.NEWS.in` beside it -- when a release has one. That file is named
`.NEWS.in__disabled` while no release needs work from the operator, and
nothing generates or installs a NEWS file then.

| Path | What |
|---|---|
| `control`, `copyright`, `rules`, `source/format` | The source package. `3.0 (native)`, `debhelper-compat (= 13)`, `${misc:Depends}` only. |
| `*.install` | Which staged paths each package takes. The metapackage ships nothing and so has none. |
| `*.service`, `*.logrotate` | One systemd unit and one rotation snippet per daemon. Placed by `dh_installsystemd`, which puts them under `/usr/lib` on both supported releases -- the `/lib` alias older debhelpers used is what lintian rejects at error severity. |
| `*.postinst`, `*.postrm` | The group, the two unix users, the `/etc/krb5.conf` include line, and what purge removes. |
| `kerbridge-config.{templates,config}`, `po/` | The debconf questions, and the translation template. |
| `*.lintian-overrides` | One line per shipped binary. A static-PIE musl binary reads to lintian as a shared library with no prerequisites. |
| `man/` | The hand-written man pages, one per daemon. The rest are generated by `clap_mangen`, one per command of `kbconfig`, `kbmanage` and `kbsetup`, and have no committed copy. |
| `examples/` | Caddy and nginx in front of the broker; ufw and nftables on the domain controller. |
| `about.toml`, `about.hbs` | `cargo-about`'s input for `THIRD-PARTY-NOTICES`, which every static binary has to carry. |
| `Dockerfile`, `Dockerfile.dockerignore` | `make debian-docker`: the binaries in the pinned toolchain, then `dpkg-buildpackage` and `lintian` on trixie, out to `dist/debian/`. Its own ignore file because this is the one image whose context needs `debian/` and `.git/`. |
| `check-install` | The other half of `make test-deb`: installs what that built, on trixie and noble, and checks that bookworm and jammy refuse `kerbridge-issuerd`. Throwaway containers, no init in any of them. |
| `check-manifests` | A `make test-fast` gate, with no Docker and no build. It checks the values that two files each must agree about: the binaries, the package names, the compat level, the version, and the newest `CHANGELOG.md` section. |

## `testbench/`

Only what is below, and nothing else. `crates/` is the implementation now, so the
Python reference implementations and the spike bring-up scripts are gone.

- `fixtures/` — the corpora `cargo test` loads, and the two generators that are
  the only way to regenerate them. `entra-token/make_fixtures.py` is also *run*
  by `make test-stack`.
- `entra-tenant/` — the tools for driving a live Entra tenant. Kept because they
  implement nothing KerBridge ships and the work they serve is still open.
- `wire.py` — decodes a tcpdump capture without tshark, which
  [`docs/windows-testbench.md`](docs/windows-testbench.md) needs and nothing else provides.

The bench's *deployment* fixtures are deliberately not here: the seeded
accounts, `mockidp`'s tenant id and `nas1`'s address live in tracked
[`deploy/bench.env`](deploy/bench.env), because compose and the deploy scripts
read it beside `.env` and `make test-stack` stages only tracked files into its
disposable tree.

Separate from `crates/` because none of it is production code. See
[`testbench/README.md`](testbench/README.md).

## `website/` - the user help site

`help.kerbridge.org`, which the agent's **Help** menu opens
(`kerbridge_client::HELP_URL`). Written for the person at the keyboard rather
than the operator, and generated: one page per language, both platforms in each.

Its own Cargo workspace, as `client/` is, so a templating dependency stays out of
the lockfiles of anything that ships.

| Path | What |
|---|---|
| `content/en.toml` | The page's prose. The source; the others are translations of it and must carry exactly its keys. |
| `templates/` | The markup. `page.html.j2` is the whole page; `index.html.j2` is the language chooser at the root. |
| `assets/` | One stylesheet, one script, and the self-hosted Noto Sans subsets. |
| `src/main.rs` | The generator. |
| `dist/` | Output. Not committed, not authored — every byte of it is built. |

**Labels are not written here.** The page quotes the agent constantly, and those
words already exist, in every language, in
[`client/kerbridge-client/src/strings/`](client/kerbridge-client/src/strings/).
The generator includes that module directly, so the template writes
`{{ s.act_drop_ticket }}` and a renamed field is a build error rather than a page
that teaches a button nobody has. A translator writes prose and never a label.

Nothing else is authored either: the state icons are rebuilt by
[`docs/scripts/make-state-icons.py`](docs/scripts/make-state-icons.py) from the
constants the agents draw from, and the screenshots and the logo are copied from
`docs/`, which owns them because `README.md` shows the same files.

`make -C website` builds it, `serve` previews it, and `check` renders every
language without writing anything — that last one is what `make test` runs.

[`.github/workflows/website.yml`](.github/workflows/website.yml) publishes it to
GitHub Pages on a push to `main` that touches one of the generator's inputs.
