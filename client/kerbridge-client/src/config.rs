//! Where the helper keeps its (non-secret) state, and who gets to decide what.
//!
//! Three layers, and the distinction is the whole point:
//!
//! * A policy layer -- what *IT* decided. Read-only to the agent, and it wins. A
//!   fleet-deployed machine gets its broker URL here and the Settings field goes
//!   read-only, so a user cannot point the agent at somebody else's broker. That
//!   is `HKLM\Software\Policies\KerBridge` on Windows and a *forced* managed
//!   preference on macOS -- the one an MDM profile writes, not anything the user
//!   can set.
//! * `config.toml` -- what *this user* chose. Editable by hand; the Settings
//!   window writes it. In `%APPDATA%\KerBridge\` on Windows and
//!   `~/Library/Application Support/KerBridge/` on macOS.
//! * The deployment defaults -- what the broker's `/config` says a client here
//!   should do when nobody above has said. They reach a machine no management
//!   system owns, which is the half policy cannot cover.
//!
//! **A setting the user has not touched is absent from `config.toml`, never
//! written out at its default.** That is what leaves room for the layer below:
//! a stated value cannot be told apart from a decision, so writing defaults
//! would pin every machine to whatever the build shipped on the day it first
//! ran. The same rule governs the server's own templates
//! (`kerbridge_core::config::template`).
//!
//! **No secret is stored in any of them.** The OIDC refresh token lives in the
//! agent process's memory and dies with it; the access token is discarded the
//! moment the ticket comes back. What persists is a URL, a few booleans and a
//! cached copy of the broker's Kerberos block -- the last so the agent can name
//! the realm, and check enrollment against it, before the first successful
//! discovery of a run.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::discovery::{Defaults, KerberosConfig};
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

#[cfg_attr(windows, path = "windows/config.rs")]
#[cfg_attr(target_os = "macos", path = "macos/config.rs")]
#[cfg_attr(target_os = "linux", path = "linux/config.rs")]
mod imp;

/// Folder name for this user's state. The product name, not a component name,
/// and the same string on every platform.
pub const APP_DIR: &str = "KerBridge";

pub fn app_dir() -> Option<PathBuf> {
    imp::app_dir()
}

pub fn config_path() -> Option<PathBuf> {
    app_dir().map(|d| d.join("config.toml"))
}

pub fn log_path() -> Option<PathBuf> {
    app_dir().map(|d| d.join("kerbridge.log"))
}

/// The broker's Kerberos block as last discovered, persisted so the tray can
/// render and check enrollment offline.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct Cache {
    #[serde(default)]
    pub realm: String,
    #[serde(default)]
    pub kdcs: Vec<String>,
    #[serde(default)]
    pub services: Vec<String>,
}

impl Cache {
    pub fn to_kerberos(&self) -> KerberosConfig {
        KerberosConfig {
            realm: self.realm.clone(),
            kdcs: self.kdcs.clone(),
            services: self.services.clone(),
        }
    }
}

/// The device grant this machine holds, as far as this machine knows.
///
/// Not a secret and deliberately not authoritative: the key itself lives in the
/// TPM and the grant itself lives in the directory. What is here is the handle
/// the broker gave back and the claimed identity to present with it -- the two
/// things the tray would otherwise have to re-derive from a sign-in it is
/// specifically trying to avoid. Every one of them is re-checked server-side on
/// every exchange, so a stale copy costs a refused request, never access.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct Grant {
    /// The operator handle, for self-revocation at sign-out.
    pub grant_id: String,
    /// The `kb1|` value to claim. The broker looks the object up by this and
    /// then checks the presented key is among *that* object's grants, so
    /// claiming someone else's fails.
    pub identity: String,
    /// The realm principal this grant last obtained, learned from the exchange
    /// itself. `None` until one exchange has run.
    ///
    /// The `kb1|` value above cannot be compared with anything in the ticket
    /// cache -- it is an issuer and a subject, not a name the KDC ever uses --
    /// so this is the only way the agent can tell a ticket the grant produced
    /// from one somebody else's sign-in left behind. That distinction is what
    /// stops a delegated machine from adopting, and keeping, an engineer's
    /// ticket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// What an assertion must name, copied from `/config` at grant time.
    pub audience: String,
    /// Unix seconds by which someone must sign in through a browser again. The
    /// broker enforces its own copy, clamped by the current operator setting;
    /// this one is only what the tray shows.
    pub sign_in_required_by: i64,
}

/// `config.toml` itself. A process changes it only through [`Settings::update`].
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct FileConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker_url: Option<String>,
    /// Whom this machine authorizes itself for -- a login name or a literal
    /// `kb1|` value. Absent is the ordinary case: whoever signs in here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_for: Option<String>,
    /// What this machine is supposed to be working as: `realm|delegated-user`,
    /// with the second half empty where nobody is delegated. Absent means it is
    /// not supposed to be working at all, which is the difference between a
    /// laptop that has never signed in and one whose ticket lapsed.
    ///
    /// A scope rather than a flag because the two things that void the
    /// expectation -- retargeting the broker, and a machine-wide `GrantFor`
    /// being changed under it -- are both read at load and neither is an
    /// observable event. Comparing at load needs no event.
    ///
    /// **Declared before `grant` and `cache`**: `toml::to_string_pretty` cannot
    /// emit a bare value after a table, so moving it below either one makes
    /// [`Settings::update`] fail at runtime, and only on machines holding a grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_working_as: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<Grant>,
    /// Whether this machine has settled its autostart entry, and to what.
    ///
    /// Not a copy of the entry -- the registry (or `SMAppService`) is the truth,
    /// and Task Manager can change it behind us. This says only that something
    /// deliberate happened: the user used the checkbox, or a deployment default
    /// was applied once. `None` means neither has, which is what lets a
    /// [`Defaults`] answer seed a fresh profile and never override a choice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autostart: Option<bool>,
    /// Gates the *entire* NTLM-fallback machinery. `None` is "the user has not
    /// decided", which is what lets the deployment default speak; the built-in
    /// answer is on where there is an NTLM fallback to recover from, which is
    /// Windows and nowhere else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ntlm_fallback_recovery: Option<bool>,
    /// Suppress every OS notification and every unsolicited status surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub silent: Option<bool>,
    /// Let the OS's own token store (WAM/WHfB on Windows) issue the broker
    /// token before the browser is tried. Built-in answer is on; turning it off
    /// forces the browser flow. `None` as above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_sign_in: Option<bool>,
    /// A browser sign-in this agent left at the authority. Persisted because the
    /// SSO cookie outlives this process: a flag that resets on restart stops
    /// offering the cleanup in exactly the walk-away case it exists for.
    ///
    /// Not proof the session is still live -- cookies get cleared, sessions
    /// expire. Opening a logout page for a session that has gone is a no-op,
    /// while failing to offer one for a session that has not is the leak, so
    /// this errs toward offering.
    #[serde(default)]
    pub browser_session: bool,
    #[serde(default)]
    pub cache: Cache,
}

/// See [`FileConfig::ntlm_fallback_recovery`]. macOS clears the same expiry on
/// its own within about ten minutes and needs nothing restarted (measured --
/// research spike `macos-ticket-injection` Q9), so the machinery is off
/// there and the Settings window has no switch for it.
fn ntlm_fallback_default() -> bool {
    cfg!(windows)
}

/// Prepend `https://` unless the string already carries a scheme. `contains("://")`
/// rather than a `https` check so an explicit `http://` is left as the user typed it
/// (to be rejected later by `require_https`, not silently rewritten).
fn with_https(url: &str) -> String {
    if url.contains("://") { url.to_owned() } else { format!("https://{url}") }
}

/// A user-entered broker URL as stored. A scheme-less entry
/// (`broker.example.site`) gets `https://` prepended: TLS is mandatory anyway,
/// so typing it is noise. An empty entry gives `None`.
pub(crate) fn typed_broker_url(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| with_https(text))
}

impl FileConfig {
    /// Read the file at `path`. A missing file is an empty configuration. Any
    /// other failure is an error, a file that does not parse included.
    fn read(path: &Path) -> Result<FileConfig> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(FileConfig::default()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn set_grant_for(&mut self, target: &str) {
        let target = target.trim();
        self.grant_for = (!target.is_empty()).then(|| target.to_owned());
    }

    pub fn set_cache(&mut self, k: &KerberosConfig) {
        self.cache =
            Cache { realm: k.realm.clone(), kdcs: k.kdcs.clone(), services: k.services.clone() };
    }

    /// Record what grant `grant_id` just worked as. Returns true when that is
    /// news. A different grant, or none, stays as it is: it can be newer than
    /// the grant the exchange used.
    pub fn set_grant_principal(&mut self, grant_id: &str, principal: &str) -> bool {
        match self.grant.as_mut() {
            Some(g) if g.grant_id == grant_id && g.principal.as_deref() != Some(principal) => {
                g.principal = Some(principal.to_owned());
                true
            }
            _ => false,
        }
    }

    /// Point this file at another broker, and remove every value the old
    /// broker owned: its cached Kerberos block, the device grant it issued and
    /// the browser-session marker of its authority. User choices stay.
    pub fn retarget(&mut self, broker_url: Option<String>) {
        self.broker_url = broker_url;
        self.cache = Cache::default();
        self.grant = None;
        self.browser_session = false;
    }
}

/// Replace `path` with `text` through a temporary file in the same directory.
/// A reader then sees the complete old file or the complete new one, never an
/// empty or partial file. The temporary file has the process ID in its name, so
/// two processes do not write the same one.
///
/// `std::fs::rename` replaces an existing file on every platform: on Windows it
/// is `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`. On Windows the rename
/// fails while another program holds `config.toml` open without delete sharing;
/// the old file then stays.
fn replace(path: &Path, text: &str) -> Result<()> {
    let dir = path.parent().context("config.toml has no directory")?;
    std::fs::create_dir_all(dir).context("creating the config directory")?;
    let mut name = path.file_name().context("config.toml has no file name")?.to_owned();
    name.push(format!(".{}.tmp", std::process::id()));
    let tmp = dir.join(name);
    let _ = std::fs::remove_file(&tmp);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .and_then(|mut file| file.write_all(text.as_bytes()).and_then(|()| file.sync_all()))
        .with_context(|| format!("writing {}", tmp.display()))
        .and_then(|()| {
            std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
        });
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// Machine policy. Absent values mean "not managed", which is the normal case.
#[derive(Default)]
struct Policy {
    broker_url: Option<String>,
    grant_for: Option<String>,
    autostart: Option<bool>,
    ntlm_fallback_recovery: Option<bool>,
    silent: Option<bool>,
    windows_sign_in: Option<bool>,
}

/// The resolved view the app uses: file preferences with policy layered on top,
/// and the deployment's own defaults and DNS underneath both.
pub struct Settings {
    file: FileConfig,
    policy: Policy,
    /// A broker found in DNS this run (see [`crate::srv`]). Deliberately not
    /// written to disk: DNS stays the authority, so a broker that moves is
    /// followed on the next start instead of being pinned here.
    discovered: Option<String>,
    /// What the broker's `/config` says this deployment prefers, as of this
    /// run. Memory-only for the same reason as `discovered`: the deployment
    /// stays the authority, and a value pinned here would outlive the operator
    /// changing their mind. `None` until this broker has supplied a document;
    /// `Some` with every field absent is a complete answer with no opinion.
    ///
    /// Autostart is the exception and is written, because applying it is an act
    /// on the operating system rather than a value read back -- see
    /// [`FileConfig::autostart`] and [`Settings::enforce_autostart`].
    defaults: Option<Defaults>,
    /// Where [`Settings::update`] writes. `None` where no application
    /// directory resolves; in unit tests, `None` keeps every change in memory.
    path: Option<PathBuf>,
}

impl Settings {
    /// Read both layers. Never fails: a missing or malformed `config.toml` is
    /// reported to the log and treated as "unconfigured" -- a tray that refuses
    /// to start because of a typo in a config file is worse than one that asks
    /// for its broker URL again. [`Settings::update`] reads the file again and
    /// refuses to write over one that does not parse, so the defaults used here
    /// never replace it.
    pub fn load() -> Settings {
        let path = config_path();
        let file = path
            .as_deref()
            .map(|p| {
                FileConfig::read(p).unwrap_or_else(|e| {
                    crate::log::warn(&format!("config.toml unusable ({e:#}); using defaults"));
                    FileConfig::default()
                })
            })
            .unwrap_or_default();

        let policy = Policy {
            broker_url: imp::policy_string("BrokerUrl").filter(|s| !s.is_empty()),
            grant_for: imp::policy_string("GrantFor").filter(|s| !s.trim().is_empty()),
            autostart: imp::policy_bool("Autostart"),
            ntlm_fallback_recovery: imp::policy_bool("NtlmFallbackRecovery"),
            silent: imp::policy_bool("Silent"),
            windows_sign_in: imp::policy_bool("WindowsSignIn"),
        };
        Settings { file, policy, discovered: None, defaults: None, path }
    }

    /// Settings that hold `file` in memory only.
    #[cfg(test)]
    pub(crate) fn for_test(file: FileConfig) -> Settings {
        Settings { file, policy: Policy::default(), discovered: None, defaults: None, path: None }
    }

    /// Settings that read and write the file at `path`, as `load` reads it.
    #[cfg(test)]
    pub(crate) fn for_test_at(path: &Path) -> Settings {
        Settings {
            file: FileConfig::read(path).unwrap_or_default(),
            path: Some(path.to_owned()),
            ..Settings::for_test(FileConfig::default())
        }
    }

    /// Apply `change` to `config.toml` as it is on disk now, and make the
    /// result this process's file layer.
    ///
    /// 1. Read and parse the current file. A missing file is empty.
    /// 2. Apply `change`. It sets or clears only the fields it names, so a
    ///    value that another process wrote to another field stays.
    /// 3. If the value changed, write it through [`replace`].
    ///
    /// **A file that does not parse is never replaced.** `change` then applies
    /// in memory only, and the update returns an error if `change` changed the
    /// value. After a failed write, the merged value stays in memory only until
    /// the next update reads the file.
    ///
    /// This prevents lost updates from a stale snapshot, and a partial file
    /// after a crash. It is not concurrency control: two processes that read
    /// the same version can both write, and the last write wins. A resident
    /// agent sees a change from another process only at its next update.
    /// Only the file layer is written, so a policy value never goes into the
    /// user's file.
    pub fn update(&mut self, change: impl FnOnce(&mut FileConfig)) -> Result<()> {
        let Some(path) = self.path.as_deref() else {
            change(&mut self.file);
            return if cfg!(test) {
                Ok(())
            } else {
                Err(anyhow!("cannot find the application directory"))
            };
        };
        let mut file = match FileConfig::read(path) {
            Ok(file) => file,
            Err(e) => {
                let before = self.file.clone();
                change(&mut self.file);
                return if self.file == before {
                    Ok(())
                } else {
                    Err(e.context("not replacing config.toml"))
                };
            }
        };
        let before = file.clone();
        change(&mut file);
        let written = if file == before {
            Ok(())
        } else {
            toml::to_string_pretty(&file)
                .context("serializing config.toml")
                .and_then(|text| replace(path, &text))
        };
        self.file = file;
        written
    }

    /// Broker URL in precedence order: HKLM policy > `config.toml` > DNS > unset.
    /// What IT decided beats what the user chose, and both beat what the network
    /// volunteered.
    pub fn broker_url(&self) -> Option<&str> {
        self.broker_url_with(self.file.broker_url.as_deref())
    }

    /// What [`Settings::broker_url`] answers when `config.toml` holds `user`.
    pub(crate) fn broker_url_with<'a>(&'a self, user: Option<&'a str>) -> Option<&'a str> {
        self.policy.broker_url.as_deref().or(user).or(self.discovered.as_deref())
    }

    /// Record what [`crate::srv::discover_broker`] found. It sits below both
    /// layers above, so a late lookup cannot move a configured client.
    pub fn set_discovered(&mut self, url: String) {
        self.discovered = Some(url);
    }

    /// True when policy supplies the broker URL, so the UI must not offer to edit it.
    pub fn broker_url_locked(&self) -> bool {
        self.policy.broker_url.is_some()
    }

    /// Whom this machine authorizes itself for, machine-wide value first.
    ///
    /// Neither layer is a security control: the broker checks the delegate group
    /// whatever the client asks for, so this only decides what it asks for. The
    /// machine-wide layer wins because the MSI can write it and the person at
    /// an unattended machine is not the person who decided what it builds as.
    pub fn grant_for(&self) -> Option<&str> {
        self.policy.grant_for.as_deref().or(self.file.grant_for.as_deref())
    }

    /// True when policy supplies it, so the UI shows it rather than offering to
    /// edit something it cannot change.
    pub fn grant_for_locked(&self) -> bool {
        self.policy.grant_for.is_some()
    }

    /// The scope this machine last landed a ticket in. See
    /// [`FileConfig::expected_working_as`].
    pub fn expected_working_as(&self) -> Option<&str> {
        self.file.expected_working_as.as_deref()
    }

    /// Replace the deployment defaults from one accepted discovery document.
    pub fn set_defaults(&mut self, defaults: Defaults) {
        self.defaults = Some(defaults);
    }

    /// Mark the current discovery document as unresolved.
    pub fn clear_defaults(&mut self) {
        self.defaults = None;
    }

    pub fn defaults_ready(&self) -> bool {
        self.defaults.is_some()
    }

    /// Policy, then the file, then the deployment, then the built-in answer --
    /// and only on the platform that has an NTLM fallback to recover from. The
    /// `cfg!` is what stops a deployment-wide `true` from arming machinery on
    /// macOS that macOS does not need and has no switch for.
    pub fn ntlm_fallback_recovery(&self) -> bool {
        cfg!(windows)
            && self
                .policy
                .ntlm_fallback_recovery
                .or(self.file.ntlm_fallback_recovery)
                .or(self.defaults.and_then(|defaults| defaults.ntlm_fallback_recovery))
                .unwrap_or_else(ntlm_fallback_default)
    }

    /// The effective silent setting. `None` only when neither policy nor the
    /// user's choice resolves it and the discovery document is unresolved. The
    /// built-in `false` applies once the document has supplied its complete
    /// defaults snapshot.
    pub fn resolved_silent(&self) -> Option<bool> {
        self.policy
            .silent
            .or(self.file.silent)
            .or_else(|| self.defaults.map(|defaults| defaults.silent.unwrap_or(false)))
    }

    pub fn silent(&self) -> bool {
        self.resolved_silent().unwrap_or(false)
    }

    pub fn silent_locked(&self) -> bool {
        self.policy.silent.is_some()
    }

    /// Both halves: the stored preference, **and** a platform with a credential
    /// store to ride. The flag defaults to on and travels with the file, so
    /// without the second half every Mac claims a supply it does not have --
    /// `Facts::supply` answers `WindowsSignIn`, which suppresses `NoSupply`
    /// and offers a renewal nothing on that machine can supply.
    ///
    /// `cfg!` rather than a `Host` question for the same reason
    /// `ntlm_fallback_default` uses it: it is a fact about the build, not about
    /// the machine or the moment.
    pub fn windows_sign_in(&self) -> bool {
        cfg!(windows)
            && self
                .policy
                .windows_sign_in
                .or(self.file.windows_sign_in)
                .or(self.defaults.and_then(|defaults| defaults.windows_sign_in))
                .unwrap_or(true)
    }

    /// True when policy supplies it, so the checkbox reads the managed value
    /// and does not move.
    pub fn windows_sign_in_locked(&self) -> bool {
        self.policy.windows_sign_in.is_some()
    }

    /// True when policy decides it, so the checkbox reads the managed value and
    /// does not move -- the same rule as the machine-wide entry, and for the
    /// same reason: a box the user can move but that changes nothing is a lie.
    pub fn autostart_managed(&self) -> bool {
        self.policy.autostart.is_some()
    }

    /// Make the operating system agree with whichever layer decides autostart.
    /// An error says only that `config.toml` did not record a seed.
    ///
    /// The login entry is per-user on both platforms, so nothing a policy value
    /// or a deployment default says takes effect until something writes one.
    /// The MSI's machine-wide `Run` value is the one route that needs no such
    /// write.
    ///
    /// **A policy answer is applied and not recorded.** Recording it would
    /// tattoo the file, so a machine leaving the policy's scope would go on
    /// starting the agent with nothing left to say why. A deployment default is
    /// recorded, because it is a seed: it decides a profile that has never
    /// decided, once, and a later choice then wins over it.
    pub fn enforce_autostart(&mut self) -> Result<()> {
        // Policy is applied on every start, because it is the answer that must
        // hold whatever else touched the entry. A user's own settled answer is *not* re-applied: the entry
        // itself is the truth for that case, and rewriting it here would undo
        // whatever they did to it outside this window. A deployment default is
        // applied once, to a profile that has never had an answer.
        let (want, seed) = match (self.policy.autostart, self.file.autostart) {
            (Some(policy), _) => (policy, false),
            (None, Some(_)) => return Ok(()),
            (None, None) => match self.defaults.and_then(|defaults| defaults.autostart) {
                Some(default) => (default, true),
                None => return Ok(()),
            },
        };
        // Machine-wide beats every per-user entry, and no per-user act can
        // countermand it. Say so rather than looping on a write that cannot win.
        if autostart_machine_wide() {
            if !want {
                crate::log::warn(
                    "autostart is asked to be off, but a machine-wide Run entry starts the agent                      anyway; only an administrator can remove that",
                );
            }
            return Ok(());
        }
        if autostart_enabled() != want {
            if let Err(e) = set_autostart(want) {
                crate::log::warn(&format!("could not apply the autostart entry: {e:#}"));
                return Ok(());
            }
            crate::log::info(&format!("autostart set to {want} by {}", self.autostart_source()));
        }
        if seed { self.seed_autostart(want) } else { Ok(()) }
    }

    /// Record a deployment default as this profile's autostart answer. A seed
    /// decides only a profile that has not decided: a choice recorded since,
    /// by this process or another one, stays.
    fn seed_autostart(&mut self, want: bool) -> Result<()> {
        self.update(|f| {
            f.autostart.get_or_insert(want);
        })
    }

    /// Which layer decided, for the log.
    fn autostart_source(&self) -> &'static str {
        if self.policy.autostart.is_some() {
            "machine policy"
        } else if self.file.autostart.is_some() {
            "this user"
        } else {
            "the deployment default"
        }
    }

    pub fn browser_session(&self) -> bool {
        self.file.browser_session
    }

    pub fn cache(&self) -> &Cache {
        &self.file.cache
    }

    pub fn grant(&self) -> Option<&Grant> {
        self.file.grant.as_ref()
    }
}

// ---- autostart --------------------------------------------------------------

/// Whether this executable is registered to start at login.
///
/// Per-user on both platforms, and that is required rather than convenient: the
/// ticket has to land in the interactive user's own ticket cache -- their
/// non-elevated LUID on Windows, their session's `API:` collection on macOS -- so
/// the agent has to be launched *by that user's session*.
pub fn autostart_enabled() -> bool {
    imp::autostart_enabled()
}

/// Whether autostart is set machine-wide, which no per-user setting can
/// countermand. Windows only: the MSI writes an `HKLM` `Run` value when a
/// deployment asks for it.
pub fn autostart_machine_wide() -> bool {
    imp::autostart_machine_wide()
}

/// Whether this machine starts the agent at login at all, by either route.
///
/// The one to gate behaviour on. [`autostart_enabled`] is the per-user
/// preference `set_autostart` writes and nothing else -- reading it alone left
/// an HKLM-deployed fleet starting the agent every logon and never attempting
/// the sign-in that autostart exists for.
pub fn autostart_active() -> bool {
    autostart_enabled() || autostart_machine_wide()
}

pub fn set_autostart(on: bool) -> Result<()> {
    imp::set_autostart(on)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `toml::to_string_pretty` cannot emit a bare value after a table, and
    /// `grant` and `cache` are both tables sitting among the scalars in
    /// [`FileConfig`] -- so the field order matters. Declaring either one
    /// earlier makes `save` fail at runtime, and only on the machines that
    /// actually hold a grant.
    #[test]
    fn a_config_holding_a_grant_round_trips() {
        let stored = FileConfig {
            broker_url: Some("https://broker.example.site".into()),
            grant_for: Some("svc-builder".into()),
            expected_working_as: Some("EXAMPLE.SITE|svc-builder".into()),
            grant: Some(Grant {
                grant_id: "1a2b3c4d".into(),
                identity: "kb1|entra|33334444-dddd-5555-eeee-6666ffff7777".into(),
                principal: Some("svc-builder@EXAMPLE.SITE".into()),
                audience: "kerbridge://EXAMPLE.SITE".into(),
                sign_in_required_by: 1_785_000_000,
            }),
            autostart: Some(true),
            ntlm_fallback_recovery: Some(true),
            silent: Some(true),
            windows_sign_in: Some(false),
            browser_session: true,
            cache: Cache {
                realm: "EXAMPLE.SITE".into(),
                kdcs: vec!["kerbridge.example.site".into()],
                services: vec![],
            },
        };
        let text = toml::to_string_pretty(&stored).expect("serializes");
        let back: FileConfig = toml::from_str(&text).expect("parses back");
        let grant = back.grant.expect("the grant survives the round trip");
        assert_eq!(grant.grant_id, "1a2b3c4d");
        assert_eq!(grant.sign_in_required_by, 1_785_000_000);
        assert_eq!(grant.principal.as_deref(), Some("svc-builder@EXAMPLE.SITE"));
        assert_eq!(back.grant_for.as_deref(), Some("svc-builder"));
        assert_eq!(back.expected_working_as.as_deref(), Some("EXAMPLE.SITE|svc-builder"));
        assert_eq!(back.windows_sign_in, Some(false));
        assert_eq!(back.silent, Some(true));
        assert_eq!(back.autostart, Some(true));
        assert_eq!(back.cache.realm, "EXAMPLE.SITE");
    }

    /// State written by 1.0.1 remains usable after the new client settings are
    /// added. The upgrade must not purge tickets or discard a device grant.
    #[test]
    fn a_1_0_1_config_keeps_its_broker_state() {
        let older = r#"
            broker_url = "https://broker.example.site"
            expected_working_as = "EXAMPLE.SITE|"
            browser_session = true

            [grant]
            grant_id = "1a2b3c4d"
            identity = "kb1|entra|33334444-dddd-5555-eeee-6666ffff7777"
            audience = "kerbridge://EXAMPLE.SITE"
            sign_in_required_by = 1785000000

            [cache]
            realm = "EXAMPLE.SITE"
            kdcs = ["kerbridge.example.site"]
        "#;
        let back: FileConfig = toml::from_str(older).expect("parses");
        let settings = settings(back);

        assert_eq!(settings.broker_url(), Some("https://broker.example.site"));
        assert_eq!(settings.cache().realm, "EXAMPLE.SITE");
        assert!(settings.grant().is_some());
        assert!(settings.grant().unwrap().principal.is_none());
        assert!(settings.browser_session());
        assert_eq!(settings.expected_working_as(), Some("EXAMPLE.SITE|"));
    }

    fn settings(file: FileConfig) -> Settings {
        Settings::for_test(file)
    }

    #[test]
    fn a_cleared_user_broker_returns_to_dns() {
        let mut settings = settings(FileConfig::default());
        settings.set_discovered("https://dns.example.site".into());
        let typed = typed_broker_url(" typed.example.site ");
        assert_eq!(typed.as_deref(), Some("https://typed.example.site"));
        assert_eq!(settings.broker_url_with(typed.as_deref()), typed.as_deref());

        settings.update(|f| f.retarget(typed)).unwrap();
        assert_eq!(settings.broker_url(), Some("https://typed.example.site"));
        settings.update(|f| f.retarget(typed_broker_url("  "))).unwrap();

        assert_eq!(settings.broker_url(), Some("https://dns.example.site"));
        assert!(settings.file.broker_url.is_none());
    }

    /// The order the whole feature rests on: what IT decided, then what the
    /// user chose, then what the deployment publishes, then the built-in
    /// answer. Each layer only speaks where every layer above it is silent.
    #[test]
    fn each_layer_only_answers_where_the_one_above_it_is_silent() {
        let on = cfg!(windows);
        let mut s = settings(FileConfig::default());
        // Nobody has said anything: the built-in answer, which is on.
        assert_eq!(s.windows_sign_in(), on);
        assert!(!s.windows_sign_in_locked());

        s.set_defaults(Defaults { windows_sign_in: Some(false), ..Defaults::default() });
        assert!(!s.windows_sign_in());

        // The user's own choice beats the deployment's default.
        s.update(|f| f.windows_sign_in = Some(true)).unwrap();
        assert_eq!(s.windows_sign_in(), on);

        // And policy beats both, and says so, so the checkbox stops offering.
        s.policy.windows_sign_in = Some(false);
        assert!(!s.windows_sign_in());
        assert!(s.windows_sign_in_locked());
    }

    /// A deployment default is a seed and a policy value is not. Recording a
    /// policy answer in `config.toml` would leave a machine that has left the
    /// policy's scope still obeying it, with nothing left to say why.
    #[test]
    fn a_deployment_default_is_recorded_and_a_policy_value_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut s = Settings::for_test_at(&path);
        s.seed_autostart(true).unwrap();
        assert_eq!(on_disk(&path).autostart, Some(true));

        // The same default, arriving again, does not override a user who then
        // turns it off. This holds also when another process records the choice.
        let mut agent = Settings::for_test_at(&path);
        Settings::for_test_at(&path).update(|f| f.autostart = Some(false)).unwrap();
        agent.seed_autostart(true).unwrap();
        assert_eq!(on_disk(&path).autostart, Some(false));
        assert_eq!(agent.file.autostart, Some(false));

        let mut s = settings(FileConfig::default());
        s.policy.autostart = Some(true);
        assert!(s.autostart_managed());
        assert_eq!(s.file.autostart, None);
    }

    /// The NTLM machinery is Windows' alone. A deployment-wide `true` reaching a
    /// Mac would arm a repair that macOS neither needs nor offers a switch for.
    #[test]
    fn the_ntlm_fallback_machinery_stays_on_the_platform_that_has_one() {
        let mut s = settings(FileConfig::default());
        s.set_defaults(Defaults { ntlm_fallback_recovery: Some(true), ..Defaults::default() });
        assert_eq!(s.ntlm_fallback_recovery(), cfg!(windows));
    }

    #[test]
    fn resolved_silent_waits_for_the_broker_when_no_higher_layer_answers() {
        let mut s = settings(FileConfig::default());
        assert!(!s.defaults_ready());
        assert_eq!(s.resolved_silent(), None);
        assert!(!s.silent(), "silent() uses the built-in false while unresolved");

        s.set_defaults(Defaults { silent: Some(false), ..Defaults::default() });
        assert!(s.defaults_ready());
        assert_eq!(s.resolved_silent(), Some(false));

        s.set_defaults(Defaults { silent: Some(true), ..Defaults::default() });
        assert_eq!(s.resolved_silent(), Some(true));

        s.set_defaults(Defaults::default());
        assert_eq!(s.resolved_silent(), Some(false), "an absent broker value is a complete answer");

        s.file.autostart = Some(false);
        s.clear_defaults();
        assert!(!s.defaults_ready());
        assert_eq!(s.resolved_silent(), None);
        assert_eq!(s.file.autostart, Some(false), "an applied autostart choice remains stored");
    }

    #[test]
    fn policy_and_user_values_resolve_silent_without_the_broker() {
        for value in [false, true] {
            let mut user = settings(FileConfig { silent: Some(value), ..FileConfig::default() });
            assert_eq!(user.resolved_silent(), Some(value));
            user.set_defaults(Defaults { silent: Some(!value), ..Defaults::default() });
            assert_eq!(user.resolved_silent(), Some(value));
            user.clear_defaults();
            assert_eq!(user.resolved_silent(), Some(value));

            let mut policy = settings(FileConfig { silent: Some(!value), ..FileConfig::default() });
            policy.policy.silent = Some(value);
            assert_eq!(policy.resolved_silent(), Some(value));
            policy.set_defaults(Defaults { silent: Some(!value), ..Defaults::default() });
            assert_eq!(policy.resolved_silent(), Some(value));
            policy.clear_defaults();
            assert_eq!(policy.resolved_silent(), Some(value));
        }
    }

    #[test]
    fn silent_precedence_is_builtin_then_broker_then_user_then_policy() {
        let mut s = settings(FileConfig::default());
        s.set_defaults(Defaults { silent: Some(true), ..Defaults::default() });
        s.update(|f| f.silent = Some(false)).unwrap();
        s.policy.silent = Some(true);

        assert_eq!(s.resolved_silent(), Some(true));
        assert!(s.silent_locked());

        s.policy.silent = None;
        assert_eq!(s.resolved_silent(), Some(false));

        s.file.silent = None;
        assert_eq!(s.resolved_silent(), Some(true));

        s.set_defaults(Defaults::default());
        assert_eq!(s.resolved_silent(), Some(false));
        assert!(!s.silent());
    }

    /// The template and the code have to name the same registry values. A
    /// policy an administrator sets and the agent never reads is worse than no
    /// template at all: the Settings window keeps offering the setting, so
    /// nothing on either end says the policy did not land.
    #[test]
    fn the_group_policy_template_names_the_values_the_agent_reads() {
        const ADMX_SRC: &str = include_str!("../../kerbridge-agent-windows/policy/KerBridge.admx");
        const ADML: &str =
            include_str!("../../kerbridge-agent-windows/policy/en-US/KerBridge.adml");

        // Comments stripped first: both files explain themselves in prose that
        // quotes the very markup asserted on below.
        let admx = strip_xml_comments(ADMX_SRC);
        let admx = admx.as_str();

        for value in [
            "BrokerUrl",
            "GrantFor",
            "Autostart",
            "NtlmFallbackRecovery",
            "Silent",
            "WindowsSignIn",
        ] {
            assert!(
                admx.contains(&format!("valueName=\"{value}\"")),
                "{value} is read by Settings::load but no policy writes it"
            );
        }
        // Every policy writes the branch the agent reads first.
        assert_eq!(
            admx.matches("key=\"Software\\Policies\\KerBridge\"").count(),
            6,
            "a policy writing anywhere else would never be read"
        );
        // Intune refuses a template that names a namespace it does not already
        // hold, so a `<using>` here would cost every operator a windows.admx
        // upload first. Nothing outside this file is referenced.
        assert!(!admx.contains("<using"), "an ingested template may reference no other namespace");
        // Every reference resolves: a missing string renders as the raw id in
        // the editor, which an administrator sees and cannot fix.
        for reference in admx.split("$(string.").skip(1) {
            let id = reference.split(')').next().unwrap_or_default();
            assert!(ADML.contains(&format!("id=\"{id}\"")), "{id} has no en-US string");
        }
        for reference in admx.split("$(presentation.").skip(1) {
            let id = reference.split(')').next().unwrap_or_default();
            assert!(
                ADML.contains(&format!("presentation id=\"{id}\"")),
                "{id} has no en-US presentation"
            );
        }
    }

    /// Everything outside `<!-- -->`. Not an XML parser: the one thing asked of
    /// it is that a file's own prose about its markup is not read as markup.
    fn strip_xml_comments(xml: &str) -> String {
        let mut out = String::with_capacity(xml.len());
        let mut rest = xml;
        while let Some(start) = rest.find("<!--") {
            out.push_str(&rest[..start]);
            match rest[start..].find("-->") {
                Some(end) => rest = &rest[start + end + 3..],
                None => return out,
            }
        }
        out.push_str(rest);
        out
    }

    /// A device that has never been granted one writes no `[grant]` table at
    /// all, so an existing `config.toml` is untouched by the feature shipping.
    #[test]
    fn no_grant_writes_no_table() {
        let text = toml::to_string_pretty(&FileConfig::default()).expect("serializes");
        assert!(!text.contains("grant"), "{text}");
        assert!(toml::from_str::<FileConfig>(&text).unwrap().grant.is_none());
    }

    // ---- persistence ----------------------------------------------------------

    fn on_disk(path: &Path) -> FileConfig {
        FileConfig::read(path).expect("config.toml parses")
    }

    fn grant(id: &str) -> Grant {
        Grant {
            grant_id: id.into(),
            identity: "kb1|entra|33334444-dddd-5555-eeee-6666ffff7777".into(),
            principal: None,
            audience: "kerbridge://EXAMPLE.SITE".into(),
            sign_in_required_by: 1_785_000_000,
        }
    }

    fn kerberos(realm: &str) -> KerberosConfig {
        KerberosConfig {
            realm: realm.into(),
            kdcs: vec!["kerbridge.example.site".into()],
            services: vec![],
        }
    }

    /// Every file in `dir`, so a test can see a temporary file left behind.
    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// The agent loads before the CLI creates a grant, and saves an unrelated
    /// setting after it. The grant stays, and the agent then holds it.
    #[test]
    fn a_stale_agent_snapshot_cannot_erase_a_grant_the_cli_saved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut agent = Settings::for_test_at(&path);
        let mut cli = Settings::for_test_at(&path);

        cli.update(|f| {
            f.set_cache(&kerberos("EXAMPLE.SITE"));
            f.grant = Some(grant("1a2b3c4d"));
        })
        .unwrap();
        assert!(agent.grant().is_none(), "the agent's snapshot is stale");
        agent.update(|f| f.silent = Some(true)).unwrap();

        let stored = on_disk(&path);
        assert_eq!(stored.grant.as_ref().map(|g| g.grant_id.as_str()), Some("1a2b3c4d"));
        assert_eq!(stored.cache.realm, "EXAMPLE.SITE");
        assert_eq!(stored.silent, Some(true));
        assert!(agent.file == stored, "the merged file is the agent's new baseline");
    }

    /// Two processes load the same file. Each saves one field. Whichever
    /// order they save in, both fields stay.
    #[test]
    fn sequential_stale_writers_keep_each_others_fields_in_both_orders() {
        for agent_first in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("config.toml");
            let mut agent = Settings::for_test_at(&path);
            let mut cli = Settings::for_test_at(&path);
            let user_choice = |f: &mut FileConfig| f.windows_sign_in = Some(false);
            let cache = |f: &mut FileConfig| f.set_cache(&kerberos("EXAMPLE.SITE"));

            if agent_first {
                agent.update(user_choice).unwrap();
                cli.update(cache).unwrap();
            } else {
                cli.update(cache).unwrap();
                agent.update(user_choice).unwrap();
            }

            let stored = on_disk(&path);
            assert_eq!(stored.windows_sign_in, Some(false), "agent_first={agent_first}");
            assert_eq!(stored.cache.realm, "EXAMPLE.SITE", "agent_first={agent_first}");
            let last = if agent_first { &cli } else { &agent };
            assert!(last.file == stored, "agent_first={agent_first}");
        }
    }

    /// The CLI's grant paths. `--grant` writes the grant with its cache, a
    /// second `--grant` replaces the whole grant, and `--grant-give-up`
    /// clears the grant only. A newer unrelated value stays each time.
    #[test]
    fn cli_grant_create_replace_and_remove_are_explicit_patches() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut cli = Settings::for_test_at(&path);
        let mut agent = Settings::for_test_at(&path);
        let create = |id: &str| {
            let grant = grant(id);
            move |f: &mut FileConfig| {
                f.set_cache(&kerberos("EXAMPLE.SITE"));
                f.grant = Some(grant);
            }
        };

        cli.update(create("old")).unwrap();
        cli.update(|f| {
            assert!(f.set_grant_principal("old", "riku@EXAMPLE.SITE"));
        })
        .unwrap();
        agent.update(|f| f.grant_for = Some("svc-builder".into())).unwrap();

        cli.update(create("new")).unwrap();
        let stored = on_disk(&path);
        let replaced = stored.grant.as_ref().unwrap();
        assert_eq!(replaced.grant_id, "new");
        assert!(replaced.principal.is_none(), "a replaced grant keeps nothing of the old one");
        assert_eq!(stored.grant_for.as_deref(), Some("svc-builder"));
        cli.update(|f| {
            assert!(!f.set_grant_principal("old", "riku@EXAMPLE.SITE"), "not the newer grant");
        })
        .unwrap();

        agent
            .update(|f| {
                f.silent = Some(true);
                f.expected_working_as = Some("EXAMPLE.SITE|svc-builder".into());
            })
            .unwrap();
        cli.update(|f| f.grant = None).unwrap();
        let stored = on_disk(&path);
        assert!(stored.grant.is_none(), "a clear is written, not skipped");
        assert_eq!(stored.silent, Some(true));
        assert_eq!(stored.grant_for.as_deref(), Some("svc-builder"));
        assert_eq!(stored.expected_working_as.as_deref(), Some("EXAMPLE.SITE|svc-builder"));
        assert_eq!(stored.cache.realm, "EXAMPLE.SITE");
    }

    /// Retarget cleanup clears the broker-owned fields and nothing else, even
    /// when the user chose something after the agent loaded.
    #[test]
    fn retarget_clears_exactly_the_broker_owned_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut window = Settings::for_test_at(&path);
        window
            .update(|f| {
                f.broker_url = Some("https://a.example.site".into());
                f.expected_working_as = Some("A.SITE|".into());
                f.set_cache(&kerberos("A.SITE"));
                f.grant = Some(grant("1a2b3c4d"));
                f.browser_session = true;
            })
            .unwrap();
        let mut agent = Settings::for_test_at(&path);
        window
            .update(|f| {
                f.silent = Some(true);
                f.autostart = Some(false);
                f.set_grant_for(" svc-builder ");
            })
            .unwrap();

        agent.update(|f| f.retarget(Some("https://b.example.site".into()))).unwrap();

        let stored = on_disk(&path);
        assert_eq!(stored.broker_url.as_deref(), Some("https://b.example.site"));
        assert!(stored.cache == Cache::default());
        assert!(stored.grant.is_none());
        assert!(!stored.browser_session);
        assert_eq!(stored.silent, Some(true));
        assert_eq!(stored.autostart, Some(false));
        assert_eq!(stored.grant_for.as_deref(), Some("svc-builder"));
        assert_eq!(stored.expected_working_as.as_deref(), Some("A.SITE|"));
        assert!(agent.file == stored);
    }

    /// A file that does not parse is an error and stays as it is. It is
    /// never replaced with defaults.
    #[test]
    fn a_malformed_file_is_refused_and_left_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let damaged = "broker_url = \"https://broker.example.site\"\nsilent = tru\n";
        std::fs::write(&path, damaged).unwrap();

        let mut agent = Settings::for_test_at(&path);
        assert!(agent.file == FileConfig::default(), "load uses defaults");
        let refused = agent.update(|f| f.windows_sign_in = Some(false));

        assert!(refused.is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), damaged);
        assert_eq!(names(dir.path()), ["config.toml"]);
        assert_eq!(agent.file.windows_sign_in, Some(false), "the change holds in memory");

        // The same change again leaves the value as it is, which is no error.
        assert!(agent.update(|f| f.windows_sign_in = Some(false)).is_ok());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), damaged);
    }

    /// An update that changes nothing does not write. A hand-edited file then
    /// keeps its comments and layout.
    #[test]
    fn an_update_that_changes_nothing_does_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let edited = "# set by hand\nexpected_working_as = \"EXAMPLE.SITE|\"\n";
        std::fs::write(&path, edited).unwrap();
        let mut agent = Settings::for_test_at(&path);

        agent.update(|f| f.expected_working_as = Some("EXAMPLE.SITE|".into())).unwrap();
        agent
            .update(|f| {
                f.set_grant_principal("1a2b3c4d", "riku@EXAMPLE.SITE");
            })
            .unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), edited);
    }

    /// A failed replacement removes its temporary file and leaves the target
    /// as it was. A non-empty directory at the target makes the rename fail.
    #[test]
    fn a_failed_replacement_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("kept"), "x").unwrap();

        assert!(replace(&target, "silent = true\n").is_err());
        assert_eq!(names(dir.path()), ["config.toml"]);
        assert_eq!(names(&target), ["kept"]);
    }

    /// A reader sees the complete old file or the complete new one, never an
    /// empty or partial file.
    #[test]
    fn a_reader_never_sees_a_partial_file() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let large = KerberosConfig {
            realm: "EXAMPLE.SITE".into(),
            kdcs: (0..2_000).map(|n| format!("kdc{n}.example.site")).collect(),
            services: vec![],
        };
        let mut writer = Settings::for_test_at(&path);
        writer.update(|f| f.broker_url = Some("https://broker.example.site".into())).unwrap();

        let done = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let reader = scope.spawn(|| {
                let mut reads = 0;
                while !done.load(Ordering::Relaxed) {
                    let text = std::fs::read_to_string(&path).unwrap();
                    let seen: FileConfig = toml::from_str(&text).expect("a complete file");
                    assert!(seen.broker_url.is_some(), "an empty or partial file: {text:?}");
                    assert!(matches!(seen.cache.kdcs.len(), 0 | 1 | 2_000), "a partial cache");
                    reads += 1;
                }
                reads
            });
            for n in 0..100 {
                if n % 2 == 0 {
                    writer.update(|f| f.set_cache(&large)).unwrap();
                } else {
                    writer.update(|f| f.set_cache(&kerberos("EXAMPLE.SITE"))).unwrap();
                }
            }
            done.store(true, Ordering::Relaxed);
            assert!(reader.join().unwrap() > 0);
        });
        assert_eq!(names(dir.path()), ["config.toml"]);
    }
}
