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

use std::path::PathBuf;

use crate::discovery::{Defaults, KerberosConfig};
use anyhow::{Context, Result};
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

/// `config.toml` itself.
#[derive(Serialize, Deserialize, Clone, Default)]
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
    /// [`Settings::save`] fail at runtime, and only on machines holding a grant.
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

/// Machine policy. Absent values mean "not managed", which is the normal case.
#[derive(Default)]
struct Policy {
    broker_url: Option<String>,
    grant_for: Option<String>,
    autostart: Option<bool>,
    ntlm_fallback_recovery: Option<bool>,
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
    /// changing their mind. Empty until the first discovery of a run, so the
    /// built-in answer is what a machine starting offline uses.
    ///
    /// Autostart is the exception and is written, because applying it is an act
    /// on the operating system rather than a value read back -- see
    /// [`FileConfig::autostart`] and [`Settings::enforce_autostart`].
    defaults: Defaults,
}

impl Settings {
    /// Read both layers. Never fails: a missing or malformed `config.toml` is
    /// reported to the log and treated as "unconfigured" -- a tray that refuses
    /// to start because of a typo in a config file is worse than one that asks
    /// for its broker URL again.
    pub fn load() -> Settings {
        let file = config_path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|text| match toml::from_str::<FileConfig>(&text) {
                Ok(c) => c,
                Err(e) => {
                    crate::log::warn(&format!("config.toml unreadable ({e}); using defaults"));
                    FileConfig::default()
                }
            })
            .unwrap_or_default();

        let policy = Policy {
            broker_url: imp::policy_string("BrokerUrl").filter(|s| !s.is_empty()),
            grant_for: imp::policy_string("GrantFor").filter(|s| !s.trim().is_empty()),
            autostart: imp::policy_bool("Autostart"),
            ntlm_fallback_recovery: imp::policy_bool("NtlmFallbackRecovery"),
            windows_sign_in: imp::policy_bool("WindowsSignIn"),
        };
        Settings { file, policy, discovered: None, defaults: Defaults::default() }
    }

    /// Broker URL in precedence order: HKLM policy > `config.toml` > DNS > unset.
    /// What IT decided beats what the user chose, and both beat what the network
    /// volunteered.
    pub fn broker_url(&self) -> Option<&str> {
        self.policy
            .broker_url
            .as_deref()
            .or(self.file.broker_url.as_deref())
            .or(self.discovered.as_deref())
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

    /// Store a user-entered broker URL. A scheme-less entry (`broker.example.site`)
    /// gets `https://` prepended -- TLS is mandatory anyway, so typing it is noise.
    pub fn set_broker_url(&mut self, url: &str) {
        let url = url.trim();
        self.file.broker_url = (!url.is_empty()).then(|| with_https(url));
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

    pub fn set_grant_for(&mut self, target: &str) {
        let target = target.trim();
        self.file.grant_for = (!target.is_empty()).then(|| target.to_owned());
    }

    /// The scope this machine last landed a ticket in. See
    /// [`FileConfig::expected_working_as`].
    pub fn expected_working_as(&self) -> Option<&str> {
        self.file.expected_working_as.as_deref()
    }

    /// Record, or forget, that expectation. Returns true when it is news, so the
    /// ordinary re-injection does not rewrite `config.toml` every few hours --
    /// a landed exchange is not the same thing as a changed one.
    pub fn set_expected_working_as(&mut self, scope: Option<&str>) -> bool {
        let next = scope.map(str::to_owned);
        let changed = next != self.file.expected_working_as;
        self.file.expected_working_as = next;
        changed
    }

    /// Record what the broker's `/config` said this deployment prefers. Sits
    /// below both layers above, so a late discovery cannot move a machine whose
    /// user or whose IT has already decided.
    pub fn set_defaults(&mut self, defaults: Defaults) {
        self.defaults = defaults;
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
                .or(self.defaults.ntlm_fallback_recovery)
                .unwrap_or_else(ntlm_fallback_default)
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
                .or(self.defaults.windows_sign_in)
                .unwrap_or(true)
    }

    /// True when policy supplies it, so the checkbox reads the managed value
    /// and does not move.
    pub fn windows_sign_in_locked(&self) -> bool {
        self.policy.windows_sign_in.is_some()
    }

    pub fn set_windows_sign_in(&mut self, on: bool) {
        self.file.windows_sign_in = Some(on);
    }

    /// True when policy decides it, so the checkbox reads the managed value and
    /// does not move -- the same rule as the machine-wide entry, and for the
    /// same reason: a box the user can move but that changes nothing is a lie.
    pub fn autostart_managed(&self) -> bool {
        self.policy.autostart.is_some()
    }

    /// Make the operating system agree with whichever layer decides autostart,
    /// and report whether `config.toml` now needs saving.
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
    pub fn enforce_autostart(&mut self) -> bool {
        // Policy is applied on every start, because it is the answer that must
        // hold whatever else touched the entry. A user's own settled answer is *not* re-applied: the entry
        // itself is the truth for that case, and rewriting it here would undo
        // whatever they did to it outside this window. A deployment default is
        // applied once, to a profile that has never had an answer.
        let (want, seed) = match (self.policy.autostart, self.file.autostart) {
            (Some(policy), _) => (policy, false),
            (None, Some(_)) => return false,
            (None, None) => match self.defaults.autostart {
                Some(default) => (default, true),
                None => return false,
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
            return false;
        }
        if autostart_enabled() != want {
            if let Err(e) = set_autostart(want) {
                crate::log::warn(&format!("could not apply the autostart entry: {e:#}"));
                return false;
            }
            crate::log::info(&format!("autostart set to {want} by {}", self.autostart_source()));
        }
        seed && self.set_autostart_choice(want)
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

    /// Record the autostart answer this machine has settled on. Returns true
    /// when that is news, so seeding a default does not rewrite `config.toml`
    /// on every start.
    pub fn set_autostart_choice(&mut self, on: bool) -> bool {
        let changed = self.file.autostart != Some(on);
        self.file.autostart = Some(on);
        changed
    }

    pub fn browser_session(&self) -> bool {
        self.file.browser_session
    }

    /// Returns true when that is news, so a re-injection does not rewrite
    /// `config.toml` every few hours.
    pub fn set_browser_session(&mut self, on: bool) -> bool {
        let changed = self.file.browser_session != on;
        self.file.browser_session = on;
        changed
    }

    pub fn cache(&self) -> &Cache {
        &self.file.cache
    }

    pub fn grant(&self) -> Option<&Grant> {
        self.file.grant.as_ref()
    }

    /// Record, or forget, this machine's device grant. Forgetting is what
    /// giving the grant up does after the TPM key is already gone.
    pub fn set_grant(&mut self, grant: Option<Grant>) {
        self.file.grant = grant;
    }

    /// Record what the grant just worked as. Returns true when that is news, so
    /// the ordinary re-injection does not rewrite `config.toml` every few hours.
    pub fn set_grant_principal(&mut self, principal: &str) -> bool {
        match self.file.grant.as_mut() {
            Some(g) if g.principal.as_deref() != Some(principal) => {
                g.principal = Some(principal.to_owned());
                true
            }
            _ => false,
        }
    }

    /// Remember the broker's Kerberos block. Returns true when it changed, which
    /// is the tray's cue to re-check enrollment.
    pub fn set_cache(&mut self, k: &KerberosConfig) -> bool {
        let next =
            Cache { realm: k.realm.clone(), kdcs: k.kdcs.clone(), services: k.services.clone() };
        let changed = next != self.file.cache;
        self.file.cache = next;
        changed
    }

    /// Write `config.toml`. Only the file layer is written, so a policy-supplied
    /// broker URL is never baked into the user's file.
    pub fn save(&self) -> Result<()> {
        let path = config_path().context("locating the application directory")?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).context("creating the config directory")?;
        }
        let text = toml::to_string_pretty(&self.file).context("serializing config.toml")?;
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))
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
        assert_eq!(back.autostart, Some(true));
        assert_eq!(back.cache.realm, "EXAMPLE.SITE");
    }

    /// A grant written before this build carries no principal, and reading one
    /// must not fail -- an agent that refused its own `config.toml` after an
    /// update would need a browser sign-in to recover a working grant.
    #[test]
    fn a_grant_from_an_older_build_still_loads() {
        let older = r#"
            broker_url = "https://broker.example.site"
            [grant]
            grant_id = "1a2b3c4d"
            identity = "kb1|entra|33334444-dddd-5555-eeee-6666ffff7777"
            audience = "kerbridge://EXAMPLE.SITE"
            sign_in_required_by = 1785000000
        "#;
        let back: FileConfig = toml::from_str(older).expect("parses");
        assert!(back.grant.expect("the grant is read").principal.is_none());
        assert!(back.grant_for.is_none());
    }

    fn settings(file: FileConfig) -> Settings {
        Settings {
            file,
            policy: Policy::default(),
            discovered: None,
            defaults: Defaults::default(),
        }
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
        s.set_windows_sign_in(true);
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
        let mut s = settings(FileConfig::default());
        s.set_defaults(Defaults { autostart: Some(true), ..Defaults::default() });
        assert!(s.set_autostart_choice(true), "the seed is news the first time");
        assert_eq!(s.file.autostart, Some(true));
        assert!(!s.set_autostart_choice(true), "and not news the second");

        // A user who then turns it off is not overridden by the same default
        // arriving again: `enforce_autostart` stops at a file value.
        s.set_autostart_choice(false);
        assert_eq!(s.file.autostart, Some(false));

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

        for value in ["BrokerUrl", "GrantFor", "Autostart", "NtlmFallbackRecovery", "WindowsSignIn"]
        {
            assert!(
                admx.contains(&format!("valueName=\"{value}\"")),
                "{value} is read by Settings::load but no policy writes it"
            );
        }
        // Every policy writes the branch the agent reads first.
        assert_eq!(
            admx.matches("key=\"Software\\Policies\\KerBridge\"").count(),
            5,
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

    /// A landed exchange is not the same thing as a changed one: without the
    /// guard, every silent renewal rewrites `config.toml`.
    #[test]
    fn recording_the_same_expectation_twice_is_not_news() {
        let mut s = Settings {
            file: FileConfig::default(),
            policy: Policy::default(),
            discovered: None,
            defaults: Defaults::default(),
        };
        assert!(s.set_expected_working_as(Some("EXAMPLE.SITE|")));
        assert!(!s.set_expected_working_as(Some("EXAMPLE.SITE|")));
        assert_eq!(s.expected_working_as(), Some("EXAMPLE.SITE|"));

        // A delegated machine's target is half the scope, so changing it is news.
        assert!(s.set_expected_working_as(Some("EXAMPLE.SITE|svc-builder")));
        assert!(s.set_expected_working_as(None));
        assert!(!s.set_expected_working_as(None));
    }

    /// A device that has never been granted one writes no `[grant]` table at
    /// all, so an existing `config.toml` is untouched by the feature shipping.
    #[test]
    fn no_grant_writes_no_table() {
        let text = toml::to_string_pretty(&FileConfig::default()).expect("serializes");
        assert!(!text.contains("grant"), "{text}");
        assert!(toml::from_str::<FileConfig>(&text).unwrap().grant.is_none());
    }
}
