//! What the machine's state *means*, as a pure function of what it is.
//!
//! [`crate::agent`] decides what the machine does; this decides what a surface
//! may say about it. The split is why a window procedure can stay a pure
//! function of [`crate::agent::Status`]: a surface that also decides is a second
//! place the lifecycle is settled, and that disagreement stays invisible until a
//! build publishes under the wrong name.
//!
//! **There is no precedence anywhere here.** One ordered enum could only ever
//! report the loudest of several concurrently true facts, and reporting one true
//! thing so loudly that another disappears behind it is the fault this module
//! exists to remove. So [`Condition`] is one rung, [`Blocker`] is a list, and
//! [`Action`] is flat -- the surface decides what is primary, what is secondary,
//! and what it does not draw at all.
//!
//! `client/DESIGN.md` @ the status model is the specification, and its
//! derivation and transition tables are this file's tests.

/// What the machine can do about the realm right now. Pure `f(T, H, S)` -- see
/// [`Facts`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Condition {
    /// A usable ticket, and the supply behind it is intact.
    Working,
    /// No ticket, and none is expected here.
    NotStarted,
    /// A usable ticket and an intact supply, but transport has been failing for
    /// a while.
    Flaky,
    /// A usable ticket, but the supply is gone: it stops at a known time.
    WillStop,
    /// No ticket, and this machine is supposed to be working.
    Stopped,
}

/// What is missing *right now*. Immediate, unentailed blockers only.
///
/// Blockers **explain**; [`Action`]s are how a user resolves them. They are not
/// parallel lists and nothing lines up between them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Blocker {
    /// First run; nothing configured.
    NoBrokerUrl,
    /// Unreachable, TLS-refused, rate-limited or 5xx -- merged because all four
    /// clear on a retry, which is the only difference that changes what a user
    /// does. The distinct sentences stay in `message`.
    NetworkError,
    /// No discovery has landed here, so there is no realm.
    RealmUnknown,
    /// Windows does not know the realm (enrollment).
    RealmNotRegistered,
    /// Nothing to exchange with, and a browser is allowed.
    NoSupply,
    /// Delegated, so only a grant can get a ticket, and there isn't one.
    NoGrant,
    /// Policy refused this grant; re-authorizing cannot help.
    GrantRefused,
    /// The broker or the IdP said no to this identity.
    Refused,
    /// The ticket is fine, the drives are not. The agent's diagnosis, never a
    /// hunch -- [`Action::RestartWorkstation`] carries the hunch path.
    NtlmFallback,
}

/// What may be started. Flat and unordered; the surface presents or ignores.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    SignIn,
    CreateGrant,
    ReinjectTicket,
    Cancel,
    DropKrbTicket,
    SignOutIdp,
    GiveUpGrant,
    Enroll,
    Reenroll,
    Unenroll,
    RestartWorkstation,
    OpenSettings,
}

impl Action {
    /// True for the two operations that do not take the agent's busy slot: the
    /// cloud logout runs on its own thread and the revoke can overlap a sign-in.
    /// Everything else is one at a time.
    pub fn outside_busy_slot(self) -> bool {
        matches!(self, Action::SignOutIdp | Action::GiveUpGrant)
    }
}

/// Which silent path stands behind the next renewal -- the fact S is made of,
/// and the only thing the details drawer can say it with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Supply {
    Grant,
    WindowsSignIn,
    BrowserSignIn,
    None,
}

/// The class of the last failure. `message` carries the sentence; this decides
/// which blocker, if any, the sentence stands behind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fault {
    Network,
    Refused,
    GrantRefused,
    /// A failure with no blocker of its own -- an empty WAM, an abandoned
    /// browser. It still counts as something being wrong, which is what the
    /// surface keys its fault ink and its log button on.
    Other,
}

/// Everything the description is a function of, gathered on the UI thread.
///
/// A struct rather than arguments because the derivation is checked against a
/// published truth table, and a table is easier to test than a call.
pub struct Facts {
    /// A broker is configured, by policy, by the user or by DNS.
    pub broker: bool,
    /// A realm has been discovered, or was cached by an earlier run.
    pub realm_known: bool,
    /// The OS is registered for that realm -- `enroll::state` answers `Enrolled`.
    pub enrolled: bool,
    /// A live injected ticket, whatever the OS can do with it.
    pub ticket: bool,
    /// The ticket is far enough through its life that its end is near rather than
    /// distant. Read only by [`Condition::WillStop`], which is a statement about
    /// when this ticket stops and needs to arrive when that is worth hearing.
    pub ticket_late: bool,
    /// **H** -- this machine is supposed to be working here.
    pub expected: bool,
    /// A `grant_for` target is set, so only a grant may get a ticket.
    pub delegated: bool,
    /// A grant is held and its browser-sign-in deadline has not passed.
    pub grant_valid: bool,
    /// An OIDC refresh token is in memory.
    pub refresh_token: bool,
    /// A browser session this agent put at the authority, and nothing else. Not
    /// a fact about the realm -- releasing it leaves every ticket in the cache
    /// and takes the silent supply instead, which is why it is gated on neither
    /// `usable` nor the broker.
    ///
    /// The OS's own account is deliberately not counted. This process cannot
    /// sign out of the OS; the most it could do is demand a fresh prompt next
    /// time, which retires no session -- the account was there before and stays
    /// after -- while spending the silent renewal the product exists for.
    pub cloud_session: bool,
    /// The OS's own token store may be asked for a token: the user has not
    /// turned it off *and* this platform has one. Both, or a Mac reports a
    /// supply that cannot exist -- see `Settings::windows_sign_in`.
    pub windows_sign_in: bool,
    /// The deployment offers device grants at all, *and* this platform can hold
    /// one. Both halves, because an offer the machine cannot honor is worse
    /// than no offer: macOS has no Secure Enclave key yet and would answer the
    /// click with a refusal.
    pub grants_enabled: bool,
    /// Policy allows the NTLM-fallback machinery.
    pub ntlm_recovery: bool,
    /// A fallback was diagnosed and the unelevated restart did not clear it.
    pub ntlm_confirmed: bool,
    pub fault: Option<Fault>,
    /// Transport has been failing since the first failure with nothing landed
    /// after it, for longer than the agent's quiet period.
    pub flaky_elapsed: bool,
    /// This platform has an enrollment to offer. macOS resolves the realm from
    /// DNS with no configuration, so three of the actions name an OS it does not
    /// run.
    pub enrollment_platform: bool,
    /// A browser sign-in is waiting on its loopback redirect -- the one place
    /// the cancel flag is read, and therefore the only moment cancelling does
    /// anything.
    pub browser_leg: bool,
}

/// The whole of what a surface is given to render, plus the one fact it would
/// otherwise have to re-derive.
pub struct Description {
    pub condition: Condition,
    pub blockers: Vec<Blocker>,
    pub actions: Vec<Action>,
    pub supply: Supply,
    /// A ticket this machine holds could actually be spent. Not derivable from
    /// `blockers`, because `NoBrokerUrl` swallows the two that would say it.
    pub usable: bool,
}

impl Facts {
    /// **S** -- a silent renewal can land. Possession, not prediction, and named
    /// in the order the sign-in worker actually tries them.
    fn supply(&self) -> Supply {
        if self.grant_valid {
            return Supply::Grant;
        }
        // Delegated, so nothing else may get a ticket: `run_sign_in`'s guard
        // refuses to fall through to the signer's own token, which makes a refresh
        // token in memory and a Windows account both worth nothing here.
        if self.delegated {
            return Supply::None;
        }
        if self.windows_sign_in {
            return Supply::WindowsSignIn;
        }
        if self.refresh_token {
            return Supply::BrowserSignIn;
        }
        Supply::None
    }

    /// A ticket the OS cannot use is not access. With the realm absent from
    /// `…\Lsa\Kerberos\Domains` a broker exchange still succeeds and the TGT
    /// still injects, and it then sits valid and unusable
    /// (`docs/windows-kerberos-findings.md` @ "Can DNS SRV records replace
    /// Windows external-realm registration?" and @ "Can a failed diagnostic
    /// alter the Windows ticket cache?").
    fn usable(&self) -> bool {
        self.realm_known && self.enrolled
    }

    /// **T** -- holds a *usable* ticket.
    fn holds_access(&self) -> bool {
        self.ticket && self.usable()
    }
}

pub fn describe(f: &Facts) -> Description {
    let supply = f.supply();
    let blockers = blockers(f, supply);
    Description {
        condition: condition(f, supply),
        actions: actions(f, supply, &blockers),
        blockers,
        supply,
        usable: f.usable(),
    }
}

/// The derivation table, and nothing else: no network fact enters it. A broker
/// outage never moves the rung -- it appears as [`Blocker::NetworkError`] and,
/// if it persists, as [`Condition::Flaky`].
fn condition(f: &Facts, supply: Supply) -> Condition {
    // A duration, not a distance. The schedule re-arms from the ticket midpoint,
    // so a "the next attempt is far away" rule would go quiet exactly as the
    // machine approaches the lapse.
    let flaky = f.flaky_elapsed && f.fault == Some(Fault::Network);
    match (f.holds_access(), supply != Supply::None) {
        // ¬S is a certainty about the end of this ticket, not about now. Raising
        // it the moment the supply goes spends the warning color nine hours
        // ahead of a single browser click, on a machine whose access is perfect
        // -- and on any deployment where ¬S is the steady state, every boot lands
        // there and the color stops meaning anything. Late is when it is worth
        // saying.
        (true, false) if f.ticket_late => Condition::WillStop,
        (true, true) if flaky => Condition::Flaky,
        (true, _) => Condition::Working,
        (false, _) if f.expected => Condition::Stopped,
        (false, _) => Condition::NotStarted,
    }
}

/// Immediate blockers, and unentailed ones only.
///
/// [`Blocker::NoBrokerUrl`] swallows everything downstream of it and
/// [`Blocker::RealmNotRegistered`] never appears without a known realm, so a
/// first-run machine emits exactly one entry rather than four of which three are
/// consequences. Without that rule every surface invents its own precedence, and
/// the chain this module exists to remove comes back unwritten.
///
/// `RealmNotRegistered` beside `NoSupply` is *not* entailment: both are true
/// and both immediate. That signing in before enrollment injects a ticket nothing
/// can use is carried by [`actions`], not by this list.
fn blockers(f: &Facts, supply: Supply) -> Vec<Blocker> {
    if !f.broker {
        return vec![Blocker::NoBrokerUrl];
    }
    let mut out = Vec::new();
    if !f.realm_known {
        out.push(Blocker::RealmUnknown);
    } else if !f.enrolled {
        out.push(Blocker::RealmNotRegistered);
    }
    match f.fault {
        Some(Fault::Network) => out.push(Blocker::NetworkError),
        Some(Fault::Refused) => out.push(Blocker::Refused),
        Some(Fault::GrantRefused) => out.push(Blocker::GrantRefused),
        Some(Fault::Other) | None => {}
    }
    if f.realm_known && f.delegated && !f.grant_valid {
        out.push(Blocker::NoGrant);
    }
    if !f.delegated && supply == Supply::None {
        out.push(Blocker::NoSupply);
    }
    if f.ntlm_confirmed {
        out.push(Blocker::NtlmFallback);
    }
    out
}

/// What may be started, flat and unordered.
///
/// Two blockers imply no action at all: [`Blocker::GrantRefused`]
/// (re-authorizing is the one thing that cannot help) and
/// [`Blocker::RealmUnknown`] (it waits).
///
/// **Nothing that gets or spends a ticket is offered while `usable` is false.**
/// Three measured reasons: the ticket cannot work; enrollment from cold requires
/// a restart, which discards any ticket obtained first; and this is the one state
/// measured to *destroy* a ticket, where a failed `klist get` evicted a still
/// valid TGT 2/2. `agent::autostart_sign_in` refuses on the same condition.
fn actions(f: &Facts, supply: Supply, blockers: &[Blocker]) -> Vec<Action> {
    let mut out = Vec::new();
    if !f.broker {
        out.push(Action::OpenSettings);
    } else {
        let usable = f.usable();
        if f.enrollment_platform && f.realm_known {
            if f.enrolled {
                out.push(Action::Reenroll);
                out.push(Action::Unenroll);
            } else {
                out.push(Action::Enroll);
            }
        }
        // Offered with no blocker present, which is the user's hunch rather than
        // the agent's diagnosis: broken drives are what someone reaches for this
        // with, and the agent only sometimes knows why.
        if f.ntlm_recovery && f.realm_known {
            out.push(Action::RestartWorkstation);
        }
        if usable && f.grants_enabled && !blockers.contains(&Blocker::GrantRefused) {
            out.push(Action::CreateGrant);
        }
        if usable && !f.delegated {
            out.push(Action::SignIn);
        }
        // A "Renew now" that provably cannot get a ticket is worse than a false futility
        // clause, because the user pays for it with a click.
        if usable && supply != Supply::None {
            out.push(Action::ReinjectTicket);
        }
        if f.holds_access() {
            out.push(Action::DropKrbTicket);
        }
        if f.grant_valid {
            out.push(Action::GiveUpGrant);
        }
    }
    // Outside the broker arm, because it is not about the realm: it ends a
    // session at the authority and spends no ticket, so neither the `usable`
    // rule nor a missing broker URL has anything to say about it. `create_grant`
    // acquires its token non-silently, so this holds wherever the agent's
    // `just_authorized` does -- which is the whole of how a surface can promote
    // this one without the model knowing that word.
    if f.cloud_session {
        out.push(Action::SignOutIdp);
    }
    // The cancel flag is read in exactly one place, the browser's accept loop,
    // so the button exists exactly while a leg is waiting there. Not merely
    // while a sign-in worker runs: that worker also spends time in discovery, in
    // WAM's *blocking* get and in the ticket exchange, and a Cancel drawn over
    // any of those is a control that does nothing when pressed.
    if f.browser_leg {
        out.push(Action::Cancel);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A machine that works: configured, enrolled, holding a ticket, with
    /// Windows sign-in behind it.
    fn working() -> Facts {
        Facts {
            broker: true,
            realm_known: true,
            enrolled: true,
            ticket: true,
            ticket_late: false,
            expected: true,
            delegated: false,
            grant_valid: false,
            refresh_token: false,
            cloud_session: false,
            windows_sign_in: true,
            grants_enabled: true,
            ntlm_recovery: true,
            ntlm_confirmed: false,
            fault: None,
            flaky_elapsed: false,
            enrollment_platform: true,
            browser_leg: false,
        }
    }

    /// `client/DESIGN.md` @ how the condition is derived, in full. Five rungs,
    /// three facts, no network term.
    #[test]
    fn the_derivation_table() {
        // T ∧ S
        assert_eq!(describe(&working()).condition, Condition::Working);

        // T ∧ ¬S, and the ticket is late enough for its end to be news.
        let f = Facts { windows_sign_in: false, ticket_late: true, ..working() };
        assert_eq!(describe(&f).condition, Condition::WillStop);

        // T ∧ ¬S with most of the ticket still to run. The end is just as
        // certain; it is not yet worth the warning color, and on a deployment
        // where ¬S is the steady state this is every machine after every boot.
        let f = Facts { windows_sign_in: false, ..working() };
        assert_eq!(describe(&f).condition, Condition::Working);

        // T ∧ S ∧ the flaky rule.
        let f = Facts { fault: Some(Fault::Network), flaky_elapsed: true, ..working() };
        assert_eq!(describe(&f).condition, Condition::Flaky);

        // ¬T ∧ H
        let f = Facts { ticket: false, ..working() };
        assert_eq!(describe(&f).condition, Condition::Stopped);

        // ¬T ∧ ¬H
        let f = Facts { ticket: false, expected: false, ..working() };
        assert_eq!(describe(&f).condition, Condition::NotStarted);
    }

    /// The invariant the whole redesign exists for: a valid TGT the OS cannot
    /// spend is not access. Getting this wrong reports `Working` on a machine
    /// whose drives do not open.
    #[test]
    fn an_unusable_ticket_is_not_access() {
        for (realm_known, enrolled) in [(true, false), (false, false)] {
            let f = Facts { realm_known, enrolled, ..working() };
            let d = describe(&f);
            assert_eq!(d.condition, Condition::Stopped, "realm={realm_known} enrolled={enrolled}");
            assert!(!d.usable);
            assert!(!d.actions.contains(&Action::SignIn), "nothing that gets a ticket is offered");
            assert!(!d.actions.contains(&Action::ReinjectTicket));
            assert!(!d.actions.contains(&Action::CreateGrant));
            assert!(!d.actions.contains(&Action::DropKrbTicket));
        }
    }

    /// Only the timing rule separates `Flaky` from `Working`: a transport
    /// failure this minute is not yet news, because it may fix itself.
    #[test]
    fn flaky_is_a_duration_and_not_a_distance() {
        let f = Facts { fault: Some(Fault::Network), flaky_elapsed: false, ..working() };
        assert_eq!(describe(&f).condition, Condition::Working);

        // And it is transport's alone: a refusal that has stood for a week is a
        // `Refused` blocker, not an uncertain renewal.
        let f = Facts { fault: Some(Fault::Refused), flaky_elapsed: true, ..working() };
        assert_eq!(describe(&f).condition, Condition::Working);
    }

    /// A first-run machine emits one blocker, not four of which three are
    /// consequences of the first.
    #[test]
    fn entailed_blockers_are_not_emitted() {
        let f = Facts {
            broker: false,
            realm_known: false,
            enrolled: false,
            ticket: false,
            ticket_late: false,
            expected: false,
            windows_sign_in: false,
            ..working()
        };
        let d = describe(&f);
        assert_eq!(d.blockers, vec![Blocker::NoBrokerUrl]);
        assert_eq!(d.actions, vec![Action::OpenSettings]);
        assert_eq!(d.condition, Condition::NotStarted);

        // And an unknown realm suppresses the enrollment blocker beneath it,
        // which would otherwise name a realm nobody has.
        let f = Facts { broker: true, realm_known: false, ..f };
        assert!(!describe(&f).blockers.contains(&Blocker::RealmNotRegistered));
    }

    /// Two blockers are the honest "nothing you press helps".
    #[test]
    fn two_blockers_imply_no_action() {
        // Policy refused this grant, on a delegated machine that can get a ticket no
        // other way: authorizing again is the one thing that cannot help.
        let f =
            Facts { ticket: false, delegated: true, fault: Some(Fault::GrantRefused), ..working() };
        let d = describe(&f);
        assert!(d.blockers.contains(&Blocker::GrantRefused));
        assert!(!d.actions.contains(&Action::CreateGrant));
        assert!(!d.actions.contains(&Action::SignIn), "delegated machines never sign in");

        // An unknown realm waits: no enrollment to apply, nothing to exchange.
        let f = Facts { realm_known: false, ticket: false, ..working() };
        let d = describe(&f);
        assert!(d.blockers.contains(&Blocker::RealmUnknown));
        for a in [Action::Enroll, Action::Reenroll, Action::SignIn, Action::RestartWorkstation] {
            assert!(!d.actions.contains(&a), "{a:?}");
        }
    }

    /// `RealmNotRegistered` beside `NoSupply` is two immediate facts, not a
    /// chain -- the suppression rule must not eat the second.
    #[test]
    fn two_immediate_blockers_both_stand() {
        let f = Facts {
            enrolled: false,
            ticket: false,
            ticket_late: false,
            expected: false,
            windows_sign_in: false,
            ..working()
        };
        let d = describe(&f);
        assert!(d.blockers.contains(&Blocker::RealmNotRegistered));
        assert!(d.blockers.contains(&Blocker::NoSupply));
        assert!(d.actions.contains(&Action::Enroll), "the one thing that helps is offered");
    }

    /// S is possession, and on a delegated machine only one thing counts.
    #[test]
    fn the_supply_is_what_the_worker_would_try() {
        assert_eq!(describe(&working()).supply, Supply::WindowsSignIn);

        let f = Facts { grant_valid: true, ..working() };
        assert_eq!(describe(&f).supply, Supply::Grant, "the grant is tried first");

        let f = Facts { windows_sign_in: false, refresh_token: true, ..working() };
        assert_eq!(describe(&f).supply, Supply::BrowserSignIn);

        // Delegated: a refresh token in memory and a Windows account are both
        // worth nothing, because the exchange guard refuses to use either.
        let f = Facts { delegated: true, refresh_token: true, ticket_late: true, ..working() };
        assert_eq!(describe(&f).supply, Supply::None);
        assert_eq!(describe(&f).condition, Condition::WillStop);
        assert!(describe(&f).blockers.contains(&Blocker::NoGrant));
    }

    /// Giving up the grant on a delegated machine is what `WillStop` is for: the
    /// ticket lives on, and nothing can replace it.
    #[test]
    fn a_delegated_machine_with_a_grant_works_and_offers_to_give_it_up() {
        let f = Facts { delegated: true, grant_valid: true, ..working() };
        let d = describe(&f);
        assert_eq!(d.condition, Condition::Working);
        assert_eq!(d.supply, Supply::Grant);
        assert!(d.actions.contains(&Action::GiveUpGrant));
        assert!(d.actions.contains(&Action::ReinjectTicket));
        assert!(!d.actions.contains(&Action::SignIn));
        assert!(d.blockers.is_empty());
    }

    /// Cancel is read in one place only, so it is offered in one place only.
    /// A sign-in worker that has not reached the browser -- discovery, WAM's
    /// blocking get, the ticket exchange -- has nothing for it to set.
    #[test]
    fn cancel_is_offered_only_while_a_browser_leg_runs() {
        assert!(!describe(&working()).actions.contains(&Action::Cancel));

        let f = Facts { browser_leg: true, ..working() };
        assert!(describe(&f).actions.contains(&Action::Cancel));
    }

    /// The one offer about the cloud rather than the realm: there whenever there
    /// is a session to release, and nowhere else.
    ///
    /// Neither of the two rules that gate every other offer reaches it: it spends
    /// no ticket, so `usable` is not its business, and the session it releases
    /// lives at the authority, which a machine keeps after its broker URL is
    /// taken away.
    #[test]
    fn signing_out_of_the_cloud_is_offered_whenever_there_is_a_session() {
        assert!(!describe(&working()).actions.contains(&Action::SignOutIdp));

        let f = Facts { cloud_session: true, ..working() };
        assert!(describe(&f).actions.contains(&Action::SignOutIdp));

        // Unusable: nothing that gets or spends a ticket survives, and this
        // still does.
        let f = Facts { cloud_session: true, enrolled: false, ..working() };
        let d = describe(&f);
        assert!(d.actions.contains(&Action::SignOutIdp));
        assert!(!d.actions.contains(&Action::SignIn));
        assert!(!d.actions.contains(&Action::ReinjectTicket));

        // And a machine with no broker left to name still has a session of its
        // own to give up.
        let f = Facts { cloud_session: true, broker: false, ..working() };
        assert!(describe(&f).actions.contains(&Action::SignOutIdp));
    }

    /// The repair is the user's hunch as well as the agent's diagnosis, so the
    /// action stands without the blocker -- but not where policy turned the
    /// whole machinery off.
    #[test]
    fn the_repair_is_offered_without_a_diagnosis() {
        let d = describe(&working());
        assert!(d.actions.contains(&Action::RestartWorkstation));
        assert!(!d.blockers.contains(&Blocker::NtlmFallback));

        let f = Facts { ntlm_confirmed: true, ..working() };
        assert!(describe(&f).blockers.contains(&Blocker::NtlmFallback));

        let f = Facts { ntlm_recovery: false, ..working() };
        assert!(!describe(&f).actions.contains(&Action::RestartWorkstation));
    }

    /// A platform with no enrollment is never offered one, and never blocked on
    /// one either.
    #[test]
    fn a_platform_without_enrollment_offers_none() {
        let f = Facts { enrollment_platform: false, ..working() };
        let d = describe(&f);
        for a in [Action::Enroll, Action::Reenroll, Action::Unenroll] {
            assert!(!d.actions.contains(&a), "{a:?}");
        }
        assert!(d.actions.contains(&Action::SignIn));
    }
}
