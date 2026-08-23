//! All user-visible UI text, isolated for i18n.
//!
//! Every string the user can read lives here -- nothing user-facing is spelled out
//! in the widget code, the state machine, or the elevated dialogs. Adding a
//! language is a new `<lang>.rs` with one `Strings` const, a `mod`/`use` pair
//! below, a `Lang` variant, and one arm each in `pick` and `lang_for_tag`. No
//! runtime i18n dependency; the table is plain `&'static str` fields, so the
//! compiler catches a missing key the moment a language is added.
//!
//! In the core rather than in an agent crate because it is the product's copy,
//! not one platform's: two agents wording the same refusal differently is two
//! translation sets to keep in step and one of them stale.
//!
//! Templated strings keep their placeholders (`{realm}`, `{principal}`, `{time}`,
//! `{broker}`, `{detail}`) *in the table* so a translator can move them;
//! substitution is the trivial `fill` helper below rather than `format!`
//! scattered through the UI.

use std::sync::OnceLock;

use crate::sys;

mod de;
mod en;
mod es;
mod fi;
mod fr;
mod it;
mod ja;
mod ko;
mod pt;
mod ru;
mod zh;

use de::DE;
use en::EN;
use es::ES;
use fi::FI;
use fr::FR;
use it::IT;
use ja::JA;
use ko::KO;
use pt::PT;
use ru::RU;
use zh::ZH;

/// Languages we can render. Extend this + `ALL` + `pick` + `lang_for_tag` + one
/// `<lang>.rs` module per language.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Fi,
    Es,
    Fr,
    Zh,
    Ja,
    Pt,
    De,
    It,
    Ko,
    Ru,
}

impl Lang {
    /// Every language, for callers that render all of them rather than the one
    /// this desktop is set to -- the help site, and the tests below.
    pub const ALL: [Lang; 11] = [
        Lang::En,
        Lang::Fi,
        Lang::Es,
        Lang::Fr,
        Lang::Zh,
        Lang::Ja,
        Lang::Pt,
        Lang::De,
        Lang::It,
        Lang::Ko,
        Lang::Ru,
    ];
}

/// Return the active table. The language is the OS display language, read once
/// on first use and cached -- it does not change under a running process, and
/// `tr()` is on hot UI paths.
pub fn tr() -> &'static Strings {
    static ACTIVE: OnceLock<&'static Strings> = OnceLock::new();
    ACTIVE.get_or_init(|| pick(lang_for_tag(&sys::ui_language())))
}

/// The table for one language, regardless of what this desktop is set to.
/// Public for the help site, which renders every language from these tables so
/// that a page can never teach a label the product does not say.
pub fn pick(lang: Lang) -> &'static Strings {
    match lang {
        Lang::En => &EN,
        Lang::Fi => &FI,
        Lang::Es => &ES,
        Lang::Fr => &FR,
        Lang::Zh => &ZH,
        Lang::Ja => &JA,
        Lang::Pt => &PT,
        Lang::De => &DE,
        Lang::It => &IT,
        Lang::Ko => &KO,
        Lang::Ru => &RU,
    }
}

/// Map a BCP-47 language tag ([`sys::ui_language`]) to a table we have, falling
/// back to English for anything untranslated.
///
/// Matched on the primary subtag, so every regional variant of a language
/// resolves to the same table -- Portuguese is one table (`Pt`, Brazilian) that
/// serves pt-PT and pt-BR alike. Chinese is the exception in the other direction:
/// only Simplified is translated, so a tag has to *say* Simplified -- by script
/// (`zh-Hans`) or by a region that has no other reading (`zh-CN`, `zh-SG`) -- and
/// everything else Chinese falls back to English rather than render Simplified to
/// a Traditional reader.
fn lang_for_tag(tag: &str) -> Lang {
    let tag = tag.to_ascii_lowercase();
    let mut subtags = tag.split(['-', '_']);
    match subtags.next().unwrap_or_default() {
        "de" => Lang::De,
        "es" => Lang::Es,
        "fi" => Lang::Fi,
        "fr" => Lang::Fr,
        "it" => Lang::It,
        "ja" => Lang::Ja,
        "ko" => Lang::Ko,
        "pt" => Lang::Pt,
        "ru" => Lang::Ru,
        "zh" if subtags.any(|s| matches!(s, "hans" | "cn" | "sg")) => Lang::Zh,
        _ => Lang::En,
    }
}

/// Replace `{name}` occurrences. Trivial by design -- UI strings are short and
/// rendered rarely, and keeping the placeholders in the table is what matters.
pub fn fill(template: &str, subs: &[(&str, &str)]) -> String {
    let mut s = template.to_string();
    for (k, v) in subs {
        s = s.replace(&format!("{{{k}}}"), v);
    }
    s
}

/// A ticket lifetime as the flyout shows it: "3h 42m", "6m", "under a minute".
/// Here rather than in the UI because the units are translatable text.
pub fn duration(secs: i64) -> String {
    let s = tr();
    let mins = secs / 60;
    if mins <= 0 {
        return s.dur_under_a_minute.into();
    }
    let (h, m) = (mins / 60, mins % 60);
    if h > 0 {
        fill(s.dur_hours_minutes, &[("h", &h.to_string()), ("m", &m.to_string())])
    } else {
        fill(s.dur_minutes, &[("m", &m.to_string())])
    }
}

/// A whole number of days as the UI shows it: "1 day", "4 days".
///
/// A noun phrase rather than a bare number, and every string that mentions a
/// span of days takes it as one -- because the surrounding words have to agree
/// with it, and in several of these languages that agreement is not something a
/// `{n}` substitution can express.
pub fn days(n: i64) -> String {
    let s = tr();
    if n == 1 { s.dur_one_day.into() } else { fill(s.dur_days, &[("d", &n.to_string())]) }
}

/// Defines `Strings` and, from the same declaration list, the reflection over
/// it that Rust does not otherwise offer. The help site renders every label in
/// this table and the test below compares every field across eleven languages;
/// both need field *names*, and a hand-kept second list of them goes stale
/// silently.
///
/// `macro_rules!` and not a derive macro: every field is the same
/// `&'static str` and there is no type to inspect, so a proc-macro crate would
/// put `syn`, `quote` and `proc-macro2` into a shipped client's build for a
/// lookup table this produces in four lines. The cost is that `rustfmt` leaves
/// the list below alone -- it is data, so keep it one field per line.
macro_rules! strings {
    ($($(#[$attr:meta])* $name:ident,)*) => {
        /// One field per user-visible string. Fields grouped by surface.
        ///
        /// **One label per meaning.** Two keys carrying the same words is a bug: a
        /// second spelling of an existing sentence belongs at the call site's rewrite,
        /// not here.
        pub struct Strings {
            $($(#[$attr])* pub $name: &'static str,)*
        }

        impl Strings {
            /// Every field as (name, value), in declaration order.
            pub fn fields(&self) -> impl Iterator<Item = (&'static str, &'static str)> {
                [$((stringify!($name), self.$name),)*].into_iter()
            }
        }
    };
}

strings! {
    // ---- app ----
    /// This table's own BCP-47 tag. Not drawn anywhere: it is how a caller
    /// holding a `&Strings` names the language it is holding -- the help site
    /// builds `<html lang>` and its per-language URL from it. A field rather
    /// than a `Lang` method so a new language cannot be added without declaring
    /// one.
    ///
    /// As precise as the table is, no more: `pt` serves both Portuguese locales
    /// from one Brazilian table, while `zh-Hans` says Simplified because
    /// [`lang_for_tag`] gives bare `zh` to English on purpose.
    lang_tag,
    app_name,
    tagline,

    // ---- tray context menu ----
    //
    // The menu is the flyout's superset in the flyout's order; everything else
    // in it is an `act_*` label, so only these four are its own.
    menu_open_status,
    menu_settings,
    menu_help,
    menu_quit,

    // ---- the condition headline ----
    //
    // `NotStarted` has none, except that `cond_off` stands in for it in exactly
    // one case: when an identity line would otherwise be the whole card.
    cond_working,
    cond_flaky,
    cond_will_stop,
    cond_stopped,
    cond_off,

    // ---- the identity line ----
    //
    // Two verbs, one rule: delegated machines *work as* an account nobody at the
    // keyboard signed in as.
    id_signed_in_as, // {account}
    id_working_as,   // {account}

    // ---- clocks ----
    /// Only rendered where the ticket's end is a deadline rather than a
    /// countdown to an automatic renewal -- `Flaky` and `WillStop`.
    access_ends_in, // {duration}
    grant_expires_in,  // {days}
    dur_hours_minutes, // {h} {m}
    dur_minutes,       // {m}
    dur_under_a_minute,
    dur_one_day,
    dur_days, // {d}

    // ---- blocker lines ----
    //
    // Fragments: sentence case, no trailing period. They explain; actions
    // resolve; `message` carries the detail and these never restate it.
    blk_no_broker_url,
    blk_network_error,        // {broker}
    blk_realm_unknown,        // {broker}
    blk_realm_not_registered, // {realm}
    /// Never drawn on the status card -- with the headline above it and the
    /// button below it, it is the third statement of one fact. Kept for the
    /// infotip, and for any surface with no button to carry it.
    blk_no_supply,
    blk_no_grant, // {account}
    blk_grant_refused,
    blk_refused,
    /// Keeps its `(NTLM)` tag: nothing else nearby names the mechanism, and that
    /// keyword is what has to reach the support request.
    blk_ntlm_fallback,

    // ---- the details drawer ----
    //
    // Row order is fixed: realm, source, ticket, supply, next attempt -- with the
    // meter above them while a ticket is held.
    details_heading,
    meter_label,
    d_realm,
    /// Drawn only where a source is known: a broker predating source routing
    /// names none, and a labelled blank is worse than a missing row.
    d_source,
    d_ticket,
    d_ticket_value,         // {time}
    d_ticket_value_norenew, // {time}
    /// The drawer's one *changing* fact: without it `WillStop` shows a deadline
    /// with nothing anywhere saying why nothing will stop it.
    d_supply,
    d_supply_grant,
    d_supply_wam,
    d_supply_browser,
    d_supply_none,
    d_next,

    // ---- the two notes ----
    //
    // Neither is a fault: they set `message` with nothing wrong behind them, so
    // the surface draws them in neutral ink and offers no log.
    /// *may*, because which clients hold an SMB session open is theirs to decide.
    err_sign_off_failed,
    signed_off_note,
    /// Both grant notes **recommend** rather than warn: warn about loss,
    /// recommend about hygiene. The session left behind is an inconvenience to
    /// undo, and dressing it as a casualty argues against the safer click.
    granted_note,
    /// The same recommendation where the credential lives in the OS: nothing
    /// opened, and what lingers is silent reuse of the Windows account.
    granted_note_wam,

    /// Every action gated away. Reachable on a delegated machine in a grants-off
    /// deployment, which is broken by construction; stating it beats inventing
    /// an offer.
    no_action,

    // ---- action labels ----
    //
    // One label per `describe::Action`, plus the two that are chosen by state
    // rather than by call site. The ellipsis carries meaning: Windows uses it
    // for a command that needs more from you before it can finish, so a browser
    // round trip takes one and a silent re-injection does not. Elevation never earns
    // one -- the shield already says it.
    act_sign_in,
    /// While a usable ticket is held: the sign-in loop *prolongs* access there
    /// rather than getting it.
    act_sign_in_extend,
    act_create_grant,
    /// While a grant is held. Pressing it creates a fresh grant for the same
    /// account, which is a renewal rather than a change.
    act_create_grant_again,
    act_reinject,
    act_cancel,
    /// Deliberately not *Sign out*: a purge takes the tickets, and an SMB
    /// session already open keeps serving files off an empty cache.
    act_drop_ticket,
    act_sign_out_idp,
    act_give_up_grant,
    act_enroll,
    act_reenroll,
    /// Keeps `{realm}` deliberately -- name the casualties before an
    /// irreversible click.
    act_unenroll, // {realm}
    /// Names the outcome, not the service; `LanmanWorkstation` stays in the
    /// confirmation.
    act_restart_workstation,
    act_open_settings,
    act_open_log,

    // ---- failure messages ----
    //
    // One form throughout: `<mechanism state>: <what it means for you>`. The tag
    // is the sysadmin's handle, the sentence is the end user's consequence, and
    // the tag must not restate the sentence. No message predicts that an action
    // will fail, and none promises a fix.
    err_broker_unreachable, // {broker} {detail}
    /// No `{detail}`: the detail is a certificate, it is already in the log, and
    /// the person who can act on it is not the person reading this.
    err_tls_untrusted, // {broker}
    /// The broker answered; the address is one segment short of a source.
    err_broker_ambiguous_source, // {broker} {sources}
    err_not_admitted,       // {detail}
    err_invalid_proof,      // {broker} {detail}
    err_rate_limited,       // {broker}
    err_server_unavailable, // {broker} {detail}
    err_bad_request,        // {broker} {detail}
    err_broker_protocol,    // {broker} {detail}
    /// The authority refused, which names a host that is not the broker's.
    err_idp_refused, // {issuer} {detail}
    err_sign_in,            // {detail}
    err_sign_in_timeout,
    err_silent_refresh, // {detail}
    err_wam_empty,
    /// Deliberately tagless: it is the one case where no mechanism failed,
    /// because Windows' own sign-in was never consulted.
    err_browser_required,
    err_internal, // {detail}
    err_grant_disabled,
    err_grant_key,          // {detail}
    err_grant_failed,       // {detail}
    err_grant_too_many,     // {detail}
    err_grant_not_allowed,  // {detail}
    err_grant_not_delegate, // {detail}
    /// A delegated machine with no usable grant. Points at where the fact lives
    /// and never promises the reader can change it -- the target may be
    /// machine-wide policy.
    err_grant_reauthorize, // {target}
    err_elevation_failed,   // {detail}
    /// `EnableLUA=0` stays inline: it is the searchable handle, and this is the
    /// one failure whose reader is necessarily an administrator.
    err_elevation_unavailable,
    /// The elevated child ran and left nothing readable behind. Never a
    /// fabricated success, and never what a declined prompt produces -- a
    /// decline is silence.
    err_elevated_unconfirmed,

    // ---- per-operation failure titles ----
    //
    // There is no per-failure headline anywhere else: condition + blockers +
    // message leave no slot for one. These three front a notification, where the
    // title is structural.
    fail_title_enroll, // {realm}
    fail_title_repair,
    fail_title_unenroll, // {realm}

    // ---- the four-phase modal ----
    //
    // One dialog, six operations. Close is not Stop: in the working phase it
    // detaches, and the outcome arrives as a notification.
    dlg_waiting,
    dlg_close,
    /// The confirm's default button, in every one of the six.
    btn_cancel,

    dlg_repair_question,
    dlg_repair_body, // {realm}
    /// Generated from the services actually found running, and omitted when
    /// there are none: it names the casualties rather than warning generically.
    dlg_repair_dependents, // {services}
    dlg_repair_save,
    /// *anyway*, not a mirror of the label that opened it: this is an
    /// unintended-consequence confirmation, and the mirror is broken here and
    /// nowhere else.
    dlg_repair_commit,
    dlg_repair_working,
    /// The third of the trio with `enroll_incomplete` and `unenroll_incomplete`:
    /// the elevated step ran and did not get all the way through, and the
    /// transcript is the log's rather than the dialog's.
    repair_incomplete,
    dlg_repair_result,

    dlg_enroll_question, // {realm}
    /// Followed by the literal plan, which *is* the confirmation -- so what is
    /// shown must be exactly what executes.
    dlg_enroll_body,
    dlg_enroll_reboot,
    dlg_enroll_commit,
    dlg_enroll_working,
    dlg_enroll_result, // {realm}
    enroll_already,    // {realm}
    enroll_incomplete,
    enroll_discovery_failed,

    dlg_unenroll_question, // {realm}
    dlg_unenroll_body,
    dlg_unenroll_note,    // {realm}
    dlg_unenroll_commit,  // {realm}
    dlg_unenroll_working, // {realm}
    dlg_unenroll_result,  // {realm}
    unenroll_already,     // {realm}
    unenroll_incomplete,

    dlg_grant_off_question,
    dlg_grant_off_body, // {broker}
    /// The undelegated body affirms the access rather than warning about it: it
    /// is not affected, and the device signs in the way it did before.
    dlg_grant_off_body_own, // {realm}
    /// `{remaining}` is the **ticket's** life, not the grant's days: after
    /// removal no renewal can land, so access stops at ticket end.
    dlg_grant_off_body_delegated, // {target} {realm} {remaining}
    dlg_grant_off_commit,
    dlg_grant_off_working,
    dlg_grant_off_result,
    /// The two independent facts: the key here, and the record at the broker.
    dlg_grant_off_result_sub, // {broker}
    /// The key is gone and unusable, but the directory row survives holding a
    /// device-grant slot, and the bill arrives later as a refused authorization.
    dlg_grant_off_result_stale, // {broker}
    dlg_grant_unsaved,

    /// The one place the noun *device grant* survives in the UI, and the one
    /// place the key's user scope is stated.
    grant_confirm, // {days}
    dlg_grant_commit,
    dlg_grant_working,
    grant_done, // {days}

    // ---- notifications ----
    //
    // Title <= 48 EN characters, sentence case, no ending punctuation; body <= 200,
    // complete sentences. No string names the app -- the attribution header
    // already reads it from the exe -- and none claims drives, because the tray
    // knows about a ticket and cannot know whether any share is mapped.
    notify_ready_title,    // {realm}
    notify_ready_body,     // {identity} {duration}
    notify_expiring_title, // {realm} {duration}
    notify_expiring_body,  // {action}
    notify_stopped_title,  // {realm}
    notify_stopped_body,   // {action}
    /// Both units deliberately: relative days in the title to glance at, an
    /// absolute date in the body, because this one exists to schedule a visit.
    notify_grant_due_title, // {days}
    notify_grant_due_body, // {realm} {date}

    // ---- settings ----
    settings_title,
    tab_basic,
    tab_advanced,
    tab_about,
    settings_section_connection,
    settings_broker_label,
    settings_broker_sub,
    /// Reused verbatim for the locked delegated-user field: the sentence is
    /// about who decided, not about which setting it was.
    settings_broker_managed,
    settings_save,
    /// Sits on the Advanced tab, where the absence it explains actually is.
    settings_gate,
    settings_section_signin,
    settings_startup_label,
    /// macOS only: its Settings is an `NSAlert` whose checkbox needs a tooltip.
    settings_startup_sub,
    /// Windows only: why the checkbox above reads on and will not move -- a
    /// machine-wide autostart entry, which a per-user setting cannot countermand.
    settings_startup_managed,
    settings_wam_label,
    settings_wam_sub,
    settings_section_authorization,
    /// Past tense, and from the held grant, so it cannot be edited into a lie.
    /// Not `id_working_as`: there that means the identity the tickets carry
    /// right now, here it means whose access this authorization buys, and the
    /// two diverge the moment a ticket lapses with a grant still held.
    settings_grant_state, // {account}
    /// Labeled for the future it controls, not for the present it does not
    /// govern.
    settings_grant_for_label,
    settings_grant_for_sub,
    settings_section_windows,
    settings_enrolled,     // {realm}
    settings_not_enrolled, // {realm}
    settings_section_troubleshoot,
    settings_troubleshoot_sub,
    /// GPL-3.0-or-later notice, on the About tab.
    about_license,
    /// macOS only, both of them: an `NSAlert` is delayed-commit by construction
    /// and still needs two button titles. Windows' Settings is instant-apply.
    settings_ok,
    settings_cancel,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mapping the platform seam feeds. Testable because the seam hands over
    /// a tag: a live Win32 LANGID would have to be faked.
    #[test]
    fn tags_resolve_to_a_table() {
        assert!(matches!(lang_for_tag("fi-FI"), Lang::Fi));
        assert!(matches!(lang_for_tag("de-CH"), Lang::De));
        // Both Portuguese locales share the one table.
        assert!(matches!(lang_for_tag("pt-PT"), Lang::Pt));
        assert!(matches!(lang_for_tag("pt-BR"), Lang::Pt));
        // Case and separator are the platform's business, not the caller's.
        assert!(matches!(lang_for_tag("JA-JP"), Lang::Ja));
        assert!(matches!(lang_for_tag("ru_RU"), Lang::Ru));
    }

    #[test]
    fn only_simplified_chinese_is_chinese() {
        for tag in ["zh-CN", "zh-SG", "zh-Hans", "zh-Hans-CN"] {
            assert!(matches!(lang_for_tag(tag), Lang::Zh), "{tag}");
        }
        // A Traditional reader gets English, not a script they do not read.
        for tag in ["zh-TW", "zh-HK", "zh-MO", "zh-Hant-HK", "zh"] {
            assert!(matches!(lang_for_tag(tag), Lang::En), "{tag}");
        }
    }

    /// Including the empty tag a platform with no answer reports.
    #[test]
    fn anything_untranslated_is_english() {
        for tag in ["en-US", "sv-SE", "", "-", "nonsense"] {
            assert!(matches!(lang_for_tag(tag), Lang::En), "{tag}");
        }
    }

    /// Translation drops things, and neither kind of drop is visible in the diff
    /// that introduces it: an empty field renders as a blank line, and a lost
    /// placeholder renders the literal `{realm}` to a user.
    #[test]
    fn no_translation_is_empty_or_loses_a_placeholder() {
        let placeholders = |s: &str| {
            let mut found: Vec<String> = s
                .match_indices('{')
                .filter_map(|(i, _)| s[i..].find('}').map(|j| s[i..=i + j].to_string()))
                .collect();
            found.sort();
            found
        };
        // English is the source every other table is translated from.
        let en: Vec<_> = pick(Lang::En).fields().collect();
        for lang in Lang::ALL {
            let s = pick(lang);
            let tag = s.lang_tag;
            for ((name, english), (_, translated)) in en.iter().zip(s.fields()) {
                assert!(!translated.trim().is_empty(), "{tag}: {name} is empty");
                assert_eq!(
                    placeholders(english),
                    placeholders(translated),
                    "{tag}: {name} does not carry the same placeholders as English",
                );
            }
        }
    }

    /// `ALL` is hand-written, so it can fall behind `Lang` silently -- and a
    /// language missing from it is a language the help site never publishes.
    #[test]
    fn every_language_is_in_all_exactly_once() {
        let mut tags: Vec<&str> = Lang::ALL.iter().map(|&l| pick(l).lang_tag).collect();
        tags.sort_unstable();
        let n = tags.len();
        tags.dedup();
        assert_eq!(tags.len(), n, "a tag appears twice in Lang::ALL: {tags:?}");
        // Round-trips: the tag a table declares must resolve back to that table.
        for lang in Lang::ALL {
            let tag = pick(lang).lang_tag;
            assert!(matches!(pick(lang_for_tag(tag)), s if std::ptr::eq(s, pick(lang))), "{tag}");
        }
    }
}
