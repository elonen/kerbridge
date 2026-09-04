//! The menu, which on this platform is also the status window.
//!
//! **[`plan`] is a pure function of [`Status`] and the menu is a pure function of
//! [`Plan`].** That is what makes "has anything changed?" a comparison rather
//! than a guess, and it is the same rule the Windows window procedure follows.
//! The menu is rebuilt from a plan, never mutated in place: a menu is small, and
//! a function of the state is one fewer thing that can be left showing
//! yesterday's answer.
//!
//! What each state offers is the core's, not this file's; [`ORDER`] is the only
//! ranking, and it is this surface's alone.

use std::cell::{Cell, OnceCell};

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject, NSObjectProtocol, ProtocolObject, Sel};
use objc2::{MainThreadMarker, MainThreadOnly, define_class, msg_send, sel};
use objc2_app_kit::{
    NSColor, NSFont, NSFontAttributeName, NSForegroundColorAttributeName, NSMenu, NSMenuDelegate,
    NSMenuItem,
};
use objc2_foundation::{NSAttributedString, NSDictionary, NSString};

use kerbridge_client::agent::{self, Status};
use kerbridge_client::describe::{Action, Blocker, Condition};
use kerbridge_client::present::{
    action_label, blocker_line, days_until, headline, holds_access, identity,
};
use kerbridge_client::strings::{days, duration, fill, tr};

/// Menu order: access, authorization, ticket, grant, IdP exit.
const ORDER: [Action; 8] = [
    Action::Cancel,
    Action::OpenSettings,
    Action::ReinjectTicket,
    Action::SignIn,
    Action::CreateGrant,
    Action::DropKrbTicket,
    Action::GiveUpGrant,
    Action::SignOutIdp,
];

pub const CONFIRMED: [Action; 2] = [Action::CreateGrant, Action::GiveUpGrant];

/// `NSAlert` blocks; show grant progress on the disabled item.
fn running_label(act: Action) -> Option<&'static str> {
    let s = tr();
    match act {
        Action::CreateGrant => Some(s.dlg_grant_working),
        Action::GiveUpGrant => Some(s.dlg_grant_off_working),
        _ => None,
    }
}

/// One offer, as the menu will draw it.
#[derive(PartialEq, Eq)]
pub struct Offer {
    pub action: Action,
    label: String,
    /// Keep disabled items visible to preserve their menu position.
    disabled: bool,
}

/// How wide a status line may get before it is broken, in columns.
const WRAP_COLUMNS: usize = 56;

/// One line of the status card, already broken to [`WRAP_COLUMNS`].
#[derive(PartialEq, Eq)]
struct Line {
    text: String,
    /// The condition's own line, drawn in bold. At most one.
    headline: bool,
}

impl Line {
    fn info(text: impl AsRef<str>) -> Line {
        Line { text: wrap(text.as_ref()), headline: false }
    }

    fn headline(text: &str) -> Line {
        Line { text: wrap(text), headline: true }
    }
}

/// Break `text` at [`WRAP_COLUMNS`], preferring spaces and splitting a word that
/// does not fit on a line of its own.
///
/// Columns rather than characters, and a hard split rather than only a soft one,
/// because both are what the translated tables need: the same sentence in
/// Japanese is twice as wide per character and has no spaces to break at, so
/// counting characters would leave it just as wide and breaking only at spaces
/// would not break it at all.
fn wrap(text: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut line = String::new();
    let mut width = 0;
    for word in text.split_whitespace() {
        for chunk in chunks(word) {
            let w = columns(&chunk);
            if width > 0 && width + 1 + w > WRAP_COLUMNS {
                lines.push(std::mem::take(&mut line));
                width = 0;
            }
            if width > 0 {
                line.push(' ');
                width += 1;
            }
            line.push_str(&chunk);
            width += w;
        }
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines.join("\n")
}

/// One word as pieces that each fit a line. A word inside the budget is itself.
fn chunks(word: &str) -> Vec<String> {
    if columns(word) <= WRAP_COLUMNS {
        return vec![word.to_owned()];
    }
    let mut out = Vec::new();
    let mut chunk = String::new();
    let mut width = 0;
    for c in word.chars() {
        let w = char_columns(c);
        if width + w > WRAP_COLUMNS {
            out.push(std::mem::take(&mut chunk));
            width = 0;
        }
        chunk.push(c);
        width += w;
    }
    if !chunk.is_empty() {
        out.push(chunk);
    }
    out
}

fn columns(s: &str) -> usize {
    s.chars().map(char_columns).sum()
}

/// Two columns for the East Asian wide and fullwidth ranges, one for everything
/// else. The usual approximation, and enough for a menu -- it decides where a
/// line breaks, not how anything is drawn.
fn char_columns(c: char) -> usize {
    match c {
        '\u{1100}'..='\u{115F}'
        | '\u{2E80}'..='\u{A4CF}'
        | '\u{AC00}'..='\u{D7A3}'
        | '\u{F900}'..='\u{FAFF}'
        | '\u{FE30}'..='\u{FE6F}'
        | '\u{FF00}'..='\u{FF60}'
        | '\u{FFE0}'..='\u{FFE6}'
        | '\u{20000}'..='\u{3FFFD}' => 2,
        _ => 1,
    }
}

/// Everything the menu draws. Compared rather than [`Status`], which has no
/// `PartialEq` and most of which never reaches a menu item.
#[derive(PartialEq, Eq)]
pub struct Plan {
    lines: Vec<Line>,
    actions: Vec<Offer>,
    /// A ticket the OS can spend, so the Kerberos details would describe
    /// something rather than nothing.
    details: bool,
}

/// The whole of what the menu says about the current state.
pub fn plan(st: &Status) -> Plan {
    let s = tr();
    let mut lines = Vec::new();
    if let Some(headline) = headline(st) {
        lines.push(Line::headline(headline));
    }
    if let Some(identity) = identity(st) {
        lines.push(Line::info(identity));
    }
    // The ticket clock, whenever there is access to put a number on.
    if holds_access(st)
        && let Some(t) = &st.ticket
    {
        let left = duration(t.remaining);
        lines.push(Line::info(if matches!(st.condition, Condition::Flaky | Condition::WillStop) {
            fill(s.access_ends_in, &[("duration", &left)])
        } else {
            format!("{}: {}", s.meter_label, left)
        }));
    }
    if let Some(deadline) = st.grant_expiry {
        lines.push(Line::info(fill(s.grant_expires_in, &[("days", &days(days_until(deadline)))])));
    }
    // Suppress `NoSupply` when a headline exists to avoid repeating information.
    let has_headline = lines.iter().any(|l| l.headline);
    lines.extend(
        st.blockers
            .iter()
            .filter(|b| !(has_headline && **b == Blocker::NoSupply))
            .map(|b| Line::info(blocker_line(*b, st))),
    );
    if !st.message.is_empty() {
        lines.push(Line::info(&st.message));
    }

    // The busy slot blocks confirmation, not revocation.
    let slot_taken = st.in_flight.iter().any(|a| !a.outside_busy_slot());
    let actions: Vec<Offer> = ORDER
        .into_iter()
        .filter(|act| st.actions.contains(act))
        .map(|act| {
            let running = st.in_flight.contains(&act);
            Offer {
                action: act,
                label: match running_label(act).filter(|_| running) {
                    Some(working) => working.to_owned(),
                    None => action_label(act, st),
                },
                disabled: running
                    || (slot_taken && CONFIRMED.contains(&act) && !act.outside_busy_slot()),
            }
        })
        .collect();

    Plan { lines, actions, details: st.usable }
}

impl Plan {
    /// The label of the offer this surface is leading with, for the two
    /// notifications that name one.
    ///
    /// *Cancel* is skipped although it leads the menu: those two sentences read
    /// "{action} to keep access", and stopping a sign-in is the opposite of that.
    pub fn primary_label(&self) -> String {
        self.actions
            .iter()
            .find(|o| o.action != Action::Cancel)
            .map(|o| o.label.clone())
            .unwrap_or_else(|| tr().no_action.into())
    }

    pub fn action(&self, index: usize) -> Option<Action> {
        self.actions.get(index).map(|o| o.action)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Offer(usize),
    Details,
    Log,
    Settings,
    Help,
    About,
    Quit,
}

impl Command {
    fn tag(self) -> isize {
        match self {
            Command::Offer(i) => i as isize,
            Command::Details => -1,
            Command::Log => -2,
            Command::Settings => -3,
            Command::Help => -4,
            Command::About => -5,
            Command::Quit => -6,
        }
    }

    fn from_tag(tag: isize) -> Option<Command> {
        Some(match tag {
            i if i >= 0 => Command::Offer(i as usize),
            -1 => Command::Details,
            -2 => Command::Log,
            -3 => Command::Settings,
            -4 => Command::Help,
            -5 => Command::About,
            -6 => Command::Quit,
            _ => return None,
        })
    }
}

thread_local! {
    /// Whether the menu is on screen. Two things read it: the rebuild, which must
    /// not replace a menu that is being tracked, and gate 2, which suppresses a
    /// notification about something this surface is already saying.
    static OPEN: Cell<bool> = const { Cell::new(false) };
}

pub fn is_open() -> bool {
    OPEN.with(Cell::get)
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements, and this type has no
    // Drop and no instance variables -- every menu item carries what it needs in
    // its own tag.
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "KerBridgeMenuTarget"]
    struct Target;

    impl Target {
        #[unsafe(method(perform:))]
        fn perform(&self, sender: &NSMenuItem) {
            let tag = sender.tag();
            match Command::from_tag(tag) {
                Some(command) => crate::perform(command),
                // Unreachable while every item this file builds carries a tag it
                // also knows; logged rather than ignored so a future item that
                // forgets one is not silently inert.
                None => kerbridge_client::log::warn(&format!("menu item {tag} has no command")),
            }
        }
    }

    unsafe impl NSObjectProtocol for Target {}

    // SAFETY: both methods are the protocol's own, and the delegate is set on a
    // menu this file built.
    unsafe impl NSMenuDelegate for Target {
        #[unsafe(method(menuWillOpen:))]
        fn menu_will_open(&self, _menu: &NSMenu) {
            OPEN.with(|o| o.set(true));
        }

        #[unsafe(method(menuDidClose:))]
        fn menu_did_close(&self, _menu: &NSMenu) {
            OPEN.with(|o| o.set(false));
            agent::status_closed();
            // A change that arrived while the menu was tracking was not drawn
            // into it -- see [`crate::refresh`] -- so ask for it again. On the
            // next pass rather than here: the menu AppKit is telling us about is
            // still on its stack.
            crate::ui::redraw_later();
        }
    }
);

thread_local! {
    /// The one target every menu item points at, for the life of the process.
    ///
    /// **`NSMenuItem.target` does not retain**, and neither does `NSMenu.delegate`.
    /// A target created per rebuild is deallocated the moment the rebuild returns,
    /// and an item whose target has gone is an item AppKit disables -- which is how
    /// every command in this menu, including Quit, came to be unclickable. It holds
    /// no state, so one instance serves every menu this file will ever build.
    static TARGET: OnceCell<Retained<Target>> = const { OnceCell::new() };
}

impl Target {
    fn shared(mtm: MainThreadMarker) -> Retained<Self> {
        TARGET.with(|t| t.get_or_init(|| unsafe { msg_send![Self::alloc(mtm), init] }).clone())
    }
}

/// Build the whole menu for `plan`.
pub fn build(mtm: MainThreadMarker, plan: &Plan) -> Retained<NSMenu> {
    let s = tr();
    let menu = NSMenu::new(mtm);
    // Off, so the `setEnabled` calls below are the last word. Left on, AppKit
    // decides for itself by walking the responder chain for each action, and a
    // background agent with no key window is not somewhere that search ends well.
    menu.setAutoenablesItems(false);
    let target = Target::shared(mtm);
    // Not an owning reference either -- see [`Target::shared`].
    menu.setDelegate(Some(ProtocolObject::from_ref(&*target)));

    // The state, as disabled items. This is the flyout's status card.
    for line in &plan.lines {
        info(mtm, &menu, line);
    }

    if !plan.actions.is_empty() {
        separator(mtm, &menu);
    }
    for (i, offer) in plan.actions.iter().enumerate() {
        let item = item(mtm, &menu, &offer.label, Command::Offer(i), &target);
        item.setEnabled(!offer.disabled);
    }

    separator(mtm, &menu);
    // The details answer a question nobody has while the thing is working, which
    // is why they are a sheet rather than four more lines on the card -- the same
    // reason the Windows flyout keeps them behind a disclosure triangle.
    if plan.details {
        item(mtm, &menu, &opens_a_dialog(s.details_heading), Command::Details, &target);
    }
    // The Mac's Settings is one alert, so it has no Troubleshoot section to hold
    // the permanent route to the log. This is it.
    item(mtm, &menu, s.act_open_log, Command::Log, &target);
    item(mtm, &menu, s.menu_settings, Command::Settings, &target);
    item(mtm, &menu, s.menu_help, Command::Help, &target);
    item(mtm, &menu, &opens_a_dialog(s.tab_about), Command::About, &target);
    separator(mtm, &menu);
    item(mtm, &menu, s.menu_quit, Command::Quit, &target);

    menu
}

/// The platform's promise that a command opens something rather than doing it.
/// A convention of this UI, not of the strings -- the `act_*` labels spell their
/// own, because whether one is earned is the action's business and not the
/// surface's.
fn opens_a_dialog(title: &str) -> String {
    format!("{title}…")
}

/// One clickable item.
fn item(
    mtm: MainThreadMarker,
    menu: &NSMenu,
    title: &str,
    command: Command,
    target: &Retained<Target>,
) -> Retained<NSMenuItem> {
    let empty = NSString::from_str("");
    let selector: Sel = sel!(perform:);
    // SAFETY: `perform:` is the selector `Target` above implements, and the
    // target set below is the object that implements it.
    let item = unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(
            NSMenuItem::alloc(mtm),
            &NSString::from_str(title),
            Some(selector),
            &empty,
        )
    };
    item.setTag(command.tag());
    item.setEnabled(true);
    // Not an owning reference -- see [`Target::shared`], which is why the target
    // has to outlive every menu rather than the other way round.
    unsafe { item.setTarget(Some(target)) };
    menu.addItem(&item);
    item
}

/// One line of state, information rather than an offer -- so disabled, and drawn
/// in the ink the platform grays a disabled control with.
///
/// **Attributed, always.** A plain title is drawn as a single line whatever is in
/// it, so the breaks [`wrap`] put there would be lost; an attributed one honors
/// them. That costs the automatic disabled gray -- an attributed string carries
/// its own color and would otherwise land black on a dark menu -- so the color
/// is set here rather than inherited.
fn info(mtm: MainThreadMarker, menu: &NSMenu, line: &Line) {
    let empty = NSString::from_str("");
    let title = NSString::from_str(&line.text);
    // SAFETY: no action, so there is no selector to get wrong.
    let item = unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(NSMenuItem::alloc(mtm), &title, None, &empty)
    };
    // The condition is the one line that has to read at a glance, and every line
    // in this block is already the same gray. Weight is what is left.
    let font = if line.headline {
        NSFont::boldSystemFontOfSize(NSFont::systemFontSize())
    } else {
        NSFont::menuFontOfSize(NSFont::systemFontSize())
    };
    let attrs = NSDictionary::from_slices(
        &[unsafe { NSFontAttributeName }, unsafe { NSForegroundColorAttributeName }],
        &[&*font as &AnyObject, &*NSColor::disabledControlTextColor() as &AnyObject],
    );
    // SAFETY: both attribute names are AppKit's own, and each value is the type
    // the name it is paired with denotes.
    let styled = unsafe { NSAttributedString::new_with_attributes(&title, &attrs) };
    item.setAttributedTitle(Some(&styled));
    item.setEnabled(false);
    menu.addItem(&item);
}

fn separator(mtm: MainThreadMarker, menu: &NSMenu) {
    menu.addItem(&NSMenuItem::separatorItem(mtm));
}

#[cfg(test)]
mod tests {
    use kerbridge_client::describe::Supply;

    use super::*;

    fn offering(actions: &[Action]) -> Status {
        Status {
            condition: Condition::Working,
            blockers: Vec::new(),
            actions: actions.to_vec(),
            in_flight: Vec::new(),
            supply: Supply::BrowserSignIn,
            usable: true,
            realm: "EXAMPLE.SITE".into(),
            source: String::new(),
            broker_host: "kerbridge.example.site".into(),
            help_url: String::new(),
            idp_name: String::new(),
            principal: String::new(),
            ticket: None,
            next_attempt_at_earliest: None,
            message: String::new(),
            fault: false,
            holds_grant: false,
            grant_expiry: None,
            grant_target: String::new(),
            just_authorized: false,
        }
    }

    fn offered(plan: &Plan) -> Vec<Action> {
        plan.actions.iter().map(|o| o.action).collect()
    }

    #[test]
    fn both_grant_actions_reach_the_menu() {
        let st = offering(&[Action::CreateGrant, Action::GiveUpGrant, Action::SignIn]);
        let offered = offered(&plan(&st));
        assert!(offered.contains(&Action::CreateGrant), "{offered:?}");
        assert!(offered.contains(&Action::GiveUpGrant), "{offered:?}");
    }

    #[test]
    fn the_menu_reads_top_to_bottom_in_the_order_the_help_page_uses() {
        let st = offering(&ORDER);
        assert_eq!(offered(&plan(&st)), ORDER);
    }

    #[test]
    fn a_sign_in_in_flight_holds_only_the_action_that_needs_the_slot() {
        let mut st = offering(&[Action::CreateGrant, Action::GiveUpGrant]);
        st.in_flight = vec![Action::SignIn];
        let plan = plan(&st);
        let disabled =
            |act: Action| plan.actions.iter().find(|o| o.action == act).unwrap().disabled;
        assert!(disabled(Action::CreateGrant));
        assert!(!disabled(Action::GiveUpGrant));
    }

    #[test]
    fn a_running_grant_action_says_so_on_its_own_item() {
        let mut st = offering(&[Action::CreateGrant]);
        st.in_flight = vec![Action::CreateGrant];
        let plan = plan(&st);
        let offer = &plan.actions[0];
        assert!(offer.disabled);
        assert_eq!(offer.label, tr().dlg_grant_working);
    }

    #[test]
    fn every_confirmed_action_is_in_the_order() {
        for act in CONFIRMED {
            assert!(ORDER.contains(&act), "{act:?}");
        }
    }

    /// The line that provoked this: a failure sentence with the URL that
    /// produced it, which unbroken set the width of the whole menu.
    #[test]
    fn a_failure_sentence_is_broken_to_the_budget() {
        let long = "Network: kerbridge.example.site didn't answer. (fetching broker /config: \
                    GET https://kerbridge.example.site/config: timeout: global)";
        let wrapped = wrap(long);
        assert!(wrapped.contains('\n'));
        for line in wrapped.lines() {
            assert!(columns(line) <= WRAP_COLUMNS, "{line:?}");
        }
        // Nothing but the breaks changed.
        assert_eq!(
            wrapped.split_whitespace().collect::<Vec<_>>(),
            long.split_whitespace().collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_line_inside_the_budget_is_left_alone() {
        let short = "Can't reach kerbridge.example.site";
        assert_eq!(wrap(short), short);
    }

    /// A URL long enough to overflow a line on its own has no space to break at,
    /// and neither does any of the CJK tables -- so the split has to be able to
    /// land mid-word or those stay exactly as wide as they were.
    #[test]
    fn a_word_that_cannot_fit_is_split_anyway() {
        let url = format!("https://{}.example.site/config", "a".repeat(120));
        for line in wrap(&url).lines() {
            assert!(columns(line) <= WRAP_COLUMNS, "{line:?}");
        }

        // Two columns each and not one space between them: counting characters
        // would leave this twice as wide as the budget.
        let ja = "この Mac は共有にアクセスできません".repeat(6);
        let wrapped = wrap(&ja);
        assert!(wrapped.contains('\n'));
        for line in wrapped.lines() {
            assert!(columns(line) <= WRAP_COLUMNS, "{line:?}");
        }
    }
}
