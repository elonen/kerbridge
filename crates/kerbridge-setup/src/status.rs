//! `kbsetup status` -- what is done, what is left, and the command for the next
//! step.
//!
//! **The verb an operator meets first.** An operator who has just installed the
//! packages is at a terminal rather than at the deployment guide. This reads
//! what is on disk and answers the only question they have.
//!
//! It is a *reporter*, not a fifth checker. Each step below is answered by
//! whichever component already owns that question -- `dc::State` for the realm,
//! [`crate::pasted`] for the credentials, `systemctl` for the units -- and
//! nothing is decided here that is decided anywhere else. The boundary the
//! `verify` module comment draws stays: `kbsetup verify` asks whether durable
//! state matches the config set, `kbconfig check` whether the set is coherent,
//! `kbmanage doctor` whether an identity can reach a file server. This asks
//! *how far through the procedure is this host*, which none of the three does.
//!
//! **Nothing here writes, prompts, or opens a socket.** So it is safe on a
//! half-finished host, which is the only kind that runs it.

use std::io::IsTerminal;
use std::path::Path;

use anyhow::Result;
use kerbridge_core::config::Config;

use crate::units::{self, UNITS};
use crate::verify::{MATCHES, MISMATCH};
use crate::{dc, pasted, run, secrets};

/// Where the detail column starts: `"  [x] 1. "` and a 20-wide title. A
/// continuation line is indented to it, so the report reads as one column of
/// findings rather than two of ragged text.
const GUTTER: usize = 9 + 20 + 1;

pub enum State {
    Done,
    Todo,
    /// True of a step this host cannot answer from here: the TLS terminator is
    /// someone else's program, and `systemctl` is absent on a Compose
    /// deployment. Reported as neither done nor outstanding, because claiming
    /// either would be a guess.
    Unknown,
}

pub struct Step {
    pub title: &'static str,
    pub state: State,
    /// What was found. One line.
    pub detail: String,
    /// The command that advances this step, or that answers it where this
    /// cannot.
    pub next: Option<String>,
}

impl Step {
    fn mark(&self, ink: &Palette) -> String {
        let (colour, mark) = match self.state {
            State::Done => (ink.done, "[x]"),
            State::Todo => (ink.todo, "[ ]"),
            State::Unknown => (ink.unknown, "[?]"),
        };
        format!("{colour}{mark}{}", ink.reset)
    }
}

/// The escape sequences, or empty strings where colour would be noise.
///
/// Off unless stdout is a terminal, and off whenever `NO_COLOR` is set at all
/// -- the no-color.org convention, where the variable's *presence* is the
/// signal and its value means nothing.
///
/// The terminal test is the one that earns its keep here: the
/// `kerbridge-issuerd` postinst runs this verb, and dpkg captures what a
/// maintainer script prints. Without the test an installation's closing report
/// would be escape sequences in an apt log.
struct Palette {
    done: &'static str,
    todo: &'static str,
    unknown: &'static str,
    command: &'static str,
    strong: &'static str,
    reset: &'static str,
}

impl Palette {
    fn of(stream: &impl IsTerminal) -> Self {
        if !stream.is_terminal() || std::env::var_os("NO_COLOR").is_some() {
            return Self::plain();
        }
        Self {
            done: "\x1b[32m",
            todo: "\x1b[33m",
            // Dim rather than a colour of its own: [?] is not a third verdict,
            // it is the absence of one, and it must not compete for the eye
            // with the steps that are outstanding.
            unknown: "\x1b[2m",
            // Bold, and no colour: bold renders in the theme's own
            // foreground, so it cannot come out invisible on a light
            // background the way an explicit white does.
            command: "\x1b[1m",
            strong: "\x1b[1m",
            reset: "\x1b[0m",
        }
    }

    fn plain() -> Self {
        Self { done: "", todo: "", unknown: "", command: "", strong: "", reset: "" }
    }
}

pub fn run(dir: &Path) -> Result<u8> {
    let config = crate::load(dir)?;
    let steps = walk(dir, &config)?;
    say(&config, &steps);
    Ok(if steps.iter().any(|step| matches!(step.state, State::Todo)) { MISMATCH } else { MATCHES })
}

/// The procedure, in the order `SETUP.md` runs it.
///
/// Every step is reported, and the walk never stops at the first outstanding
/// one: an operator waiting on a certificate wants to get the directory and the
/// credentials done meanwhile, and a list that stopped would hide them.
pub fn walk(dir: &Path, config: &Config) -> Result<Vec<Step>> {
    let mut steps = vec![Step {
        title: "configuration set",
        state: State::Done,
        // Reaching here means `Config::load` accepted it, which is the same
        // parse and the same cross-checks every daemon does at startup.
        detail: format!(
            "{}, realm {}, {}",
            dir.display(),
            config.realm.realm,
            match config.sources.len() {
                0 => "no cloud IdP source".to_owned(),
                n => format!(
                    "{n} source ({})",
                    config.sources.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ")
                ),
            }
        ),
        next: None,
    }];

    steps.push(realm_step(config));
    steps.push(directory_step(config)?);
    steps.push(credentials_step(config)?);
    steps.push(terminator_step(config));
    if let Some(step) = units_step() {
        steps.push(step);
    }
    Ok(steps)
}

fn realm_step(config: &Config) -> Step {
    let dc = dc::Dc::at(&config.issuerd.sam_db);
    match dc.state() {
        dc::State::Provisioned => Step {
            title: "realm provisioned",
            state: State::Done,
            detail: config.issuerd.sam_db.display().to_string(),
            next: None,
        },
        dc::State::Absent => Step {
            title: "realm provisioned",
            state: State::Todo,
            detail: format!("no Samba database at {}", config.issuerd.sam_db.display()),
            next: Some("kbsetup realm".to_owned()),
        },
        // Two situations look like this and they want opposite answers, so this
        // says only that they exist and sends the operator to the one place
        // that words both. Guessing here is how a working DC gets destroyed.
        dc::State::Unfinished => Step {
            title: "realm provisioned",
            state: State::Todo,
            detail: format!(
                "a Samba database at {} with no {} beside it -- either a provision that stopped \
                 partway or a DC kbsetup did not make",
                config.issuerd.sam_db.display(),
                dc.stamp().display()
            ),
            next: Some("kbsetup verify".to_owned()),
        },
    }
}

/// Answered by the broker's own bind password, which `kbsetup directory`
/// generates together with the account. There is no lighter witness that does
/// not need the directory open: the accounts and the delegation live in
/// `sam.ldb`, and reading it here would make this verb as expensive as the one
/// it reports on.
fn directory_step(config: &Config) -> Result<Step> {
    let path = &config.broker.bind_password_file;
    Ok(if secrets::existing(path)?.is_some() {
        Step {
            title: "directory",
            state: State::Done,
            detail: "the OUs, the service accounts and their delegation".to_owned(),
            next: None,
        }
    } else {
        Step {
            title: "directory",
            state: State::Todo,
            detail: format!("{} is empty, so no service account exists yet", path.display()),
            next: Some("kbsetup directory".to_owned()),
        }
    })
}

fn credentials_step(config: &Config) -> Result<Step> {
    let wanted = pasted::wanted(config);
    if wanted.is_empty() {
        return Ok(Step {
            title: "your credentials",
            state: State::Done,
            detail: "this set names none for you to supply".to_owned(),
            next: None,
        });
    }
    let missing = pasted::missing(config)?;
    // An optional one left unset is a deployment that chose to do without it --
    // notification off, which is supported -- so it is reported and does not
    // hold the step open.
    let required: Vec<&pasted::Pasted> = missing.iter().filter(|want| !want.optional).collect();

    // A credential that is there and unreadable is worse than one that is
    // absent: every root-run check reports it in place, and every daemon that
    // opens it exits. Only the pasted ones are examined -- `kbsetup` wrote the
    // rest itself, at the mode and group their reader needs.
    let gid = secrets::daemon_group(&config.issuerd)?;
    let mut denied = Vec::new();
    for want in &wanted {
        if !want.present()? {
            continue;
        }
        if let Some(why) = secrets::unreadable_by(&want.path, gid) {
            denied.push(format!("\n{:GUTTER$}{}: {why}", "", want.named()));
        }
    }

    let mut detail = if missing.is_empty() {
        format!("{} in place", wanted.len())
    } else {
        format!(
            "{} of {} missing: {}",
            missing.len(),
            wanted.len(),
            missing.iter().map(pasted::Pasted::named).collect::<Vec<_>>().join(", ")
        )
    };
    detail.push_str(&denied.concat());
    Ok(Step {
        title: "your credentials",
        state: if required.is_empty() && denied.is_empty() { State::Done } else { State::Todo },
        detail,
        next: (!missing.is_empty()).then(|| "kbsetup secrets".to_owned()),
    })
}

/// Never answered from here: the terminator is a program KerBridge does not
/// ship, on a port KerBridge does not open, and `kbsetup` links no HTTP client
/// -- it runs beside `issuerd`, which links none either. `kbmanage endpoint` is
/// the check, and it needs no config set and binds nothing.
fn terminator_step(config: &Config) -> Step {
    let host =
        config.realm.ldap_host().rsplit_once(':').map_or(config.realm.ldap_host(), |(h, _)| h);
    Step {
        title: "TLS terminator",
        state: State::Unknown,
        detail: format!("the broker serves {} and refuses anything wider", config.broker.listen),
        next: Some(format!("kbmanage endpoint https://{host}")),
    }
}

/// `None` on a host with no `systemctl`, which is every Compose deployment.
/// Absent rather than `Unknown`: a step that cannot apply is not a step this
/// host has left to do.
fn units_step() -> Option<Step> {
    let mut found = Vec::new();
    for unit in UNITS {
        // `is-active` exits non-zero for every state that is not active, and
        // prints the state either way -- so the status is the stdout, not the
        // exit code.
        let done = run::attempt(&["systemctl", "is-active", unit], None).ok()?;
        found.push(format!("{unit} {}", done.stdout.trim()));
    }
    let failed: Vec<&str> = UNITS.into_iter().filter(units::is_failed).collect();

    // A failed unit stated a reason, and `systemctl status` truncates it away.
    // Quoting it here is what stops an operator debugging this tool instead of
    // their deployment.
    let mut detail = found.join(", ");
    for unit in &failed {
        if let Some(said) = units::last_line(unit) {
            detail.push_str(&format!("\n{:GUTTER$}{unit}: {said}", ""));
        }
    }
    Some(Step {
        title: "services",
        // A dead daemon is work outstanding, whatever else on this host is
        // finished -- and the exit status has to say so.
        state: if failed.is_empty() { State::Unknown } else { State::Todo },
        detail,
        // The reader, never a remedy: a unit is `failed` for as many reasons as
        // it has start conditions, and restarting one before its cause is fixed
        // only spends the restart budget again.
        next: failed.first().map(|unit| units::reader(unit)),
    })
}

fn say(config: &Config, steps: &[Step]) {
    let ink = Palette::of(&std::io::stdout());
    println!();
    println!("  {}{} -- setup status{}", ink.strong, config.realm.realm, ink.reset);
    println!();
    for (n, step) in steps.iter().enumerate() {
        println!("  {} {}. {:<20} {}", step.mark(&ink), n + 1, step.title, step.detail);
        if let Some(next) = &step.next {
            // An instruction rather than a name, so that the column is
            // scannable for the line to type without reading the detail above.
            println!("{:GUTTER$}-> Run `{}{next}{}`", "", ink.command, ink.reset);
        }
        // One blank line per step, so that a two-line step reads as one
        // item: without it a wrapped detail and the next mark sit together.
        println!();
    }
    match steps.iter().find(|step| matches!(step.state, State::Todo)) {
        Some(step) => {
            println!(
                "  {}Next:{} run `{}{}{}`",
                ink.strong,
                ink.reset,
                ink.command,
                step.next.as_deref().unwrap_or("--"),
                ink.reset
            );
            println!();
        }
        None => {
            println!(
                "  {}Every step this host can answer is done.{} What is left is off it: the TLS \
                 terminator,\n  the file server, and a workstation. Run `{}kbmanage doctor{}` to \
                 walk the chain end to end.",
                ink.strong, ink.reset, ink.command, ink.reset
            );
            println!();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{SOURCE_WITH_CREDENTIAL, set_with};

    /// A freshly installed host: a config set and nothing else. Every step that
    /// this host can answer is outstanding, and each one names its command.
    #[test]
    fn a_host_with_only_a_config_set_has_every_step_left() {
        let set = set_with(&[("idp_entra.toml", SOURCE_WITH_CREDENTIAL)]);
        let config = Config::load(set.dir()).unwrap();
        let steps = walk(set.dir(), &config).unwrap();

        let by_title = |title| steps.iter().find(|s| s.title == title).unwrap();
        assert!(matches!(by_title("configuration set").state, State::Done));
        assert_eq!(by_title("realm provisioned").next.as_deref(), Some("kbsetup realm"));
        assert_eq!(by_title("directory").next.as_deref(), Some("kbsetup directory"));
        assert_eq!(by_title("your credentials").next.as_deref(), Some("kbsetup secrets"));
    }

    /// The step order is the order `SETUP.md` runs them, and `Next:` is the
    /// first outstanding one rather than the last or the worst.
    #[test]
    fn next_is_the_first_outstanding_step() {
        let set = set_with(&[("idp_entra.toml", SOURCE_WITH_CREDENTIAL)]);
        let config = Config::load(set.dir()).unwrap();
        let steps = walk(set.dir(), &config).unwrap();
        let first = steps.iter().find(|s| matches!(s.state, State::Todo)).unwrap();
        assert_eq!(first.title, "realm provisioned");
    }

    /// Captured output must carry no escape sequence: the postinst runs this
    /// verb, and dpkg puts what a maintainer script prints into the apt log.
    #[test]
    fn the_plain_palette_renders_the_marks_and_nothing_else() {
        let ink = Palette::plain();
        let step = |state| Step { title: "t", state, detail: String::new(), next: None };
        assert_eq!(step(State::Done).mark(&ink), "[x]");
        assert_eq!(step(State::Todo).mark(&ink), "[ ]");
        assert_eq!(step(State::Unknown).mark(&ink), "[?]");
    }

    /// The terminator can never be answered from this host, so it must never
    /// hold the exit code open -- otherwise a fully configured deployment
    /// reports itself unfinished for ever.
    #[test]
    fn the_terminator_step_is_never_outstanding() {
        let config = crate::testing::config();
        assert!(matches!(terminator_step(&config).state, State::Unknown));
    }
}
