//! The KerBridge client core -- shared by the CLI (`kerbridge`) and by each
//! platform's agent (`../kerbridge-agent-windows/`, `../kerbridge-agent-macos/`).
//!
//! Everything a client needs to turn a cloud identity into a usable on-prem
//! Kerberos ticket lives here, so no two binaries can drift:
//!
//! ```text
//!  srv ─► discovery ─► oidc ─► broker ─► krbcred ─► tickets (the sign-in pipeline)
//!                      device ─┘                            (the same, without a browser)
//!  config · log · enroll · repair                           (host state and plumbing)
//!  agent · describe · present · icon · strings              (what a background agent is)
//! ```
//!
//! `session::inject` is the single implementation of "exchange this token for a
//! TGT and land it in the caller's ticket cache", so the CLI's one-shot and
//! an agent's silent re-injection are literally the same code path. `agent` is
//! the same idea one level up: the state machine, the re-injection schedule and
//! the user-visible text are the product's, not one platform's. A platform's
//! agent crate supplies the UI behind [`agent::Host`] and owns nothing else.
//!
//! # Where the platforms differ
//!
//! Two kinds of seam, and the difference is which direction they point.
//! [`agent::Host`] is a runtime trait, because its implementation lives *above*
//! this crate in the agent binary. Everything else is a `#[cfg]` seam pointing
//! *down* at the OS, chosen when the binary is built.
//!
//! The `#[cfg]` seams are `tickets`, `srv`, `enroll`, `device`, `time`, `config`,
//! `elevate`, `repair` and `sys`. Each is a module in its own right rather than a
//! single `platform.rs`, so the reason a thing differs is written next to the
//! thing: `repair.rs` holds the subject and what both platforms agree on, and
//! names its two arms with one `#[cfg_attr(path)]`.
//!
//! Those arms live in `windows/`, `macos/` and `linux/`, one file per subject, so
//! a reader asking "what does this do on Windows" has one place to look instead
//! of nine. None of the folders is a module -- there is no `windows/mod.rs` and no
//! `platform::` path -- because each file is reached by `#[path]` from the subject
//! that owns it. The grouping is for the reader; the module tree is unchanged.
//!
//! `reg`, `cf` and `os` are not seams: they are one platform's toolbox, used only
//! by that platform's arms, and they sit in the same folders for the same reason.
//!
//! **The Linux arm is not a Linux client.** It exists so that CI can run this
//! crate -- the platform-neutral majority above the seams is the great bulk of
//! what a client does, and until the arm existed none of it ran anywhere
//! automated. A green Linux run says nothing about LSA submission, Heimdal, WAM,
//! device keys or realm registration, all of which are measured on the Windows
//! and macOS benches. `linux/os.rs` is where that is written out at length, and
//! `client/DESIGN.md` says it once more for a reader who never opens the folder.

pub mod agent;
pub mod broker;
#[cfg(target_os = "macos")]
#[path = "macos/cf.rs"]
pub mod cf;
pub mod config;
pub mod describe;
pub mod device;
pub mod discovery;
pub mod elevate;
pub mod enroll;
pub mod http;
pub mod icon;
pub mod krbcred;
pub mod log;
pub mod oidc;
#[cfg(target_os = "linux")]
#[path = "linux/os.rs"]
pub mod os;
pub mod present;
#[cfg(windows)]
#[path = "windows/reg.rs"]
pub mod reg;
pub mod repair;
pub mod session;
pub mod srv;
pub mod strings;
pub mod sys;
pub mod tickets;
pub mod time;
pub mod tls;

/// Where a surface's *Help* goes when the deployment publishes no page of its
/// own (`discovery`'s `help_url`). One address, because two agents pointing at
/// different pages is one of them wrong.
pub const HELP_URL: &str = "https://help.kerbridge.org";

/// The help address to actually open: the page told which language to serve and
/// which platform's half to show, since one page documents both and the reader
/// should not have to pick what the agent already knows.
///
/// Query parameters and nothing else, so this is safe on the *deployment's* own
/// `help_url` too -- a page that does not know them ignores them, where an
/// appended path would 404. `base` may already carry a query.
pub fn help_url_for(base: &str, os: &str) -> String {
    let (base, fragment) = base.split_once('#').map_or((base, ""), |(b, f)| (b, f));
    let sep = if base.contains('?') { '&' } else { '?' };
    let lang = strings::tr().lang_tag;
    let hash = if fragment.is_empty() { String::new() } else { format!("#{fragment}") };
    format!("{base}{sep}lang={lang}&os={os}{hash}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The language is whatever this host is set to, so assert the shape around
    /// it rather than the tag.
    #[test]
    fn help_url_carries_the_platform_and_keeps_the_fragment_last() {
        let url = help_url_for(HELP_URL, "win");
        assert!(url.starts_with("https://help.kerbridge.org?lang="), "{url}");
        assert!(url.ends_with("&os=win"), "{url}");

        // A deployment's own page may already carry a query, and a fragment has
        // to stay at the end or it swallows the parameters.
        let url = help_url_for("https://it.example.site/help?topic=drives#ntlm", "mac");
        assert!(url.starts_with("https://it.example.site/help?topic=drives&lang="), "{url}");
        assert!(url.ends_with("&os=mac#ntlm"), "{url}");
    }
}
