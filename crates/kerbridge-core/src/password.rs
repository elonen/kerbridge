//! One generator for every password KerBridge creates, in the one place all of
//! its creators can reach.
//!
//! Samba applies the Windows complexity rule and refuses a password missing one
//! of upper, lower and digit -- measured against the pinned baseline (Samba
//! 4.22.10) with the same function the directory enforces with:
//!
//! ```text
//! check_password_quality("AbcdefghijklmnopqrstuvwxyzABCDEF")  -> False
//! check_password_quality("Abcdefghijklmnopqrstuvwxyz1BCDEF")  -> True
//! ```
//!
//! This is the only place a password for *this realm* is made.
//! `testbench/entra-tenant/setup_directory.py` keeps a generator of its own
//! because it makes *Entra* passwords through Graph, bound by that tenant's
//! policy rather than Samba's.
//!
//! **Construction, never rejection.** The measurement that argued for it: on
//! the same baseline,
//! about one 32-character alphanumeric draw in 270 contains no digit -- 11 of
//! 3000 -- so across the four accounts a deployment generates, roughly one
//! bootstrap in seventy failed with "the password does not meet the complexity
//! criteria" and succeeded on a re-run, rare enough to read as infrastructure
//! flakiness rather than as a bug. A fixed affix removes that failure rate
//! rather than lowering it, and costs no strength: the random half is the whole
//! of the entropy either way.
//!
//! **The alphabet is the caller's, and only the caller's.** Both forms are
//! complex by construction, so this is not a security choice -- it is about who
//! reads the value. A service account's password is pasted between processes and
//! seen by nobody, and [`Alphabet::Base64Url`] packs the most entropy per byte.
//! The realm Administrator's is break-glass: `SETUP.md` tells an operator where
//! to read it and they type it at a Windows prompt, so it takes
//! [`Alphabet::Alphanumeric`]: these values are pasted into config, typed at
//! prompts and piped between processes, and punctuation would buy no strength
//! worth that.
//!
//! Behind the `password` feature, per `lib.rs`'s rule: it needs `ring`, and
//! `issuerd` -- which links this crate and holds KDC authority -- creates no
//! accounts and must not gain it.

use base64::Engine;
use ring::rand::SecureRandom;

/// Upper, lower and digit in three characters, prepended to every draw. Fixed
/// rather than drawn: a random affix would only move the failure this exists to
/// remove.
const COMPLEXITY: &str = "Kb1";

/// The alphabet a password's random half is drawn from. Both are complex by
/// construction; see the module comment for which to ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alphabet {
    /// `Kb1-` and 24 base64url characters. 144 bits, and the form
    /// `kerbridge-sync` writes: every service account it has created binds with
    /// one, so the shape is compatibility rather than taste.
    Base64Url,
    /// `Kb1` and 32 characters of `A-Za-z0-9`. ~190 bits, and nothing in it that
    /// a person retyping it can mistake for punctuation.
    Alphanumeric,
}

/// A password the realm will accept, every time.
pub fn generate(alphabet: Alphabet) -> String {
    match alphabet {
        // 18 bytes rather than 24: base64 of 18 is 24 characters with no
        // padding, so nothing has to be trimmed and no `=` reaches a config file.
        Alphabet::Base64Url => {
            let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(entropy::<18>());
            format!("{COMPLEXITY}-{body}")
        }
        Alphabet::Alphanumeric => format!("{COMPLEXITY}{}", alphanumeric(32)),
    }
}

const ALNUM: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// `n` characters of `A-Za-z0-9`, uniformly.
///
/// A byte is 256 values and the alphabet is 62, so a bare `% 62` would make the
/// first eight letters slightly likelier than the rest. The bias is far too
/// small to matter here and is removed anyway, because "too small to matter" is
/// an argument nobody can check later: bytes at or above 248 are dropped, which
/// leaves exactly four whole cycles of the alphabet. The discard cannot fail:
/// it drops a *byte*, not a password, and simply draws more.
fn alphanumeric(n: usize) -> String {
    let mut out = String::with_capacity(n);
    while out.len() < n {
        for byte in entropy::<64>() {
            if byte < 248 {
                out.push(ALNUM[usize::from(byte) % ALNUM.len()] as char);
                if out.len() == n {
                    break;
                }
            }
        }
    }
    out
}

/// The `getrandom(2)` syscall through `ring`, never a `/dev/urandom` read: it is
/// musl-safe and it is the same OS RNG the broker draws nonces from. A failure
/// is a broken host, and a guessable password is never an acceptable fallback,
/// so this panics rather than degrading.
fn entropy<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    ring::rand::SystemRandom::new().fill(&mut buf).expect("system RNG");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classes(password: &str) -> (bool, bool, bool) {
        (
            password.chars().any(|c| c.is_ascii_uppercase()),
            password.chars().any(|c| c.is_ascii_lowercase()),
            password.chars().any(|c| c.is_ascii_digit()),
        )
    }

    /// The property the whole module exists for, asserted over enough draws that
    /// the one-in-270 measured in the module comment would show: at 3000 draws a
    /// live rejection hazard fails this about eleven times over, and construction
    /// cannot fail it once.
    #[test]
    fn every_draw_meets_sambas_complexity_rule_by_construction() {
        for alphabet in [Alphabet::Base64Url, Alphabet::Alphanumeric] {
            for _ in 0..3000 {
                let password = generate(alphabet);
                assert_eq!(classes(&password), (true, true, true), "{alphabet:?}: {password}");
            }
        }
    }

    /// `kerbridge-sync` writes this exact shape, and every service account it
    /// has created binds with one. The length and the separator are the
    /// compatibility, not just the prefix.
    #[test]
    fn the_base64url_form_is_the_one_sync_already_writes() {
        let password = generate(Alphabet::Base64Url);
        assert!(password.starts_with("Kb1-"), "{password}");
        assert_eq!(password.len(), 4 + 24, "{password}");
        assert!(
            password[4..].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "{password}"
        );
    }

    /// The point of the second alphabet: nothing in it that a person retyping it
    /// off a screen can mistake for punctuation.
    #[test]
    fn the_alphanumeric_form_carries_no_punctuation() {
        let password = generate(Alphabet::Alphanumeric);
        assert_eq!(password.len(), 3 + 32, "{password}");
        assert!(password.bytes().all(|b| b.is_ascii_alphanumeric()), "{password}");
    }

    /// A generator that returned a constant would pass every test above.
    #[test]
    fn two_draws_differ() {
        assert_ne!(generate(Alphabet::Base64Url), generate(Alphabet::Base64Url));
        assert_ne!(generate(Alphabet::Alphanumeric), generate(Alphabet::Alphanumeric));
    }

    /// Every character of the alphabet is reachable, and no character outside it
    /// is. A `% 62` written against the wrong length, or a bound that dropped a
    /// whole cycle, would leave a hole this finds.
    #[test]
    fn the_alphanumeric_draw_covers_its_whole_alphabet() {
        let drawn: std::collections::BTreeSet<char> = alphanumeric(20_000).chars().collect();
        let alphabet: std::collections::BTreeSet<char> = ALNUM.iter().map(|&b| b as char).collect();
        assert_eq!(drawn, alphabet);
    }
}
