//! What a `sAMAccountName` may be.
//!
//! Two components decide this and they must decide it identically: `sync`
//! *derives* the name and `issuerd` *validates* the one it reads back. They had
//! separate copies of the rule and the copies disagreed -- sync's filter is
//! Unicode-aware, issuerd's was ASCII-only -- so a user with a non-ASCII name
//! synchronized cleanly, looked healthy in the directory, and could never
//! obtain a ticket. Nothing logged a warning until the first sign-in, which
//! failed with `account not eligible`. Measured 2026-07-29; see
//! research spike `unicode-name`.
//!
//! [`sanitize`] and [`validate`] are therefore one rule with two entry points,
//! and the invariant tying them together is that **`sanitize`'s output always
//! satisfies `validate`**. There is a test for exactly that.
//!
//! Nothing below the project constrains this. Samba stores whatever bytes it is
//! given, enforces no length limit of its own, and `kinit` treats the principal
//! as opaque bytes; Windows accepts a non-ASCII client principal, renders it,
//! and its SMB redirector uses it. Every limit here is ours, chosen to keep the
//! name safe to hand to a command line and to an LDAP filter.
//!
//! ## Normalization is the caller's job, and it is not optional
//!
//! Unicode can spell the same name two ways: `å` is either `U+00E5` or `a` +
//! `U+030A`. They render identically and are different bytes, so they are
//! different principals, and a directory holding both holds two accounts no
//! human can tell apart.
//!
//! [`validate`] refuses the decomposed form, and does so for free: Unicode's
//! `Alphabetic` property covers the combining marks that Indic, Thai, Arabic
//! and Hebrew names genuinely need -- `is_alphanumeric` accepts `U+093E`,
//! `U+0E34`, `U+064B`, `U+05B0` -- but *not* the Latin combining diacriticals in
//! `U+0300..=U+036F`, which NFC composes away anyway. So a name that has been
//! NFC-normalized passes, and a decomposed Latin one is refused with a legible
//! message instead of silently becoming a second account.
//!
//! Callers that derive a name must normalize to NFC first. That needs Unicode
//! tables, so it cannot happen here: `issuerd` links this crate and holds KDC
//! authority, and `lib.rs`'s rule is that nothing here may widen its dependency
//! surface. `sync`, which is the only writer and already carries heavy
//! dependencies, owns the normalization.

use std::fmt;

/// Longest a `sAMAccountName` may be, in **bytes**.
///
/// Bytes rather than characters because the ceiling exists to bound what is
/// handed to a subprocess, and because a character budget alone silently
/// disagrees with a byte one: 20 characters of 4-byte UTF-8 is 80 bytes. AD's
/// documented 20-*character* user limit is an NT4-compatibility convention that
/// Samba does not apply -- measured -- and a real Windows DC is out of scope for
/// KerBridge, so it is not what this defends.
pub const MAX_BYTES: usize = 64;

/// Why a `sAMAccountName` was refused. Carries the offending value so the
/// operator is told which character and which code point, rather than being
/// left to guess at a name that may be visually indistinguishable from a valid
/// one.
#[derive(Debug, PartialEq, Eq)]
pub enum Rejected {
    Empty,
    TooLong(usize),
    LeadingDash,
    Character(char),
}

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "is empty"),
            Self::TooLong(n) => write!(f, "is {n} bytes, over the {MAX_BYTES}-byte limit"),
            Self::LeadingDash => write!(f, "starts with '-'"),
            // The NFC hint only when the character is actually a combining
            // mark. Appended to every rejection, it sends someone who typed a
            // space off to normalize a name that is already composed.
            Self::Character(c) => {
                write!(
                    f,
                    "holds {c:?} (U+{:04X}), which is outside the allowed set \
                     (letters, digits, '.', '-', '_')",
                    *c as u32
                )?;
                if is_combining_mark(*c) {
                    write!(
                        f,
                        "; that is a combining mark, so the name is decomposed and needs NFC normalization"
                    )?;
                }
                Ok(())
            }
        }
    }
}

/// Whether `c` is a combining mark -- well enough to decide whether the NFC hint
/// is worth offering.
///
/// A range check rather than a Unicode property lookup, because this crate
/// carries no Unicode tables by design: `issuerd` links it and holds KDC
/// authority, so nothing here may widen its dependency surface. A hint that is
/// occasionally silent costs less than that.
///
/// These are the blocks that can reach this message at all -- marks Unicode does
/// not count as alphabetic. The marks Indic, Thai, Arabic and Hebrew names need
/// carry `Other_Alphabetic`, so [`allowed`] accepts them and they never arrive
/// here as a rejection.
fn is_combining_mark(c: char) -> bool {
    matches!(c as u32,
        0x0300..=0x036F     // Combining Diacritical Marks -- what macOS NFD emits
        | 0x0483..=0x0489   // Cyrillic
        | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20F0 | 0xFE20..=0xFE2F)
}

/// The character rule, and the only place it is written down.
///
/// An allowlist, because that is what keeps out the metacharacters of the four
/// languages this value reaches without having to enumerate them: `@` and `/`
/// separate Kerberos principal components, `*()\` are LDAP filter syntax,
/// `,+"<>;=` are DN syntax, and AD's own restricted set is a subset of those
/// plus `[]:|?`. A denylist would have to stay in step with all four.
pub fn allowed(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '-' | '_')
}

/// Whether a name read out of the directory may be used.
///
/// The leading-`-` check is not redundant with `issuerd` passing `--` to
/// `kinit`: that one is structural, this one is readable, and a directory write
/// is the untrusted input in both cases.
pub fn validate(sam: &str) -> Result<(), Rejected> {
    if sam.is_empty() {
        return Err(Rejected::Empty);
    }
    if sam.len() > MAX_BYTES {
        return Err(Rejected::TooLong(sam.len()));
    }
    if sam.starts_with('-') {
        return Err(Rejected::LeadingDash);
    }
    match sam.chars().find(|c| !allowed(*c)) {
        Some(c) => Err(Rejected::Character(c)),
        None => Ok(()),
    }
}

/// The comparison key for a `sAMAccountName`, and the only place *that* rule is
/// written down.
///
/// AD's account-name namespace is unique **case-insensitively** -- measured
/// 2026-07-29 against Samba 4.22.10, which refuses a case-only collision twice
/// over: once on the RDN and again, independently, in `samldb`
/// (`sAMAccountName 'ZZ-CASECHECK' already in use!`). Rust `String` equality is
/// case-*sensitive*, so any collision check written with `==` or a plain
/// `HashSet<String>` disagrees with the directory it is trying to predict.
///
/// The consequence of getting this wrong is silent and permanent rather than
/// noisy: two names differing only in case pass the planner's collision gate,
/// both are planned, AD accepts the first and refuses the second, and the
/// failure is recorded and stepped over -- every cycle, forever.
///
/// Fold the **key**, never the value: the name written to the directory has to
/// stay as the operator spelled it, because a group name is what they typed and
/// what a resource ACL displays. Use this for set membership and equality only.
///
/// [`str::to_lowercase`] for the same reason [`sanitize`] uses it -- the two must
/// agree, or a name `sanitize` derives and a name `fold` looks up differ.
pub fn fold(sam: &str) -> String {
    sam.to_lowercase()
}

/// The name [`sanitize`] derives when nothing of the source survives it.
///
/// Public because a caller choosing between several source attributes has to
/// tell "this one yielded a real name" from "this one yielded nothing", and
/// cannot do it by inspecting the source: `...` is three [`allowed`] characters
/// and no name, because the trim takes them all.
pub const FALLBACK: &str = "kbuser";

/// Fold an arbitrary source string into a name [`validate`] will accept:
/// lowercase, keep only allowed characters, cap at `max_chars` *and*
/// `max_bytes`, trim separators off both ends, and never yield an empty name --
/// [`FALLBACK`] when nothing is left.
///
/// **NFC-normalize `source` first** -- see the module note.
///
/// Lowercasing is [`str::to_lowercase`], not `to_ascii_lowercase`: AD compares
/// a `sAMAccountName` case-insensitively while Kerberos principals are
/// case-sensitive, so a name that is only sometimes lowered is a name that
/// sometimes fails to match. `to_ascii_lowercase` leaves `Åsa.Ångström`
/// half-folded.
pub fn sanitize(source: &str, max_chars: usize, max_bytes: usize) -> String {
    let mut out = String::new();
    let mut chars = 0;
    // `char::to_lowercase` can expand (`İ` -> `i` + `U+0307`), and an expansion
    // that produces a combining mark is dropped by `allowed` -- which is what we
    // want, since that mark is exactly the decomposed form the rule refuses.
    for c in source.chars().flat_map(char::to_lowercase) {
        if !allowed(c) {
            continue;
        }
        if chars >= max_chars || out.len() + c.len_utf8() > max_bytes {
            break;
        }
        out.push(c);
        chars += 1;
    }
    // Leading `-` would be derived here and refused by `validate`, which is the
    // class of disagreement this module exists to remove.
    let trimmed = out.trim_start_matches('-').trim_end_matches(['.', '-']);
    if trimmed.is_empty() { FALLBACK.to_owned() } else { trimmed.to_owned() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The NFC hint is advice for one specific mistake, so it has to be absent
    /// from every other rejection. Told that a space "is decomposed and needs
    /// NFC normalization", an operator goes and looks for a problem they do not
    /// have.
    #[test]
    fn the_nfc_hint_appears_only_for_a_combining_mark() {
        let why = |s: &str| validate(s).unwrap_err().to_string();

        let decomposed = why("a\u{30a}sa");
        assert!(decomposed.contains("U+030A"), "{decomposed}");
        assert!(decomposed.contains("NFC"), "a real combining mark earns the hint: {decomposed}");

        for ordinary in ["bob bobson", "bob@example", "bob/bobson", "bob:bobson"] {
            let m = why(ordinary);
            assert!(!m.contains("NFC"), "{ordinary:?} is not a normalization problem: {m}");
            assert!(m.contains("outside the allowed set"), "{m}");
        }
    }

    /// The invariant the two callers depend on. Its absence is the bug this
    /// module was written for: sync derived names issuerd then refused.
    #[test]
    fn everything_sanitize_produces_is_something_validate_accepts() {
        let nasty = [
            "Alice.Anderson",
            "-leading-dash",
            "--",
            "!!!",
            "",
            "  spaces  ",
            "Åsa Ångström",     // cased non-ASCII
            "иван.петров",      // Cyrillic
            "山田.太郎",        // CJK, 3-byte
            "민준 박",          // Hangul
            "देवनागरी",          // Devanagari, needs its combining marks
            "a\u{30a}sa",       // decomposed Latin: the marks must be dropped
            "user@example.com", // Kerberos + LDAP metacharacters
            "cn=x,dc=y",
            "wild*card()",
            &"ä".repeat(40), // 80 bytes of 2-byte characters
            &"𝕏".repeat(30), // 4-byte characters
        ];
        for s in nasty {
            let got = sanitize(s, 20, MAX_BYTES);
            assert!(validate(&got).is_ok(), "sanitize({s:?}) = {got:?}, which validate rejects");
        }
    }

    /// `sanitize` and `fold` have to agree, or a name one derives is a name the
    /// other fails to find: a derived name is already its own key.
    #[test]
    fn a_sanitized_name_is_already_folded() {
        for s in ["Alice.Anderson", "Åsa Ångström", "Иван Петров", "İstanbul", "山田.太郎"]
        {
            let derived = sanitize(s, 20, MAX_BYTES);
            assert_eq!(fold(&derived), derived, "sanitize({s:?}) = {derived:?} is not its own key");
        }
    }

    /// Group sams skip `sanitize` -- they are the display name verbatim -- so this
    /// is the only thing standing between `Sales`/`sales` and a silent, permanent
    /// half-sync.
    #[test]
    fn case_only_variants_share_one_key() {
        for (a, b) in [("Sales", "sales"), ("SALES", "sAlEs"), ("Åsa", "åsa"), ("ИВАН", "иван")]
        {
            assert_eq!(fold(a), fold(b), "{a:?} and {b:?} must be one key");
        }
        assert_ne!(fold("sales"), fold("sales1"));
    }

    #[test]
    fn ascii_behavior_is_unchanged() {
        assert_eq!(sanitize("Alice.Anderson", 20, MAX_BYTES), "alice.anderson");
        assert_eq!(sanitize("a b c!!!", 20, MAX_BYTES), "abc");
        assert_eq!(sanitize("trailing--", 20, MAX_BYTES), "trailing");
        assert_eq!(sanitize("!!!", 20, MAX_BYTES), "kbuser");
        assert_eq!(sanitize("abcdefghij", 4, MAX_BYTES), "abcd");
    }

    #[test]
    fn non_ascii_names_survive_derivation_and_validation() {
        for (source, want) in
            [("Иван Петров", "иванпетров"), ("山田.太郎", "山田.太郎"), ("민준.박", "민준.박")]
        {
            let got = sanitize(source, 20, MAX_BYTES);
            assert_eq!(got, want);
            assert!(validate(&got).is_ok());
        }
    }

    /// The whole point of lowercasing with Unicode rather than ASCII.
    #[test]
    fn cased_non_ascii_is_folded_not_half_folded() {
        let got = sanitize("Åsa Ångström", 20, MAX_BYTES);
        assert_eq!(got, "åsaångström");
        assert!(got.chars().all(|c| !c.is_uppercase()));
    }

    /// Marks that NFC does not compose are required for these scripts and
    /// must survive; the Latin ones NFC does compose must not.
    #[test]
    fn marks_real_scripts_need_are_allowed_and_latin_decomposition_is_not() {
        for c in ['\u{093E}', '\u{0E34}', '\u{064B}', '\u{05B0}'] {
            assert!(allowed(c), "U+{:04X} should be allowed", c as u32);
        }
        for c in ['\u{030A}', '\u{0308}'] {
            assert!(!allowed(c), "U+{:04X} should be refused", c as u32);
        }
    }

    /// A decomposed name is refused rather than quietly becoming a second
    /// account that renders identically to the first.
    #[test]
    fn a_decomposed_name_is_refused_with_a_legible_reason() {
        let nfd = "a\u{30a}sa.a\u{30a}ngstro\u{308}m";
        let nfc = "\u{e5}sa.\u{e5}ngstr\u{f6}m";
        assert!(validate(nfc).is_ok());
        assert_eq!(validate(nfd), Err(Rejected::Character('\u{30a}')));
        assert!(validate(nfd).unwrap_err().to_string().contains("U+030A"));
        assert!(validate(nfd).unwrap_err().to_string().contains("NFC"));
    }

    /// The two budgets have to be enforced together: 20 characters of 4-byte
    /// UTF-8 is 80 bytes, which the character cap alone would let through.
    #[test]
    fn the_byte_budget_binds_where_the_character_budget_does_not() {
        let wide = "𝕏".repeat(30); // 4 bytes each
        let got = sanitize(&wide, 20, MAX_BYTES);
        assert!(got.len() <= MAX_BYTES, "{} bytes", got.len());
        assert_eq!(got.chars().count(), 16); // 64 / 4
        assert!(validate(&got).is_ok());

        assert_eq!(validate(&"a".repeat(MAX_BYTES)), Ok(()));
        assert_eq!(validate(&"a".repeat(MAX_BYTES + 1)), Err(Rejected::TooLong(MAX_BYTES + 1)));
        // 33 two-byte characters is 66 bytes: under any character budget, over
        // the byte one.
        assert_eq!(validate(&"ä".repeat(33)), Err(Rejected::TooLong(66)));
    }

    #[test]
    fn names_kinit_would_read_as_options_are_refused() {
        assert_eq!(validate("-k"), Err(Rejected::LeadingDash));
        assert_eq!(validate(""), Err(Rejected::Empty));
        assert_eq!(sanitize("-k", 20, MAX_BYTES), "k");
    }

    #[test]
    fn metacharacters_of_every_language_this_value_reaches_are_refused() {
        for bad in ["a@b", "a/b", "a\\b", "a*b", "a(b", "a)b", "a,b", "a+b", "a=b", "a b", "a\0b"] {
            assert!(validate(bad).is_err(), "accepted {bad:?}");
        }
    }
}
