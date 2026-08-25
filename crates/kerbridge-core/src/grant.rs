//! The device-grant value, and every rule the workspace shares about it.
//!
//! A device grant is one `extensionName` value on a synchronized user, saying
//! that a key this machine holds may stand in for a browser sign-in until a
//! stamped time. Four programs touch it -- `issuerd` writes it, the broker
//! authenticates against it, `kbmanage` displays and deletes it, sync deletes it
//! at retirement -- so the encoding lives here for the reason
//! [`crate::ExternalIdentity`] does: a private copy on each side is a divergence
//! waiting to happen, and a disagreement here either denies every granted login
//! or admits one it should not.
//!
//! ```text
//! kbkey1|label=<escaped>|es256=<base64url-sha256>|start=<epoch>|end=<epoch>|seen=<epoch>
//! ```
//!
//! The payload is `key=value` rather than positional so a field can be added
//! without a version bump, a migration or a dual-write. Fields split on their
//! **first** `=`, so `=` inside a value needs no escaping; only `%` and `|` are
//! escaped, identical to the `kb1|` rule.
//!
//! **Exactly one recognized algorithm key** must be present, and the key *name*
//! is the algorithm while its value is the thumbprint. A future `mldsa44=` is
//! simply unparseable to an older reader, which then finds no key material and
//! rejects the whole value -- algorithm agility that fails closed by
//! construction.
//!
//! **Single-writer invariant.** Only `issuerd` ever *emits* one of these values;
//! sync and `kbmanage` may only delete whole values. One emitter is what makes
//! "unknown keys are ignored" safe -- a second one could parse a value, re-emit
//! it, and silently drop a key it did not understand. Do not add a second
//! emitter.

use std::fmt;

/// Version tag and delimiter, in the `kb1|` / `kbrole1|` / `kbstate1|` family.
pub const GRANT_PREFIX: &str = "kbkey1|";

/// ECDSA P-256 with SHA-256 -- the only algorithm a grant may name today. The
/// thumbprint is base64url-unpadded SHA-256 over the raw uncompressed public
/// point (`0x04 || X || Y`), which is the form both CNG hands out and `ring`
/// verifies against, so no SPKI encoding sits between the two ends.
pub const ALG_ES256: &str = "es256";

/// The algorithm key names a reader recognizes. Anything else makes the value
/// key-less, and a key-less value is refused.
const ALGORITHMS: [&str; 1] = [ALG_ES256];

/// Base64url of a SHA-256 digest, unpadded.
pub const THUMBPRINT_LEN: usize = 43;

/// Escaped label ceiling, in bytes. `extensionName` allows 255 per value and the
/// fixed overhead is ~111, so this leaves room for roughly two more fields
/// without touching the format again.
pub const MAX_LABEL: usize = 96;

/// One device grant, decoded. `label` is held unescaped; [`Self::encode`] does
/// the escaping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceGrant {
    pub label: String,
    /// One of [`ALGORITHMS`], borrowed from it rather than from the input, so a
    /// decoded grant can only ever name an algorithm this build knows.
    pub alg: &'static str,
    pub thumbprint: String,
    pub start: u64,
    pub end: u64,
    /// Last use, at day granularity -- see [`needs_touch`]. Absent until the
    /// grant has been used.
    pub seen: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum GrantError {
    /// Not a `kbkey1|` value at all. Every other `extensionName` value on the
    /// object reads as this, so callers filter on it rather than log it.
    NotAGrant,
    /// A field with no `=` in it.
    NotAField,
    /// The same key twice. Which of the two was meant is undefined, so neither.
    Duplicate,
    /// Zero or more than one recognized algorithm key.
    Algorithms(usize),
    Missing(&'static str),
    BadValue(&'static str),
    BadEscape,
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAGrant => write!(f, "not a {GRANT_PREFIX} value"),
            Self::NotAField => write!(f, "a field carries no key"),
            Self::Duplicate => write!(f, "duplicate key"),
            Self::Algorithms(0) => write!(f, "no recognized algorithm key"),
            Self::Algorithms(n) => write!(f, "{n} algorithm keys"),
            Self::Missing(k) => write!(f, "missing {k}"),
            Self::BadValue(k) => write!(f, "unusable {k}"),
            Self::BadEscape => write!(f, "malformed percent escape"),
        }
    }
}

impl std::error::Error for GrantError {}

impl DeviceGrant {
    /// Fields in fixed order -- label, key, start, end, seen -- so stored values
    /// stay diffable. Parsing is order-free.
    ///
    /// Label first because it is what an operator sees in a truncated ADUC
    /// column. That puts client-chosen data immediately after the prefix, which
    /// is exactly why escaping `|` is necessary rather than cosmetic: without
    /// it a label could forge `|end=`.
    pub fn encode(&self) -> String {
        let mut out = format!(
            "{GRANT_PREFIX}label={}|{}={}|start={}|end={}",
            crate::escape_field(&self.label),
            self.alg,
            self.thumbprint,
            self.start,
            self.end
        );
        if let Some(seen) = self.seen {
            out.push_str(&format!("|seen={seen}"));
        }
        out
    }

    /// Parse a stored value. Anything malformed is an error rather than a
    /// partially-trusted grant: nothing may ever authenticate on a record it had
    /// to guess at.
    pub fn decode(value: &str) -> Result<Self, GrantError> {
        let payload = value.strip_prefix(GRANT_PREFIX).ok_or(GrantError::NotAGrant)?;

        let mut label = None;
        let mut alg: Option<(&'static str, String)> = None;
        let mut start = None;
        let mut end = None;
        let mut seen = None;
        let mut keys: Vec<&str> = Vec::new();

        for field in payload.split('|') {
            let (key, raw) = field.split_once('=').ok_or(GrantError::NotAField)?;
            if keys.contains(&key) {
                return Err(GrantError::Duplicate);
            }
            keys.push(key);

            if let Some(known) = algorithm(key) {
                // Unreachable while [`ALGORITHMS`] holds one entry -- two
                // spellings of the same key are [`GrantError::Duplicate`]
                // instead -- and here so that the day it grows, two key names
                // this build can both verify is a refusal rather than a silent
                // choice of whichever came first.
                if alg.is_some() {
                    return Err(GrantError::Algorithms(2));
                }
                if !is_thumbprint(raw) {
                    return Err(GrantError::BadValue("thumbprint"));
                }
                alg = Some((known, raw.to_owned()));
                continue;
            }
            match key {
                "label" => {
                    let text = crate::unescape_field(raw).map_err(|_| GrantError::BadEscape)?;
                    if text.chars().any(char::is_control) {
                        return Err(GrantError::BadValue("label"));
                    }
                    label = Some(text);
                }
                "start" => start = Some(epoch(raw, "start")?),
                "end" => end = Some(epoch(raw, "end")?),
                "seen" => seen = Some(epoch(raw, "seen")?),
                // Unknown keys are ignored, which is what makes the format
                // extensible in one direction. Safe only because there is one
                // emitter -- see the module note.
                _ => {}
            }
        }

        let (alg, thumbprint) = alg.ok_or(GrantError::Algorithms(0))?;
        Ok(Self {
            label: label.unwrap_or_default(),
            alg,
            thumbprint,
            start: start.ok_or(GrantError::Missing("start"))?,
            end: end.ok_or(GrantError::Missing("end"))?,
            seen,
        })
    }

    /// When this grant actually stops working, which is not always what `end=`
    /// says.
    ///
    /// Lowering `configs/main.toml` `device_grant_days` clamps every outstanding grant, so the
    /// knob means what an operator thinks it means: setting it to 0 stops every
    /// device at its next exchange. `min` gives the right asymmetry for free --
    /// lowering bites immediately, raising does not retroactively stretch a
    /// grant the user authorized for 30 days into a 90-day one.
    pub fn effective_end(&self, grant_days: u32) -> u64 {
        self.end.min(self.start.saturating_add(u64::from(grant_days) * 86_400))
    }

    /// Has the operator's knob moved this grant's deadline in below what was
    /// stamped? Worth a column in `kbmanage device list`: it is the switch
    /// visibly biting.
    pub fn clamped(&self, grant_days: u32) -> bool {
        self.effective_end(grant_days) < self.end
    }

    pub fn valid_at(&self, now: u64, grant_days: u32) -> bool {
        now < self.effective_end(grant_days)
    }

    /// The operator's handle for this device: the first four bytes of the
    /// thumbprint, in hex. Short enough to read off a screen and type back into
    /// `kbmanage device revoke`, and unlike the label it is not client-chosen --
    /// two devices claiming one name would otherwise revoke the wrong one.
    pub fn short_id(&self) -> String {
        short_id(&self.thumbprint).unwrap_or_default()
    }
}

/// The [`DeviceGrant::short_id`] derivation, over a bare thumbprint -- what a
/// caller holding an operator-typed id compares against.
pub fn short_id(thumbprint: &str) -> Option<String> {
    let b = thumbprint.as_bytes();
    if b.len() < 6 {
        return None;
    }
    let mut acc: u64 = 0;
    for &c in &b[..6] {
        acc = (acc << 6) | u64::from(b64url_value(c)?);
    }
    // Six base64url characters carry 36 bits; the leading 32 are the digest's
    // first four bytes and the remaining 4 belong to the fifth.
    Some(format!("{:08x}", (acc >> 4) as u32))
}

fn b64url_value(c: u8) -> Option<u32> {
    Some(match c {
        b'A'..=b'Z' => u32::from(c - b'A'),
        b'a'..=b'z' => u32::from(c - b'a') + 26,
        b'0'..=b'9' => u32::from(c - b'0') + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    })
}

/// Exactly a base64url-unpadded SHA-256 digest, and nothing else. The value
/// reaches an LDIF and a comparison, so a permissive check here would be both.
pub fn is_thumbprint(s: &str) -> bool {
    s.len() == THUMBPRINT_LEN && s.bytes().all(|c| b64url_value(c).is_some())
}

/// This build's own spelling of an algorithm name, or `None` if it cannot verify
/// one. Returning the static rather than a bool is what keeps a caller from
/// storing the string it was handed: a [`DeviceGrant`] can only ever name an
/// algorithm that is in [`ALGORITHMS`].
pub fn algorithm(s: &str) -> Option<&'static str> {
    ALGORITHMS.iter().copied().find(|a| *a == s)
}

/// A client-supplied label, reduced to something safe to store and to print.
///
/// The tray supplies it, so anything running as that user supplies whatever it
/// likes. Control characters go -- a label carrying ANSI escapes rendered into a
/// `kbmanage` table is a real, small hole -- and the result is clamped so its
/// *escaped* form fits [`MAX_LABEL`] bytes, truncated on a whole character so no
/// escape sequence is ever cut in half. The `|` escaping that stops a label from
/// forging `|end=` is [`DeviceGrant::encode`]'s job, not this one's.
pub fn sanitize_label(raw: &str) -> String {
    let mut out = String::new();
    let mut escaped = 0usize;
    for c in raw.chars() {
        if c.is_control() {
            continue;
        }
        let cost = match c {
            '%' | '|' => 3,
            _ => c.len_utf8(),
        };
        if escaped + cost > MAX_LABEL {
            break;
        }
        escaped += cost;
        out.push(c);
    }
    out
}

/// Should this exchange write a new `seen` stamp?
///
/// `seen` answers one question -- is this device dead wood -- so it is kept at day
/// granularity and never finer. Writing on a UTC day change makes the displayed
/// day exact; the 12 h fallback bounds how long a device that only ever runs
/// mid-afternoon can go unstamped. Roughly one write per device per day, and its
/// failure is ignored: it is a display stamp, not data.
pub fn needs_touch(seen: Option<u64>, now: u64) -> bool {
    match seen {
        None => true,
        Some(seen) => now / 86_400 != seen / 86_400 || now.saturating_sub(seen) >= 12 * 3_600,
    }
}

/// Whole days since a grant was last used, or `None` if it never has been. A
/// stamp in the future reads as today rather than as negative days.
pub fn seen_days_ago(seen: Option<u64>, now: u64) -> Option<u64> {
    Some(now.saturating_sub(seen?) / 86_400)
}

fn epoch(raw: &str, key: &'static str) -> Result<u64, GrantError> {
    raw.parse().map_err(|_| GrantError::BadValue(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TP: &str = "GsNH2NUyRXY46_dTvTB1SIf7hkZ8LYlOKPT-ODdVUgo";

    fn sample() -> DeviceGrant {
        DeviceGrant {
            label: "BUILD01\\svc-builder".into(),
            alg: ALG_ES256,
            thumbprint: TP.into(),
            start: 1_785_000_000,
            end: 1_787_592_000,
            seen: None,
        }
    }

    #[test]
    fn encodes_the_documented_shape() {
        assert_eq!(
            sample().encode(),
            format!("kbkey1|label=BUILD01\\svc-builder|es256={TP}|start=1785000000|end=1787592000")
        );
        let used = DeviceGrant { seen: Some(1_785_086_400), ..sample() };
        assert!(used.encode().ends_with("|seen=1785086400"));
        // The whole point of the length budget: a full-width label still fits
        // the 255 bytes `extensionName` allows per value.
        let wide = DeviceGrant { label: "x".repeat(MAX_LABEL), ..used };
        assert!(wide.encode().len() <= 255, "{} bytes", wide.encode().len());
    }

    #[test]
    fn round_trips() {
        for g in [sample(), DeviceGrant { seen: Some(1_785_086_400), ..sample() }] {
            assert_eq!(DeviceGrant::decode(&g.encode()), Ok(g));
        }
    }

    /// Without escaping, a label could close its own field and forge the
    /// deadline that bounds it. The label is the one client-chosen part of the
    /// value and it sits first, so this is the escaping's whole job.
    #[test]
    fn a_label_cannot_forge_a_later_deadline() {
        let g = DeviceGrant { label: "evil|end=9999999999".into(), ..sample() };
        let encoded = g.encode();
        assert!(!encoded.contains("evil|end="), "{encoded}");
        let back = DeviceGrant::decode(&encoded).unwrap();
        assert_eq!(back.end, 1_787_592_000);
        assert_eq!(back.label, "evil|end=9999999999");
        // Only `%` and `|`; `=` inside a value needs no escaping because fields
        // split on the first one.
        let g = DeviceGrant { label: "a=b 100% c".into(), ..sample() };
        assert_eq!(DeviceGrant::decode(&g.encode()).unwrap().label, "a=b 100% c");
    }

    #[test]
    fn a_field_can_be_added_without_a_version_bump() {
        // An older reader meeting a key it does not know must still
        // authenticate the grant, or adding a field would be a flag day.
        let value = format!("kbkey1|label=x|es256={TP}|start=1|end=2|nextfield=whatever");
        assert_eq!(DeviceGrant::decode(&value).unwrap().end, 2);
    }

    /// A future algorithm makes the value key-less rather than differently-keyed,
    /// so an older broker refuses it instead of accepting a signature it cannot
    /// check.
    #[test]
    fn algorithm_agility_fails_closed() {
        let future = format!("kbkey1|label=x|mldsa44={TP}|start=1|end=2");
        assert_eq!(DeviceGrant::decode(&future), Err(GrantError::Algorithms(0)));
        // Alongside a key it does know, the unrecognized one is just another
        // unknown key: the grant still verifies, under the algorithm this build
        // can actually check.
        let both = format!("kbkey1|label=x|es256={TP}|mldsa44=zz|start=1|end=2");
        assert_eq!(DeviceGrant::decode(&both).unwrap().alg, ALG_ES256);
    }

    #[test]
    fn refuses_anything_it_would_have_to_guess_at() {
        use GrantError::*;
        let ok = format!("kbkey1|label=x|es256={TP}|start=1|end=2");
        assert!(DeviceGrant::decode(&ok).is_ok());
        assert_eq!(DeviceGrant::decode("kbrole1|realm-admission"), Err(NotAGrant));
        assert_eq!(DeviceGrant::decode(&ok.replace("|start=1", "")), Err(Missing("start")));
        assert_eq!(DeviceGrant::decode(&ok.replace("|end=2", "")), Err(Missing("end")));
        assert_eq!(DeviceGrant::decode(&format!("{ok}|end=3")), Err(Duplicate));
        assert_eq!(DeviceGrant::decode(&ok.replace("end=2", "end=soon")), Err(BadValue("end")));
        assert_eq!(DeviceGrant::decode(&format!("{ok}|orphan")), Err(NotAField));
        assert_eq!(DeviceGrant::decode("kbkey1|"), Err(NotAField));
        // A truncated or over-long thumbprint can never match, but it is refused
        // rather than carried, so nothing downstream compares against junk.
        assert_eq!(DeviceGrant::decode(&ok.replace(TP, &TP[..42])), Err(BadValue("thumbprint")));
        assert_eq!(
            DeviceGrant::decode(&ok.replace(TP, &format!("{}+", &TP[..42]))),
            Err(BadValue("thumbprint"))
        );
        assert_eq!(DeviceGrant::decode(&ok.replace("label=x", "label=%ZZ")), Err(BadEscape));
        assert_eq!(
            DeviceGrant::decode(&ok.replace("label=x", "label=a\u{7}b")),
            Err(BadValue("label"))
        );
    }

    /// Lowering the knob has to bite outstanding grants, or "I disabled it and
    /// it stayed on" lands during an incident. Raising it must not stretch one.
    #[test]
    fn the_duration_knob_clamps_both_ways() {
        // Stamped for 30 days.
        let g = DeviceGrant { start: 1_000_000, end: 1_000_000 + 30 * 86_400, ..sample() };
        assert_eq!(g.effective_end(30), g.end);
        assert!(!g.clamped(30));
        assert_eq!(g.effective_end(90), g.end, "raising must not stretch it");
        assert_eq!(g.effective_end(7), 1_000_000 + 7 * 86_400);
        assert!(g.clamped(7));
        assert_eq!(g.effective_end(0), g.start);
        assert!(!g.valid_at(g.start, 0), "0 stops every device at its next exchange");
        assert!(g.valid_at(g.start + 6 * 86_400, 7));
        assert!(!g.valid_at(g.start + 8 * 86_400, 7));
    }

    /// The stamp is what makes the displayed day exact; the elapsed rule is what
    /// bounds a device that only ever runs at the same hour.
    #[test]
    fn seen_is_stamped_once_a_day_and_read_in_whole_days() {
        const DAY: u64 = 86_400;
        // 2026-07-25T12:00:00Z, midday so neither rule sits on a boundary.
        let noon = 1_784_980_800;
        assert!(needs_touch(None, noon), "a grant that has never been used");
        assert!(!needs_touch(Some(noon), noon + 3_600));
        assert!(needs_touch(Some(noon), noon + 12 * 3_600), "12 h elapsed");
        assert!(needs_touch(Some(noon), noon + 13 * 3_600), "and the day rolled over");
        // Same instant either side of midnight: the day rule fires where a pure
        // elapsed-time rule would let an active device display "1 day ago".
        assert!(needs_touch(Some(noon + 11 * 3_600), noon + 13 * 3_600));

        assert_eq!(seen_days_ago(None, noon), None);
        assert_eq!(seen_days_ago(Some(noon), noon), Some(0));
        assert_eq!(seen_days_ago(Some(noon), noon + DAY - 1), Some(0));
        assert_eq!(seen_days_ago(Some(noon), noon + 3 * DAY), Some(3));
        assert_eq!(
            seen_days_ago(Some(noon + DAY), noon),
            Some(0),
            "a future stamp is not negative"
        );
    }

    #[test]
    fn a_short_id_is_the_leading_four_digest_bytes_in_hex() {
        // "AAAA" is 24 zero bits, so the first four bytes are zero.
        assert_eq!(short_id("AAAAAA").unwrap(), "00000000");
        assert_eq!(short_id("____________").unwrap(), "ffffffff");
        let id = sample().short_id();
        assert_eq!(id.len(), 8);
        assert!(id.bytes().all(|c| c.is_ascii_hexdigit()), "{id}");
        // Distinct thumbprints give distinct handles at this width in practice;
        // what matters is that the handle is a function of the key and not of
        // the client-chosen label.
        assert_eq!(DeviceGrant { label: "other".into(), ..sample() }.short_id(), id);
        assert_eq!(short_id("short"), None);
        assert_eq!(short_id("not+b64url"), None);
    }

    /// Both label components are already bounded by Windows (NetBIOS 15, local
    /// account 20), so the ceiling is only reachable with non-ASCII, where
    /// escaping can triple a character.
    #[test]
    fn a_label_is_clamped_on_a_character_boundary() {
        assert_eq!(sanitize_label("BUILD01\\svc-builder"), "BUILD01\\svc-builder");
        assert_eq!(sanitize_label("BUILD01\r\n (revoked)\u{1b}[31m"), "BUILD01 (revoked)[31m");
        let long = sanitize_label(&"ä".repeat(200));
        // Two bytes each, so 48 fit and the 49th would overrun.
        assert_eq!(long.chars().count(), 48);
        assert!(DeviceGrant { label: long, ..sample() }.encode().len() <= 255);
        // Escaping triples these, so 32 fit -- and the escaped form lands exactly
        // on the ceiling rather than a byte over it with a `%7` left dangling.
        let pipes = sanitize_label(&"|".repeat(200));
        assert_eq!(pipes.chars().count(), 32);
        let g = DeviceGrant { label: pipes.clone(), ..sample() };
        assert_eq!(crate::escape_field(&pipes).len(), MAX_LABEL);
        assert_eq!(DeviceGrant::decode(&g.encode()).unwrap().label, pipes);
    }
}
