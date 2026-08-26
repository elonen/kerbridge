//! What every KerBridge component must agree on. Three kinds of thing, in
//! descending order of how loudly a disagreement would fail.
//!
//! **Formats**, which must match byte for byte: the provider-neutral
//! [`ExternalIdentity`] that sync writes into Samba AD and the broker reads
//! back, the directory markers and constants in [`state`], the device-grant
//! value in [`grant`], and the broker-to-`issuerd` wire protocol in [`issuer`].
//! All four components depend on this crate and none keeps a private copy -- a reader and a writer
//! disagreeing here breaks logins silently, with nothing in either program
//! looking wrong.
//!
//! Two shapes, and which one a format takes is decided by how it is consumed,
//! not by taste. **Searched by exact match** -> positional, fixed arity, one
//! canonical encoding: LDAP compares the whole value as one token, so every byte
//! is part of the primary key, and a format admitting two encodings of one
//! identity returns *no* answer rather than a wrong one -- which reads as "user
//! not synchronized". **Parsed after retrieval** -> `key=value`, extensible.
//! [`ExternalIdentity`] and [`state`]'s role markers are the first; [`grant`] is
//! the second. `GLOSSARY.md` holds the table.
//!
//! **Decisions**, which are not wire formats but must still be identical
//! everywhere, because a laxer copy would go on working and looking healthy:
//! [`secret`]'s rule about what permissions a credential file may have,
//! [`tls`]'s about what an LDAPS bind trusts, and [`sam`]'s about what a
//! `sAMAccountName` may be. The checks quietly diverged until one of them had
//! none at all, which is how both got here -- and [`sam`] is here because sync's
//! copy and `issuerd`'s copy did diverge, so a non-ASCII user synchronized
//! cleanly and could never obtain a ticket.
//!
//! **Vocabulary**, which is ordinary shared code and here only because the
//! copies had started to disagree: [`time`] (four transcriptions of the same
//! calendar, two of them differing on what a bad date meant), [`dn`], [`env`],
//! [`is_guid`] and [`password`] (three generators for the accounts of one
//! deployment, satisfying Samba's complexity rule two different ways).
//! [`audit`] is here for the other reason two components must agree: the broker
//! and `issuerd` record the two halves of one grant, and an operator reads them
//! side by side.
//!
//! **Configuration** is here for the first reason rather than the third:
//! [`config`] parses the `main.toml` set that every binary reads, so a ticket
//! ceiling or a device-grant cap cannot mean one thing to the broker and
//! another to `issuerd`.
//!
//! One rule governs what may be added, and it is `DESIGN.md`'s: `issuerd` links
//! this crate and holds KDC authority, so nothing here may widen its dependency
//! surface. Anything needing a dependency goes behind a feature `issuerd` does
//! not enable, as [`tls`] does. There are two unconditional exceptions, and each
//! is an exception to the letter of the rule rather than to what it protects.
//! [`config`]'s `toml` is small and pure Rust, and what `issuerd` buys with it
//! is losing the ability to disagree silently with the broker about a number
//! they share. [`secret`]'s `rustix` -- three calls asking the kernel who this
//! process is, so a denied read can name its own fix -- is the one that does
//! cost `issuerd` a crate, and what the whole crate buys with it is the
//! `forbid(unsafe_code)` below.

#![forbid(unsafe_code)]

pub mod audit;
pub mod config;
pub mod dn;
pub mod grant;
pub mod issuer;
/// Requires the `password` feature; `issuerd` creates no accounts and does not
/// enable it, which is what keeps `ring` out of the one process holding KDC
/// authority.
#[cfg(feature = "password")]
pub mod password;
pub mod problem;
pub mod sam;
pub mod secret;
pub mod source;
pub mod state;
pub mod time;
/// Requires the `tls` feature; `issuerd` speaks no TLS and does not enable it.
#[cfg(feature = "tls")]
pub mod tls;

use std::fmt;

pub use source::Source;

/// The canonical cloud identity, independent of which IdP produced it.
///
/// Two things, because two things are what every consumer uses: which
/// configured [`Source`] owns the object, and which account within it. Needing a
/// tenant *and* an issuer to say the first is an Entra-shaped requirement, not a
/// general one, and the source name replaces both.
///
/// The subject is **adapter-owned and opaque**. Only the IdP module that
/// produced it may construct or interpret it; this crate checks well-formedness
/// and nothing else. An adapter may give it structure if it wants to, but
/// changing that structure later orphans every object in that source, so the
/// choice is made once.
///
/// Mutable attributes -- `preferred_username`, `upn`, email, display name, group
/// names -- are never mapping keys, and there is deliberately no way to carry
/// one here: no extension map, no `#[serde(flatten)]`, no public fields. Every
/// field added to this type becomes a mapping key someone comes to depend on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalIdentity {
    source: Source,
    subject: String,
}

/// Format version tag.
///
/// A version tag exists to tell two stored shapes apart, so it earns its keep
/// only once both exist somewhere. While nothing is deployed, a structural
/// change to the encoding redefines `kb1` in place. Once a realm holds objects,
/// the same change needs a new tag and is a migration rather than an edit.
const VERSION_TAG: &str = "kb1";

/// `kb1`, the source name, the subject.
const FIELD_COUNT: usize = 3;

/// What `msDS-ExternalDirectoryObjectId` holds: `rangeUpper: 256` on a
/// single-valued Unicode string ([MS-ADA2]), counted in characters rather than
/// bytes.
///
/// Enforced at construction rather than trusted, because with an adapter-defined
/// subject this crate can no longer bound the length by reasoning about the
/// content.
pub const MAX_IDENTITY_LEN: usize = 256;

/// Why a value is not an identity -- when parsing one, and when building one,
/// which are the same rules by construction: [`ExternalIdentity::decode`] ends
/// in [`ExternalIdentity::new`].
#[derive(Debug, PartialEq, Eq)]
pub enum IdentityError {
    /// Missing or unrecognized version tag.
    UnknownVersion,
    /// Not exactly three pipe-delimited fields.
    FieldCount(usize),
    /// A `%` escape that is not `%25` or `%7C`, or a truncated one.
    BadEscape,
    /// A field that must be non-empty was empty.
    EmptyField(&'static str),
    /// A subject that is not in the form its adapter requires. The adapter
    /// supplies the words.
    SubjectShape(&'static str),
    /// Longer than the attribute can hold, in characters.
    TooLong(usize),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownVersion => write!(f, "unknown external-identity version tag"),
            Self::FieldCount(n) => write!(f, "expected {FIELD_COUNT} fields, found {n}"),
            Self::BadEscape => write!(f, "malformed percent escape"),
            Self::EmptyField(name) => write!(f, "empty {name} field"),
            Self::SubjectShape(want) => write!(f, "subject is not {want}"),
            Self::TooLong(n) => {
                write!(f, "{n} characters, over the {MAX_IDENTITY_LEN} the attribute holds")
            }
        }
    }
}

impl std::error::Error for IdentityError {}

impl ExternalIdentity {
    /// The only way to build one, so an adapter cannot produce a malformed or
    /// half-empty identity and store it.
    pub fn new(source: &Source, subject: impl Into<String>) -> Result<Self, IdentityError> {
        let subject = subject.into();
        if subject.is_empty() {
            return Err(IdentityError::EmptyField("subject"));
        }
        let id = Self { source: source.clone(), subject };
        let len = id.encode().chars().count();
        if len > MAX_IDENTITY_LEN {
            return Err(IdentityError::TooLong(len));
        }
        Ok(id)
    }

    /// Which source owns this object, for comparison and bucketing.
    pub fn source(&self) -> &Source {
        &self.source
    }

    /// The adapter's opaque account key. Sync uses it as the join key of the
    /// reconciliation loop; nothing else may look inside it.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// This identity as a human reads it -- a log line, a notification subject,
    /// an operator's console. See [`Label`] for why it is not a `String`.
    pub fn label(&self) -> Label {
        Label(format!("{}/{}", self.source.name(), self.subject))
    }

    /// Encode for storage in `msDS-ExternalDirectoryObjectId`.
    ///
    /// `kb1|<source name>|<subject>`, where each field escapes only `%` (the
    /// escape introducer) and `|` (the delimiter). Canonical Entra values
    /// contain neither, so they stay human-readable in `ldbsearch` output and
    /// audit logs.
    pub fn encode(&self) -> String {
        format!(
            "{VERSION_TAG}|{}|{}",
            escape_field(self.source.name()),
            escape_field(&self.subject),
        )
    }

    /// Parse a stored attribute value back into an identity.
    pub fn decode(value: &str) -> Result<Self, IdentityError> {
        let fields: Vec<&str> = value.split('|').collect();
        if fields.len() != FIELD_COUNT {
            return Err(IdentityError::FieldCount(fields.len()));
        }
        if fields[0] != VERSION_TAG {
            return Err(IdentityError::UnknownVersion);
        }
        let source = Source::new(unescape_field(fields[1])?)?;
        Self::new(&source, unescape_field(fields[2])?)
    }

    /// An equality filter matching exactly this identity.
    ///
    /// The encoded value is RFC 4515-escaped unconditionally. Canonical Entra
    /// values need no escaping, but a malformed or hostile subject must not be
    /// able to inject filter syntax.
    pub fn ldap_filter(&self) -> String {
        format!("(msDS-ExternalDirectoryObjectId={})", escape_ldap_filter_value(&self.encode()))
    }
}

/// An identity rendered for a human.
///
/// Deliberately not a string: it implements [`fmt::Display`] and nothing else --
/// no `Deref<Target = str>`, no `as_str`, no `split`. Everything downstream of
/// an adapter treats an identity as two opaque halves, and the way that stops
/// being true is somebody reading a substring back out of a message they were
/// only meant to print. Making that impossible is cheaper than remembering the
/// rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label(String);

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub(crate) fn escape_field(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    for c in field.chars() {
        match c {
            '%' => out.push_str("%25"),
            '|' => out.push_str("%7C"),
            _ => out.push(c),
        }
    }
    out
}

pub(crate) fn unescape_field(field: &str) -> Result<String, IdentityError> {
    let mut out = String::with_capacity(field.len());
    let mut chars = field.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        let hi = chars.next().ok_or(IdentityError::BadEscape)?;
        let lo = chars.next().ok_or(IdentityError::BadEscape)?;
        match (hi, lo.to_ascii_uppercase()) {
            ('2', '5') => out.push('%'),
            ('7', 'C') => out.push('|'),
            _ => return Err(IdentityError::BadEscape),
        }
    }
    Ok(out)
}

/// Decode a binary `objectSid` into its `S-1-5-21-…` string form.
///
/// The SID is what durable filesystem ACLs hold and what `idmap_rid` derives a
/// uid from, so every component that shows an operator *which* object they are
/// looking at needs the same rendering of it.
///
/// `objectSid` is a binary attribute: revision, sub-authority count, a
/// big-endian 48-bit identifier authority, then that many little-endian
/// sub-authorities. The mixed endianness is the part worth writing down.
pub fn decode_sid(raw: &[u8]) -> anyhow::Result<String> {
    if raw.len() < 8 {
        anyhow::bail!("SID is {} bytes, shorter than its own header", raw.len());
    }
    let revision = raw[0];
    let sub_authority_count = raw[1] as usize;
    let expected = 8 + 4 * sub_authority_count;
    if raw.len() < expected {
        anyhow::bail!(
            "SID declares {sub_authority_count} sub-authorities but is only {} bytes",
            raw.len()
        );
    }
    let authority = raw[2..8].iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    let mut out = format!("S-{revision}-{authority}");
    for i in 0..sub_authority_count {
        let off = 8 + 4 * i;
        let value = u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]);
        out.push_str(&format!("-{value}"));
    }
    Ok(out)
}

/// Decode `objectSid` from an LDAP entry, looking in **both** places a client
/// may have put it.
///
/// `ldap3` sorts an attribute into `bin_attrs` only when its bytes fail UTF-8,
/// and puts it in `attrs` otherwise -- its own documentation says to check both.
/// A SID is binary, but nothing stops a particular one from being valid UTF-8,
/// and whether it is depends on the domain SID and the RID together. Measured on
/// the bench, whose domain SID happens to make almost every account's SID valid:
/// every value arrived in `attrs`, so a `bin_attrs`-only read found none of
/// them. Checking one map works until the day a deployment's random domain SID
/// falls the other way, and then it fails for that whole realm at once.
///
/// `String` here came from `str::from_utf8`, which is exact rather than lossy,
/// so its bytes are the original octets.
pub fn decode_sid_attr(binary: Option<&[Vec<u8>]>, text: Option<&[String]>) -> Option<String> {
    let raw = binary
        .and_then(|v| v.first())
        .map(|v| v.as_slice())
        .or_else(|| text.and_then(|v| v.first()).map(|s| s.as_bytes()))?;
    decode_sid(raw).ok()
}

/// Refuse a directory URL that is not `ldaps://`.
///
/// Every bind this project makes carries a service-account password, and sync's
/// writes carry `unicodePwd` besides. `ldap://` puts both on the wire in the
/// clear, and the failure is silent: the bind succeeds, synchronization works,
/// and nothing looks wrong. It is one character away from the right value in a
/// hand-edited `.env`, so the URL is checked where it is read rather than
/// trusted because provisioning wrote it. StartTLS is not accepted either --
/// nothing here negotiates it, so it would fail closed anyway, but saying so is
/// more useful than a connection error.
pub fn require_ldaps(url: &str) -> anyhow::Result<()> {
    if url.starts_with("ldaps://") {
        return Ok(());
    }
    anyhow::bail!(
        "{url} is not ldaps:// -- the bind password, and every password sync writes, \
         would cross the network in the clear"
    )
}

/// Is this the canonical GUID form -- `8-4-4-4-12` hex, in lowercase?
///
/// A shape check and deliberately not a parse: the two callers want opposite
/// things from it and neither wants the value. The broker refuses a token whose
/// `tid` or `oid` is not in this form, because those become directory
/// coordinates; sync refuses a Graph credential file that *is* in it, because
/// that is the portal's *Secret ID* pasted in place of the secret *Value*.
/// Parsing with a UUID crate would accept the braced and URN forms too, which
/// loosens the first check and breaks the second.
///
/// Case is part of the form. The broker stores a subject from a token and sync
/// stores it from the directory; the two are compared byte for byte, so two
/// spellings orphan every account in that source.
///
/// A caller that wants the shape in any case lowercases first, and says so.
pub fn is_guid(s: &str) -> bool {
    let mut parts = s.split('-');
    for len in [8usize, 4, 4, 4, 12] {
        let Some(p) = parts.next() else { return false };
        if p.len() != len || !p.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return false;
        }
    }
    parts.next().is_none()
}

/// RFC 4515 escaping for an LDAP filter assertion value.
pub fn escape_ldap_filter_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\5c"),
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\0' => out.push_str("\\00"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entra_sample() -> ExternalIdentity {
        ExternalIdentity::new(
            &Source::new("entra").unwrap(),
            "33334444-dddd-5555-eeee-6666ffff7777",
        )
        .unwrap()
    }

    #[test]
    fn encodes_the_canonical_entra_value() {
        let expected = "kb1|entra|33334444-dddd-5555-eeee-6666ffff7777";
        assert_eq!(entra_sample().encode(), expected);
        assert_eq!(expected.len(), 46);
    }

    #[test]
    fn canonical_entra_values_need_no_escaping() {
        assert!(!entra_sample().encode().contains('%'));
    }

    #[test]
    fn round_trips() {
        let id = entra_sample();
        assert_eq!(ExternalIdentity::decode(&id.encode()), Ok(id));
    }

    #[test]
    fn round_trips_values_containing_delimiter_and_introducer() {
        let id =
            ExternalIdentity::new(&Source::new("a|b").unwrap(), "%7C-is-literal-here").unwrap();
        let encoded = id.encode();
        assert_eq!(encoded, "kb1|a%7Cb|%257C-is-literal-here");
        assert_eq!(encoded.split('|').count(), 3, "escaping must not add delimiters");
        assert_eq!(ExternalIdentity::decode(&encoded), Ok(id));
    }

    #[test]
    fn rejects_malformed_values() {
        use IdentityError::*;
        assert_eq!(ExternalIdentity::decode("kb1|a"), Err(FieldCount(2)));
        assert_eq!(ExternalIdentity::decode("kb1|a|b|c"), Err(FieldCount(4)));
        assert_eq!(ExternalIdentity::decode("kb2|a|b"), Err(UnknownVersion));
        assert_eq!(ExternalIdentity::decode("|a|b"), Err(UnknownVersion));
        assert_eq!(ExternalIdentity::decode("kb1|a|%ZZ"), Err(BadEscape));
        assert_eq!(ExternalIdentity::decode("kb1|a|%2"), Err(BadEscape));
        assert_eq!(ExternalIdentity::decode("kb1|a|"), Err(EmptyField("subject")));
        assert_eq!(ExternalIdentity::decode("kb1||b"), Err(EmptyField("source name")));
    }

    /// The ceiling is the attribute's, so it has to bind on the way in as well
    /// as on the way back: an adapter that built a 300-character subject would
    /// otherwise have sync write a value AD silently refuses, on every cycle,
    /// for that one account.
    #[test]
    fn an_identity_over_the_attribute_ceiling_is_refused_at_construction() {
        let entra = Source::new("entra").unwrap();
        // "kb1|entra|" is 10 characters, so this is exactly at the ceiling.
        let longest = "s".repeat(MAX_IDENTITY_LEN - 10);
        let id = ExternalIdentity::new(&entra, &longest).unwrap();
        assert_eq!(id.encode().chars().count(), MAX_IDENTITY_LEN);
        assert_eq!(
            ExternalIdentity::new(&entra, format!("{longest}s")),
            Err(IdentityError::TooLong(MAX_IDENTITY_LEN + 1))
        );
        assert_eq!(
            ExternalIdentity::decode(&format!("kb1|entra|{longest}s")),
            Err(IdentityError::TooLong(MAX_IDENTITY_LEN + 1))
        );
        // Characters, not bytes: `rangeUpper` counts a Unicode string's length,
        // so a subject of multi-byte characters is not short by three quarters.
        assert!(ExternalIdentity::new(&entra, "ä".repeat(MAX_IDENTITY_LEN - 10)).is_ok());
    }

    /// The label is the only thing a consumer outside an adapter may read, and
    /// it must carry both coordinates: an operator joining a `DENY` log line to
    /// a notification has nothing else to join on.
    #[test]
    fn a_label_names_both_halves_and_cannot_be_taken_apart() {
        assert_eq!(
            entra_sample().label().to_string(),
            "entra/33334444-dddd-5555-eeee-6666ffff7777"
        );
        // If `Label` ever grows a `str` deref or an `as_str`, this stops being
        // the only way to get at the text and the type stops meaning anything.
        assert_eq!(format!("{}", entra_sample().label()), entra_sample().label().to_string());
    }

    #[test]
    fn decodes_a_domain_account_sid() {
        // S-1-5-21-1234567890-987654321-1111111111-1103
        let mut raw = vec![0x01, 0x05, 0, 0, 0, 0, 0, 0x05];
        for v in [21u32, 1234567890, 987654321, 1111111111, 1103] {
            raw.extend_from_slice(&v.to_le_bytes());
        }
        assert_eq!(decode_sid(&raw).unwrap(), "S-1-5-21-1234567890-987654321-1111111111-1103");
    }

    #[test]
    fn decodes_a_wellknown_sid() {
        // S-1-5-32-544, BUILTIN\Administrators.
        let raw = [
            vec![0x01, 0x02, 0, 0, 0, 0, 0, 0x05],
            32u32.to_le_bytes().to_vec(),
            544u32.to_le_bytes().to_vec(),
        ]
        .concat();
        assert_eq!(decode_sid(&raw).unwrap(), "S-1-5-32-544");
    }

    #[test]
    fn refuses_a_truncated_sid() {
        assert!(decode_sid(&[0x01, 0x05, 0, 0, 0, 0, 0, 0x05]).is_err());
        assert!(decode_sid(&[0x01]).is_err());
    }

    /// The bench's own domain SID, which is valid UTF-8 -- so ldap3 files it
    /// under `attrs` and a `bin_attrs`-only read finds nothing. Reading it from
    /// the text side must give the identical answer, or the broker denies every
    /// login in a realm whose SID happens to fall this way.
    #[test]
    fn a_sid_is_decoded_from_whichever_map_ldap3_filed_it_under() {
        let raw = hex("0105000000000005150000002c663671ecb2be7f2842333052040000");
        let expected = "S-1-5-21-1899390508-2143204076-808665640-1106";
        assert_eq!(decode_sid(&raw).unwrap(), expected);
        let text = String::from_utf8(raw.clone()).expect("this one really is valid UTF-8");

        use std::slice::from_ref;
        assert_eq!(decode_sid_attr(Some(from_ref(&raw)), None).as_deref(), Some(expected));
        assert_eq!(decode_sid_attr(None, Some(from_ref(&text))).as_deref(), Some(expected));
        // Binary wins when both are somehow present, and neither means None.
        assert_eq!(
            decode_sid_attr(Some(from_ref(&raw)), Some(from_ref(&text))).as_deref(),
            Some(expected)
        );
        assert_eq!(decode_sid_attr(None, None), None);
        assert_eq!(decode_sid_attr(Some(&[]), Some(&[])), None);
        assert_eq!(decode_sid_attr(None, Some(&["nonsense".to_owned()])), None);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// Both callers' cases, in one place because they are one rule: the broker
    /// admits a claim only if this is true, sync refuses a credential only if it
    /// is, and a drift in either direction breaks the other's check silently.
    #[test]
    fn recognizes_guids() {
        assert!(is_guid("33334444-dddd-5555-eeee-6666ffff7777"));
        assert!(is_guid("0a94cc71-1a92-4730-a2d9-8213912b4e6d"));
        // An uppercase spelling is a different subject.
        assert!(!is_guid("690222BE-FF1A-4D56-ABD1-7E4F7D38E474"));
        // One uppercase digit is enough.
        assert!(!is_guid("690222be-ff1a-4d56-abd1-7e4f7d38e47A"));
        assert!(!is_guid("690222bE-ff1a-4d56-abd1-7e4f7d38e474"));
        // What a caller that wants the shape in any case does.
        assert!(is_guid(&"690222BE-FF1A-4D56-ABD1-7E4F7D38E474".to_ascii_lowercase()));
        // One hex digit short in the last group.
        assert!(!is_guid("690222be-ff1a-4d56-abd1-7e4f7d38e47"));
        assert!(!is_guid("33334444-dddd-5555-eeee-6666ffff7777-extra"));
        assert!(!is_guid("690222be_ff1a_4d56_abd1_7e4f7d38e474"));
        assert!(!is_guid("zzzzzzzz-ff1a-4d56-abd1-7e4f7d38e474"));
        assert!(!is_guid(""));
        assert!(!is_guid("short"));
        // A real secret value can carry dashes without being a Secret ID.
        assert!(!is_guid("aB3~qX9.some-real-looking-secret-value-Zz0"));
        assert!(!is_guid("abc-def-ghi-jkl-mno"));
        // The braced and URN forms a UUID parser would accept are not this shape.
        assert!(!is_guid("{33334444-dddd-5555-eeee-6666ffff7777}"));
        assert!(!is_guid("urn:uuid:33334444-dddd-5555-eeee-6666ffff7777"));
    }

    #[test]
    fn filter_escapes_a_hostile_subject() {
        let id = ExternalIdentity::new(&Source::new("entra").unwrap(), "*)(cn=").unwrap();
        let filter = id.ldap_filter();
        assert!(filter.contains("\\2a\\29\\28"), "got {filter}");
        // Exactly one opening and one closing paren survive: the filter's own.
        assert_eq!(filter.matches('(').count(), 1);
        assert_eq!(filter.matches(')').count(), 1);
    }
}
