//! Reading what the `ldb` tools print, and the two string surgeries the deny
//! needs.
//!
//! Everything here is pure, and that is deliberate: it is the half of
//! `kbsetup directory` a bench without a domain controller can still hold to
//! account.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use base64::Engine;

pub type Entry = BTreeMap<String, Vec<String>>;

/// Every entry an `ldbsearch` printed.
///
/// Three properties of LDIF matter here and each has bitten somebody:
///
/// * **Long values are folded.** A continuation line begins with one space and
///   belongs to the value above it. An SDDL security descriptor is far longer
///   than 79 characters, so a parser that reads line by line sees a truncated
///   descriptor and concludes the deny is absent -- and then writes a second one.
/// * **`::` means base64.** `ldbsearch` encodes any value it cannot print
///   safely, and `schemaIDGUID` is always raw bytes.
/// * **Only blocks with a `dn` are entries.** A subtree search also returns
///   `ref:` referral blocks for the Configuration and Schema partitions, and
///   counting those made one unambiguous match look like four --
///   `crates/kerbridge-issuerd/src/issue.rs:424-426` records finding that the hard way.
pub fn entries(text: &str) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut current = Entry::new();
    // (attribute, accumulated text, base64?)
    let mut pending: Option<(String, String, bool)> = None;

    fn flush(current: &mut Entry, p: Option<(String, String, bool)>) {
        let Some((key, value, b64)) = p else { return };
        let value = if b64 {
            match base64::engine::general_purpose::STANDARD.decode(&value) {
                // Kept as bytes rather than as text: `schemaIDGUID` is not UTF-8
                // and must not be lossily mangled on the way through. The
                // escaped form round-trips through [`raw`].
                Ok(raw) => raw.iter().map(|b| format!("\\{b:02x}")).collect(),
                // An undecodable value is dropped rather than guessed at. Every
                // caller here fails closed on a missing attribute.
                Err(_) => return,
            }
        } else {
            value
        };
        current.entry(key).or_default().push(value);
    }

    for line in text.lines().chain(std::iter::once("")) {
        if let Some(rest) = line.strip_prefix(' ') {
            if let Some((_, value, _)) = pending.as_mut() {
                value.push_str(rest);
            }
            continue;
        }
        flush(&mut current, pending.take());

        if line.is_empty() || line.starts_with('#') {
            if line.is_empty() && current.contains_key("dn") {
                entries.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(":: ") {
            pending = Some((k.to_owned(), v.to_owned(), true));
        } else if let Some((k, v)) = line.split_once(": ") {
            pending = Some((k.to_owned(), v.to_owned(), false));
        }
    }
    entries
}

pub fn first<'a>(entry: &'a Entry, attr: &str) -> Option<&'a String> {
    entry.get(attr).and_then(|values| values.first())
}

/// The bytes behind a value [`entries`] decoded from base64.
pub fn raw(value: &str) -> Option<Vec<u8>> {
    value
        .split('\\')
        .skip(1)
        .map(|byte| u8::from_str_radix(byte, 16).ok())
        .collect::<Option<Vec<u8>>>()
        .filter(|bytes| !bytes.is_empty())
}

/// A GUID attribute as the text `samba-tool dsacl set --sddl=` wants it.
///
/// Accepts both spellings, because which one arrives depends on whether the
/// attribute went through a syntax handler on the way out: the canonical text
/// form is passed through, and 16 raw bytes are formatted from AD's mixed-endian
/// layout -- first three fields little-endian, last two as written. That is what
/// `ndr_unpack(misc.GUID, ...)` did in the Python this replaces, spelled out
/// rather than delegated.
pub fn guid(value: &str) -> Result<String> {
    if let Some(bytes) = raw(value) {
        if bytes.len() != 16 {
            bail!("a GUID attribute came back as {} bytes, not 16", bytes.len());
        }
        let le = |s: &[u8]| s.iter().rev().map(|b| format!("{b:02x}")).collect::<String>();
        let be = |s: &[u8]| s.iter().map(|b| format!("{b:02x}")).collect::<String>();
        return Ok(format!(
            "{}-{}-{}-{}-{}",
            le(&bytes[0..4]),
            le(&bytes[4..6]),
            le(&bytes[6..8]),
            be(&bytes[8..10]),
            be(&bytes[10..16])
        ));
    }
    let text = value.trim().trim_matches(['{', '}']);
    let shaped = text.len() == 36
        && text.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
        && text.match_indices('-').map(|(i, _)| i).eq([8, 13, 18, 23]);
    if shaped { Ok(text.to_ascii_lowercase()) } else { bail!("not a GUID: {value:?}") }
}

/// `ace` as the DACL's **first** entry.
///
/// Position is the whole point, and it is the reason the deny exists at all: a
/// user object's default security descriptor grants SELF write of the
/// Personal-Information property set as an *explicit* ACE, the access check
/// grants on the first match, and a deny ordered after it is never reached. That
/// was measured -- an inherited deny, by attribute GUID or by property set,
/// before or after the object existed, left the write succeeding; an explicit
/// deny on the object refused it with LDAP 50.
///
/// The DACL marker is matched rather than searched for, because an owner or
/// group alias can put a bare `D:` earlier in the string.
pub fn insert_first_ace(sddl: &str, ace: &str) -> Result<String> {
    let bytes = sddl.as_bytes();
    let mut at = 0;
    while let Some(found) = sddl[at..].find("D:") {
        let mut cursor = at + found + 2;
        while bytes.get(cursor).is_some_and(u8::is_ascii_uppercase) {
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b'(') {
            return Ok(format!("{}{ace}{}", &sddl[..cursor], &sddl[cursor..]));
        }
        at += found + 2;
    }
    bail!("no DACL to insert into: {sddl}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The failure this parser exists to prevent: a folded security descriptor
    /// read line by line looks like a descriptor that does not carry the deny,
    /// and the sweep then writes a second one onto every user, every run.
    #[test]
    fn a_folded_value_is_rejoined() {
        let text = "dn: CN=Alice,OU=Entra,DC=example,DC=site\n\
                    nTSecurityDescriptor: D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWP\n \
                    CRCCDCLCLORCWOWDSDDTSW;;;SY)\n\
                    \n";
        let found = entries(text);
        assert_eq!(found.len(), 1);
        assert_eq!(
            first(&found[0], "nTSecurityDescriptor").unwrap(),
            "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
        );
    }

    /// A subtree search over the schema partition returns referrals, and they
    /// carry no `dn`.
    #[test]
    fn a_referral_block_is_not_an_entry() {
        let text = "# referral\nref: ldap://example.site/CN=Configuration,DC=example,DC=site\n\n\
                    dn: CN=User,CN=Schema,CN=Configuration,DC=example,DC=site\n\
                    defaultSecurityDescriptor: D:(A;;RPWP;;;PS)\n\n";
        let found = entries(text);
        assert_eq!(found.len(), 1);
        assert_eq!(
            first(&found[0], "dn").unwrap(),
            "CN=User,CN=Schema,CN=Configuration,DC=example,DC=site"
        );
    }

    /// The mixed-endian layout, against a `schemaIDGUID` whose text form this
    /// repository already writes down: `extensionName` is
    /// `bf967972-0de6-11d0-a285-00aa003049e2` -- one of the three GUIDs
    /// `RENAMEABLE` names. The one the deny needs is read out of the
    /// live schema rather than hardcoded -- a wrong GUID there would deny
    /// nothing and look fine -- so the decoding is the half that has to be right
    /// here.
    #[test]
    fn a_base64_guid_decodes_to_its_canonical_text() {
        let bytes = [
            0x72, 0x79, 0x96, 0xbf, 0xe6, 0x0d, 0xd0, 0x11, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30,
            0x49, 0xe2,
        ];
        let text = format!(
            "dn: CN=Extension-Name,CN=Schema,CN=Configuration,DC=example,DC=site\n\
             schemaIDGUID:: {}\n\n",
            base64::engine::general_purpose::STANDARD.encode(bytes)
        );
        let found = entries(&text);
        let value = first(&found[0], "schemaIDGUID").unwrap();
        assert_eq!(guid(value).unwrap(), "bf967972-0de6-11d0-a285-00aa003049e2");
    }

    /// The other spelling, for the same attribute read through a syntax handler.
    #[test]
    fn a_text_guid_passes_through() {
        assert_eq!(
            guid("BF967972-0DE6-11D0-A285-00AA003049E2").unwrap(),
            "bf967972-0de6-11d0-a285-00aa003049e2"
        );
        assert_eq!(
            guid("{bf967972-0de6-11d0-a285-00aa003049e2}").unwrap(),
            "bf967972-0de6-11d0-a285-00aa003049e2"
        );
        assert!(guid("not-a-guid").is_err());
        assert!(guid("\\ff\\ff").is_err(), "a short byte string is not a GUID");
    }

    #[test]
    fn the_ace_lands_before_every_other_one() {
        let sddl = "O:DAG:DAD:AI(A;;RPWP;;;PS)(A;;RP;;;WD)";
        assert_eq!(
            insert_first_ace(sddl, "(OD;;WP;guid;;PS)").unwrap(),
            "O:DAG:DAD:AI(OD;;WP;guid;;PS)(A;;RPWP;;;PS)(A;;RP;;;WD)"
        );
    }

    /// A DACL-only read has nothing before `D:`, which is the form the sweep
    /// asks for with `--controls="sd_flags:1:4"`.
    #[test]
    fn a_dacl_only_descriptor_is_handled() {
        assert_eq!(insert_first_ace("D:(A;;RPWP;;;PS)", "(X)").unwrap(), "D:(X)(A;;RPWP;;;PS)");
    }

    /// An owner or group alias can spell `D:` before the DACL marker ever
    /// arrives -- `O:S-1-5-21-...` is not the only way a `D` and a colon meet.
    #[test]
    fn a_d_colon_that_is_not_the_dacl_is_stepped_over() {
        let sddl = "O:BAG:S-1-5-21-D:1D:(A;;RP;;;WD)";
        assert_eq!(insert_first_ace(sddl, "(X)").unwrap(), "O:BAG:S-1-5-21-D:1D:(X)(A;;RP;;;WD)");
    }

    #[test]
    fn a_descriptor_with_no_dacl_is_refused_rather_than_guessed_at() {
        assert!(insert_first_ace("O:DAG:DA", "(X)").is_err());
    }
}
