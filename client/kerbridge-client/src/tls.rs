//! What the host actually presented, for the one transport failure whose own
//! message names no evidence.
//!
//! A trust failure says only that the chain was not trusted, and three different
//! faults produce it: the certificate is for another name, it has expired, or it
//! comes from a CA this machine has never been told about. Which one it is, is in
//! the certificate that was refused and nowhere else.
//!
//! So on a TLS failure the host is connected to a second time with validation
//! off, purely to read that certificate back out. The probe sends no request and
//! reads no body: it completes a handshake, takes the peer certificate, and drops
//! the connection. It is **not** a fallback -- the request that failed stays
//! failed, and nothing here decides to trust anything. It only reports.
//!
//! The X.509 read is four fields deep and written out here for the same reason
//! [`crate::krbcred`]'s ASN.1 is: a certificate parser is a large dependency
//! traveling into every binary that links this library, to answer a question
//! this small.

use std::fmt;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// The probe is diagnostic, and it runs on a thread the user is waiting on. A
/// host that accepts the connection and then says nothing must not add its own
/// stall to a request that has already failed.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The four fields that tell the three trust failures apart, plus the names the
/// certificate is actually valid for -- which is the field hostname validation
/// reads, and the one a `CN` alone can no longer answer for.
pub struct Peer {
    pub subject: String,
    pub issuer: String,
    pub dns_names: Vec<String>,
    pub not_before: String,
    pub not_after: String,
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let or_none = |s: &str| if s.is_empty() { "(none)".to_string() } else { s.to_string() };
        writeln!(f, "certificate the host presented:")?;
        writeln!(f, "  subject  {}", or_none(&self.subject))?;
        if !self.dns_names.is_empty() {
            writeln!(f, "  names    {}", self.dns_names.join(", "))?;
        }
        writeln!(f, "  issuer   {}", or_none(&self.issuer))?;
        write!(f, "  valid    {} to {}", self.not_before, self.not_after)
    }
}

/// Handshake with `url`'s host, accepting anything, and report what it sent.
///
/// `None` for every way this can go wrong -- the host stopped answering between
/// the failed request and this one, the certificate is not parseable, there is no
/// certificate at all. The caller is already reporting a failure; a failure to
/// explain it is not a second error to raise.
pub fn peer(url: &str) -> Option<Peer> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port_or_known_default()?;

    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .ok()?;
    let address = (host, port).to_socket_addrs().ok()?.next()?;
    let stream = TcpStream::connect_timeout(&address, PROBE_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(PROBE_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(PROBE_TIMEOUT)).ok()?;

    let session = connector.connect(host, stream).ok()?;
    let der = session.peer_certificate().ok()??.to_der().ok()?;
    Peer::from_der(&der)
}

// ------------------------------------------------------------------- X.509

impl Peer {
    /// Walk `Certificate` (RFC 5280 4.1) positionally as far as the extensions.
    ///
    /// ```text
    /// Certificate     ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    /// TBSCertificate  ::= SEQUENCE { [0] version OPTIONAL, serialNumber, signature,
    ///                                issuer, validity, subject, subjectPublicKeyInfo,
    ///                                ..., [3] extensions OPTIONAL }
    /// ```
    fn from_der(der: &[u8]) -> Option<Peer> {
        let mut tbs = Der(der).seq()?.seq()?;
        // `version` is `[0] EXPLICIT` and optional; what follows it is the serial
        // number either way, so one lookahead distinguishes them.
        let (tag, _) = tbs.next()?;
        if tag == CONTEXT_0 {
            tbs.next()?; // serialNumber
        }
        tbs.next()?; // signature AlgorithmIdentifier
        let issuer = name(tbs.seq()?);
        let mut validity = tbs.seq()?;
        let not_before = time(validity.next()?)?;
        let not_after = time(validity.next()?)?;
        let subject = name(tbs.seq()?);
        tbs.next()?; // subjectPublicKeyInfo
        Some(Peer { subject, issuer, dns_names: dns_names(&mut tbs), not_before, not_after })
    }
}

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const OID: u8 = 0x06;
const OCTET_STRING: u8 = 0x04;
const BOOLEAN: u8 = 0x01;
const BMP_STRING: u8 = 0x1e;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
/// `[0]`, constructed -- `version` in a TBSCertificate.
const CONTEXT_0: u8 = 0xa0;
/// `[3]`, constructed -- `extensions`.
const CONTEXT_3: u8 = 0xa3;
/// `[2]` primitive -- `dNSName` inside a GeneralName, implicitly tagged, so the
/// IA5String tag is replaced rather than wrapped.
const CONTEXT_2_PRIMITIVE: u8 = 0x82;
/// `id-ce-subjectAltName`, 2.5.29.17.
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];

/// A cursor over one DER element's contents.
struct Der<'a>(&'a [u8]);

impl<'a> Der<'a> {
    /// The next element as `(tag, contents)`, stepping over it. `None` at the end
    /// of the contents and on anything malformed -- every caller here treats the
    /// two the same way, by giving up on the certificate.
    fn next(&mut self) -> Option<(u8, &'a [u8])> {
        let (&tag, rest) = self.0.split_first()?;
        let (&first, rest) = rest.split_first()?;
        let (len, rest) = if first < 0x80 {
            (first as usize, rest)
        } else {
            // Long form: the low seven bits count the length's own bytes. 0x80 is
            // the indefinite length, which DER forbids, and a length needing more
            // than four bytes is not a certificate anyone sent us.
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 4 {
                return None;
            }
            let (bytes, rest) = rest.split_at_checked(count)?;
            (bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize), rest)
        };
        let (contents, rest) = rest.split_at_checked(len)?;
        self.0 = rest;
        Some((tag, contents))
    }

    /// The next element, which must be a SEQUENCE, as a cursor over its contents.
    fn seq(&mut self) -> Option<Der<'a>> {
        match self.next()? {
            (SEQUENCE, contents) => Some(Der(contents)),
            _ => None,
        }
    }
}

/// `Name ::= RDNSequence`, rendered `O=…, CN=…` in the order the certificate
/// carries them -- the same order, and the same spelling, that
/// `openssl x509 -subject` prints, so the two can be compared by eye.
///
/// Returns what it could read rather than failing: an unparseable attribute in a
/// DN is not a reason to drop the validity dates on the floor.
fn name(mut rdns: Der) -> String {
    let mut parts = Vec::new();
    while let Some((SET, set)) = rdns.next() {
        let mut set = Der(set);
        while let Some(mut attribute) = set.seq() {
            let Some((OID, oid)) = attribute.next() else { continue };
            let Some((tag, value)) = attribute.next() else { continue };
            parts.push(format!("{}={}", attribute_name(oid), text(tag, value)));
        }
    }
    parts.join(", ")
}

/// The short names every tool prints, and the dotted form for anything else --
/// an OID nobody recognizes is still evidence, and hiding it would leave a hole
/// in the DN where an attribute was.
fn attribute_name(oid: &[u8]) -> String {
    match oid {
        [0x55, 0x04, 0x03] => "CN".into(),
        [0x55, 0x04, 0x06] => "C".into(),
        [0x55, 0x04, 0x07] => "L".into(),
        [0x55, 0x04, 0x08] => "ST".into(),
        [0x55, 0x04, 0x0a] => "O".into(),
        [0x55, 0x04, 0x0b] => "OU".into(),
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19] => "DC".into(),
        other => dotted(other),
    }
}

/// An OID's dotted decimal form: the first byte packs two arcs, the rest are
/// base-128 with the top bit as a continuation flag (X.690 8.19).
fn dotted(oid: &[u8]) -> String {
    let Some((&first, rest)) = oid.split_first() else { return "?".into() };
    let mut out = format!("{}.{}", first / 40, first % 40);
    let mut arc: u64 = 0;
    for &byte in rest {
        arc = (arc << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            out.push_str(&format!(".{arc}"));
            arc = 0;
        }
    }
    out
}

/// A DirectoryString's contents. Everything a DN uses is UTF-8 or a subset of it,
/// except BMPString, which is UTF-16.
fn text(tag: u8, value: &[u8]) -> String {
    if tag == BMP_STRING {
        let units: Vec<u16> =
            value.as_chunks::<2>().0.iter().map(|&pair| u16::from_be_bytes(pair)).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(value).into_owned()
    }
}

/// `Time ::= UTCTime | GeneralizedTime`, as `YYYY-MM-DD HH:MMZ`.
///
/// The minutes are there for the failure that is otherwise unreadable: a
/// certificate that expired earlier today prints a date that still looks valid.
/// UTCTime's two-digit year is 1950..=2049 (RFC 5280 4.1.2.5.1), which is also
/// why a certificate valid past 2049 is written the other way.
fn time((tag, value): (u8, &[u8])) -> Option<String> {
    let digits = std::str::from_utf8(value).ok()?;
    let (year, rest) = match tag {
        UTC_TIME => {
            let yy: i32 = digits.get(0..2)?.parse().ok()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, digits.get(2..10)?)
        }
        GENERALIZED_TIME => (digits.get(0..4)?.parse().ok()?, digits.get(4..12)?),
        _ => return None,
    };
    Some(format!(
        "{year:04}-{}-{} {}:{}Z",
        rest.get(0..2)?,
        rest.get(2..4)?,
        rest.get(4..6)?,
        rest.get(6..8)?
    ))
}

/// The `dNSName` entries of the subjectAltName extension, which is what hostname
/// validation actually reads. Empty when the certificate carries none.
fn dns_names(tbs: &mut Der) -> Vec<String> {
    let mut names = Vec::new();
    // Whatever optional fields stand between the public key and the extensions,
    // skip: only `[3]` is wanted, and only its contents.
    let mut extensions = loop {
        match tbs.next() {
            Some((CONTEXT_3, contents)) => break Der(contents),
            Some(_) => continue,
            None => return names,
        }
    };
    let Some(mut extensions) = extensions.seq() else { return names };
    while let Some(mut extension) = extensions.seq() {
        let Some((OID, oid)) = extension.next() else { continue };
        if oid != OID_SUBJECT_ALT_NAME {
            continue;
        }
        // `critical` is an optional BOOLEAN before the wrapped value.
        let wrapped = match extension.next() {
            Some((OCTET_STRING, value)) => value,
            Some((BOOLEAN, _)) => match extension.next() {
                Some((OCTET_STRING, value)) => value,
                _ => continue,
            },
            _ => continue,
        };
        let Some(mut general_names) = Der(wrapped).seq() else { continue };
        while let Some((tag, value)) = general_names.next() {
            if tag == CONTEXT_2_PRIMITIVE {
                names.push(String::from_utf8_lossy(value).into_owned());
            }
        }
        break;
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Issued by a private CA, with two names in the SAN and dates inside
    /// UTCTime's window -- the shape of every broker certificate this will be
    /// pointed at. Regenerate with `testbench/fixtures/tls/make_fixtures.sh`.
    const LAN_CA_LEAF: &[u8] = include_bytes!("../../../testbench/fixtures/tls/lan-ca-leaf.der");
    /// The other arm of each branch: valid past 2049, so GeneralizedTime rather
    /// than UTCTime; a non-ASCII organization, so a real UTF8String; and no
    /// subjectAltName.
    const FAR_FUTURE: &[u8] = include_bytes!("../../../testbench/fixtures/tls/far-future.der");

    #[test]
    fn reads_the_fields_that_tell_the_trust_failures_apart() {
        let peer = Peer::from_der(LAN_CA_LEAF).expect("fixture parses");
        assert_eq!(peer.subject, "O=Example Org, CN=kerbridge.example.site");
        assert_eq!(peer.issuer, "O=Example Org, CN=Example LAN CA");
        assert_eq!(peer.dns_names, ["kerbridge.example.site", "nas1.example.site"]);
        assert_eq!(peer.not_before, "2026-01-02 03:04Z");
        assert_eq!(peer.not_after, "2027-01-02 03:04Z");
    }

    #[test]
    fn generalized_time_and_a_non_ascii_dn() {
        let peer = Peer::from_der(FAR_FUTURE).expect("fixture parses");
        assert_eq!(peer.subject, "O=Ekämpel Öy, CN=kerbridge.example.site");
        assert_eq!(peer.not_before, "2025-01-02 03:04Z");
        assert_eq!(peer.not_after, "2055-01-02 03:04Z");
        assert!(peer.dns_names.is_empty(), "no SAN in this one: {:?}", peer.dns_names);
    }

    /// The rendering is what an operator reads, so it is worth pinning.
    #[test]
    fn renders_as_a_block() {
        let peer = Peer::from_der(LAN_CA_LEAF).expect("fixture parses");
        assert_eq!(
            peer.to_string(),
            "certificate the host presented:\n  \
             subject  O=Example Org, CN=kerbridge.example.site\n  \
             names    kerbridge.example.site, nas1.example.site\n  \
             issuer   O=Example Org, CN=Example LAN CA\n  \
             valid    2026-01-02 03:04Z to 2027-01-02 03:04Z"
        );
    }

    /// Truncation is the shape a probe fails in -- a host that closes the
    /// connection mid-certificate. Every prefix must be refused, not panicked on.
    #[test]
    fn every_truncation_is_refused_rather_than_panicking() {
        for cut in 0..LAN_CA_LEAF.len() {
            assert!(Peer::from_der(&LAN_CA_LEAF[..cut]).is_none(), "prefix of {cut} bytes parsed");
        }
    }

    #[test]
    fn garbage_is_refused() {
        for bad in [&b""[..], &[0x30][..], &[0x30, 0x84, 0xff, 0xff, 0xff, 0xff][..], &[0xff; 64]] {
            assert!(Peer::from_der(bad).is_none());
        }
    }

    #[test]
    fn unknown_oids_keep_their_place_in_the_dn() {
        assert_eq!(attribute_name(&[0x55, 0x04, 0x03]), "CN");
        // 1.2.840.113549.1.9.1 -- emailAddress, deliberately not in the table.
        assert_eq!(
            attribute_name(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01]),
            "1.2.840.113549.1.9.1"
        );
    }
}
