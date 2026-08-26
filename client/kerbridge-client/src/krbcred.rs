//! Convert the broker's MIT ccache into a KRB-CRED (`.krbcred`) blob.
//!
//! `KerbSubmitTicketMessage` wants a DER-encoded KRB-CRED message (RFC 4120 5.8.1),
//! the same structure Rubeus/Mimikatz `ptt` submit. A ccache holds the identical
//! ticket + session key, so this is a pure repackaging with no crypto: parse the
//! ccache, keep only the real TGT credential, and re-encode as an *unencrypted*
//! KRB-CRED (enc-part etype 0), which is the convention for a local
//! pass-the-ticket.
//!
//! Both halves are written out here rather than taken from a crate. The obvious
//! candidates -- `kerberos_asn1` and `kerberos_ccache` -- are AGPL-3.0, and a
//! statically linked Rust dependency travels into every binary that links this
//! library. What they were used for is one cache layout and five ASN.1 types,
//! all of them nailed down by RFC 4120 and by the same format
//! `crates/kerbridge-issuerd/src/ccache.rs` already reads on the server side.
//!
//! The cache layout is the one documented in that file; this reader keeps more of
//! each credential, because re-encoding needs the session key, the ticket and the
//! flags that validating did not:
//!
//! ```text
//! u16 version (0x0504)     u16 header_len   header[header_len]
//! principal default        credential*  (to EOF)
//!
//! principal  ::= u32 name_type  u32 n_components  str realm  str comp[n]
//! credential ::= principal client  principal server
//!                u16 keytype  str key
//!                u32 authtime  u32 starttime  u32 endtime  u32 renew_till
//!                u8 is_skey  u32 tktflags
//!                u32 n_addr  (u16 type, str)[n_addr]
//!                u32 n_authdata  (u16 type, str)[n_authdata]
//!                str ticket  str second_ticket
//! str        ::= u32 len  bytes[len]
//! ```
//!
//! v4 has **no** `etype` field in the keyblock -- that exists only in v3 -- and all
//! integers are big-endian, unlike the native-endian v1/v2 caches.
//!
//! The ticket itself is copied out of the cache verbatim: it is already the KDC's
//! own DER, and nothing here is entitled to re-encode bytes the KDC signed.
//!
//! The credential's times come back with the blob: the tray schedules its
//! re-injection from the ticket it actually injected, rather than trusting the
//! LSA cache (where an expired ticket can linger and a live one can be evicted).

use anyhow::{Result, anyhow, bail, ensure};

/// A TGT ready to submit, with the lifetime the KDC granted it.
pub struct Tgt {
    /// DER KRB-CRED bytes for `KerbSubmitTicketMessage`.
    pub krbcred: Vec<u8>,
    /// Unix seconds. `renew_till` is 0 when the ticket is not renewable.
    pub start: i64,
    pub end: i64,
    pub renew_till: i64,
}

/// Parse `ccache_bytes`, isolate the TGT, and return it as KRB-CRED + lifetime.
pub fn ccache_to_tgt(ccache_bytes: &[u8]) -> Result<Tgt> {
    let tgt = credentials(ccache_bytes)?
        .into_iter()
        .find(Credential::is_tgt)
        .ok_or_else(|| anyhow!("no TGT (krbtgt/...) credential found in the broker ccache"))?;

    Ok(Tgt {
        krbcred: krb_cred(&tgt),
        // A KDC may omit the optional `starttime`, in which case MIT stores 0 and
        // klist falls back to `authtime`. Do the same: a zero start would make the
        // ticket look 55 years old to anything computing elapsed lifetime.
        start: if tgt.starttime != 0 { tgt.starttime as i64 } else { tgt.authtime as i64 },
        end: tgt.endtime as i64,
        renew_till: tgt.renew_till as i64,
    })
}

/// One credential as a ccache holds it, for a caller that wants to *look at* a
/// cache rather than repackage one.
///
/// The Linux arm of [`crate::tickets`] is that caller: it writes the broker's
/// bytes to a `FILE:` cache and reads one back to answer "what is in there".
/// It goes through this module so the tree holds one ccache reader -- a second
/// one goes stale against the layout described above.
pub struct CachedCred {
    /// `user@REALM`.
    pub client: String,
    /// `krbtgt/REALM@REALM`, `cifs/nas1.example.site@REALM`, and so on.
    pub server: String,
    /// Unix seconds, with the same `authtime` fallback [`ccache_to_tgt`] applies.
    pub start: i64,
    pub end: i64,
    /// 0 when the ticket is not renewable.
    pub renew_till: i64,
    /// True for this cache's own ticket-granting ticket. See
    /// [`Credential::is_tgt`] for why the two-component form is required and
    /// what it keeps out.
    pub is_tgt: bool,
}

/// Every credential in `ccache_bytes`, in file order.
pub fn read_cache(ccache_bytes: &[u8]) -> Result<Vec<CachedCred>> {
    Ok(credentials(ccache_bytes)?
        .into_iter()
        .map(|c| CachedCred {
            client: c.client.to_string(),
            server: c.server.to_string(),
            start: if c.starttime != 0 { c.starttime as i64 } else { c.authtime as i64 },
            end: c.endtime as i64,
            renew_till: c.renew_till as i64,
            is_tgt: c.is_tgt(),
        })
        .collect())
}

// ---------------------------------------------------------------- ccache read

const VERSION_V4: u16 = 0x0504;

struct Principal {
    name_type: u32,
    realm: String,
    components: Vec<String>,
}

impl std::fmt::Display for Principal {
    /// The conventional `comp/comp@REALM` spelling, which is what `klist` prints
    /// and what every caller here compares against.
    ///
    /// No escaping: MIT escapes a literal `/`, `@` or NUL inside a component,
    /// and none of the principals this client meets has one -- they are a login
    /// name, `krbtgt`, and a service host name. A name that did carry one would
    /// render ambiguously rather than wrongly, and the comparisons above are
    /// equality against names built the same way.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.components.join("/"), self.realm)
    }
}

struct Credential {
    client: Principal,
    server: Principal,
    keytype: u16,
    key: Vec<u8>,
    authtime: u32,
    starttime: u32,
    endtime: u32,
    renew_till: u32,
    flags: u32,
    /// The KDC's DER `Ticket`, exactly as the cache stored it.
    ticket: Vec<u8>,
}

impl Credential {
    /// True for a local ticket-granting ticket -- `krbtgt/REALM@REALM`.
    ///
    /// A fresh cache also carries `X-CACHECONF:` pseudo-credentials whose
    /// "ticket" is a configuration string rather than an encoded ticket; feeding
    /// one to the KRB-CRED encoder would hand the LSA nonsense. They name
    /// `krbtgt/...` in a *component*, so matching the service name alone would
    /// accept one. Requiring the two-component form against the credential's own
    /// realm also skips a cross-realm TGT, which is not ours to inject.
    fn is_tgt(&self) -> bool {
        self.server.components.len() == 2
            && self.server.components[0] == "krbtgt"
            && self.server.components[1] == self.server.realm
    }
}

/// Every credential in the cache, in file order.
fn credentials(bytes: &[u8]) -> Result<Vec<Credential>> {
    let mut r = Reader { b: bytes, at: 0 };
    let version = r.u16()?;
    ensure!(
        version == VERSION_V4,
        "unsupported ccache version {version:#06x}, expected {VERSION_V4:#06x}"
    );
    let header_len = r.u16()? as usize;
    r.skip(header_len)?;
    r.principal()?; // default principal; every credential names its own client

    let mut out = Vec::new();
    while r.at < r.b.len() {
        out.push(r.credential()?);
    }
    Ok(out)
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self.at.checked_add(n).filter(|e| *e <= self.b.len());
        let Some(end) = end else {
            bail!("truncated ccache: wanted {n} bytes at offset {}", self.at);
        };
        let slice = &self.b[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n).map(|_| ())
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn bytes(&mut self) -> Result<Vec<u8>> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn str(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.bytes()?).into_owned())
    }

    fn principal(&mut self) -> Result<Principal> {
        let name_type = self.u32()?;
        let n = self.u32()? as usize;
        let realm = self.str()?;
        let components = (0..n).map(|_| self.str()).collect::<Result<_>>()?;
        Ok(Principal { name_type, realm, components })
    }

    fn credential(&mut self) -> Result<Credential> {
        let client = self.principal()?;
        let server = self.principal()?;
        let keytype = self.u16()?;
        let key = self.bytes()?;
        let authtime = self.u32()?;
        let starttime = self.u32()?;
        let endtime = self.u32()?;
        let renew_till = self.u32()?;
        self.skip(1)?; // is_skey
        let flags = self.u32()?;
        for _ in 0..self.u32()? {
            self.u16()?; // address type
            self.bytes()?;
        }
        for _ in 0..self.u32()? {
            self.u16()?; // authdata type
            self.bytes()?;
        }
        let ticket = self.bytes()?;
        self.bytes()?; // second ticket
        Ok(Credential {
            client,
            server,
            keytype,
            key,
            authtime,
            starttime,
            endtime,
            renew_till,
            flags,
            ticket,
        })
    }
}

// ------------------------------------------------------------- KRB-CRED write

const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_INTEGER: u8 = 0x02;
const TAG_GENERAL_STRING: u8 = 0x1b;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;
/// `[APPLICATION n]`, constructed.
const fn app(n: u8) -> u8 {
    0x60 | n
}
/// `[n]`, constructed -- the context tag every Kerberos struct member carries.
fn ctx(n: u8, content: Vec<u8>) -> Vec<u8> {
    tlv(0xa0 | n, &content)
}

/// The whole message: KRB-CRED with an unencrypted enc-part (RFC 4120 5.8.1).
fn krb_cred(c: &Credential) -> Vec<u8> {
    let enc_part = tlv(app(29), &tlv(TAG_SEQUENCE, &ctx(0, tlv(TAG_SEQUENCE, &cred_info(c)))));

    let body = [
        ctx(0, integer(5)),  // pvno
        ctx(1, integer(22)), // msg-type: KRB-CRED
        ctx(2, tlv(TAG_SEQUENCE, &c.ticket)),
        // EncryptedData with etype 0 and no kvno: "the cipher is the plaintext",
        // which is what a local pass-the-ticket submits and what the LSA expects.
        ctx(
            3,
            tlv(
                TAG_SEQUENCE,
                &[ctx(0, integer(0)), ctx(2, tlv(TAG_OCTET_STRING, &enc_part))].concat(),
            ),
        ),
    ]
    .concat();

    tlv(app(22), &tlv(TAG_SEQUENCE, &body))
}

/// One `KrbCredInfo`: everything about the ticket that is not the ticket.
fn cred_info(c: &Credential) -> Vec<u8> {
    let mut f = vec![
        // EncryptionKey
        ctx(
            0,
            tlv(
                TAG_SEQUENCE,
                &[ctx(0, integer(c.keytype as i64)), ctx(1, tlv(TAG_OCTET_STRING, &c.key))]
                    .concat(),
            ),
        ),
        ctx(1, general_string(&c.client.realm)),
        ctx(2, principal_name(&c.client)),
        ctx(3, ticket_flags(c.flags)),
        ctx(4, kerberos_time(c.authtime)),
    ];
    // starttime and renew-till are OPTIONAL, and MIT writes 0 for "absent". A
    // literal 0 would encode as 1970-01-01, which is a lie rather than a default.
    if c.starttime != 0 {
        f.push(ctx(5, kerberos_time(c.starttime)));
    }
    f.push(ctx(6, kerberos_time(c.endtime)));
    if c.renew_till != 0 {
        f.push(ctx(7, kerberos_time(c.renew_till)));
    }
    f.push(ctx(8, general_string(&c.server.realm)));
    f.push(ctx(9, principal_name(&c.server)));

    tlv(TAG_SEQUENCE, &f.concat())
}

/// `PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF }`
fn principal_name(p: &Principal) -> Vec<u8> {
    let names: Vec<u8> = p.components.iter().flat_map(|s| general_string(s)).collect();
    tlv(
        TAG_SEQUENCE,
        &[ctx(0, integer(p.name_type as i64)), ctx(1, tlv(TAG_SEQUENCE, &names))].concat(),
    )
}

/// `TicketFlags ::= BIT STRING (SIZE (32..MAX))`. MIT stores the same 32 bits in
/// the cache's `tktflags`, bit 0 in the most significant position -- so the four
/// big-endian bytes are the BIT STRING content, with no unused trailing bits.
fn ticket_flags(flags: u32) -> Vec<u8> {
    let mut v = vec![0u8]; // unused-bit count
    v.extend_from_slice(&flags.to_be_bytes());
    tlv(TAG_BIT_STRING, &v)
}

/// `KerberosTime ::= GeneralizedTime` -- UTC, whole seconds, no fraction (RFC 4120
/// 5.2.3 forbids one).
fn kerberos_time(unix: u32) -> Vec<u8> {
    let (y, m, d) = civil_from_days((unix / 86_400) as i64);
    let s = unix % 86_400;
    let text = format!("{y:04}{m:02}{d:02}{:02}{:02}{:02}Z", s / 3600, (s / 60) % 60, s % 60);
    tlv(TAG_GENERALIZED_TIME, text.as_bytes())
}

/// Proleptic-Gregorian date from a day count since the Unix epoch (Howard
/// Hinnant's `civil_from_days`) -- a calendar without a calendar library.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn general_string(s: &str) -> Vec<u8> {
    tlv(TAG_GENERAL_STRING, s.as_bytes())
}

/// DER `INTEGER`: minimal two's-complement, which for these non-negative values
/// means dropping leading zero bytes but keeping one when the high bit is set.
fn integer(v: i64) -> Vec<u8> {
    let be = v.to_be_bytes();
    let mut first = 0;
    while first < 7 && be[first] == 0 && be[first + 1] & 0x80 == 0 {
        first += 1;
    }
    tlv(TAG_INTEGER, &be[first..])
}

/// Tag + DER length + content. Lengths above 127 take the long form.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let be = n.to_be_bytes();
        let first = be.iter().position(|b| *b != 0).unwrap();
        out.push(0x80 | (be.len() - first) as u8);
        out.extend_from_slice(&be[first..]);
    }
    out.extend_from_slice(content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cache and the KRB-CRED it must encode to, byte for byte.
    ///
    /// These are not hand-derived: they are what the `kerberos_ccache` /
    /// `kerberos_asn1` implementation this module replaced produced for this
    /// input -- the encoding a Windows LSA was measured accepting. Pinning the
    /// bytes is what makes the rewrite a refactor rather than a rewrite.
    ///
    /// One `alice@EXAMPLE.SITE` TGT, aes256 session key, 10 h life, renewable
    /// for a week, `FORWARDABLE | RENEWABLE | INITIAL`. The cache is a file
    /// rather than a constant because the macOS ticket store tests inject this
    /// same cache for real, and two copies of it could drift apart.
    const GOLDEN_CCACHE: &[u8] =
        include_bytes!("../../../testbench/fixtures/kerberos/golden.ccache");

    const GOLDEN_KRBCRED: &str = concat!(
        "7682018a30820186a003020105a103020116a28180307e617c307aa003020105a10e1b0c",
        "4558414d504c452e53495445a221301fa003020102a11830161b066b72627467741b0c45",
        "58414d504c452e53495445a340303ea003020112a103020102a232043000010203040506",
        "0708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a",
        "2b2c2d2e2fa381f63081f3a003020100a281eb0481e87d81e53081e2a081df3081dc3081",
        "d9a02b3029a003020112a12204205a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        "5a5a5a5a5a5a5a5a5a5aa10e1b0c4558414d504c452e53495445a2123010a003020101a1",
        "0930071b05616c696365a30703050000500000a411180f32303236303732383132303030",
        "305aa511180f32303236303732383132303030305aa611180f3230323630373238323230",
        "3030305aa711180f32303236303830343132303030305aa80e1b0c4558414d504c452e53",
        "495445a921301fa003020102a11830161b066b72627467741b0c4558414d504c452e5349",
        "5445",
    );

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn encodes_the_golden_cache_byte_for_byte() {
        let tgt = ccache_to_tgt(GOLDEN_CCACHE).unwrap();
        assert_eq!(tgt.krbcred, unhex(GOLDEN_KRBCRED));
        // 2026-07-28 12:00:00Z, +10 h, renewable to +7 d.
        assert_eq!(
            (tgt.start, tgt.end, tgt.renew_till),
            (1_785_240_000, 1_785_276_000, 1_785_844_800)
        );
    }

    /// Builds a cache in the layout the module doc documents, so a mistake in the
    /// reader shows up as a parse failure rather than a plausible wrong answer.
    struct Builder(Vec<u8>);

    impl Builder {
        fn new() -> Self {
            // version, then a 12-byte DELTATIME header exactly as kinit writes.
            let mut b = vec![0x05, 0x04, 0x00, 0x0c];
            b.extend_from_slice(&[0x00, 0x01, 0x00, 0x08]);
            b.extend_from_slice(&[0u8; 8]);
            Self(b)
        }

        fn bytes(&mut self, s: &[u8]) {
            self.0.extend_from_slice(&(s.len() as u32).to_be_bytes());
            self.0.extend_from_slice(s);
        }

        fn principal(&mut self, realm: &str, components: &[&str]) {
            self.0.extend_from_slice(&1u32.to_be_bytes());
            self.0.extend_from_slice(&(components.len() as u32).to_be_bytes());
            self.bytes(realm.as_bytes());
            for c in components {
                self.bytes(c.as_bytes());
            }
        }

        fn credential(
            &mut self,
            server: (&str, &[&str]),
            times: [u32; 4],
            flags: u32,
            ticket: &[u8],
        ) {
            self.principal("EXAMPLE.SITE", &["alice"]);
            self.principal(server.0, server.1);
            self.0.extend_from_slice(&18u16.to_be_bytes()); // keytype
            self.bytes(&[0x5a; 32]);
            for t in times {
                self.0.extend_from_slice(&t.to_be_bytes());
            }
            self.0.push(0); // is_skey
            self.0.extend_from_slice(&flags.to_be_bytes());
            self.0.extend_from_slice(&0u32.to_be_bytes()); // addresses
            self.0.extend_from_slice(&0u32.to_be_bytes()); // authdata
            self.bytes(ticket);
            self.bytes(b""); // second ticket
        }
    }

    /// The `X-CACHECONF:` pseudo-credential kinit writes first, then the TGT.
    /// The ticket bytes are a marker, not DER: nothing here parses the ticket.
    fn sample(times: [u32; 4], flags: u32) -> Vec<u8> {
        let mut b = Builder::new();
        b.principal("EXAMPLE.SITE", &["alice"]);
        b.credential(
            (
                "X-CACHECONF:",
                &["krb5_ccache_conf_data", "fast_avail", "krbtgt/EXAMPLE.SITE@EXAMPLE.SITE"],
            ),
            [0, 0, 0, 0],
            0,
            b"yes",
        );
        b.credential(("EXAMPLE.SITE", &["krbtgt", "EXAMPLE.SITE"]), times, flags, TICKET);
        b.0
    }

    const TICKET: &[u8] = b"--not-really-der-but-distinctive--";

    #[test]
    fn picks_the_tgt_and_not_the_config_entry() {
        // The config entry names krbtgt/... in a *component*, so a looser match
        // would submit a configuration string to the LSA as a ticket.
        let tgt = ccache_to_tgt(&sample([1000, 1000, 37000, 605_800], 0)).unwrap();
        assert!(contains(&tgt.krbcred, TICKET));
        assert!(!contains(&tgt.krbcred, b"yes"));
    }

    #[test]
    fn carries_the_kdcs_ticket_bytes_verbatim() {
        // Re-encoding the ticket would put this code between the KDC's signature
        // and the LSA. It is copied, not parsed.
        let tgt = ccache_to_tgt(&sample([1000, 1000, 37000, 0], 0)).unwrap();
        assert!(contains(&tgt.krbcred, TICKET));
    }

    #[test]
    fn a_missing_starttime_falls_back_to_authtime() {
        // MIT stores 0 for an absent optional time. Taken literally that is
        // 1970-01-01, which would make the ticket look 55 years old to the tray's
        // half-life timer.
        let tgt = ccache_to_tgt(&sample([1000, 0, 37000, 0], 0)).unwrap();
        assert_eq!(tgt.start, 1000);
        // ... and the field is omitted from the encoding rather than sent as 1970.
        assert!(!contains(&tgt.krbcred, b"\xa5\x11\x18\x0f"), "starttime [5] must be absent");
    }

    #[test]
    fn omits_renew_till_when_the_ticket_is_not_renewable() {
        let renewable = ccache_to_tgt(&sample([1000, 1000, 37000, 605_800], 0)).unwrap();
        let plain = ccache_to_tgt(&sample([1000, 1000, 37000, 0], 0)).unwrap();
        assert!(contains(&renewable.krbcred, b"\xa7\x11\x18\x0f"));
        assert!(!contains(&plain.krbcred, b"\xa7\x11\x18\x0f"));
        assert_eq!(plain.renew_till, 0);
    }

    #[test]
    fn reports_a_cache_with_no_tgt_rather_than_encoding_nothing() {
        let mut b = Builder::new();
        b.principal("EXAMPLE.SITE", &["alice"]);
        b.credential(("EXAMPLE.SITE", &["cifs", "nas.example.site"]), [1, 1, 2, 0], 0, TICKET);
        let err = ccache_to_tgt(&b.0).err().unwrap().to_string();
        assert!(err.contains("no TGT"), "{err}");
    }

    #[test]
    fn rejects_a_foreign_version() {
        let mut c = sample([1000, 1000, 37000, 0], 0);
        c[1] = 0x03; // the v3 layout has an extra etype field we do not read
        let err = ccache_to_tgt(&c).err().unwrap().to_string();
        assert!(err.contains("unsupported ccache version"), "{err}");
    }

    #[test]
    fn rejects_truncation_instead_of_guessing() {
        let full = sample([1000, 1000, 37000, 0], 0);
        assert!(ccache_to_tgt(&full[..full.len() - 4]).is_err());
    }

    #[test]
    fn kerberos_time_is_utc_to_the_second() {
        // GeneralizedTime, 15 bytes, no fractional part.
        assert_eq!(kerberos_time(0)[..2], [TAG_GENERALIZED_TIME, 15]);
        // The epoch, a leap day, and the golden fixture's instant.
        assert_eq!(&kerberos_time(0)[2..], b"19700101000000Z");
        assert_eq!(&kerberos_time(1_709_164_800)[2..], b"20240229000000Z");
        assert_eq!(&kerberos_time(1_785_240_000)[2..], b"20260728120000Z");
    }

    #[test]
    fn der_lengths_take_the_long_form_past_127_bytes() {
        assert_eq!(tlv(0x04, &[0u8; 3])[..2], [0x04, 0x03]);
        assert_eq!(tlv(0x04, &[0u8; 200])[..3], [0x04, 0x81, 200]);
        assert_eq!(tlv(0x04, &[0u8; 400])[..4], [0x04, 0x82, 0x01, 0x90]);
    }

    #[test]
    fn integers_are_minimal_but_never_negative_by_accident() {
        assert_eq!(integer(0), [0x02, 0x01, 0x00]);
        assert_eq!(integer(5), [0x02, 0x01, 0x05]);
        assert_eq!(integer(18), [0x02, 0x01, 0x12]);
        // 128 needs a leading zero or it would decode as -128.
        assert_eq!(integer(128), [0x02, 0x02, 0x00, 0x80]);
    }
}
