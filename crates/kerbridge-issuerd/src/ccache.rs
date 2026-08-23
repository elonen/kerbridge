//! Just enough MIT ccache v4 to validate what `kinit` produced.
//!
//! `issuerd` must confirm that the cache it is about to hand back holds a TGT
//! for exactly the account it resolved, issued by the configured realm -- so it
//! has to read the bytes rather than trust the exit status. That needs four
//! timestamps and two principal names, which is a small enough slice of the
//! format to do without a dependency.
//!
//! Layout, confirmed by decoding a real `kinit` cache byte by byte:
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
//! Two things that are easy to get wrong and are pinned here by measurement:
//! v4 has **no** `etype` field in the keyblock -- that exists only in v3 -- and
//! all integers are big-endian, unlike the native-endian v1/v2 caches.

use anyhow::{Result, bail, ensure};

const VERSION_V4: u16 = 0x0504;

/// A credential's principal, flattened to the `name/name@REALM` text form.
#[derive(Debug, PartialEq, Eq)]
pub struct Principal {
    pub realm: String,
    pub components: Vec<String>,
}

impl Principal {
    /// `components/joined/by/slash@REALM`, the form `kinit` and `klist` print.
    pub fn display(&self) -> String {
        format!("{}@{}", self.components.join("/"), self.realm)
    }
}

/// RFC 4120 `TicketFlags`, in the packed form MIT stores them: bit 0 is the
/// most significant bit. Only the three issuance actually asserts on are named.
pub const TKT_FLG_INVALID: u32 = 0x0100_0000;
pub const TKT_FLG_RENEWABLE: u32 = 0x0080_0000;
pub const TKT_FLG_INITIAL: u32 = 0x0040_0000;

#[derive(Debug)]
pub struct Credential {
    pub client: Principal,
    pub server: Principal,
    pub starts_at: u32,
    pub expires_at: u32,
    pub renew_until: u32,
    pub flags: u32,
}

impl Credential {
    /// True for a real ticket-granting ticket.
    ///
    /// A fresh cache also carries `X-CACHECONF:` pseudo-credentials whose
    /// "ticket" is a configuration string rather than an encoded ticket. They
    /// name `krbtgt/...` in a *component*, so matching on the service name
    /// alone would accept one.
    pub fn is_tgt(&self, realm: &str) -> bool {
        self.server.realm == realm
            && self.server.components.len() == 2
            && self.server.components[0] == "krbtgt"
            && self.server.components[1] == realm
    }
}

/// Every credential in the cache, in file order.
pub fn credentials(bytes: &[u8]) -> Result<Vec<Credential>> {
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

    fn str(&mut self) -> Result<String> {
        let len = self.u32()? as usize;
        let raw = self.take(len)?;
        Ok(String::from_utf8_lossy(raw).into_owned())
    }

    fn principal(&mut self) -> Result<Principal> {
        let _name_type = self.u32()?;
        let n = self.u32()? as usize;
        let realm = self.str()?;
        let components = (0..n).map(|_| self.str()).collect::<Result<_>>()?;
        Ok(Principal { realm, components })
    }

    fn credential(&mut self) -> Result<Credential> {
        let client = self.principal()?;
        let server = self.principal()?;
        self.u16()?; // keytype
        self.str()?; // key
        let _authtime = self.u32()?;
        let starts_at = self.u32()?;
        let expires_at = self.u32()?;
        let renew_until = self.u32()?;
        self.skip(1)?; // is_skey
        let flags = self.u32()?;
        for _ in 0..self.u32()? {
            self.u16()?; // address type
            self.str()?;
        }
        for _ in 0..self.u32()? {
            self.u16()?; // authdata type
            self.str()?;
        }
        self.str()?; // ticket
        self.str()?; // second ticket
        Ok(Credential { client, server, starts_at, expires_at, renew_until, flags })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a cache in the layout documented above, so a mistake in the
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

        fn str(&mut self, s: &str) {
            self.0.extend_from_slice(&(s.len() as u32).to_be_bytes());
            self.0.extend_from_slice(s.as_bytes());
        }

        fn principal(&mut self, realm: &str, components: &[&str]) {
            self.0.extend_from_slice(&1u32.to_be_bytes());
            self.0.extend_from_slice(&(components.len() as u32).to_be_bytes());
            self.str(realm);
            for c in components {
                self.str(c);
            }
        }

        fn credential(
            &mut self,
            client: (&str, &[&str]),
            server: (&str, &[&str]),
            times: [u32; 4],
            flags: u32,
        ) {
            self.principal(client.0, client.1);
            self.principal(server.0, server.1);
            self.0.extend_from_slice(&0u16.to_be_bytes()); // keytype
            self.str(""); // key
            for t in times {
                self.0.extend_from_slice(&t.to_be_bytes());
            }
            self.0.push(0); // is_skey
            self.0.extend_from_slice(&flags.to_be_bytes()); // tktflags
            self.0.extend_from_slice(&0u32.to_be_bytes()); // addresses
            self.0.extend_from_slice(&0u32.to_be_bytes()); // authdata
            self.str("ticket");
            self.str("");
        }
    }

    fn sample() -> Vec<u8> {
        let mut b = Builder::new();
        b.principal("EXAMPLE.SITE", &["alice"]);
        // The config pseudo-credential kinit writes first, which names
        // krbtgt/EXAMPLE.SITE@EXAMPLE.SITE in a component.
        b.credential(
            ("EXAMPLE.SITE", &["alice"]),
            (
                "X-CACHECONF:",
                &["krb5_ccache_conf_data", "fast_avail", "krbtgt/EXAMPLE.SITE@EXAMPLE.SITE"],
            ),
            [0, 0, 0, 0],
            0,
        );
        b.credential(
            ("EXAMPLE.SITE", &["alice"]),
            ("EXAMPLE.SITE", &["krbtgt", "EXAMPLE.SITE"]),
            [1000, 1000, 37000, 605800],
            TKT_FLG_INITIAL | TKT_FLG_RENEWABLE,
        );
        b.0
    }

    #[test]
    fn reads_every_credential() {
        assert_eq!(credentials(&sample()).unwrap().len(), 2);
    }

    #[test]
    fn identifies_the_tgt_and_rejects_the_config_entry() {
        let creds = credentials(&sample()).unwrap();
        let tgts: Vec<_> = creds.iter().filter(|c| c.is_tgt("EXAMPLE.SITE")).collect();
        assert_eq!(tgts.len(), 1, "the X-CACHECONF: entry must not match");
        assert_eq!(tgts[0].client.display(), "alice@EXAMPLE.SITE");
        assert_eq!(tgts[0].server.display(), "krbtgt/EXAMPLE.SITE@EXAMPLE.SITE");
        assert_eq!((tgts[0].starts_at, tgts[0].expires_at), (1000, 37000));
        assert_eq!(tgts[0].renew_until, 605800);
        // The flags decide whether this is the ticket that was asked for, so
        // reading them off the right offset is not a detail.
        assert_eq!(tgts[0].flags, TKT_FLG_INITIAL | TKT_FLG_RENEWABLE);
        assert_eq!(tgts[0].flags & TKT_FLG_INVALID, 0);
    }

    #[test]
    fn a_tgt_for_another_realm_is_not_ours() {
        let creds = credentials(&sample()).unwrap();
        assert!(!creds.iter().any(|c| c.is_tgt("OTHER.SITE")));
    }

    #[test]
    fn rejects_a_foreign_version() {
        let mut b = sample();
        b[1] = 0x03; // the v3 layout has an extra etype field we do not read
        assert!(credentials(&b).unwrap_err().to_string().contains("unsupported ccache version"));
    }

    #[test]
    fn rejects_truncation_instead_of_guessing() {
        let full = sample();
        assert!(credentials(&full[..full.len() - 4]).is_err());
    }
}
