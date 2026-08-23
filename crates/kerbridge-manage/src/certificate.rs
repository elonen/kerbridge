//! What a failed handshake was *about*, in one place.
//!
//! Two links ask it. The LDAPS preflight in [`crate::directory`] handshakes with
//! the DC, and the HTTPS probe in [`crate::endpoint`] handshakes with the public
//! endpoint; both get a `rustls` error and both have to separate an unknown
//! issuer from a name outside the SAN, because those two send an operator to
//! opposite files. A second mapping would eventually disagree about one of them,
//! and nothing would report that it had.

use crate::model::CertFault;

/// The typed verdict behind a `rustls` error.
pub fn of(e: &rustls::Error) -> CertFault {
    use rustls::CertificateError as C;

    match e {
        // A signature the configured CA cannot account for is the same fact as
        // an issuer it does not know: this CA is not the one that signed it.
        rustls::Error::InvalidCertificate(C::UnknownIssuer | C::BadSignature) => {
            CertFault::Untrusted
        }
        rustls::Error::InvalidCertificate(C::NotValidForName) => {
            CertFault::WrongName { presented: Vec::new() }
        }
        rustls::Error::InvalidCertificate(C::NotValidForNameContext { presented, .. }) => {
            CertFault::WrongName { presented: presented.clone() }
        }
        rustls::Error::InvalidCertificate(C::Expired | C::ExpiredContext { .. }) => {
            CertFault::Expired
        }
        other => CertFault::Other(other.to_string()),
    }
}

/// The same verdict, from the error a completed I/O reports.
///
/// `complete_io` wraps a TLS error in an `io::ErrorKind::InvalidData` error, so
/// the typed one is underneath it -- and the type is what these links are for.
pub fn of_io(e: &std::io::Error) -> CertFault {
    match e.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()) {
        Some(tls) => of(tls),
        None => CertFault::Other(e.to_string()),
    }
}
