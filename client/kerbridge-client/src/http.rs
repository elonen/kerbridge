//! One outbound HTTP agent, shared by every module that makes a request.
//!
//! TLS is validated against the OS trust store via `native-tls` -- SChannel on
//! Windows. That store holds both the operator's LAN CA (which signs the broker
//! certificate) and the public roots for `login.microsoftonline.com`, so the
//! same agent reaches the broker and the IdP without carrying its own roots.
//!
//! `root_certs(PlatformVerifier)` is necessary, not decoration. ureq's
//! `TlsConfig` defaults `root_certs` to its bundled webpki set even under the
//! native-tls provider, and native-tls treats any supplied roots as the *only*
//! trusted roots -- so the default would hand SChannel the webpki bundle, switch
//! it out of system-store validation, and reject the LAN-CA-signed broker
//! certificate with "unable to find any user-specified roots in the final cert
//! chain". Selecting the platform verifier is what lets SChannel use the
//! Windows store, where the operator installed the LAN CA.

/// How long any single request may take end to end. The tray runs these on a
/// worker thread that owns its only "busy" slot, so a request that never returns
/// would stop every future re-injection for the life of the process -- a stalled
/// read has to become an error, not a hang.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// `http_status_as_error(false)`: a 4xx or 5xx carries a body the caller wants
/// to read, not a transport error to unwrap.
pub fn agent() -> ureq::Agent {
    ureq::config::Config::builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .http_status_as_error(false)
        .tls_config(
            ureq::tls::TlsConfig::builder()
                .provider(ureq::tls::TlsProvider::NativeTls)
                .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                .build(),
        )
        .build()
        .new_agent()
}

/// True when the request died somewhere in TLS rather than on the network.
///
/// Not the same question as "was the certificate refused" -- a handshake that
/// aborts before any certificate exists lands in the same error variant. Which
/// of the two it was is [`Failure::untrusted`].
fn is_tls(e: &ureq::Error) -> bool {
    matches!(e, ureq::Error::NativeTls(_) | ureq::Error::Tls(_))
}

/// A failed request, classified by the evidence there turned out to be for it.
pub struct Failure {
    /// The request and what went wrong, plus the certificate the host presented
    /// when there was one.
    pub message: String,
    /// The host answered with a certificate that validation refused.
    ///
    /// False for a TLS failure that produced no certificate at all -- an
    /// aborted handshake, which on SChannel is what an IP literal gets, sending
    /// no SNI to a server with no default certificate (measured 2026-08-04,
    /// Windows 11 25H2: `SEC_E_INTERNAL_ERROR`, os error -2146893052, and the
    /// permissive probe fails identically). Reporting that as a trust problem
    /// sends its reader looking for a certificate that never existed.
    pub untrusted: bool,
}

/// Describe a failed request, probing for the certificate when TLS is what
/// failed.
///
/// The probe is a second connection, so it is made only on the failure that
/// cannot be diagnosed without one. See [`crate::tls`].
///
/// Logs it too, here rather than at each caller: what a user is shown is one
/// sentence that sends them to the log for the rest, and that has to be true
/// wherever the failure happened. Callers must not log it again.
pub fn describe(url: &str, e: &ureq::Error) -> Failure {
    let mut message = format!("{url}: {e}");
    if !is_tls(e) {
        return Failure { message, untrusted: false };
    }
    let Some(peer) = crate::tls::peer(url) else {
        crate::log::warn(&format!("TLS handshake failed before any certificate: {message}"));
        return Failure { message, untrusted: false };
    };
    message.push('\n');
    message.push_str(&peer.to_string());
    crate::log::warn(&format!("TLS validation failed: {message}"));
    Failure { message, untrusted: true }
}

/// Marker for an [`anyhow::Error`] whose cause was TLS validation, carrying
/// [`describe`]'s message.
///
/// Typed rather than recognized by its message text, because the UI has to tell
/// it from an unreachable host somehow: "check your network, then retry" is
/// actively wrong advice about a host that answered, on time, with a certificate
/// nobody trusts.
#[derive(Debug)]
pub struct Untrusted {
    /// Whose certificate was refused -- which is not always the broker. The one
    /// discovery call reaches the IdP too, and a message that names the broker
    /// for a certificate the IdP presented sends its reader to the wrong host.
    pub host: String,
    pub detail: String,
}

impl Untrusted {
    pub fn new(url: &str, detail: String) -> Self {
        Self { host: host_of_url(url), detail }
    }
}

/// The host part of a URL, or the whole URL when it will not parse -- a failure
/// message with a mangled address in it still beats one with nothing.
pub fn host_of_url(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_owned))
        .unwrap_or_else(|| url.to_owned())
}

impl std::fmt::Display for Untrusted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for Untrusted {}

/// The host whose certificate was refused, if that is what failed anywhere in
/// this error's chain.
pub fn untrusted_host(e: &anyhow::Error) -> Option<&str> {
    e.chain().find_map(|cause| cause.downcast_ref::<Untrusted>()).map(|u| u.host.as_str())
}
