//! The endpoint half: one `GET /config` over the path a client would use.
//!
//! This is the readiness question both deployments share, and the only piece of
//! it that is not about Docker. `deploy/scripts/compose/wait-ready.sh` used to own it,
//! beside four `docker inspect` checks and a Caddy TLS-strategy branch that
//! cannot survive off Compose; `ci-stack.sh` grew a second, weaker copy that
//! would have passed a broker answering an unrouted 404. What both need is here
//! once: connect, judge the certificate, ask, and tell the two 404s apart.
//!
//! Blocking I/O, like the LDAPS preflight beside it in [`crate::directory`] and
//! for the same reason: this is one request with a deadline, run by a human or a
//! poll loop, and there is nothing to overlap it with.
//!
//! What is deliberately *not* here: the HTTP client. A dependency that follows
//! redirects, negotiates HTTP/2 and pools connections would answer a different
//! question from the one asked -- "did something eventually serve me" rather
//! than "does this endpoint answer this path" -- and the answer has to be the
//! literal status the endpoint gave, because a 404 is a pass in one case and the
//! whole failure in the other.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, bail};

use crate::model::{Answer, CertFault, Endpoint, TrustAnchor};

/// The document every client bootstraps from, and so the one path worth asking
/// for: it is served by the broker itself, behind whatever terminates TLS.
const CONFIG_PATH: &str = "/config";

/// A ceiling on what is read back. The discovery document is a few hundred
/// bytes; anything past this is not the broker answering, and reading it to the
/// end would let a wrong endpoint hold the probe open instead of failing it.
const MAX_BODY: usize = 64 * 1024;

/// What to ask, and how to judge the answer.
pub struct Request {
    /// The public base a client would be given: `https://kerbridge.example.site`,
    /// with an optional port and an optional source segment. `/config` is
    /// appended, because that is the path being asked about.
    pub base: String,
    /// Connect here instead of resolving the base's host, as `curl --resolve`
    /// does: `127.0.0.1`, or `127.0.0.1:8443`. The certificate is still judged
    /// against the name in the URL, which is the point -- a published port on
    /// loopback and a name only the site's own resolver answers are the normal
    /// shape of this endpoint.
    pub via: Option<String>,
    pub anchor: TrustAnchor,
    /// Complete the handshake whatever certificate is presented, and report what
    /// was wrong with it instead of stopping there.
    ///
    /// Safe here in a way it would not be on the bind path: this exchange sends
    /// no credential and carries nothing back that a listener could not have
    /// asked for itself. An operator supplying their own certificate is not
    /// asked to prove it to us -- but they are told what it would say to a
    /// client, which is the fact they actually need.
    pub any_cert: bool,
    pub timeout: Duration,
}

/// Ask the endpoint, and record every link on the way.
///
/// Returns `Err` only for a request that cannot be made at all -- a URL that
/// does not parse, a scheme that is not HTTP. Everything the network answers,
/// including nothing, is a field on [`Endpoint`] for `doctor` to word.
pub fn probe(req: &Request) -> Result<Endpoint> {
    let url = url::Url::parse(&req.base)
        .map_err(|e| anyhow::anyhow!("{} is not a URL: {e}", req.base))?;
    let tls = match url.scheme() {
        "https" => true,
        "http" => false,
        other => bail!(
            "{} names the {other} scheme: the endpoint is HTTP, over TLS the deployment \
             terminates (https://) or plain to a broker's own listen address (http://)",
            req.base
        ),
    };
    let Some(host) = host_of(&url) else { bail!("{} names no host to ask", req.base) };
    let port = url.port().unwrap_or(if tls { 443 } else { 80 });
    // A base may carry the source segment -- `https://host/entra` -- because
    // that is the URL a multi-source deployment hands a client. Asking for
    // `/config` under it is then the unambiguous question, and the 404 that
    // lists the sources cannot arise.
    let prefix = url.path().trim_end_matches('/');
    let path = match prefix.strip_suffix(CONFIG_PATH) {
        Some(_) => prefix.to_owned(),
        None => format!("{prefix}{CONFIG_PATH}"),
    };

    let mut endpoint = Endpoint {
        asked: format!("{}://{host}:{port}{path}", url.scheme()),
        host: host.clone(),
        port,
        tls,
        via: None,
        anchor: req.anchor.clone(),
        any_cert: req.any_cert,
        resolve: None,
        tcp: None,
        cert: None,
        session: None,
        answer: None,
    };

    let addrs: Vec<SocketAddr> = match &req.via {
        Some(via) => match parse_via(via, port) {
            Ok(addr) => {
                endpoint.via = Some(addr);
                vec![addr]
            }
            Err(e) => {
                endpoint.resolve = Some(Err(e));
                return Ok(endpoint);
            }
        },
        None => match (host.as_str(), port).to_socket_addrs() {
            Ok(found) => {
                let addrs: Vec<SocketAddr> = found.collect();
                if addrs.is_empty() {
                    endpoint.resolve =
                        Some(Err("the resolver answered with no address".to_owned()));
                    return Ok(endpoint);
                }
                endpoint.resolve = Some(Ok(addrs.iter().map(SocketAddr::ip).collect()));
                addrs
            }
            Err(e) => {
                endpoint.resolve = Some(Err(e.to_string()));
                return Ok(endpoint);
            }
        },
    };

    // Every address, not just the first: an AAAA record on a host with no IPv6
    // route is the case where stopping at the first refusal reports a working
    // endpoint as down.
    let mut opened = None;
    let mut refused = String::new();
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, req.timeout) {
            Ok(sock) => {
                opened = Some((*addr, sock));
                break;
            }
            Err(e) => refused = format!("{addr}: {e}"),
        }
    }
    let Some((addr, mut sock)) = opened else {
        endpoint.tcp = Some(Err(refused));
        return Ok(endpoint);
    };
    endpoint.tcp = Some(Ok(addr));
    // Without these, a peer that accepts a connection and then says nothing
    // hangs the probe instead of diagnosing it -- which for a readiness loop is
    // the difference between a report and a stall.
    let _ = sock.set_read_timeout(Some(req.timeout));
    let _ = sock.set_write_timeout(Some(req.timeout));

    if !tls {
        endpoint.answer = Some(exchange(&mut sock, &host, port, &path));
        return Ok(endpoint);
    }

    let verdict = Arc::new(Mutex::new(None));
    let config = match client_config(&req.anchor, req.any_cert, verdict.clone()) {
        Ok(config) => config,
        Err(fault) => {
            endpoint.cert = Some(Err(fault));
            return Ok(endpoint);
        }
    };
    let name = match rustls::pki_types::ServerName::try_from(host.clone()) {
        Ok(name) => name,
        Err(e) => {
            endpoint.cert = Some(Err(CertFault::Other(format!(
                "{host} is not a name a certificate can carry: {e}"
            ))));
            return Ok(endpoint);
        }
    };
    let mut conn = match rustls::ClientConnection::new(Arc::new(config), name) {
        Ok(conn) => conn,
        Err(e) => {
            endpoint.session = Some(Err(e.to_string()));
            return Ok(endpoint);
        }
    };
    let handshake = conn.complete_io(&mut sock);
    // Read the verifier's note first: with `any_cert` the handshake completed
    // over a certificate it had already objected to, and that objection is the
    // remark the caller needs. Without it, the same note is the diagnosis of the
    // failure below.
    endpoint.cert = verdict.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Err(e) = handshake {
        // Recorded with or without a certificate verdict beside it: the two are
        // different failures, and with no verdict nothing was presented at all
        // -- what an endpoint whose issuance is still in flight looks like from
        // here.
        endpoint.session = Some(Err(e.to_string()));
        return Ok(endpoint);
    }
    endpoint.session = Some(Ok(()));

    let mut stream = rustls::StreamOwned::new(conn, sock);
    endpoint.answer = Some(exchange(&mut stream, &host, port, &path));
    Ok(endpoint)
}

/// `--resolve`: an address, with the URL's port unless it carries its own.
fn parse_via(via: &str, port: u16) -> Result<SocketAddr, String> {
    if let Ok(addr) = via.parse::<SocketAddr>() {
        return Ok(addr);
    }
    match via.parse::<IpAddr>() {
        Ok(ip) => Ok(SocketAddr::new(ip, port)),
        Err(e) => Err(format!(
            "--resolve {via} is not an address: {e}. It takes an IP, or an IP and a port \
             -- 127.0.0.1, or 127.0.0.1:8443 -- and never a name, since naming one is \
             what it exists to avoid"
        )),
    }
}

/// The URL's host, unbracketed: `ServerName` and `to_socket_addrs` both want the
/// address itself, and `host_str` would hand them a v6 URL's brackets.
fn host_of(url: &url::Url) -> Option<String> {
    match url.host()? {
        url::Host::Domain(name) => Some(name.to_owned()),
        url::Host::Ipv4(addr) => Some(addr.to_string()),
        url::Host::Ipv6(addr) => Some(addr.to_string()),
    }
}

/// A client that records the verdict rather than only acting on it.
///
/// Trust is a fact the operator needs whichever way it comes out: under an ACME
/// strategy a certificate the public roots reject is the failure, and under a
/// supplied one the same certificate is the operator's own business and the
/// route behind it is what was being asked about. One handshake answers both,
/// so there is no second probe whose result could differ from the first.
#[derive(Debug)]
struct Recording {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    any_cert: bool,
    verdict: Arc<Mutex<Option<Result<(), CertFault>>>>,
}

impl rustls::client::danger::ServerCertVerifier for Recording {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let outcome = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        *self.verdict.lock().unwrap_or_else(|e| e.into_inner()) = Some(match &outcome {
            Ok(_) => Ok(()),
            Err(e) => Err(crate::certificate::of(e)),
        });
        match outcome {
            Err(e) if !self.any_cert => Err(e),
            _ => Ok(rustls::client::danger::ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn client_config(
    anchor: &TrustAnchor,
    any_cert: bool,
    verdict: Arc<Mutex<Option<Result<(), CertFault>>>>,
) -> Result<rustls::ClientConfig, CertFault> {
    let store = match anchor {
        // Compiled in rather than read from the host's store. The binary this
        // ships as is `scratch` plus itself and a package installs it on hosts
        // whose bundle may be anywhere; a probe that silently trusted an empty
        // store would report every ACME certificate as untrusted.
        TrustAnchor::Public => {
            let mut store = rustls::RootCertStore::empty();
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            store
        }
        TrustAnchor::Ca(path) => {
            kerbridge_core::tls::root_store(path).map_err(|e| CertFault::NoCa(format!("{e:#}")))?
        }
    };
    // Named rather than inherited, for the reason `kerbridge_core::tls` gives:
    // `ClientConfig::builder()` resolves a process-global default provider.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(store),
        provider.clone(),
    )
    .build()
    .map_err(|e| CertFault::NoCa(e.to_string()))?;
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| CertFault::Other(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Recording { inner, any_cert, verdict }))
        .with_no_client_auth();
    // Offered so that nothing negotiates HTTP/2 behind this probe's back: what
    // is written below is a 1.1 request, and Caddy speaks h2 to anything that
    // asks.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// One request, one response, and the connection closed by the far end.
///
/// `Connection: close` rather than a content-length dance: the body is read to
/// the end of the stream, so an answer framed either way arrives whole.
fn exchange<S: Read + Write>(
    io: &mut S,
    host: &str,
    port: u16,
    path: &str,
) -> Result<Answer, String> {
    let authority = match (port, host.contains(':')) {
        (443 | 80, false) => host.to_owned(),
        (443 | 80, true) => format!("[{host}]"),
        (_, false) => format!("{host}:{port}"),
        (_, true) => format!("[{host}]:{port}"),
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: kbmanage/{}\r\n\
         Accept: application/json\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    io.write_all(request.as_bytes()).map_err(|e| format!("writing the request: {e}"))?;
    io.flush().map_err(|e| format!("writing the request: {e}"))?;

    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match io.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > MAX_BODY {
                    break;
                }
            }
            // A peer that closes without a TLS `close_notify` is every proxy
            // under load; the bytes already read are the answer, and only an
            // empty read is a failure to report.
            Err(e) if !raw.is_empty() => {
                let _ = e;
                break;
            }
            Err(e) => return Err(format!("reading the response: {e}")),
        }
    }
    parse(&raw)
}

/// The status, and the source list if the body carries one. Nothing else about
/// the document is this link's business.
fn parse(raw: &[u8]) -> Result<Answer, String> {
    if raw.is_empty() {
        return Err("the connection closed with no response".to_owned());
    }
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "the answer is not an HTTP response".to_owned())?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let body = &raw[split + 4..];

    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status: u16 =
        status_line.split_whitespace().nth(1).and_then(|code| code.parse().ok()).ok_or_else(
            || format!("the answer does not start with a status line: {status_line:?}"),
        )?;

    let chunked = lines.any(|line| {
        let (name, value) = line.split_once(':').unwrap_or((line, ""));
        name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
    });
    let body = if chunked { dechunk(body) } else { body.to_vec() };

    Ok(Answer { status, sources: sources_in(&body) })
}

/// The names in a `{"sources": [...]}` body, or `None` for a body that carries
/// no such list -- including one that is not JSON at all, which is what an
/// unrouted path answers with.
fn sources_in(body: &[u8]) -> Option<Vec<String>> {
    let document: serde_json::Value = serde_json::from_slice(body).ok()?;
    let listed = document.get("sources")?.as_array()?;
    Some(listed.iter().map(|name| name.as_str().unwrap_or_default().to_owned()).collect())
}

/// Chunked transfer, undone. Whatever cannot be read as a chunk ends the body,
/// because a partial answer is still worth classifying.
fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        let Some(eol) = rest.windows(2).position(|w| w == b"\r\n") else { return out };
        let size = String::from_utf8_lossy(&rest[..eol]);
        let size = size.split(';').next().unwrap_or_default().trim();
        let Ok(size) = usize::from_str_radix(size, 16) else { return out };
        rest = &rest[eol + 2..];
        if size == 0 || size > rest.len() {
            return out;
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size..];
        if rest.starts_with(b"\r\n") {
            rest = &rest[2..];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_is_appended_to_whatever_base_a_client_was_given() {
        for (base, asked) in [
            ("https://kerbridge.example.site", "https://kerbridge.example.site:443/config"),
            ("https://kerbridge.example.site/", "https://kerbridge.example.site:443/config"),
            ("https://kerbridge.example.site:8443", "https://kerbridge.example.site:8443/config"),
            (
                "https://kerbridge.example.site/entra",
                "https://kerbridge.example.site:443/entra/config",
            ),
            // Already the path being asked for: appending a second one would
            // turn the operator's own copy-paste into an unrouted 404.
            ("https://kerbridge.example.site/config", "https://kerbridge.example.site:443/config"),
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080/config"),
        ] {
            let request = Request {
                base: base.to_owned(),
                // Nothing is connected to: `--resolve` is parsed before any
                // socket is opened, and a bad one returns before this too.
                via: Some("not-an-address".to_owned()),
                anchor: TrustAnchor::Public,
                any_cert: false,
                timeout: Duration::from_secs(1),
            };
            assert_eq!(probe(&request).unwrap().asked, asked, "{base}");
        }
    }

    #[test]
    fn a_url_that_cannot_be_asked_is_refused_before_anything_is_opened() {
        let request = |base: &str| Request {
            base: base.to_owned(),
            via: None,
            anchor: TrustAnchor::Public,
            any_cert: false,
            timeout: Duration::from_secs(1),
        };
        let err = probe(&request("kerbridge.example.site")).unwrap_err().to_string();
        assert!(err.contains("is not a URL"), "{err}");
        // The mistake this catches is an operator handing it the LDAPS URL from
        // the same config set.
        let err = probe(&request("ldaps://kerbridge.example.site:636")).unwrap_err().to_string();
        assert!(err.contains("ldaps scheme"), "{err}");
    }

    #[test]
    fn resolve_takes_an_address_and_says_so_when_it_did_not() {
        let request = |via: &str| Request {
            base: "https://kerbridge.example.site".to_owned(),
            via: Some(via.to_owned()),
            anchor: TrustAnchor::Public,
            any_cert: false,
            timeout: Duration::from_secs(1),
        };
        assert_eq!(parse_via("127.0.0.1", 443), Ok("127.0.0.1:443".parse().unwrap()));
        assert_eq!(parse_via("127.0.0.1:8443", 443), Ok("127.0.0.1:8443".parse().unwrap()));
        let reported = probe(&request("localhost")).unwrap();
        let Some(Err(e)) = reported.resolve else { panic!("{:?}", reported.resolve) };
        assert!(e.contains("is not an address"), "{e}");
        assert!(reported.tcp.is_none(), "nothing may be opened after that");
    }

    #[test]
    fn the_two_404s_are_told_apart_by_the_body() {
        let unrouted = parse(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").unwrap();
        assert_eq!(unrouted.status, 404);
        assert_eq!(unrouted.sources, None);

        // What a broker serving several sources answers an unprefixed /config
        // with: a refusal that names them, because the operator has to put one
        // in a URL.
        let listed = parse(
            b"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n\
              {\"error\":\"which source?\",\"sources\":[\"entra\",\"google\"]}",
        )
        .unwrap();
        assert_eq!(listed.status, 404);
        assert_eq!(listed.sources.as_deref(), Some(&["entra".to_owned(), "google".to_owned()][..]));

        // The other 404 a broker itself can answer: a source segment naming
        // something this deployment does not serve. No list, like the unrouted
        // one -- which is why the wording of that verdict has to allow for both.
        let unknown = parse(
            b"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n\
              {\"error\":\"no such source\",\"request_id\":\"-\"}",
        )
        .unwrap();
        assert_eq!(unknown.sources, None);
    }

    #[test]
    fn a_chunked_body_is_read_like_any_other() {
        let answer = parse(
            b"HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\n\r\n\
              1b\r\n{\"sources\":[\"entra\"],\"a\":1}\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(answer.sources.as_deref(), Some(&["entra".to_owned()][..]));
    }

    #[test]
    fn something_that_is_not_an_http_response_is_not_a_status() {
        assert!(parse(b"").unwrap_err().contains("no response"));
        assert!(parse(b"\x15\x03\x01\x00\x02\x02\x28").unwrap_err().contains("not an HTTP"));
        let err = parse(b"nonsense\r\n\r\n").unwrap_err();
        assert!(err.contains("does not start with a status line"), "{err}");
    }
}
