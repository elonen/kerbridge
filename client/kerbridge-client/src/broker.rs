//! Talk to the KerBridge broker over TLS.
//!
//! The helper presents the IdP's access token as an HTTP bearer credential to
//! `POST {broker}/ticket`; the broker validates it, resolves the identity to a
//! Samba account, issues a TGT, and returns it as a base64 MIT ccache. That
//! ccache is injected unchanged by `krbcred.rs` + `lsa.rs`.
//!
//! The helper discriminates failures on **status code plus body**, not on
//! reachability (`client/DESIGN.md` @ the broker contract). A live broker's 4xx is
//! an identity or authorization problem the user must act on; its 5xx is a
//! server-side outage to retry; a transport error means the broker is
//! unreachable. These are different tray states, so they are different error
//! variants here rather than one opaque string.

use base64::Engine;

/// A TGT fetched from the broker.
///
/// No `Debug`: `ccache` contains a live ticket and its session key.
pub struct Ticket {
    pub principal: String,
    /// Raw MIT ccache bytes (a fresh TGT for `principal`).
    pub ccache: Vec<u8>,
}

/// The one 403 reason that means "device grants specifically", as opposed to
/// anything about this account's standing in the realm. `DESIGN.md` @ Public
/// broker API lists all five verbatim and calls them contract, because the
/// difference is what a user is told to do next: a person refused this one is
/// admitted, can sign in with a browser that same minute, and needs an
/// administrator only if they want to stop doing so.
///
/// Spelled here because the client shares no crate with the broker. `make test`
/// holds both sources and that table to the same list.
pub const REFUSED_NOT_GRANTED: &str = "account may not authorize a device";

/// The deployment has the feature off outright -- a different sentence again,
/// because no administrator action on *this account* would change it.
pub const REFUSED_GRANTS_DISABLED: &str = "device grants are not enabled";

/// The caller signed in perfectly well and is admitted -- they are simply not a
/// delegate of the account they named. A fourth sentence, because it is the only
/// one of these whose fix is an edit to *another* account's delegate group, and
/// because it must never send anyone to a browser: the sign-in that produced it
/// was already good.
pub const REFUSED_NOT_DELEGATE: &str = "you may not authorize a device for that account";

/// A broker failure, categorized so the caller can choose an action without
/// parsing a message. The string is the broker's short reason, safe to show.
#[derive(Debug)]
pub enum BrokerError {
    /// 400 -- the request itself was malformed. A helper bug, not the user's.
    BadRequest(String),
    /// 401 -- the identity proof was rejected. Re-authentication is the fix.
    InvalidProof(String),
    /// 403 -- a valid identity that is not provisioned, is disabled, is outside
    /// the admission group, or may not authorize a device. Re-injection will not
    /// help; the user must take it up with an administrator.
    ///
    /// The string is the broker's own reason, verbatim, and they are worth
    /// telling apart -- see [`REFUSED_NOT_GRANTED`].
    NotAdmitted(String),
    /// 404 -- the device this names is not on the account. Already revoked, most
    /// likely, which is the same outcome the caller wanted.
    NotFound(String),
    /// 409 -- the account already holds as many devices as the operator allows.
    /// A refusal rather than an eviction: evicting the oldest would let one
    /// device push out the others.
    Conflict(String),
    /// 429 -- rate limited. Back off and retry.
    RateLimited,
    /// 502/503 -- the directory, issuer, or realm is temporarily unavailable.
    /// The account is undamaged; retry with backoff.
    ServerUnavailable(String),
    /// Any other status from a live broker.
    Unexpected(u16, String),
    /// The broker could not be reached at all.
    Unreachable(String),
    /// The broker answered, but its certificate did not validate.
    ///
    /// Distinct from `Unreachable` because the two want opposite advice: an
    /// unreachable broker is worth retrying and this is not. The string carries
    /// the certificate that was refused, which is the only evidence there is.
    /// See [`crate::tls`].
    Untrusted(String),
    /// The broker answered, but not in the shape the contract promises.
    BadResponse(String),
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadRequest(m) => write!(f, "broker rejected the request as malformed: {m}"),
            Self::InvalidProof(m) => write!(f, "broker rejected the identity proof: {m}"),
            // Names no reason of its own. This one variant carries four of them,
            // and asserting the most common produced "not admitted to the realm:
            // account may not authorize a device" for a user who was admitted
            // and could sign in with a browser that minute.
            Self::NotAdmitted(m) => write!(f, "the broker refused this account: {m}"),
            Self::NotFound(m) => write!(f, "no such device on this account: {m}"),
            Self::Conflict(m) => write!(f, "too many devices already authorized: {m}"),
            Self::RateLimited => write!(f, "broker is rate limiting; back off and retry"),
            Self::ServerUnavailable(m) => write!(f, "broker dependency unavailable: {m}"),
            Self::Unexpected(s, m) => write!(f, "unexpected broker status {s}: {m}"),
            Self::Unreachable(m) => write!(f, "broker unreachable: {m}"),
            Self::Untrusted(m) => write!(f, "broker certificate not trusted: {m}"),
            Self::BadResponse(m) => write!(f, "broker response not understood: {m}"),
        }
    }
}

impl std::error::Error for BrokerError {}

/// Which proof a request carries, as the `Authorization` header names it.
/// Exactly one scheme, chosen here, because the broker refuses anything that is
/// neither rather than falling through to a weaker check.
pub enum AuthScheme<'a> {
    /// An IdP access token, from the browser or from WAM.
    Bearer(&'a str),
    /// A device-grant assertion, signed by this machine's TPM key.
    DeviceGrant(&'a str),
}

impl AuthScheme<'_> {
    fn header(&self) -> String {
        match self {
            Self::Bearer(t) => format!("Bearer {t}"),
            Self::DeviceGrant(a) => format!("DeviceGrant {a}"),
        }
    }
}

/// Exchange an identity proof for a TGT.
pub fn fetch_ticket(broker_url: &str, scheme: AuthScheme<'_>) -> Result<Ticket, BrokerError> {
    let url = format!("{}/ticket", broker_url.trim_end_matches('/'));
    let text = send(&url, Method::Post, Some(scheme), None)?;
    parse_ticket(&text)
}

enum Method {
    Get,
    Post,
    Delete,
}

/// One request, one classified failure. Every broker route answers the same way
/// -- a JSON body on 200, and `{"error": "...", "request_id": "..."}` on anything
/// else -- so the status mapping lives here once.
fn send(
    url: &str,
    method: Method,
    scheme: Option<AuthScheme<'_>>,
    body: Option<&serde_json::Value>,
) -> Result<String, BrokerError> {
    let agent = crate::http::agent();
    let auth = scheme.map(|s| s.header());
    // Split by method rather than built once and sent: `ureq` types a request
    // that may carry a body differently from one that may not, which is a
    // distinction worth keeping -- a `GET` with a body would be this code's bug.
    let sent = match method {
        Method::Get => {
            let mut request = agent.get(url);
            if let Some(auth) = &auth {
                request = request.header("Authorization", auth);
            }
            request.call()
        }
        Method::Delete => {
            let mut request = agent.delete(url);
            if let Some(auth) = &auth {
                request = request.header("Authorization", auth);
            }
            request.call()
        }
        Method::Post => {
            let mut request = agent.post(url);
            if let Some(auth) = &auth {
                request = request.header("Authorization", auth);
            }
            match body {
                // Serialized here rather than through a `json` feature on the
                // HTTP client: the request bodies in this file are two fixed
                // shapes, and `serde_json` is already a dependency.
                Some(json) => {
                    request.header("Content-Type", "application/json").send(json.to_string())
                }
                None => request.send_empty(),
            }
        }
    };
    let mut resp = sent.map_err(|e| {
        let failure = crate::http::describe(url, &e);
        if failure.untrusted {
            BrokerError::Untrusted(failure.message)
        } else {
            BrokerError::Unreachable(failure.message)
        }
    })?;

    let status = resp.status().as_u16();
    let text = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| BrokerError::BadResponse(format!("reading response body: {e}")))?;

    // 204 is `DELETE /devices/<id>` succeeding with nothing to say.
    if status == 200 || status == 201 || status == 204 {
        return Ok(text);
    }

    // The reason is short and safe to surface; the credential is never echoed.
    let reason = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
        .unwrap_or_else(|| text.trim().to_owned());

    Err(match status {
        400 => BrokerError::BadRequest(reason),
        401 => BrokerError::InvalidProof(reason),
        403 => BrokerError::NotAdmitted(reason),
        404 => BrokerError::NotFound(reason),
        409 => BrokerError::Conflict(reason),
        429 => BrokerError::RateLimited,
        502 | 503 => BrokerError::ServerUnavailable(reason),
        other => BrokerError::Unexpected(other, reason),
    })
}

/// Refuse the one spelling of a target the broker refuses, before it is sent.
///
/// A UPN is a second mutable spelling arriving as end-user input, so the wire
/// takes a login name or a literal `kb1|` value and nothing else. Checked here
/// as well as there because the round trip is a browser sign-in long on the
/// paths that carry a target, and being told at the end of one that the name was
/// never going to work is the worst place to learn it.
pub fn check_target(target: &str) -> Result<(), String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("empty target".to_owned());
    }
    if !target.starts_with("kb1|") && target.contains('@') {
        return Err(format!(
            "{target:?} looks like a UPN; name the account by its login name or its kb1| identity"
        ));
    }
    Ok(())
}

/// Add the account a request acts on, as the broker's `for` parameter. Absent is
/// the caller themselves, which is every request a deployment without delegation
/// ever makes.
fn for_target(url: String, target: Option<&str>) -> String {
    match target {
        Some(target) => {
            let query =
                form_urlencoded::Serializer::new(String::new()).append_pair("for", target).finish();
            format!("{url}?{query}")
        }
        None => url,
    }
}

/// A single-use nonce for a device assertion, and nothing else: the route is
/// unauthenticated because sixteen random bytes let nobody in.
pub fn fetch_nonce(broker_url: &str) -> Result<String, BrokerError> {
    let url = format!("{}/nonce", broker_url.trim_end_matches('/'));
    let text = send(&url, Method::Get, None, None)?;
    serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v.get("nonce").and_then(|n| n.as_str()).map(str::to_owned))
        .ok_or_else(|| BrokerError::BadResponse("nonce response has no `nonce`".into()))
}

/// A device grant as the broker reports it back.
pub struct Device {
    /// The operator handle, and what a revocation names.
    pub grant_id: String,
    /// The `kb1|` value this device must claim on every later exchange. Taken
    /// from the broker rather than assembled here: the encoding has exactly one
    /// implementation, and a client that spelled it differently would be refused
    /// on every exchange with nothing to point at.
    pub identity: String,
    /// What the machine called itself when it registered. Not unique -- two
    /// machines may claim the same one -- which is why a revocation names
    /// `grant_id` instead.
    pub label: String,
    /// Unix seconds.
    pub added: i64,
    /// Unix seconds, absent until the grant has been used, and day-granular
    /// when present.
    pub last_seen: Option<i64>,
    /// Unix seconds by which someone must sign in through a browser again.
    pub sign_in_required_by: i64,
    /// Whether the operator's current setting has moved that deadline in below
    /// the one stamped at registration.
    pub clamped: bool,
}

/// Strict about the three fields a later exchange depends on, lenient about the
/// rest: the others are only displayed, and a registration must not fail over a
/// field nothing acts on.
fn parse_device(json: &serde_json::Value) -> Result<Device, BrokerError> {
    let required = |key: &str| -> Result<String, BrokerError> {
        json.get(key)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or_else(|| BrokerError::BadResponse(format!("device response has no `{key}`")))
    };
    Ok(Device {
        grant_id: required("grant_id")?,
        identity: required("identity")?,
        sign_in_required_by: json
            .get("sign_in_required_by")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| {
                BrokerError::BadResponse("device response has no `sign_in_required_by`".into())
            })?,
        label: required("label").unwrap_or_default(),
        added: json.get("added").and_then(serde_json::Value::as_i64).unwrap_or_default(),
        last_seen: json.get("last_seen").and_then(serde_json::Value::as_i64),
        clamped: json.get("clamped").and_then(serde_json::Value::as_bool).unwrap_or_default(),
    })
}

/// Authorize this device, with the IdP token the user has just signed in with.
///
/// The token is what makes this an authorization at all: the broker has just
/// validated it and confirmed the account is synchronized, enabled, admitted and
/// permitted to hold device grants. No second admission decision is invented.
///
/// `target` names somebody else's account, and then the broker additionally
/// requires the signed-in user to be one of that account's delegates. The
/// [`Device::identity`] that comes back is the *target's*, which is the only
/// place this machine learns whose grant it now holds.
pub fn register_device(
    broker_url: &str,
    access_token: &str,
    alg: &str,
    public_key_b64url: &str,
    label: &str,
    target: Option<&str>,
) -> Result<Device, BrokerError> {
    let url = format!("{}/devices", broker_url.trim_end_matches('/'));
    let mut body = serde_json::json!({ "alg": alg, "key": public_key_b64url, "label": label });
    // A body field rather than a query parameter on this one route, because this
    // is the only one of the three that has a body to put it in.
    if let Some(target) = target {
        body["for"] = serde_json::Value::String(target.to_owned());
    }
    let text = send(&url, Method::Post, Some(AuthScheme::Bearer(access_token)), Some(&body))?;
    let json: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| BrokerError::BadResponse(format!("device response is not JSON: {e}")))?;
    parse_device(&json)
}

/// Every device this account has authorized, the same values `kbmanage device
/// list` prints -- read off the user's own directory object, through their token.
/// With a `target`, the account they are a delegate of instead.
///
/// A token and not an assertion: a machine holding one grant has no business
/// enumerating the account's others.
pub fn list_devices(
    broker_url: &str,
    access_token: &str,
    target: Option<&str>,
) -> Result<Vec<Device>, BrokerError> {
    let url = for_target(format!("{}/devices", broker_url.trim_end_matches('/')), target);
    let text = send(&url, Method::Get, Some(AuthScheme::Bearer(access_token)), None)?;
    let json: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| BrokerError::BadResponse(format!("device list is not JSON: {e}")))?;
    json.get("devices")
        .and_then(|v| v.as_array())
        .ok_or_else(|| BrokerError::BadResponse("device list has no `devices` array".into()))?
        .iter()
        .map(parse_device)
        .collect()
}

/// Stop one device.
///
/// Removing *another* device needs an IdP token, because a compromised machine
/// must not be able to knock the user's other devices offline. Removing *this*
/// one -- giving up the grant -- may present its own assertion, because leaving
/// is not an attack.
///
/// `target` therefore only ever goes with an [`AuthScheme::Bearer`]: the broker
/// refuses an assertion that names another account outright, on the same rule
/// that already binds a machine to its own thumbprint.
pub fn revoke_device(
    broker_url: &str,
    scheme: AuthScheme<'_>,
    grant_id: &str,
    target: Option<&str>,
) -> Result<(), BrokerError> {
    let url =
        for_target(format!("{}/devices/{grant_id}", broker_url.trim_end_matches('/')), target);
    send(&url, Method::Delete, Some(scheme), None).map(|_| ())
}

fn parse_ticket(text: &str) -> Result<Ticket, BrokerError> {
    let json: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| BrokerError::BadResponse(format!("200 body is not JSON: {e}")))?;
    let principal = json
        .get("principal")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BrokerError::BadResponse("200 body has no `principal`".into()))?
        .to_owned();
    let ccache_b64 = json
        .get("ccache_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BrokerError::BadResponse("200 body has no `ccache_b64`".into()))?;
    let ccache = base64::engine::general_purpose::STANDARD
        .decode(ccache_b64)
        .map_err(|e| BrokerError::BadResponse(format!("ccache_b64 is not base64: {e}")))?;
    Ok(Ticket { principal, ccache })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device_json() -> serde_json::Value {
        serde_json::json!({
            "grant_id": "1a2b3c4d",
            "identity": "kb1|entra|33334444-dddd-5555-eeee-6666ffff7777",
            "label": "BUILD01\\builder",
            "added": 1_785_000_000i64,
            "last_seen": 1_785_600_000i64,
            "sign_in_required_by": 1_787_592_000i64,
            "clamped": false,
        })
    }

    #[test]
    fn a_device_carries_what_a_later_exchange_and_a_listing_need() {
        let device = parse_device(&device_json()).expect("parses");
        assert_eq!(device.grant_id, "1a2b3c4d");
        assert_eq!(device.identity, "kb1|entra|33334444-dddd-5555-eeee-6666ffff7777");
        assert_eq!(device.label, "BUILD01\\builder");
        assert_eq!(device.sign_in_required_by, 1_787_592_000);
        assert_eq!(device.last_seen, Some(1_785_600_000));
        assert!(!device.clamped);

        // Omitted until the grant has been used, which is not the same as used
        // at the epoch: a listing must be able to say "never".
        let mut unused = device_json();
        unused.as_object_mut().unwrap().remove("last_seen");
        assert_eq!(parse_device(&unused).unwrap().last_seen, None);
    }

    /// A `kb1|` value carries the delimiter `|`, which is not a query-string
    /// character: the one thing this must not do is send it raw.
    #[test]
    fn a_literal_identity_survives_the_query_string() {
        let id = "kb1|entra|33334444-dddd-5555-eeee-6666ffff7777";
        let url = for_target("https://broker.example.site/devices".into(), Some(id));
        assert!(!url.contains('|'), "{url}");
        assert!(url.contains("kb1%7Centra"), "{url}");
        assert!(url.starts_with("https://broker.example.site/devices?for="), "{url}");
        assert_eq!(for_target("https://b/devices".into(), None), "https://b/devices");
    }

    #[test]
    fn a_upn_is_refused_before_it_costs_a_sign_in() {
        assert!(check_target("svc-builder").is_ok());
        assert!(check_target("kb1|entra|33334444-dddd-5555-eeee-6666ffff7777").is_ok());
        assert!(check_target("riku@example.site").is_err());
        assert!(check_target("  ").is_err());
    }

    /// The strict/lenient split: a missing display field costs a blank column, a
    /// missing required one must cost the whole registration.
    #[test]
    fn only_the_fields_a_later_exchange_depends_on_are_required() {
        for cosmetic in ["label", "added", "clamped", "last_seen"] {
            let mut json = device_json();
            json.as_object_mut().unwrap().remove(cosmetic);
            assert!(parse_device(&json).is_ok(), "{cosmetic} must not fail a registration");
        }
        for required in ["grant_id", "identity", "sign_in_required_by"] {
            let mut json = device_json();
            json.as_object_mut().unwrap().remove(required);
            assert!(parse_device(&json).is_err(), "{required} must be refused");
        }
    }
}
