//! The issuer protocol: length-prefixed JSON over a Unix socket.
//!
//! A 4-byte big-endian length followed by that many bytes, capped at 64 KiB --
//! the framing proven by the container-runtime-boundaries spike. The cap exists
//! because the length is read before anything is allocated.
//!
//! This lives in `kerbridge-core` for the same reason the identity encoding
//! does: `issuerd` and the broker are two programs that must agree on it
//! exactly, and a private copy on each side is a divergence waiting to happen.
//! Every type here therefore derives both directions -- each process uses one
//! and the other keeps it honest.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

pub const MAX_FRAME: usize = 64 * 1024;

/// The one wire format the broker returns and `kerbridge-client` injects, pinned by
/// name so neither end infers it.
pub const TICKET_FORMAT: &str = "mit-ccache-v4";

/// The verbs `issuerd` answers.
///
/// Their *narrowness* is what makes it safe to put an internet-facing broker in
/// front of a domain administrator -- not `issuerd`'s privilege, which is
/// unavoidable. Every variant names exactly one thing to do to exactly one
/// account, identified by SID; none of them takes a DN, a filter or an attribute
/// name. Keep it that way.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Liveness only. The container healthcheck uses it, so it must not touch
    /// Samba or the directory.
    Ping,
    Issue(IssueRequest),
    GrantDevice(GrantDeviceRequest),
    RevokeGrant(RevokeGrantRequest),
    /// Stamp a grant's last-use day. Separate from [`Self::Issue`] rather than
    /// folded into it so the ticket verb stays exactly as narrow as it is today;
    /// called at most once per device per day, and its failure is ignored.
    TouchGrant(TouchGrantRequest),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IssueRequest {
    /// Opaque correlation id, echoed into the audit log. Never trusted as
    /// input to anything.
    pub request_id: String,
    /// The account to issue for. A SID rather than a name because it survives
    /// a rename, and because a name arriving from outside would be a string
    /// the issuer has to defend against.
    pub account_sid: String,
    pub lifetime_seconds: Option<u32>,
    pub renewable_lifetime_seconds: Option<u32>,
}

/// Record a device grant on an account. Idempotent: re-granting a thumbprint the
/// account already carries replaces that value rather than adding a second.
#[derive(Debug, Serialize, Deserialize)]
pub struct GrantDeviceRequest {
    pub request_id: String,
    pub account_sid: String,
    /// Checked against [`crate::grant::is_algorithm`] before anything is stored;
    /// the stored value is built server-side from these parts, never taken
    /// verbatim from the caller.
    pub alg: String,
    pub thumbprint: String,
    /// Client-chosen and therefore untrusted -- see
    /// [`crate::grant::sanitize_label`].
    pub label: String,
    /// Unix seconds. `issuerd` stamps `start` from its own clock.
    pub expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeGrantRequest {
    pub request_id: String,
    pub account_sid: String,
    pub thumbprint: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TouchGrantRequest {
    pub request_id: String,
    pub account_sid: String,
    pub thumbprint: String,
    /// Unix seconds of the use being recorded.
    pub seen: u64,
}

/// Tagged, like [`Request`]. An untagged response would be dispatched by
/// shape, which makes correctness depend on variant declaration order and on
/// no variant ever growing a field that lets it match another -- a failure
/// whose symptom would be the broker reading an error as a ticket. Nothing
/// outside this workspace speaks this protocol, so there is no shape to
/// preserve.
///
/// No `Debug`: deriving it here would require it for [`Ticket`].
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ok(Ticket),
    Error {
        request_id: String,
        error: String,
    },
    Pong {
        ok: bool,
    },
    /// The directory write happened. Carries nothing: a grant's operator handle
    /// is a function of its thumbprint, so the caller already holds it.
    Done {
        request_id: String,
    },
}

/// The three timestamps are [`crate::time::rfc3339`] of the values read out of
/// the issued ccache, so the helper plans its renewal against what the KDC
/// actually granted rather than against what was asked for.
///
/// No `Debug`: `ccache_b64` contains a live TGT and session key. Formatting it
/// would leak them to logs.
#[derive(Serialize, Deserialize)]
pub struct Ticket {
    pub request_id: String,
    pub principal: String,
    pub ticket_format: String,
    pub ccache_b64: String,
    pub starts_at: String,
    pub expires_at: String,
    pub renew_until: String,
}

pub fn read_frame(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds the {MAX_FRAME} byte cap"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn write_frame(w: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "response exceeds the frame cap"));
    }
    w.write_all(&(payload.len() as u32).to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_frame() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"{\"op\":\"ping\"}").unwrap();
        assert_eq!(&buf[..4], &13u32.to_be_bytes());
        assert_eq!(read_frame(&mut &buf[..]).unwrap(), b"{\"op\":\"ping\"}");
    }

    #[test]
    fn refuses_an_oversized_length_before_allocating() {
        let mut framed = (MAX_FRAME as u32 + 1).to_be_bytes().to_vec();
        framed.push(0);
        let err = read_frame(&mut &framed[..]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// The discriminant is on the wire, so each response decodes back to the
    /// variant it was written as regardless of what fields the others carry.
    #[test]
    fn responses_round_trip_to_the_variant_they_were_written_as() {
        let ticket = Response::Ok(Ticket {
            request_id: "r1".into(),
            principal: "alice@EXAMPLE.SITE".into(),
            ticket_format: TICKET_FORMAT.into(),
            ccache_b64: "AAAA".into(),
            starts_at: "2026-07-22T10:00:00Z".into(),
            expires_at: "2026-07-22T20:00:00Z".into(),
            renew_until: "2026-07-29T10:00:00Z".into(),
        });
        let json = serde_json::to_string(&ticket).unwrap();
        assert!(
            matches!(serde_json::from_str(&json).unwrap(), Response::Ok(t) if t.principal == "alice@EXAMPLE.SITE")
        );

        let err = Response::Error { request_id: "r2".into(), error: "unknown account".into() };
        let json = serde_json::to_string(&err).unwrap();
        assert!(
            matches!(serde_json::from_str(&json).unwrap(), Response::Error { error, .. } if error == "unknown account")
        );

        let pong = Response::Pong { ok: true };
        let json = serde_json::to_string(&pong).unwrap();
        assert!(matches!(serde_json::from_str(&json).unwrap(), Response::Pong { ok: true }));
    }

    /// Round-tripping alone would still pass if the tag were removed, so the
    /// discriminant is asserted on the wire, and a response missing it is
    /// asserted to be unreadable rather than guessed at.
    #[test]
    fn the_discriminant_is_on_the_wire() {
        let json = serde_json::to_string(&Response::Pong { ok: true }).unwrap();
        assert_eq!(json, r#"{"status":"pong","ok":true}"#);

        let json =
            serde_json::to_string(&Response::Error { request_id: "r".into(), error: "e".into() })
                .unwrap();
        assert_eq!(json, r#"{"status":"error","request_id":"r","error":"e"}"#);

        // A ticket-shaped body with no status is not a ticket.
        let untagged = r#"{"request_id":"r","principal":"p","ticket_format":"mit-ccache-v4",
            "ccache_b64":"","starts_at":"","expires_at":"","renew_until":""}"#;
        assert!(serde_json::from_str::<Response>(untagged).is_err());
    }

    #[test]
    fn parses_every_operation() {
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"op":"ping"}"#).unwrap(),
            Request::Ping
        ));
        let Request::Issue(r) = serde_json::from_str::<Request>(
            r#"{"op":"issue","request_id":"r1","account_sid":"S-1-5-21-1-2-3-1103"}"#,
        )
        .unwrap() else {
            panic!("expected an issue request");
        };
        assert_eq!(r.account_sid, "S-1-5-21-1-2-3-1103");
        assert_eq!(r.lifetime_seconds, None);

        let Request::GrantDevice(r) = serde_json::from_str::<Request>(
            r#"{"op":"grant_device","request_id":"r2","account_sid":"S-1-5-21-1-2-3-1103",
                "alg":"es256","thumbprint":"t","label":"BUILD01\\svc","expires_at":1785000000}"#,
        )
        .unwrap() else {
            panic!("expected a grant request");
        };
        assert_eq!(r.label, "BUILD01\\svc");
        assert_eq!(r.expires_at, 1_785_000_000);

        assert!(matches!(
            serde_json::from_str::<Request>(
                r#"{"op":"revoke_grant","request_id":"r3","account_sid":"S","thumbprint":"t"}"#
            )
            .unwrap(),
            Request::RevokeGrant(_)
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(
                r#"{"op":"touch_grant","request_id":"r4","account_sid":"S","thumbprint":"t","seen":1}"#
            )
            .unwrap(),
            Request::TouchGrant(_)
        ));
    }

    /// A write acknowledgment must not be readable as a ticket, and vice
    /// versa -- the tag is what guarantees it.
    #[test]
    fn a_completed_write_is_its_own_variant() {
        let json = serde_json::to_string(&Response::Done { request_id: "r".into() }).unwrap();
        assert_eq!(json, r#"{"status":"done","request_id":"r"}"#);
        assert!(matches!(
            serde_json::from_str::<Response>(&json).unwrap(),
            Response::Done { request_id } if request_id == "r"
        ));
    }
}
