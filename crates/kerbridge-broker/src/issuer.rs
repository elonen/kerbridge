//! Client for `issuerd`, over its Unix socket.
//!
//! The framing and the message types come from `kerbridge-core`, so this side
//! cannot drift from the daemon's. The socket call is synchronous and runs on
//! the blocking pool: to issue a ticket, `issuerd` runs `samba-tool` and
//! `kinit` in the realm container, thus the call blocks for real.
//!
//! Three outcomes leave here and stay distinct all the way out: a ticket, a
//! refusal, and an issuer that this process could not reach. The helper
//! discriminates on the three (`docs/windows-testbench.md`). If the last two
//! became one, a policy denial and an outage would look the same to whoever
//! diagnoses one.

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, anyhow};
use kerbridge_core::issuer::{IssueRequest, Request, Response, Ticket, read_frame, write_frame};

/// How to reach `issuerd`. Each call opens its own connection; there is no pool.
pub struct Issuer {
    socket: PathBuf,
    timeout: Duration,
}

pub enum IssuerError {
    /// The issuer refused this request. A policy answer, not an outage.
    Refused(String),
    /// The issuer could not be reached, or did not answer in time.
    Unavailable(anyhow::Error),
}

impl std::fmt::Display for IssuerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(why) => write!(f, "issuer refused: {why}"),
            Self::Unavailable(e) => write!(f, "issuer unavailable: {e:#}"),
        }
    }
}

impl Issuer {
    pub fn new(socket: PathBuf, timeout: Duration) -> Self {
        Self { socket, timeout }
    }

    pub async fn issue(&self, request: IssueRequest) -> Result<Ticket, IssuerError> {
        match self.call(Request::Issue(request)).await? {
            Response::Ok(ticket) => Ok(ticket),
            other => Err(unexpected(&other)),
        }
    }

    /// Send a directory write. Every grant verb answers `Done` or an error. Any
    /// other answer means the two ends disagree about the protocol, which is an
    /// outage and not a refusal.
    pub async fn write(&self, request: Request) -> Result<(), IssuerError> {
        match self.call(request).await? {
            Response::Done { .. } => Ok(()),
            other => Err(unexpected(&other)),
        }
    }

    async fn call(&self, request: Request) -> Result<Response, IssuerError> {
        let socket = self.socket.clone();
        let timeout = self.timeout;
        tokio::task::spawn_blocking(move || call(&socket, timeout, &request))
            .await
            .map_err(|e| IssuerError::Unavailable(anyhow!("issuer call panicked: {e}")))?
    }
}

fn unexpected(response: &Response) -> IssuerError {
    let shape = match response {
        Response::Ok(_) => "a ticket",
        Response::Pong { .. } => "a pong",
        Response::Done { .. } => "a write acknowledgment",
        // `call` turns this one into `Refused` before it can reach here.
        Response::Error { .. } => "an error",
    };
    IssuerError::Unavailable(anyhow!("issuer answered with {shape}"))
}

fn call(socket: &PathBuf, timeout: Duration, request: &Request) -> Result<Response, IssuerError> {
    let mut stream = UnixStream::connect(socket).map_err(|e| {
        // A missing socket file and a refused connection are the same thing to
        // a caller: the realm container is not serving.
        IssuerError::Unavailable(
            anyhow::Error::new(e).context(format!("connecting to issuer at {}", socket.display())),
        )
    })?;
    let result = (|| -> anyhow::Result<Response> {
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let body = serde_json::to_vec(request).context("encoding issuer request")?;
        write_frame(&mut stream, &body).context("sending issuer request")?;
        let reply = read_frame(&mut stream).context("reading issuer response")?;
        serde_json::from_slice(&reply).context("decoding issuer response")
    })();

    match result {
        Ok(Response::Error { error, .. }) => Err(IssuerError::Refused(error)),
        Ok(response) => Ok(response),
        Err(e) => Err(IssuerError::Unavailable(e)),
    }
}
