//! The `kerbridge` binary's own modules -- not part of the library, and not
//! declared by `lib.rs`. Everything here is console I/O and orchestration over
//! [`kerbridge_client`]; no protocol decision lives on this side of the line.
//!
//! One module per subject, in the order a run meets them: [`resolve`] works out
//! what the run acts on, [`signin`] is the default pipeline, [`grant`] and
//! [`host`] are the subcommands, [`verify`] is the end-to-end proof.

pub(crate) mod grant;
pub(crate) mod resolve;
pub(crate) mod signin;
pub(crate) mod verify;

/// Windows only, and gated here rather than per item: realm registration and the
/// redirector repair are things macOS does not have, not things it does
/// differently. The flags themselves do not exist there either.
#[cfg(windows)]
pub(crate) mod host;
