//! Who is on the other end of the socket.
//!
//! The socket's permissions are a group check, and a group is not an identity:
//! anything that ever acquires the broker's gid -- a supplementary-group
//! mistake, or the broker itself once compromised -- could otherwise issue a
//! renewable TGT for any synchronized account. The kernel knows which process
//! actually connected, so ask it.

use std::io;
use std::os::unix::net::UnixStream;

use nix::sys::socket::{getsockopt, sockopt};

/// The connected peer's uid, from the kernel rather than from anything the peer
/// claimed. `SO_PEERCRED` on Linux, which is where this ships; `LOCAL_PEERCRED`
/// on the BSD-flavored hosts the dev loop builds on.
#[cfg(target_os = "linux")]
pub fn uid(stream: &UnixStream) -> io::Result<u32> {
    Ok(getsockopt(stream, sockopt::PeerCredentials)?.uid())
}

#[cfg(not(target_os = "linux"))]
pub fn uid(stream: &UnixStream) -> io::Result<u32> {
    Ok(getsockopt(stream, sockopt::LocalPeerCred)?.uid())
}

/// Root is allowed alongside the broker: it owns the socket, runs the container
/// healthcheck's `issuerd ping`, and could read the KDC database directly
/// anyway -- refusing it would buy nothing and break the healthcheck.
pub fn authorized(stream: &UnixStream, broker_uid: u32) -> Result<u32, String> {
    match uid(stream) {
        Ok(u) if u == 0 || u == broker_uid => Ok(u),
        Ok(u) => Err(format!("peer uid {u} is neither root nor the broker ({broker_uid})")),
        Err(e) => Err(format!("could not read peer credentials: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_uid_of_a_connected_peer() {
        let (a, _b) = UnixStream::pair().unwrap();
        let me = nix::unistd::getuid().as_raw();
        assert_eq!(uid(&a).unwrap(), me);
        assert!(authorized(&a, me).is_ok());
    }

    #[test]
    fn refuses_a_peer_that_is_neither_root_nor_the_broker() {
        let (a, _b) = UnixStream::pair().unwrap();
        let me = nix::unistd::getuid().as_raw();
        // Whatever uid this runs as, some other uid is not it. Root is the one
        // exception and is excluded from the comparison.
        let other = if me == 0 { return } else { me + 1 };
        assert!(authorized(&a, other).is_err());
    }
}
