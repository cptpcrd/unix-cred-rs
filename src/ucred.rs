//! The `ucred` module provides an interface to the `ucred` interface on Linux, the `sockpeecred`
//! interface on OpenBSD, or the `unpcbid` interface on NetBSD.
//!
//! The reason that the interfaces for all three of these are in one module is that they are all
//! essentially the same interface, with only minor implementation differences (such as the order
//! of the fields in the C struct, or the name of the socket option used to retrieve them).
//!
//! Note: This module is only here for completeness. In most cases, you should use
//! [`get_peer_ids()`] or [`get_peer_pid_ids()`], which have slightly better cross-platform
//! support.
//!
//! [`get_peer_ids()`]: ../fn.get_peer_ids.html
//! [`get_peer_pid_ids()`]: ../fn.get_peer_pid_ids.html

use std::io;
use std::os::unix::net::UnixStream;
use std::os::unix::prelude::*;

/// Represents the credentials of a Unix socket's peer.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[repr(C)]
pub struct Ucred {
    /// The peer's PID.
    ///
    /// **WARNING**: This is the PID of the process that originally opened the socket. That process
    /// may have died, and another process may now be running with that PID. Use with caution.
    #[cfg(any(target_os = "linux", target_os = "netbsd"))]
    pub pid: libc::pid_t,
    /// The peer's effective user ID.
    pub uid: libc::uid_t,
    /// The peer's effective group ID.
    pub gid: libc::gid_t,
    /// The peer's PID.
    ///
    /// **WARNING**: This is the PID of the process that originally opened the socket. That process
    /// may have died, and another process may now be running with that PID. Use with caution.
    #[cfg(target_os = "openbsd")]
    pub pid: libc::pid_t,
}

#[cfg(target_os = "netbsd")]
const PEERCRED_LEVEL: libc::c_int = 0;
#[cfg(not(target_os = "netbsd"))]
const PEERCRED_LEVEL: libc::c_int = libc::SOL_SOCKET;

#[cfg(target_os = "netbsd")]
const SO_PEERCRED: libc::c_int = crate::constants::LOCAL_PEEREID;
#[cfg(not(target_os = "netbsd"))]
const SO_PEERCRED: libc::c_int = libc::SO_PEERCRED;

pub(crate) unsafe fn get_ucred_raw(sockfd: RawFd) -> io::Result<Ucred> {
    let mut ucred = Ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };

    let len = crate::util::getsockopt_raw(
        sockfd,
        PEERCRED_LEVEL,
        SO_PEERCRED,
        std::slice::from_mut(&mut ucred),
    )?;

    if len != std::mem::size_of::<Ucred>()
        || ucred.pid == 0
        || ucred.uid == libc::uid_t::MAX
        || ucred.gid == libc::gid_t::MAX
    {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }

    Ok(ucred)
}

/// Get the credentials of the given socket's peer.
#[inline]
pub fn get_ucred(sock: &UnixStream) -> io::Result<Ucred> {
    unsafe { get_ucred_raw(sock.as_raw_fd()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::net::UnixDatagram;

    #[test]
    fn test_get_ucred() {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let pid = unsafe { libc::getpid() };

        let (a, b) = UnixStream::pair().unwrap();

        let acred = get_ucred(&a).unwrap();
        assert_eq!(acred.uid, uid);
        assert_eq!(acred.gid, gid);
        assert_eq!(acred.pid, pid);

        let bcred = get_ucred(&b).unwrap();
        assert_eq!(bcred.uid, uid);
        assert_eq!(bcred.gid, gid);
        assert_eq!(bcred.pid, pid);
    }

    #[test]
    fn test_get_ucred_error() {
        let dir = tempfile::tempdir().unwrap();

        let sock = UnixDatagram::bind(dir.path().join("sock")).unwrap();

        let eno = get_ucred(unsafe { &UnixStream::from_raw_fd(sock.into_raw_fd()) })
            .unwrap_err()
            .raw_os_error()
            .unwrap();

        assert!(matches!(eno, libc::EINVAL | libc::ENOTCONN));
    }
}
