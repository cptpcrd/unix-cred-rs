//! # unix-cred
//!
//! `unix-cred` provides simple, cross-platform interfaces to read peer credentials from Unix
//! sockets. (OS-specific interfaces are also exposed if the extra functionality is necessary).
//!
//! # Stream vs. Datagram sockets
//!
//! Some platforms support reading peer credentials from datagram sockets using ancillary messages.
//! Currently, `unix-cred` does not support this; only stream sockets are supported.
//!
//! # Which credentials am I getting?
//!
//! On all currently supported platforms, both of the following are true:
//!
//! 1. The UID and GID returned by these interfaces are the *effective* UID/GID, not the real or
//!    saved UID/GID.
//! 2. The credentials returned are cached at the time that the `connect()`/`socketpair()` call was
//!    made. (So if the process later drops privileges, or passes the file descriptor to an
//!    unprivileged process, it will still be shown as having elevated privileges.)
//!
//! # What are the other modules I see in this crate?
//!
//! The `ucred` and `xucred` modules expose the OS-specific interfaces. `ucred` provides the
//! Linux/OpenBSD/NetBSD interface, and `xucred` provides the macOS/FreeBSD/DragonFlyBSD interface.
//!
//! `ucred` is not particularly useful; in most cases you should use `get_peer_ids()` or
//! `get_peer_pid_ids()`, which are more cross-platform. However, `xucred` can be helpful since it
//! provides access to the process's full supplementary group list.

use std::io;
use std::os::unix::net::UnixStream;
use std::os::unix::prelude::*;

mod constants;
mod util;

#[cfg(any(target_os = "linux", target_os = "openbsd", target_os = "netbsd"))]
pub mod ucred;
#[cfg(any(
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "macos",
    target_os = "ios"
))]
pub mod xucred;

#[allow(clippy::needless_return)]
#[inline]
unsafe fn get_peer_ids_raw(sockfd: RawFd) -> io::Result<(libc::uid_t, libc::gid_t)> {
    #[cfg(any(target_os = "linux", target_os = "openbsd", target_os = "netbsd"))]
    {
        let cred = ucred::get_ucred_raw(sockfd)?;
        return Ok((cred.uid, cred.gid));
    }

    #[cfg(any(
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "ios"
    ))]
    {
        let cred = xucred::get_xucred_raw(sockfd)?;
        return Ok((cred.uid(), cred.gid()));
    }
}

/// Get the UID and GID of the given socket's peer.
#[inline]
pub fn get_peer_ids(sock: &UnixStream) -> io::Result<(libc::uid_t, libc::gid_t)> {
    unsafe { get_peer_ids_raw(sock.as_raw_fd()) }
}

#[cfg(any(
    target_os = "linux",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "freebsd",
))]
#[allow(clippy::needless_return)]
#[inline]
unsafe fn get_peer_pid_ids_raw(
    sockfd: RawFd,
) -> io::Result<(Option<libc::pid_t>, libc::uid_t, libc::gid_t)> {
    #[cfg(any(target_os = "linux", target_os = "openbsd", target_os = "netbsd"))]
    {
        let cred = ucred::get_ucred_raw(sockfd)?;
        return Ok((Some(cred.pid), cred.uid, cred.gid));
    }

    #[cfg(target_os = "freebsd")]
    {
        let cred = xucred::get_xucred_raw(sockfd)?;
        return Ok((cred.pid(), cred.uid(), cred.gid()));
    }
}

/// Get the PID, UID, and GID of the given socket's peer.
///
/// This only works on Linux, OpenBSD, NetBSD, and FreeBSD 13+. On other operating systems, this
/// function is not available. On FreeBSD 12 and earlier, the returned PID is always `None`.
#[cfg(any(
    target_os = "linux",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "freebsd",
))]
#[inline]
pub fn get_peer_pid_ids(
    sock: &UnixStream,
) -> io::Result<(Option<libc::pid_t>, libc::uid_t, libc::gid_t)> {
    unsafe { get_peer_pid_ids_raw(sock.as_raw_fd()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_peer_ids() {
        let (a, b) = UnixStream::pair().unwrap();

        let (auid, agid) = get_peer_ids(&a).unwrap();
        assert_eq!(auid, unsafe { libc::getuid() });
        assert_eq!(agid, unsafe { libc::getgid() });

        let (buid, bgid) = get_peer_ids(&b).unwrap();
        assert_eq!(buid, unsafe { libc::getuid() });
        assert_eq!(bgid, unsafe { libc::getgid() });
    }

    #[test]
    fn test_get_peer_ids_bad_fd() {
        assert_eq!(
            get_peer_ids(unsafe { &UnixStream::from_raw_fd(-1) })
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EBADF),
        );

        let file = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
        assert_eq!(
            get_peer_ids(unsafe { &UnixStream::from_raw_fd(file.as_raw_fd()) })
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOTSOCK),
        );
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "freebsd",
    ))]
    #[test]
    fn test_get_peer_pid_ids() {
        let (a, b) = UnixStream::pair().unwrap();

        let (apid, auid, agid) = get_peer_pid_ids(&a).unwrap();
        assert_eq!(apid, get_expected_pid());
        assert_eq!(auid, unsafe { libc::getuid() });
        assert_eq!(agid, unsafe { libc::getgid() });

        let (bpid, buid, bgid) = get_peer_pid_ids(&b).unwrap();
        assert_eq!(bpid, get_expected_pid());
        assert_eq!(buid, unsafe { libc::getuid() });
        assert_eq!(bgid, unsafe { libc::getgid() });
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "freebsd",
    ))]
    fn get_expected_pid() -> Option<libc::pid_t> {
        #[cfg(target_os = "freebsd")]
        if !util::has_cr_pid() {
            return None;
        }

        Some(unsafe { libc::getpid() })
    }
}
