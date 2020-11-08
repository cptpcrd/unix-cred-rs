use std::io;
use std::os::unix::net::UnixStream;
use std::os::unix::prelude::*;

/// Represents the credentials of a Unix socket's peer.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[repr(C)]
pub struct Ucred {
    /// The peer's PID.
    #[cfg(any(target_os = "linux", target_os = "netbsd"))]
    pub pid: libc::pid_t,
    /// The peer's effective user ID.
    pub uid: libc::uid_t,
    /// The peer's effective group ID.
    pub gid: libc::gid_t,
    /// The peer's PID.
    #[cfg(target_os = "openbsd")]
    pub pid: libc::pid_t,
}

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
        libc::SOL_SOCKET,
        SO_PEERCRED,
        std::slice::from_mut(&mut ucred),
    )?;

    if len != std::mem::size_of::<Ucred>() {
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
}
