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

#[cfg(all(test, target_os = "freebsd"))]
fn has_cr_pid() -> bool {
    let mut uname = unsafe { std::mem::zeroed() };
    unsafe {
        libc::uname(&mut uname);
    }

    let release_len = uname
        .release
        .iter()
        .position(|c| *c == 0)
        .unwrap_or_else(|| uname.release.len());

    // uname.release is an array of `libc::c_char`s. `libc::c_char` may be either a u8 or an i8, so
    // unfortunately we have to use unsafe operations to get a reference as a &[u8].
    let release =
        unsafe { core::slice::from_raw_parts(uname.release.as_ptr() as *const u8, release_len) };

    let release_major = std::ffi::OsStr::from_bytes(release)
        .to_str()
        .unwrap()
        .split('.')
        .next()
        .unwrap()
        .parse::<i32>()
        .unwrap();

    release_major >= 13
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
        if !has_cr_pid() {
            return None;
        }

        Some(unsafe { libc::getpid() })
    }
}
