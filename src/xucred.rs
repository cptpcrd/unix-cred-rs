//! The `xucred` module provides an interface to the `xucred` interface on FreeBSD, DragonflyBSD,
//! and macOS.

use std::fmt;

use std::io;
use std::os::unix::net::UnixStream;
use std::os::unix::prelude::*;

#[cfg(target_os = "freebsd")]
mod xucred_cr {
    #[derive(Copy, Clone)]
    pub union XucredCr {
        pub cr_pid: libc::pid_t,
        _cr_unused_1: *const libc::c_void,
    }

    impl std::fmt::Debug for XucredCr {
        #[inline]
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.debug_struct("XucredCr")
                .field("pid", unsafe { &self.cr_pid })
                .finish()
        }
    }

    impl Eq for XucredCr {}

    impl std::hash::Hash for XucredCr {
        #[inline]
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            state.write_u64(unsafe { self.cr_pid } as u64)
        }
    }

    impl PartialEq<Self> for XucredCr {
        #[inline]
        fn eq(&self, other: &Self) -> bool {
            unsafe { self.cr_pid == other.cr_pid }
        }
    }
}

/// Represents the credentials of a Unix socket's peer.
#[derive(Clone, Eq, Hash, PartialEq)]
#[repr(C)]
pub struct Xucred {
    cr_version: libc::c_uint,
    cr_uid: libc::uid_t,
    cr_ngroups: libc::c_short,
    cr_groups: [libc::gid_t; crate::constants::XU_NGROUPS],
    #[cfg(target_os = "freebsd")]
    _cr: xucred_cr::XucredCr,
    #[cfg(target_os = "dragonfly")]
    _cr_unused1: *const libc::c_void,
}

impl Xucred {
    /// Get the peer's effective user ID.
    #[inline]
    pub fn uid(&self) -> libc::uid_t {
        self.cr_uid
    }

    /// Get the peer's effective group ID.
    #[inline]
    pub fn gid(&self) -> libc::gid_t {
        self.cr_groups[0]
    }

    /// Get the peer's supplementary group list.
    ///
    /// On FreeBSD, this is truncated to the first 16 supplementary groups.
    #[inline]
    pub fn groups(&self) -> &[libc::gid_t] {
        &self.cr_groups[..self.cr_ngroups as usize]
    }

    /// Get the peer's PID.
    ///
    /// This only works on FreeBSD 13+. On FreeBSD 12 and earlier, it always returns `None`.
    #[cfg(target_os = "freebsd")]
    #[inline]
    pub fn pid(&self) -> Option<libc::pid_t> {
        match unsafe { self._cr.cr_pid } {
            0 => None,
            pid => Some(pid),
        }
    }
}

impl fmt::Debug for Xucred {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut s = f.debug_struct("Xucred");

        s.field("uid", &self.uid())
            .field("gid", &self.gid())
            .field("groups", &self.groups());

        #[cfg(target_os = "freebsd")]
        s.field("pid", &self.pid());

        s.finish()
    }
}

pub(crate) unsafe fn get_xucred_raw(sockfd: RawFd) -> io::Result<Xucred> {
    let mut xucred: Xucred = std::mem::zeroed();
    xucred.cr_version = libc::XUCRED_VERSION;

    let len = crate::util::getsockopt_raw(
        sockfd,
        0,
        libc::LOCAL_PEERCRED,
        std::slice::from_mut(&mut xucred),
    )?;

    // We want to make sure that 1) the length matches, 2) the version number
    // matches, 3) we have at least one GID to pull out as the primary GID, and
    // 4) cr_ngroups isn't greater than XU_NGROUPS.
    //
    // Most of this is just paranoid sanity checks that should never actually
    // happen.

    if len != std::mem::size_of::<Xucred>()
        || xucred.cr_version != libc::XUCRED_VERSION
        || xucred.cr_ngroups < 1
        || xucred.cr_ngroups as usize > crate::constants::XU_NGROUPS
    {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }

    Ok(xucred)
}

/// Get the credentials of the given socket's peer.
#[inline]
pub fn get_xucred(sock: &UnixStream) -> io::Result<Xucred> {
    unsafe { get_xucred_raw(sock.as_raw_fd()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::net::UnixDatagram;

    fn getgroups() -> Vec<libc::gid_t> {
        let mut ngroups = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        assert!(ngroups >= 0, "{:?}", io::Error::last_os_error());

        let mut groups = Vec::new();
        groups.resize(ngroups as usize, 0);

        ngroups = unsafe { libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr()) };
        assert!(ngroups >= 0, "{:?}", io::Error::last_os_error());

        groups.truncate(ngroups as usize);
        groups
    }

    #[cfg(target_os = "freebsd")]
    fn get_expected_pid() -> Option<libc::pid_t> {
        if crate::util::has_cr_pid() {
            Some(unsafe { libc::getpid() })
        } else {
            None
        }
    }

    #[test]
    fn test_get_xucred() {
        let (a, b) = UnixStream::pair().unwrap();

        let mut groups = getgroups();
        groups.sort();

        let acred = get_xucred(&a).unwrap();
        assert_eq!(acred.uid(), unsafe { libc::geteuid() });
        assert_eq!(acred.gid(), unsafe { libc::getegid() });

        let mut agroups = Vec::from(acred.groups());
        agroups.sort();
        assert_eq!(agroups, groups);

        #[cfg(target_os = "freebsd")]
        assert_eq!(acred.pid(), get_expected_pid());

        let bcred = get_xucred(&b).unwrap();
        assert_eq!(bcred.uid(), unsafe { libc::geteuid() });
        assert_eq!(bcred.gid(), unsafe { libc::getegid() });

        let mut bgroups = Vec::from(bcred.groups());
        bgroups.sort();
        assert_eq!(bgroups, groups);

        #[cfg(target_os = "freebsd")]
        assert_eq!(bcred.pid(), get_expected_pid());
    }

    fn same_hash<T: std::hash::Hash>(a: &T, b: &T) -> bool {
        use std::hash::{BuildHasher, Hasher};

        let s = std::collections::hash_map::RandomState::new();

        let mut hasher_a = s.build_hasher();
        a.hash(&mut hasher_a);

        let mut hasher_b = s.build_hasher();
        b.hash(&mut hasher_b);

        hasher_a.finish() == hasher_b.finish()
    }

    #[test]
    fn test_xucred() {
        let (a, b) = UnixStream::pair().unwrap();

        let acred = get_xucred(&a).unwrap();
        let bcred = get_xucred(&b).unwrap();

        assert_eq!(acred, bcred);
        assert!(same_hash(&acred, &bcred));

        assert_eq!(acred, acred.clone());
        assert!(same_hash(&acred, &acred.clone()));

        let zcred: Xucred = unsafe { std::mem::zeroed() };

        assert_eq!(zcred, zcred.clone());
        assert!(same_hash(&zcred, &zcred.clone()));

        assert_ne!(acred, zcred);
        assert!(!same_hash(&acred, &zcred));

        // 0 -> no PID
        #[cfg(target_os = "freebsd")]
        assert_eq!(zcred.pid(), None);

        #[cfg(target_os = "freebsd")]
        unsafe {
            let mut cr: xucred_cr::XucredCr = std::mem::zeroed();
            assert_eq!(format!("{:?}", cr), "XucredCr { pid: 0 }");

            cr.cr_pid = 1;
            assert_eq!(format!("{:?}", cr), "XucredCr { pid: 1 }");
        }

        let mut test_cred: Xucred = unsafe { std::mem::zeroed() };

        #[cfg(target_os = "freebsd")]
        {
            assert_eq!(
                format!("{:?}", test_cred),
                "Xucred { uid: 0, gid: 0, groups: [], pid: None }"
            );

            test_cred.cr_uid = 1000;
            test_cred.cr_ngroups = 2;
            test_cred.cr_groups[0] = 1001;
            test_cred.cr_groups[1] = 10;
            assert_eq!(
                format!("{:?}", test_cred),
                "Xucred { uid: 1000, gid: 1001, groups: [1001, 10], pid: None }"
            );

            test_cred._cr.cr_pid = 1494;
            assert_eq!(
                format!("{:?}", test_cred),
                "Xucred { uid: 1000, gid: 1001, groups: [1001, 10], pid: Some(1494) }"
            );
        }

        #[cfg(not(target_os = "freebsd"))]
        {
            assert_eq!(
                format!("{:?}", test_cred),
                "Xucred { uid: 0, gid: 0, groups: [] }"
            );

            test_cred.cr_uid = 1000;
            test_cred.cr_ngroups = 2;
            test_cred.cr_groups[0] = 1001;
            test_cred.cr_groups[1] = 10;
            assert_eq!(
                format!("{:?}", test_cred),
                "Xucred { uid: 1000, gid: 1001, groups: [1001, 10] }"
            );
        }
    }

    #[test]
    fn test_get_xucred_error() {
        let dir = tempfile::tempdir().unwrap();

        let sock = UnixDatagram::bind(dir.path().join("sock")).unwrap();

        assert_eq!(
            get_xucred(unsafe { &UnixStream::from_raw_fd(sock.as_raw_fd()) })
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL),
        );
    }
}
