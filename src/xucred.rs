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
            write!(f, "{}", unsafe { self.cr_pid })
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

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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
    #[inline]
    pub fn uid(&self) -> libc::uid_t {
        self.cr_uid
    }

    #[inline]
    pub fn gid(&self) -> libc::gid_t {
        self.cr_groups[0]
    }

    #[inline]
    pub fn groups(&self) -> &[libc::gid_t] {
        &self.cr_groups[..self.cr_ngroups as usize]
    }

    #[cfg(target_os = "freebsd")]
    #[inline]
    pub fn pid(&self) -> Option<libc::pid_t> {
        match unsafe { self._cr.cr_pid } {
            0 => None,
            pid => Some(pid),
        }
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

#[inline]
pub fn get_xucred(sock: &UnixStream) -> io::Result<Xucred> {
    unsafe { get_xucred_raw(sock.as_raw_fd()) }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        if super::super::has_cr_pid() {
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
}
