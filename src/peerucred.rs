use std::io;
use std::os::unix::net::UnixStream;
use std::os::unix::prelude::*;
use std::ptr::NonNull;

#[derive(Debug)]
pub struct Ucred {
    cred: NonNull<libc::ucred_t>,
}

impl Ucred {
    #[inline]
    pub fn euid(&self) -> libc::uid_t {
        unsafe { libc::ucred_geteuid(self.cred.as_ptr()) }
    }

    #[inline]
    pub fn ruid(&self) -> libc::uid_t {
        unsafe { libc::ucred_getruid(self.cred.as_ptr()) }
    }

    #[inline]
    pub fn suid(&self) -> libc::uid_t {
        unsafe { libc::ucred_getsuid(self.cred.as_ptr()) }
    }

    #[inline]
    pub fn egid(&self) -> libc::gid_t {
        unsafe { libc::ucred_getegid(self.cred.as_ptr()) }
    }

    #[inline]
    pub fn rgid(&self) -> libc::gid_t {
        unsafe { libc::ucred_getrgid(self.cred.as_ptr()) }
    }

    #[inline]
    pub fn sgid(&self) -> libc::gid_t {
        unsafe { libc::ucred_getsgid(self.cred.as_ptr()) }
    }

    pub fn groups<'a>(&'a self) -> &'a [libc::gid_t] {
        let mut groups_ptr = std::ptr::null();
        let ngroups = unsafe { libc::ucred_getgroups(self.cred.as_ptr(), &mut groups_ptr) };

        if groups_ptr.is_null() {
            assert!(ngroups == 0, "{}", io::Error::last_os_error());
            return &[];
        }

        assert!(ngroups >= 0, "{}", io::Error::last_os_error());

        unsafe { std::slice::from_raw_parts(groups_ptr, ngroups as usize) }
    }

    #[inline]
    pub fn pid(&self) -> libc::pid_t {
        unsafe { libc::ucred_getpid(self.cred.as_ptr()) }
    }
}

impl PartialEq<Self> for Ucred {
    fn eq(&self, other: &Self) -> bool {
        self.pid() == other.pid()
            && self.euid() == other.euid()
            && self.ruid() == other.ruid()
            && self.suid() == other.suid()
            && self.egid() == other.egid()
            && self.rgid() == other.rgid()
            && self.sgid() == other.sgid()
            && self.groups() == other.groups()
    }
}

impl Eq for Ucred {}

impl std::hash::Hash for Ucred {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_i32(self.pid());

        state.write_u32(self.euid());
        state.write_u32(self.ruid());
        state.write_u32(self.suid());

        state.write_u32(self.egid());
        state.write_u32(self.rgid());
        state.write_u32(self.sgid());

        let groups = self.groups();
        state.write_usize(groups.len());
        for group in groups {
            state.write_u32(*group);
        }
    }
}

impl Clone for Ucred {
    fn clone(&self) -> Self {
        let size = unsafe { libc::ucred_size() };
        debug_assert!(size > 0);

        // Note: This relies on the fact that `ucred_t`s are allocated with malloc() and freed with
        // free().
        // Unfortunately, it doesn't seem there's another way to clone a ucred_t.

        match NonNull::new(unsafe { libc::malloc(size) } as *mut libc::ucred_t) {
            Some(cred) => {
                unsafe {
                    std::ptr::copy_nonoverlapping(self.cred.as_ptr(), cred.as_ptr(), size);
                }

                Ucred { cred }
            }

            None => std::alloc::handle_alloc_error(unsafe {
                std::alloc::Layout::from_size_align_unchecked(size, size.next_power_of_two())
            }),
        }
    }
}

impl Drop for Ucred {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            libc::ucred_free(self.cred.as_ptr());
        }
    }
}

#[inline]
pub(crate) unsafe fn getpeerucred_raw(sockfd: RawFd) -> io::Result<Ucred> {
    let mut cred = std::ptr::null_mut();

    if libc::getpeerucred(sockfd, &mut cred) < 0 {
        return Err(io::Error::last_os_error());
    }

    debug_assert!(!cred.is_null());

    Ok(Ucred {
        cred: NonNull::new_unchecked(cred),
    })
}

#[inline]
pub fn getpeerucred(sock: &UnixStream) -> io::Result<Ucred> {
    unsafe { getpeerucred_raw(sock.as_raw_fd()) }
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

    #[test]
    fn test_getpeercred() {
        let (a, b) = UnixStream::pair().unwrap();

        let mut groups = getgroups();
        groups.sort();

        let acred = getpeerucred(&a).unwrap();

        assert_eq!(acred.pid(), unsafe { libc::getpid() });

        assert_eq!(acred.euid(), unsafe { libc::geteuid() });
        assert_eq!(acred.ruid(), unsafe { libc::getuid() });
        assert_eq!(acred.suid(), unsafe { libc::geteuid() });

        assert_eq!(acred.egid(), unsafe { libc::getegid() });
        assert_eq!(acred.rgid(), unsafe { libc::getgid() });
        assert_eq!(acred.sgid(), unsafe { libc::getegid() });

        let mut agroups = Vec::from(acred.groups());
        agroups.sort();
        assert_eq!(agroups, groups);

        let bcred = getpeerucred(&b).unwrap();

        assert_eq!(bcred.pid(), unsafe { libc::getpid() });

        assert_eq!(bcred.euid(), unsafe { libc::geteuid() });
        assert_eq!(bcred.ruid(), unsafe { libc::getuid() });
        assert_eq!(bcred.suid(), unsafe { libc::geteuid() });

        assert_eq!(bcred.egid(), unsafe { libc::getegid() });
        assert_eq!(bcred.rgid(), unsafe { libc::getgid() });
        assert_eq!(bcred.sgid(), unsafe { libc::getegid() });

        let mut bgroups = Vec::from(bcred.groups());
        bgroups.sort();
        assert_eq!(bgroups, groups);
    }

    #[test]
    fn test_ucred_eq_clone() {
        let (a, b) = UnixStream::pair().unwrap();

        let acred = getpeerucred(&a).unwrap();
        let bcred = getpeerucred(&b).unwrap();

        assert_eq!(acred, bcred);
        assert_eq!(acred, acred.clone());
    }
}
