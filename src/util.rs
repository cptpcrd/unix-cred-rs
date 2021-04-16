use std::io;
use std::os::unix::prelude::*;

#[inline]
pub unsafe fn getsockopt_raw<T: Sized>(
    sockfd: RawFd,
    level: libc::c_int,
    optname: libc::c_int,
    data: &mut [T],
) -> io::Result<usize> {
    let mut len = (data.len() * std::mem::size_of::<T>()) as libc::socklen_t;

    if libc::getsockopt(
        sockfd,
        level,
        optname,
        data.as_mut_ptr() as *mut libc::c_void,
        &mut len,
    ) < 0
    {
        return Err(io::Error::last_os_error());
    }

    Ok(len as usize)
}

#[cfg(all(test, target_os = "freebsd"))]
pub fn has_cr_pid() -> bool {
    const OSRELDATE_MIB: [libc::c_int; 2] = [libc::CTL_KERN, libc::KERN_OSRELDATE];

    let mut osreldate = 0;
    let mut oldlen = core::mem::size_of::<libc::c_int>();

    assert_eq!(
        unsafe {
            libc::sysctl(
                OSRELDATE_MIB.as_ptr(),
                OSRELDATE_MIB.len() as _,
                &mut osreldate as *mut _ as *mut _,
                &mut oldlen,
                core::ptr::null(),
                0,
            )
        },
        0
    );

    osreldate > 1202000
}
