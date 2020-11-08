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
