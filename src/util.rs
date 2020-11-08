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
