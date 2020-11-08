#[cfg(target_os = "netbsd")]
pub const LOCAL_PEEREID: libc::c_int = 0x0003;

#[cfg(target_os = "freebsd")]
pub const XU_NGROUPS: usize = libc::XU_NGROUPS as usize;
#[cfg(any(target_os = "dragonfly", target_os = "macos", target_os = "ios"))]
pub const XU_NGROUPS: usize = 16;
