# unix-cred

[![crates.io](https://img.shields.io/crates/v/unix-cred.svg)](https://crates.io/crates/unix-cred)
[![Docs](https://docs.rs/unix-cred/badge.svg)](https://docs.rs/unix-cred)
[![GitHub Actions](https://github.com/cptpcrd/unix-cred-rs/workflows/CI/badge.svg?branch=master&event=push)](https://github.com/cptpcrd/unix-cred-rs/actions?query=workflow%3ACI+branch%3Amaster+event%3Apush)
[![Cirrus CI](https://api.cirrus-ci.com/github/cptpcrd/unix-cred-rs.svg?branch=master)](https://cirrus-ci.com/github/cptpcrd/unix-cred-rs)
[![codecov](https://codecov.io/gh/cptpcrd/unix-cred-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/cptpcrd/unix-cred-rs)

A Rust library that simplifies reading peer credentials from Unix sockets.

Example:

```rust
use std::os::unix::net::UnixStream;

fn main() {
    let (sock, _peer) = UnixStream::pair().unwrap();

    // This will print the UID/GID of the current process
    // (since it's in possession of the other end)
    let (uid, gid) = unix_cred::get_peer_ids(&sock).unwrap();
    println!("{} {}", uid, gid);

    // Retrieving the PID is not supported on all platforms
    // (and on some versions of some platforms None will be returned)
    // See the documentation for more details
    let (pid, uid, gid) = unix_cred::get_peer_pid_ids(&sock).unwrap();
    println!("{:?} {} {}", pid, uid, gid);
}
```

## Platform support

The following platforms have first-class support (tests are run in CI, and everything should work):

- Linux (glibc and musl)
- FreeBSD
- macOS

The following platforms have second-class support (built, but not tested, in CI):

- NetBSD

The following platforms have third-class support (not even built in CI):

- OpenBSD
- DragonFlyBSD
