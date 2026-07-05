//! OS-native peer identity extraction from Unix domain sockets.
//!
//! On Linux this uses `SO_PEERCRED` to read the peer's PID and UID from the
//! kernel.  On macOS the PID is obtained via `LOCAL_PEERPID` and the UID via
//! `getpeereid(3)`.  On all other Unix variants both values are left as `None`.

/// Peer credentials obtained from an accepted Unix domain socket.
#[derive(Debug, Clone, Default)]
pub struct UnixPeerCreds {
    /// PID of the peer process (unavailable on some platforms).
    pub pid: Option<u32>,
    /// UID of the peer process.
    pub uid: Option<u32>,
}

#[cfg(target_os = "linux")]
pub fn get_unix_peer_creds(stream: &tokio::net::UnixStream) -> UnixPeerCreds {
    use std::mem;
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if ret == 0 {
        UnixPeerCreds {
            pid: Some(cred.pid as u32),
            uid: Some(cred.uid),
        }
    } else {
        UnixPeerCreds::default()
    }
}

#[cfg(target_os = "macos")]
pub fn get_unix_peer_creds(stream: &tokio::net::UnixStream) -> UnixPeerCreds {
    use std::os::unix::io::AsRawFd;

    // macOS socket option constants not exposed in libc
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERPID: libc::c_int = 2;

    let fd = stream.as_raw_fd();

    // PID via LOCAL_PEERPID
    let pid = {
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERPID,
                &mut pid as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret == 0 { Some(pid as u32) } else { None }
    };

    // UID: getpeereid
    let uid = {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let ret = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if ret == 0 { Some(uid) } else { None }
    };

    UnixPeerCreds { pid, uid }
}

/// Fallback for Unix platforms other than Linux/macOS.
#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
pub fn get_unix_peer_creds(_stream: &tokio::net::UnixStream) -> UnixPeerCreds {
    UnixPeerCreds::default()
}
