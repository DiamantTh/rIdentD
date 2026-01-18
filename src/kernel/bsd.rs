use std::net::SocketAddr;

use super::{LookupError, UidLookup};

#[derive(Debug, Default)]
pub struct BsdLookup;

impl BsdLookup {
    pub fn new() -> Self {
        Self
    }
}

impl UidLookup for BsdLookup {
    fn lookup_uid(&self, local: SocketAddr, remote: SocketAddr) -> Result<Option<u32>, LookupError> {
        lookup_uid_bsd(local, remote)
    }
}

#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
fn lookup_uid_bsd(local: SocketAddr, remote: SocketAddr) -> Result<Option<u32>, LookupError> {
    use std::ffi::CString;
    use std::io;
    use std::mem;

    unsafe fn sysctl_lookup(
        name: &CString,
        addrs: *const libc::c_void,
        len: usize,
    ) -> Result<Option<u32>, LookupError> {
        let mut creds: libc::xucred = mem::zeroed();
        let mut out_len = mem::size_of::<libc::xucred>() as libc::size_t;
        let ret = libc::sysctlbyname(
            name.as_ptr(),
            &mut creds as *mut _ as *mut libc::c_void,
            &mut out_len,
            addrs as *mut libc::c_void,
            len as libc::size_t,
        );
        if ret != 0 {
            let err = io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(libc::ESRCH) | Some(libc::ENOENT)) {
                return Ok(None);
            }
            return Err(LookupError::Io(err));
        }
        if creds.cr_version != libc::XUCRED_VERSION {
            return Err(LookupError::Unsupported);
        }
        Ok(Some(creds.cr_uid as u32))
    }

    match (local, remote) {
        (SocketAddr::V4(local), SocketAddr::V4(remote)) => unsafe {
            let mut addrs: [libc::sockaddr_in; 2] = mem::zeroed();
            addrs[0].sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
            addrs[0].sin_family = libc::AF_INET as libc::sa_family_t;
            addrs[0].sin_port = local.port().to_be();
            addrs[0].sin_addr.s_addr = u32::from(*local.ip()).to_be();

            addrs[1].sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
            addrs[1].sin_family = libc::AF_INET as libc::sa_family_t;
            addrs[1].sin_port = remote.port().to_be();
            addrs[1].sin_addr.s_addr = u32::from(*remote.ip()).to_be();

            let name = CString::new("net.inet.tcp.getcred").unwrap();
            sysctl_lookup(&name, addrs.as_ptr() as *const libc::c_void, mem::size_of_val(&addrs))
        },
        (SocketAddr::V6(local), SocketAddr::V6(remote)) => unsafe {
            let mut addrs: [libc::sockaddr_in6; 2] = mem::zeroed();
            addrs[0].sin6_len = mem::size_of::<libc::sockaddr_in6>() as u8;
            addrs[0].sin6_family = libc::AF_INET6 as libc::sa_family_t;
            addrs[0].sin6_port = local.port().to_be();
            addrs[0].sin6_addr = libc::in6_addr {
                s6_addr: local.ip().octets(),
            };

            addrs[1].sin6_len = mem::size_of::<libc::sockaddr_in6>() as u8;
            addrs[1].sin6_family = libc::AF_INET6 as libc::sa_family_t;
            addrs[1].sin6_port = remote.port().to_be();
            addrs[1].sin6_addr = libc::in6_addr {
                s6_addr: remote.ip().octets(),
            };

            let name = CString::new("net.inet6.tcp6.getcred").unwrap();
            sysctl_lookup(&name, addrs.as_ptr() as *const libc::c_void, mem::size_of_val(&addrs))
        },
        _ => Ok(None),
    }
}

#[cfg(not(any(target_os = "freebsd", target_os = "dragonfly")))]
fn lookup_uid_bsd(_local: SocketAddr, _remote: SocketAddr) -> Result<Option<u32>, LookupError> {
    Err(LookupError::Unsupported)
}
