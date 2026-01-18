use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub fn build_socket_addrs(addrs: &[String], port: u16) -> Result<Vec<SocketAddr>, String> {
    if addrs.is_empty() {
        return Ok(vec![
            SocketAddr::from(([0, 0, 0, 0], port)),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port)),
        ]);
    }

    let mut resolved = Vec::new();
    for addr in addrs {
        if let Ok(socket) = addr.parse::<SocketAddr>() {
            resolved.push(socket);
            continue;
        }

        let candidate = if addr.contains(':') {
            format!("[{addr}]:{port}")
        } else {
            format!("{addr}:{port}")
        };

        let socket = candidate
            .parse::<SocketAddr>()
            .map_err(|_| format!("invalid address: {addr}"))?;
        resolved.push(socket);
    }

    Ok(resolved)
}

#[cfg(unix)]
pub fn username_from_uid(uid: u32) -> Option<String> {
    use libc::{c_char, getpwuid_r, passwd, sysconf, uid_t, _SC_GETPW_R_SIZE_MAX};
    use std::ffi::CStr;
    use std::mem;
    use std::ptr;

    unsafe {
        let mut pwd: passwd = mem::zeroed();
        let mut result: *mut passwd = ptr::null_mut();
        let size = sysconf(_SC_GETPW_R_SIZE_MAX);
        let bufsize = if size <= 0 { 16 * 1024 } else { size as usize };
        let mut buf = vec![0u8; bufsize];
        let rc = getpwuid_r(
            uid as uid_t,
            &mut pwd,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result,
        );
        if rc != 0 || result.is_null() {
            return None;
        }
        let name = CStr::from_ptr(pwd.pw_name).to_string_lossy().into_owned();
        Some(name)
    }
}

#[cfg(not(unix))]
pub fn username_from_uid(_uid: u32) -> Option<String> {
    None
}
