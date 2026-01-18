use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

static RNG_STATE: AtomicU64 = AtomicU64::new(0);

pub fn rand_range(upper: u32) -> u32 {
    if upper == 0 {
        return 0;
    }
    rand_u32() % upper
}

fn rand_u32() -> u32 {
    let mut state = RNG_STATE.load(Ordering::Relaxed);
    if state == 0 {
        let seed = now_millis() as u64 ^ (std::process::id() as u64);
        state = if seed == 0 { 0x9e3779b97f4a7c15 } else { seed };
    }

    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    RNG_STATE.store(state, Ordering::Relaxed);
    (state >> 32) as u32
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

#[cfg(unix)]
pub fn uid_from_username(name: &str) -> Option<u32> {
    use libc::{c_char, getpwnam_r, passwd, sysconf, _SC_GETPW_R_SIZE_MAX};
    use std::ffi::CString;
    use std::mem;
    use std::ptr;

    let c_name = CString::new(name).ok()?;
    unsafe {
        let mut pwd: passwd = mem::zeroed();
        let mut result: *mut passwd = ptr::null_mut();
        let size = sysconf(_SC_GETPW_R_SIZE_MAX);
        let bufsize = if size <= 0 { 16 * 1024 } else { size as usize };
        let mut buf = vec![0u8; bufsize];
        let rc = getpwnam_r(
            c_name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result,
        );
        if rc != 0 || result.is_null() {
            return None;
        }
        Some(pwd.pw_uid as u32)
    }
}

#[cfg(not(unix))]
pub fn uid_from_username(_name: &str) -> Option<u32> {
    None
}

#[cfg(not(unix))]
pub fn username_from_uid(_uid: u32) -> Option<String> {
    None
}
