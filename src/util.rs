use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::{fs, io};
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

#[cfg(unix)]
pub fn home_dir_from_uid(uid: u32) -> Option<PathBuf> {
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
        let dir = CStr::from_ptr(pwd.pw_dir).to_string_lossy().into_owned();
        Some(PathBuf::from(dir))
    }
}

#[cfg(unix)]
pub fn read_user_config(uid: u32, home: &Path) -> io::Result<Option<String>> {
    // Preferred new names first, then legacy fallbacks for compatibility.
    let candidates = [
        home.join(".config").join("ridentd.conf"),
        home.join(".config").join("oidentd.conf"),
        home.join(".ridentd.conf"),
        home.join(".rIdentD.conf"),
        home.join(".rIdentD.conf.d"),
        home.join(".oidentd.conf"),
    ];

    for path in candidates {
        if path.is_dir() {
            if let Some(content) = read_dir_if_owned(uid, &path)? {
                return Ok(Some(content));
            }
        } else if let Some(content) = read_if_owned(uid, &path)? {
            return Ok(Some(content));
        }
    }

    Ok(None)
}

#[cfg(unix)]
fn read_if_owned(uid: u32, path: &Path) -> io::Result<Option<String>> {
    use std::os::unix::fs::MetadataExt;

    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };

    if metadata.uid() != uid {
        return Ok(None);
    }

    let content = fs::read_to_string(path)?;
    Ok(Some(content))
}

#[cfg(unix)]
fn read_dir_if_owned(uid: u32, dir: &Path) -> io::Result<Option<String>> {
    use std::os::unix::fs::MetadataExt;

    let metadata = match fs::metadata(dir) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };

    if !metadata.is_dir() || metadata.uid() != uid {
        return Ok(None);
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("conf") {
            continue;
        }
        let meta = entry.metadata()?;
        if !meta.is_file() || meta.uid() != uid {
            continue;
        }
        entries.push(path);
    }

    if entries.is_empty() {
        return Ok(None);
    }

    entries.sort();
    let mut content = String::new();
    for path in entries {
        let file_content = fs::read_to_string(path)?;
        content.push_str(&file_content);
        if !content.ends_with('\n') {
            content.push('\n');
        }
    }

    Ok(Some(content))
}

#[cfg(not(unix))]
pub fn uid_from_username(_name: &str) -> Option<u32> {
    None
}

#[cfg(not(unix))]
pub fn username_from_uid(_uid: u32) -> Option<String> {
    None
}

#[cfg(not(unix))]
pub fn home_dir_from_uid(_uid: u32) -> Option<PathBuf> {
    None
}

#[cfg(not(unix))]
pub fn read_user_config(_uid: u32, _home: &Path) -> io::Result<Option<String>> {
    Ok(None)
}
