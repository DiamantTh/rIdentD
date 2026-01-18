use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::{LookupError, UidLookup};

#[derive(Debug, Default)]
pub struct LinuxLookup;

impl LinuxLookup {
    pub fn new() -> Self {
        Self
    }
}

impl UidLookup for LinuxLookup {
    fn lookup_uid(&self, local: SocketAddr, remote: SocketAddr) -> Result<Option<u32>, LookupError> {
        match (local, remote) {
            (SocketAddr::V4(_), SocketAddr::V4(_)) => {
                lookup_proc("/proc/net/tcp", local, remote, false)
            }
            (SocketAddr::V6(_), SocketAddr::V6(_)) => {
                lookup_proc("/proc/net/tcp6", local, remote, true)
            }
            _ => Ok(None),
        }
    }
}

#[derive(Debug, Clone)]
struct TcpEntry {
    local: SocketAddr,
    remote: SocketAddr,
    uid: u32,
}

fn lookup_proc(
    path: &str,
    local: SocketAddr,
    remote: SocketAddr,
    ipv6: bool,
) -> Result<Option<u32>, LookupError> {
    let file = File::open(path).map_err(LookupError::Io)?;
    let reader = BufReader::new(file);

    for (idx, line) in reader.lines().enumerate() {
        let line = line.map_err(LookupError::Io)?;
        if idx == 0 {
            continue;
        }
        if let Some(entry) = parse_proc_line(&line, ipv6) {
            if socket_addrs_match(&entry.local, &local) && socket_addrs_match(&entry.remote, &remote)
            {
                return Ok(Some(entry.uid));
            }
        }
    }

    Ok(None)
}

fn parse_proc_line(line: &str, ipv6: bool) -> Option<TcpEntry> {
    let mut parts = line.split_whitespace();
    let _sl = parts.next()?;
    let local = parts.next()?;
    let remote = parts.next()?;
    let _st = parts.next()?;
    let _tx_rx = parts.next()?;
    let _tr = parts.next()?;
    let _tm = parts.next()?;
    let uid = parts.next()?;

    let local = parse_addr_port(local, ipv6)?;
    let remote = parse_addr_port(remote, ipv6)?;
    let uid = uid.parse::<u32>().ok()?;

    Some(TcpEntry { local, remote, uid })
}

fn parse_addr_port(value: &str, ipv6: bool) -> Option<SocketAddr> {
    let (addr, port) = value.rsplit_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = if ipv6 {
        IpAddr::V6(parse_ipv6(addr)?)
    } else {
        IpAddr::V4(parse_ipv4(addr)?)
    };
    Some(SocketAddr::new(ip, port))
}

fn parse_ipv4(value: &str) -> Option<Ipv4Addr> {
    if value.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(value, 16).ok()?;
    let bytes = raw.swap_bytes().to_be_bytes();
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

fn parse_ipv6(value: &str) -> Option<Ipv6Addr> {
    if value.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (idx, chunk) in value.as_bytes().chunks(8).enumerate() {
        let chunk = std::str::from_utf8(chunk).ok()?;
        let raw = u32::from_str_radix(chunk, 16).ok()?;
        let be = raw.swap_bytes().to_be_bytes();
        let start = idx * 4;
        bytes[start..start + 4].copy_from_slice(&be);
    }
    Some(Ipv6Addr::from(bytes))
}

fn socket_addrs_match(left: &SocketAddr, right: &SocketAddr) -> bool {
    match (left, right) {
        (SocketAddr::V4(left), SocketAddr::V4(right)) => {
            left.ip() == right.ip() && left.port() == right.port()
        }
        (SocketAddr::V6(left), SocketAddr::V6(right)) => {
            left.ip() == right.ip() && left.port() == right.port()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_address() {
        let addr = parse_ipv4("0100007F").unwrap();
        assert_eq!(addr, Ipv4Addr::new(127, 0, 0, 1));
    }

    #[test]
    fn parse_ipv6_address() {
        let addr = parse_ipv6("00000000000000000000000001000000").unwrap();
        assert_eq!(addr, Ipv6Addr::LOCALHOST);
    }

    #[test]
    fn parse_proc_line_ipv4() {
        let line = "  1: 0100007F:1F90 0200007F:0035 01 00000000:00000000 00:00000000 00000000 1000 0 0";
        let entry = parse_proc_line(line, false).unwrap();
        assert_eq!(entry.local, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(entry.remote, "127.0.0.2:53".parse().unwrap());
        assert_eq!(entry.uid, 1000);
    }

    #[test]
    fn parse_proc_line_ipv6() {
        let line = "  2: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 1001 0 0";
        let entry = parse_proc_line(line, true).unwrap();
        assert_eq!(entry.local, "[::1]:53".parse().unwrap());
        assert_eq!(entry.remote, "[::]:0".parse().unwrap());
        assert_eq!(entry.uid, 1001);
    }
}
