use std::fmt;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use crate::ident::{ErrorCode, Response};
use crate::net::{parse_request_line, RequestHandler};

#[derive(Debug, Clone, Default)]
pub struct MasqueradeMap {
    entries: Vec<MasqueradeEntry>,
}

impl MasqueradeMap {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn load(path: &Path) -> std::io::Result<Self> {
        let input = fs::read_to_string(path)?;
        Self::parse(&input)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }

    pub fn parse(input: &str) -> Result<Self, MasqueradeError> {
        let mut entries = Vec::new();
        for (idx, raw_line) in input.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }

            let mut parts = line.split_whitespace();
            let host = parts
                .next()
                .ok_or_else(|| MasqueradeError::new(line_no, "expected host entry"))?;
            let user = parts
                .next()
                .ok_or_else(|| MasqueradeError::new(line_no, "expected user"))?;
            let os = parts
                .next()
                .ok_or_else(|| MasqueradeError::new(line_no, "expected os"))?;
            if parts.next().is_some() {
                return Err(MasqueradeError::new(
                    line_no,
                    "unexpected trailing data",
                ));
            }

            let network = parse_host(host, line_no)?;
            entries.push(MasqueradeEntry {
                network,
                user: user.to_string(),
                os: os.to_string(),
            });
        }

        Ok(Self { entries })
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<&MasqueradeEntry> {
        self.entries.iter().find(|entry| entry.network.contains(ip))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasqueradeEntry {
    pub network: IpNet,
    pub user: String,
    pub os: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    fn contains(self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                let mask = ipv4_mask(self.prefix);
                (u32::from(net) & mask) == (u32::from(addr) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                let mask = ipv6_mask(self.prefix);
                (u128::from(net) & mask) == (u128::from(addr) & mask)
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasqueradeError {
    pub line: usize,
    pub message: String,
}

impl MasqueradeError {
    fn new(line: usize, message: &str) -> Self {
        Self {
            line,
            message: message.to_string(),
        }
    }
}

impl fmt::Display for MasqueradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[line {}] {}", self.line, self.message)
    }
}

impl std::error::Error for MasqueradeError {}

#[derive(Debug, Clone)]
pub struct MasqueradeHandler {
    map: MasqueradeMap,
}

impl MasqueradeHandler {
    pub fn new(map: MasqueradeMap) -> Self {
        Self { map }
    }
}

impl RequestHandler for MasqueradeHandler {
    fn handle(&self, line: &str, _local: SocketAddr, remote: SocketAddr) -> String {
        match parse_request_line(line) {
            Ok(request) => {
                let response = match self.map.lookup(remote.ip()) {
                    Some(entry) => Response::UserId {
                        os: entry.os.clone(),
                        reply: entry.user.clone(),
                    },
                    None => Response::Error {
                        code: ErrorCode::NoUser,
                    },
                };
                crate::ident::format_response(request.lport, request.fport, response)
            }
            Err(err) => {
                let (lport, fport) = err.ports_for_response();
                crate::ident::format_response(
                    lport,
                    fport,
                    Response::Error {
                        code: ErrorCode::InvalidPort,
                    },
                )
            }
        }
    }
}

fn parse_host(token: &str, line: usize) -> Result<IpNet, MasqueradeError> {
    let (host, prefix) = match token.split_once('/') {
        Some((host, prefix)) => (host, Some(prefix)),
        None => (token, None),
    };

    let addr: IpAddr = host
        .parse()
        .map_err(|_| MasqueradeError::new(line, "invalid host address"))?;
    let max = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    let prefix = match prefix {
        Some(raw) => raw
            .parse::<u8>()
            .map_err(|_| MasqueradeError::new(line, "invalid mask"))?,
        None => max,
    };
    if prefix > max {
        return Err(MasqueradeError::new(line, "mask out of range"));
    }

    Ok(IpNet { addr, prefix })
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        (!0u32) << (32 - prefix)
    }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        (!0u128) << (128 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn parse_single_entry() {
        let input = "192.0.2.5 alice UNIX";
        let map = MasqueradeMap::parse(input).unwrap();
        assert_eq!(map.entries.len(), 1);
        let entry = &map.entries[0];
        assert_eq!(
            entry.network,
            IpNet {
                addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
                prefix: 32
            }
        );
        assert_eq!(entry.user, "alice");
        assert_eq!(entry.os, "UNIX");
    }

    #[test]
    fn lookup_matches_ipv4_mask() {
        let input = "198.51.100.0/24 bob UNIX";
        let map = MasqueradeMap::parse(input).unwrap();
        assert!(map.lookup(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))).is_some());
        assert!(map.lookup(IpAddr::V4(Ipv4Addr::new(198, 51, 101, 9))).is_none());
    }

    #[test]
    fn lookup_matches_ipv6_mask() {
        let input = "2001:db8::/64 carol UNIX";
        let map = MasqueradeMap::parse(input).unwrap();
        assert!(map
            .lookup(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()))
            .is_some());
        assert!(map
            .lookup(IpAddr::V6("2001:db9::1".parse::<Ipv6Addr>().unwrap()))
            .is_none());
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let input = r#"
# comment
203.0.113.1 dave UNIX # trailing

2001:db8::1 erin UNIX
"#;
        let map = MasqueradeMap::parse(input).unwrap();
        assert_eq!(map.entries.len(), 2);
    }

    #[test]
    fn invalid_mask_rejected() {
        let err = MasqueradeMap::parse("192.0.2.1/33 user UNIX").unwrap_err();
        assert!(err.message.contains("mask"));
    }
}
