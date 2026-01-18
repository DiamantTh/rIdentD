use std::fmt;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::ident::{ErrorCode, Response};
use crate::net::{parse_request_line, RequestHandler};

pub const DEFAULT_FORWARD_PORT: u16 = 113;
const DEFAULT_FORWARD_TIMEOUT_SECS: u64 = 5;
const DEFAULT_CONNTRACK_PATHS: [&str; 2] = ["/proc/net/nf_conntrack", "/proc/net/ip_conntrack"];

pub fn default_conntrack_path() -> Option<PathBuf> {
    for path in DEFAULT_CONNTRACK_PATHS {
        let candidate = Path::new(path);
        if candidate.exists() {
            return Some(candidate.to_path_buf());
        }
    }
    None
}

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
pub struct NatOptions {
    pub forward_port: Option<u16>,
    pub masquerade_first: bool,
    pub proxy: Option<IpAddr>,
    pub conntrack_path: PathBuf,
    pub os: String,
}

impl NatOptions {
    pub fn new(conntrack_path: PathBuf) -> Self {
        Self {
            forward_port: None,
            masquerade_first: false,
            proxy: None,
            conntrack_path,
            os: "UNIX".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NatHandler {
    map: MasqueradeMap,
    options: NatOptions,
}

impl NatHandler {
    pub fn new(map: MasqueradeMap, options: NatOptions) -> Self {
        Self { map, options }
    }
}

impl RequestHandler for NatHandler {
    fn handle(&self, line: &str, _local: SocketAddr, remote: SocketAddr) -> String {
        match parse_request_line(line) {
            Ok(request) => {
                let mapping = find_conntrack_mapping(
                    &self.options.conntrack_path,
                    request.lport,
                    request.fport,
                    remote.ip(),
                    self.options.proxy,
                );
                let response = match mapping {
                    Some(mapping) => {
                        let static_entry = self.map.lookup(mapping.internal_ip);
                        let forwarded = if self.options.forward_port.is_some() {
                            if self.options.masquerade_first {
                                None
                            } else {
                                forward_request(
                                    &mapping,
                                    self.options.forward_port.unwrap(),
                                    &self.options.os,
                                )
                            }
                        } else {
                            None
                        };

                        if let Some(response) = forwarded {
                            response
                        } else if self.options.forward_port.is_some() && self.options.masquerade_first
                        {
                            if let Some(entry) = static_entry {
                                Response::UserId {
                                    os: entry.os.clone(),
                                    reply: entry.user.clone(),
                                }
                            } else if let Some(response) = forward_request(
                                &mapping,
                                self.options.forward_port.unwrap(),
                                &self.options.os,
                            ) {
                                response
                            } else {
                                Response::Error {
                                    code: ErrorCode::NoUser,
                                }
                            }
                        } else if let Some(entry) = static_entry {
                            Response::UserId {
                                os: entry.os.clone(),
                                reply: entry.user.clone(),
                            }
                        } else {
                            Response::Error {
                                code: ErrorCode::NoUser,
                            }
                        }
                    }
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

#[derive(Debug, Clone)]
struct ConntrackMapping {
    internal_ip: IpAddr,
    internal_lport: u16,
    internal_fport: u16,
}

#[derive(Debug, Clone)]
struct ConntrackEntry {
    orig: ConntrackTuple,
    reply: ConntrackTuple,
}

#[derive(Debug, Clone)]
struct ConntrackTuple {
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
}

#[derive(Clone, Default)]
struct TupleParts {
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
    sport: Option<u16>,
    dport: Option<u16>,
}

impl TupleParts {
    fn complete(&self) -> bool {
        self.src.is_some() && self.dst.is_some() && self.sport.is_some() && self.dport.is_some()
    }

    fn into_tuple(self) -> Option<ConntrackTuple> {
        Some(ConntrackTuple {
            src: self.src?,
            dst: self.dst?,
            sport: self.sport?,
            dport: self.dport?,
        })
    }
}

fn find_conntrack_mapping(
    path: &Path,
    lport: u16,
    fport: u16,
    remote_ip: IpAddr,
    proxy: Option<IpAddr>,
) -> Option<ConntrackMapping> {
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line.ok()?;
        if let Some(entry) = parse_conntrack_line(&line) {
            if let Some(mapping) = match_entry(entry, lport, fport, remote_ip, proxy) {
                return Some(mapping);
            }
        }
    }
    None
}

fn parse_conntrack_line(line: &str) -> Option<ConntrackEntry> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 6 {
        return None;
    }
    if tokens.get(2)? != &"tcp" {
        return None;
    }
    if !tokens.iter().any(|token| *token == "ESTABLISHED") {
        return None;
    }

    let mut tuples = [TupleParts::default(), TupleParts::default()];
    let mut idx = 0usize;
    for token in tokens {
        if let Some(value) = token.strip_prefix("src=") {
            tuples[idx].src = value.parse().ok();
        } else if let Some(value) = token.strip_prefix("dst=") {
            tuples[idx].dst = value.parse().ok();
        } else if let Some(value) = token.strip_prefix("sport=") {
            tuples[idx].sport = value.parse().ok();
        } else if let Some(value) = token.strip_prefix("dport=") {
            tuples[idx].dport = value.parse().ok();
        }

        if tuples[idx].complete() {
            if idx == 0 {
                idx = 1;
            } else {
                break;
            }
        }
    }

    let orig = tuples[0].clone().into_tuple()?;
    let reply = tuples[1].clone().into_tuple()?;
    Some(ConntrackEntry { orig, reply })
}

fn match_entry(
    entry: ConntrackEntry,
    lport: u16,
    fport: u16,
    remote_ip: IpAddr,
    proxy: Option<IpAddr>,
) -> Option<ConntrackMapping> {
    if entry.reply.dport != lport || entry.reply.sport != fport {
        return None;
    }

    if entry.reply.src != remote_ip {
        if let Some(proxy_ip) = proxy {
            if remote_ip != proxy_ip || entry.reply.src == proxy_ip {
                return None;
            }
        } else {
            return None;
        }
    }

    Some(ConntrackMapping {
        internal_ip: entry.orig.src,
        internal_lport: entry.orig.sport,
        internal_fport: entry.orig.dport,
    })
}

fn forward_request(
    mapping: &ConntrackMapping,
    port: u16,
    os: &str,
) -> Option<Response> {
    let addr = SocketAddr::new(mapping.internal_ip, port);
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(DEFAULT_FORWARD_TIMEOUT_SECS))
        .ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(DEFAULT_FORWARD_TIMEOUT_SECS)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(DEFAULT_FORWARD_TIMEOUT_SECS)));
    let mut stream = stream;
    let query = format!("{},{}\r\n", mapping.internal_lport, mapping.internal_fport);
    stream.write_all(query.as_bytes()).ok()?;
    let mut reader = BufReader::new(stream);
    let mut buf = String::new();
    reader.read_line(&mut buf).ok()?;
    let reply = parse_forward_reply(&buf)?;
    Some(Response::UserId {
        os: os.to_string(),
        reply,
    })
}

fn parse_forward_reply(line: &str) -> Option<String> {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let (_, rest) = trimmed.split_once(":USERID:")?;
    let (_, reply) = rest.split_once(':')?;
    if reply.is_empty() {
        return None;
    }
    Some(reply.to_string())
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

    #[test]
    fn parse_conntrack_ipv4_line() {
        let line = "ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.2 dst=93.184.216.34 sport=12345 dport=80 packets=1 bytes=2 src=93.184.216.34 dst=203.0.113.1 sport=80 dport=54321 [ASSURED] mark=0 use=1";
        let entry = parse_conntrack_line(line).unwrap();
        assert_eq!(entry.orig.src, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(entry.orig.dst, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(entry.orig.sport, 12345);
        assert_eq!(entry.orig.dport, 80);
        assert_eq!(entry.reply.src, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(entry.reply.dst, "203.0.113.1".parse::<IpAddr>().unwrap());
        assert_eq!(entry.reply.sport, 80);
        assert_eq!(entry.reply.dport, 54321);
    }

    #[test]
    fn match_conntrack_allows_proxy_origin() {
        let line = "ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.2 dst=93.184.216.34 sport=12345 dport=80 src=93.184.216.34 dst=203.0.113.1 sport=80 dport=54321";
        let entry = parse_conntrack_line(line).unwrap();
        let mapping = match_entry(
            entry,
            54321,
            80,
            "192.0.2.9".parse::<IpAddr>().unwrap(),
            Some("192.0.2.9".parse::<IpAddr>().unwrap()),
        )
        .unwrap();
        assert_eq!(mapping.internal_ip, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(mapping.internal_lport, 12345);
        assert_eq!(mapping.internal_fport, 80);
    }
}
