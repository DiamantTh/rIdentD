pub mod server;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crate::ident::{ErrorCode, Response};
use crate::kernel::{UidLookup, UnsupportedLookup};
use crate::util::username_from_uid;

const DEFAULT_OS: &str = "UNIX";

pub trait RequestHandler {
    fn handle(&self, line: &str, local: SocketAddr, remote: SocketAddr) -> String;
}

#[derive(Clone)]
pub struct IdentHandler {
    os: String,
    lookup: Arc<dyn UidLookup + Send + Sync>,
}

impl IdentHandler {
    pub fn new(os: String, lookup: Arc<dyn UidLookup + Send + Sync>) -> Self {
        Self { os, lookup }
    }
}

impl Default for IdentHandler {
    fn default() -> Self {
        Self {
            os: DEFAULT_OS.to_string(),
            lookup: Arc::new(UnsupportedLookup),
        }
    }
}

impl RequestHandler for IdentHandler {
    fn handle(&self, line: &str, local: SocketAddr, remote: SocketAddr) -> String {
        handle_request_line_with(
            line,
            local.ip(),
            remote.ip(),
            self.lookup.as_ref(),
            &self.os,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub lport: u16,
    pub fport: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    InvalidFormat,
    InvalidPort { lport: Option<u16>, fport: Option<u16> },
}

impl ParseError {
    pub fn ports_for_response(self) -> (u16, u16) {
        match self {
            ParseError::InvalidFormat => (0, 0),
            ParseError::InvalidPort { lport, fport } => (lport.unwrap_or(0), fport.unwrap_or(0)),
        }
    }
}

pub fn parse_request_line(line: &str) -> Result<Request, ParseError> {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let mut parts = trimmed.split(',');
    let lpart = parts.next();
    let fpart = parts.next();

    if parts.next().is_some() {
        return Err(ParseError::InvalidFormat);
    }

    let lpart = lpart.ok_or(ParseError::InvalidFormat)?;
    let fpart = fpart.ok_or(ParseError::InvalidFormat)?;

    let lport = parse_port(lpart);
    let fport = parse_port(fpart);

    match (lport, fport) {
        (Some(lport), Some(fport)) => Ok(Request { lport, fport }),
        _ => Err(ParseError::InvalidPort { lport, fport }),
    }
}

pub fn handle_request_line(line: &str) -> String {
    let lookup = UnsupportedLookup;
    handle_request_line_with(
        line,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        &lookup,
        DEFAULT_OS,
    )
}

pub fn handle_request_line_with(
    line: &str,
    local_ip: IpAddr,
    remote_ip: IpAddr,
    lookup: &dyn UidLookup,
    os: &str,
) -> String {
    match parse_request_line(line) {
        Ok(request) => {
            let local = SocketAddr::new(local_ip, request.lport);
            let remote = SocketAddr::new(remote_ip, request.fport);
            let response = match lookup.lookup_uid(local, remote) {
                Ok(Some(uid)) => {
                    let reply = username_from_uid(uid).unwrap_or_else(|| uid.to_string());
                    Response::UserId {
                        os: os.to_string(),
                        reply,
                    }
                }
                _ => Response::Error {
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

fn parse_port(input: &str) -> Option<u16> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let value = trimmed.parse::<u32>().ok()?;
    if (1..=65535).contains(&value) {
        Some(value as u16)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::LookupError;
    use crate::kernel::UidLookup;
    use std::net::{IpAddr, Ipv4Addr};

    struct FixedLookup {
        uid: Option<u32>,
    }

    impl UidLookup for FixedLookup {
        fn lookup_uid(
            &self,
            _local: SocketAddr,
            _remote: SocketAddr,
        ) -> Result<Option<u32>, LookupError> {
            Ok(self.uid)
        }
    }

    #[test]
    fn parses_ports_with_spaces() {
        let req = parse_request_line(" 123 , 456 \r\n").unwrap();
        assert_eq!(req, Request { lport: 123, fport: 456 });
    }

    #[test]
    fn invalid_format_rejected() {
        let err = parse_request_line("123").unwrap_err();
        assert_eq!(err, ParseError::InvalidFormat);
    }

    #[test]
    fn invalid_port_rejected() {
        let err = parse_request_line("0,70000").unwrap_err();
        assert_eq!(
            err,
            ParseError::InvalidPort {
                lport: None,
                fport: None
            }
        );
    }

    #[test]
    fn handle_invalid_format_returns_invalid_port_error() {
        let response = handle_request_line("oops");
        assert_eq!(response, "0,0:ERROR:INVALID-PORT\r\n");
    }

    #[test]
    fn handle_request_uses_lookup_when_available() {
        let lookup = FixedLookup { uid: Some(0) };
        let response = handle_request_line_with(
            "1,2",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &lookup,
            "TESTOS",
        );
        assert!(response.starts_with("1,2:USERID:TESTOS:"));
        assert!(response.ends_with("\r\n"));
    }

    #[test]
    fn handle_request_returns_no_user_when_missing() {
        let lookup = FixedLookup { uid: None };
        let response = handle_request_line_with(
            "3,4",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &lookup,
            "TESTOS",
        );
        assert_eq!(response, "3,4:ERROR:NO-USER\r\n");
    }
}
