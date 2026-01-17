pub mod server;

use crate::ident::{ErrorCode, Response};

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
    match parse_request_line(line) {
        Ok(request) => crate::ident::format_response(
            request.lport,
            request.fport,
            Response::Error {
                code: ErrorCode::NoUser,
            },
        ),
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
}
