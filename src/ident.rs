#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidPort,
    NoUser,
    HiddenUser,
    UnknownError,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidPort => "INVALID-PORT",
            ErrorCode::NoUser => "NO-USER",
            ErrorCode::HiddenUser => "HIDDEN-USER",
            ErrorCode::UnknownError => "UNKNOWN-ERROR",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    UserId { os: String, reply: String },
    Error { code: ErrorCode },
}

pub const MAX_REPLY_LEN: usize = 512;

pub fn format_response(lport: u16, fport: u16, response: Response) -> String {
    match response {
        Response::UserId { os, reply } => {
            let os = truncate_utf8(&os, MAX_REPLY_LEN);
            let reply = truncate_utf8(&reply, MAX_REPLY_LEN);
            format!("{lport},{fport}:USERID:{os}:{reply}\r\n")
        }
        Response::Error { code } => {
            let code = code.as_str();
            format!("{lport},{fport}:ERROR:{code}\r\n")
        }
    }
}

#[derive(Debug, Clone)]
pub struct SelectionContext<'a> {
    pub uid: u32,
    pub user: &'a str,
    pub lport: u16,
    pub fport: u16,
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
}

#[derive(Debug, Clone)]
enum ForcedAction {
    Reply(Vec<String>),
    Forward { host: AddressSpec, port: u16 },
    Hide,
    Random,
    RandomNumeric,
    Numeric,
}

#[derive(Debug, Clone, Default)]
struct SystemDecision {
    allowed: HashSet<Capability>,
    forced: Option<ForcedAction>,
}

pub fn select_response(
    system: Option<&LegacyConfig>,
    user_prefs: Option<&UserConfig>,
    ctx: &SelectionContext<'_>,
    os: &str,
) -> Response {
    let decision = system
        .and_then(|config| select_system_decision(config, ctx))
        .unwrap_or_default();

    if let Some(forced) = decision.forced {
        return match apply_forced_action(forced, ctx, os) {
            Some(response) => response,
            None => Response::Error {
                code: ErrorCode::HiddenUser,
            },
        };
    }

    if let Some(pref) = user_prefs.and_then(|prefs| select_user_preference(prefs, ctx)) {
        if let Some(response) = apply_user_preference(pref, &decision.allowed, ctx, os) {
            return response;
        }
    }

    Response::UserId {
        os: os.to_string(),
        reply: ctx.user.to_string(),
    }
}

fn select_system_decision(config: &LegacyConfig, ctx: &SelectionContext<'_>) -> Option<SystemDecision> {
    let section = config
        .sections
        .iter()
        .find(|section| matches!(&section.name, UserName::Named(name) if name == ctx.user))
        .or_else(|| config.sections.iter().find(|section| section.name == UserName::Default))?;

    let rule = select_rule(&section.rules, ctx)?;
    Some(apply_system_statements(&rule.statements))
}

fn select_rule<'a>(rules: &'a [crate::config::legacy::Rule], ctx: &SelectionContext<'_>) -> Option<&'a crate::config::legacy::Rule> {
    let mut default_rule = None;
    for rule in rules {
        match &rule.range {
            RuleRange::Default => {
                if default_rule.is_none() {
                    default_rule = Some(rule);
                }
            }
            RuleRange::Spec(spec) => {
                if range_matches(spec, ctx) {
                    return Some(rule);
                }
            }
        }
    }
    default_rule
}

fn select_user_preference<'a>(
    prefs: &'a UserConfig,
    ctx: &SelectionContext<'_>,
) -> Option<UserPreference> {
    let mut global_pref = None;
    for rule in &prefs.rules {
        match &rule.range {
            UserRange::Global => {
                if global_pref.is_none() {
                    global_pref = Some(rule.preference.clone());
                }
            }
            UserRange::Spec(spec) => {
                if range_matches(spec, ctx) {
                    return Some(rule.preference.clone());
                }
            }
        }
    }
    global_pref
}

fn apply_system_statements(statements: &[CapStatement]) -> SystemDecision {
    let mut decision = SystemDecision::default();
    for statement in statements {
        match statement {
            CapStatement::ForceReply(replies) => {
                decision.forced = Some(ForcedAction::Reply(replies.clone()));
            }
            CapStatement::ForceForward { host, port } => {
                decision.forced = Some(ForcedAction::Forward {
                    host: host.clone(),
                    port: *port,
                });
            }
            CapStatement::ForceCap(cap) => {
                match cap {
                    Capability::Hide => decision.forced = Some(ForcedAction::Hide),
                    Capability::Random => decision.forced = Some(ForcedAction::Random),
                    Capability::RandomNumeric => {
                        decision.forced = Some(ForcedAction::RandomNumeric)
                    }
                    Capability::Numeric => decision.forced = Some(ForcedAction::Numeric),
                    _ => {
                        decision.allowed.insert(*cap);
                    }
                };
            }
            CapStatement::AllowCap(cap) => {
                decision.allowed.insert(*cap);
            }
            CapStatement::DenyCap(cap) => {
                decision.allowed.remove(cap);
            }
            CapStatement::AllowForward => {
                decision.allowed.insert(Capability::Forward);
            }
            CapStatement::DenyForward => {
                decision.allowed.remove(&Capability::Forward);
            }
        }
    }
    decision
}

fn apply_forced_action(
    forced: ForcedAction,
    ctx: &SelectionContext<'_>,
    os: &str,
) -> Option<Response> {
    match forced {
        ForcedAction::Reply(replies) => {
            let reply = select_reply(&replies)?;
            Some(Response::UserId {
                os: os.to_string(),
                reply,
            })
        }
        ForcedAction::Forward { host, port } => {
            let reply = forward_request(&host, port, ctx.lport, ctx.fport)?;
            Some(Response::UserId {
                os: os.to_string(),
                reply,
            })
        }
        ForcedAction::Hide => Some(Response::Error {
            code: ErrorCode::HiddenUser,
        }),
        ForcedAction::Random => Some(Response::UserId {
            os: os.to_string(),
            reply: random_ident(12),
        }),
        ForcedAction::RandomNumeric => Some(Response::UserId {
            os: os.to_string(),
            reply: random_numeric_ident(),
        }),
        ForcedAction::Numeric => Some(Response::UserId {
            os: os.to_string(),
            reply: ctx.uid.to_string(),
        }),
    }
}

fn apply_user_preference(
    pref: UserPreference,
    allowed: &HashSet<Capability>,
    ctx: &SelectionContext<'_>,
    os: &str,
) -> Option<Response> {
    match pref {
        UserPreference::Cap(cap) => match cap {
            Capability::Hide if allowed.contains(&Capability::Hide) => Some(Response::Error {
                code: ErrorCode::HiddenUser,
            }),
            Capability::Random if allowed.contains(&Capability::Random) => Some(Response::UserId {
                os: os.to_string(),
                reply: random_ident(12),
            }),
            Capability::RandomNumeric if allowed.contains(&Capability::RandomNumeric) => {
                Some(Response::UserId {
                    os: os.to_string(),
                    reply: random_numeric_ident(),
                })
            }
            Capability::Numeric if allowed.contains(&Capability::Numeric) => Some(Response::UserId {
                os: os.to_string(),
                reply: ctx.uid.to_string(),
            }),
            _ => None,
        },
        UserPreference::Reply(replies) => {
            let reply = select_reply(&replies)?;
            if can_reply(allowed, ctx.uid, &reply, ctx.fport) {
                Some(Response::UserId {
                    os: os.to_string(),
                    reply,
                })
            } else {
                None
            }
        }
        UserPreference::Forward { host, port } => {
            if !allowed.contains(&Capability::Forward) {
                return None;
            }
            if let Some(reply) = forward_request(&host, port, ctx.lport, ctx.fport) {
                if can_reply(allowed, ctx.uid, &reply, ctx.fport) {
                    return Some(Response::UserId {
                        os: os.to_string(),
                        reply,
                    });
                }
            } else if allowed.contains(&Capability::Hide) {
                return Some(Response::Error {
                    code: ErrorCode::HiddenUser,
                });
            }
            None
        }
    }
}

fn select_reply(replies: &[String]) -> Option<String> {
    if replies.is_empty() {
        return None;
    }
    let idx = rand_range(replies.len() as u32) as usize;
    replies.get(idx).cloned()
}

fn random_ident(len: usize) -> String {
    const CHARS: &[u8] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut reply = String::with_capacity(len);
    for _ in 0..len {
        let idx = rand_range(CHARS.len() as u32) as usize;
        reply.push(CHARS[idx] as char);
    }
    reply
}

fn random_numeric_ident() -> String {
    let value = rand_range(100000);
    format!("user{value}")
}

fn can_reply(allowed: &HashSet<Capability>, uid: u32, reply: &str, fport: u16) -> bool {
    if reply.is_empty() {
        return false;
    }

    if let Some(reply_uid) = uid_from_username(reply) {
        if reply_uid == uid {
            return true;
        }
        if !allowed.contains(&Capability::SpoofAll) {
            return false;
        }
    }

    if !allowed.contains(&Capability::Spoof) {
        return false;
    }

    if fport < 1024 && !allowed.contains(&Capability::SpoofPrivPort) {
        return false;
    }

    true
}

fn range_matches(spec: &RangeSpec, ctx: &SelectionContext<'_>) -> bool {
    if let Some(to) = &spec.to {
        if !address_matches(to, ctx.remote_ip) {
            return false;
        }
    }
    if let Some(from) = &spec.from {
        if !address_matches(from, ctx.local_ip) {
            return false;
        }
    }
    if let Some(range) = &spec.fport {
        if !port_in_range(ctx.fport, range) {
            return false;
        }
    }
    if let Some(range) = &spec.lport {
        if !port_in_range(ctx.lport, range) {
            return false;
        }
    }
    true
}

fn address_matches(spec: &AddressSpec, ip: IpAddr) -> bool {
    match spec {
        AddressSpec::Ip(addr) => *addr == ip,
        AddressSpec::Host(host) => host.parse::<IpAddr>().map_or(false, |addr| addr == ip),
    }
}

fn port_in_range(port: u16, range: &PortRange) -> bool {
    (range.min..=range.max).contains(&port)
}

fn forward_request(
    host: &AddressSpec,
    port: u16,
    lport: u16,
    fport: u16,
) -> Option<String> {
    use std::io::{BufRead, BufReader, Write};
    use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let mut targets: Vec<SocketAddr> = Vec::new();
    match host {
        AddressSpec::Ip(ip) => targets.push(SocketAddr::new(*ip, port)),
        AddressSpec::Host(name) => {
            if let Ok(ip) = name.parse::<IpAddr>() {
                targets.push(SocketAddr::new(ip, port));
            } else {
                let addrs = (name.as_str(), port).to_socket_addrs().ok()?;
                targets.extend(addrs);
            }
        }
    }
    let target = targets.into_iter().next()?;
    let timeout = Duration::from_secs(5);
    let stream = TcpStream::connect_timeout(&target, timeout).ok()?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let mut stream = stream;
    let query = format!("{lport},{fport}\r\n");
    stream.write_all(query.as_bytes()).ok()?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    parse_forward_reply(&line)
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

fn truncate_utf8(input: &str, max_len: usize) -> String {
    if input.len() <= max_len {
        return input.to_string();
    }

    let mut end = 0;
    for (idx, _) in input.char_indices() {
        if idx > max_len {
            break;
        }
        end = idx;
    }

    input[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::legacy::{parse_system_config, parse_user_config};
    use std::net::Ipv4Addr;

    #[test]
    fn format_error_response() {
        let response = format_response(123, 456, Response::Error { code: ErrorCode::NoUser });
        assert_eq!(response, "123,456:ERROR:NO-USER\r\n");
    }

    #[test]
    fn format_userid_response() {
        let response = format_response(
            1,
            2,
            Response::UserId {
                os: "UNIX".to_string(),
                reply: "alice".to_string(),
            },
        );
        assert_eq!(response, "1,2:USERID:UNIX:alice\r\n");
    }

    #[test]
    fn forced_hide_overrides_defaults() {
        let system = parse_system_config(
            r#"
default {
    default {
        force hide
    }
}
"#,
        )
        .unwrap();
        let ctx = SelectionContext {
            uid: 1000,
            user: "alice",
            lport: 1,
            fport: 2,
            local_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            remote_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        };
        let response = select_response(Some(&system), None, &ctx, "UNIX");
        assert_eq!(
            response,
            Response::Error {
                code: ErrorCode::HiddenUser
            }
        );
    }

    #[test]
    fn random_reply_allowed_by_capability() {
        let system = parse_system_config(
            r#"
default {
    default {
        allow random
    }
}
"#,
        )
        .unwrap();
        let user = parse_user_config("global { random }").unwrap();
        let ctx = SelectionContext {
            uid: 1000,
            user: "alice",
            lport: 1,
            fport: 2222,
            local_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            remote_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        };
        let response = select_response(Some(&system), Some(&user), &ctx, "UNIX");
        match response {
            Response::UserId { reply, .. } => {
                assert_eq!(reply.len(), 12);
            }
            _ => panic!("expected USERID response"),
        }
    }

    #[test]
    fn reply_requires_spoof_privport_for_privileged_ports() {
        let system = parse_system_config(
            r#"
default {
    default {
        allow spoof
    }
}
"#,
        )
        .unwrap();
        let user = parse_user_config(r#"global { reply "spoofed" }"#).unwrap();
        let ctx = SelectionContext {
            uid: 1000,
            user: "alice",
            lport: 1,
            fport: 22,
            local_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            remote_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        };
        let response = select_response(Some(&system), Some(&user), &ctx, "UNIX");
        assert_eq!(
            response,
            Response::UserId {
                os: "UNIX".to_string(),
                reply: "alice".to_string(),
            }
        );
    }
}
use std::collections::HashSet;
use std::net::IpAddr;

use crate::caps::Capability;
use crate::config::legacy::{
    AddressSpec, CapStatement, LegacyConfig, PortRange, RangeSpec, RuleRange, UserConfig,
    UserPreference, UserRange, UserName,
};
use crate::util::{rand_range, uid_from_username};
