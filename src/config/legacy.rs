use std::fmt;
use std::net::IpAddr;
use std::path::Path;

use crate::caps::Capability;

use super::Config;

const PORT_MIN: u16 = 1;
const PORT_MAX: u16 = 65535;

#[derive(Debug, Clone, Default)]
pub struct LegacyConfig {
    pub config: Config,
    pub sections: Vec<UserSection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSection {
    pub name: UserName,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserName {
    Default,
    Named(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub range: RuleRange,
    pub statements: Vec<CapStatement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleRange {
    Default,
    Spec(RangeSpec),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RangeSpec {
    pub to: Option<AddressSpec>,
    pub from: Option<AddressSpec>,
    pub fport: Option<PortRange>,
    pub lport: Option<PortRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressSpec {
    Ip(IpAddr),
    Host(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRange {
    pub min: u16,
    pub max: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapStatement {
    ForceCap(Capability),
    ForceReply(Vec<String>),
    ForceForward { host: AddressSpec, port: u16 },
    AllowCap(Capability),
    DenyCap(Capability),
    AllowForward,
    DenyForward,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserConfig {
    pub rules: Vec<UserPrefRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPrefRule {
    pub range: UserRange,
    pub preference: UserPreference,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserRange {
    Global,
    Spec(RangeSpec),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserPreference {
    Cap(Capability),
    Reply(Vec<String>),
    Forward { host: AddressSpec, port: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[line {}] {}", self.line, self.message)
    }
}

impl std::error::Error for ConfigError {}

pub fn load_legacy_config(path: &Path) -> std::io::Result<LegacyConfig> {
    let input = std::fs::read_to_string(path)?;
    parse_system_config(&input)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

pub fn parse_system_config(input: &str) -> Result<LegacyConfig, ConfigError> {
    let mut parser = Parser::new(input);
    parser.parse_system()
}

pub fn parse_user_config(input: &str) -> Result<UserConfig, ConfigError> {
    let mut parser = Parser::new(input);
    parser.parse_user()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    kind: TokenKind,
    line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    LBrace,
    RBrace,
    Keyword(Keyword),
    String(String),
    Eof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Keyword {
    User,
    Default,
    Global,
    To,
    From,
    Fport,
    Lport,
    Force,
    Reply,
    Forward,
    Allow,
    Deny,
    Hide,
    Random,
    Numeric,
    RandomNumeric,
    Spoof,
    SpoofAll,
    SpoofPrivPort,
}

struct Lexer<'a> {
    input: &'a [u8],
    idx: usize,
    line: usize,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            idx: 0,
            line: 1,
        }
    }

    fn next_token(&mut self) -> Result<Token, ConfigError> {
        loop {
            let Some(byte) = self.peek() else {
                return Ok(Token {
                    kind: TokenKind::Eof,
                    line: self.line,
                });
            };

            match byte {
                b' ' | b'\t' | b'\r' => {
                    self.bump();
                }
                b'\n' => {
                    self.bump();
                    self.line += 1;
                }
                b'#' => {
                    self.bump();
                    self.skip_until_newline();
                }
                b'/' if self.peek_next() == Some(b'*') => {
                    self.bump();
                    self.bump();
                    self.skip_comment_block()?;
                }
                b'{' => {
                    self.bump();
                    return Ok(Token {
                        kind: TokenKind::LBrace,
                        line: self.line,
                    });
                }
                b'}' => {
                    self.bump();
                    return Ok(Token {
                        kind: TokenKind::RBrace,
                        line: self.line,
                    });
                }
                b'"' => return self.read_quoted_string(),
                _ => return self.read_unquoted_string(),
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.idx).copied()
    }

    fn peek_next(&self) -> Option<u8> {
        self.input.get(self.idx + 1).copied()
    }

    fn bump(&mut self) {
        self.idx += 1;
    }

    fn skip_until_newline(&mut self) {
        while let Some(byte) = self.peek() {
            self.bump();
            if byte == b'\n' {
                self.line += 1;
                break;
            }
        }
    }

    fn skip_comment_block(&mut self) -> Result<(), ConfigError> {
        loop {
            let Some(byte) = self.peek() else {
                return Err(ConfigError {
                    line: self.line,
                    message: "unterminated comment".to_string(),
                });
            };

            if byte == b'\n' {
                self.line += 1;
            }

            if byte == b'*' && self.peek_next() == Some(b'/') {
                self.bump();
                self.bump();
                return Ok(());
            }

            self.bump();
        }
    }

    fn read_quoted_string(&mut self) -> Result<Token, ConfigError> {
        let line = self.line;
        let mut buf = Vec::new();
        self.bump();

        while let Some(byte) = self.peek() {
            match byte {
                b'"' => {
                    self.bump();
                    let value = String::from_utf8(buf).map_err(|_| ConfigError {
                        line,
                        message: "invalid utf-8 in string".to_string(),
                    })?;
                    return Ok(Token {
                        kind: TokenKind::String(value),
                        line,
                    });
                }
                b'\n' => {
                    self.bump();
                    self.line += 1;
                    return Err(ConfigError {
                        line,
                        message: "unterminated string".to_string(),
                    });
                }
                b'\\' => {
                    self.bump();
                    self.read_escape(&mut buf, line)?;
                }
                _ => {
                    buf.push(byte);
                    self.bump();
                }
            }
        }

        Err(ConfigError {
            line,
            message: "unterminated string".to_string(),
        })
    }

    fn read_escape(&mut self, buf: &mut Vec<u8>, line: usize) -> Result<(), ConfigError> {
        let Some(byte) = self.peek() else {
            return Err(ConfigError {
                line,
                message: "unterminated escape".to_string(),
            });
        };

        match byte {
            b'n' => {
                buf.push(b'\n');
                self.bump();
            }
            b't' => {
                buf.push(b'\t');
                self.bump();
            }
            b'r' => {
                buf.push(b'\r');
                self.bump();
            }
            b'f' => {
                buf.push(b'\x0c');
                self.bump();
            }
            b'b' => {
                buf.push(b'\x08');
                self.bump();
            }
            b'v' => {
                buf.push(b'\x0b');
                self.bump();
            }
            b'a' => {
                buf.push(b'\x07');
                self.bump();
            }
            b'x' | b'X' => {
                self.bump();
                self.read_hex_escape(buf, line)?;
            }
            b'0'..=b'7' => {
                self.read_octal_escape(buf, line)?;
            }
            b'8' | b'9' => {
                return Err(ConfigError {
                    line,
                    message: "bad escape sequence".to_string(),
                });
            }
            other => {
                buf.push(other);
                self.bump();
            }
        }

        Ok(())
    }

    fn read_octal_escape(&mut self, buf: &mut Vec<u8>, line: usize) -> Result<(), ConfigError> {
        let mut value: u32 = 0;
        let mut count = 0;

        while count < 3 {
            match self.peek() {
                Some(byte @ b'0'..=b'7') => {
                    value = (value * 8) + (byte - b'0') as u32;
                    self.bump();
                    count += 1;
                }
                _ => break,
            }
        }

        if value > 0xff {
            return Err(ConfigError {
                line,
                message: "bad escape sequence".to_string(),
            });
        }

        buf.push(value as u8);
        Ok(())
    }

    fn read_hex_escape(&mut self, buf: &mut Vec<u8>, line: usize) -> Result<(), ConfigError> {
        let mut value: u32 = 0;
        let mut count = 0;

        while count < 2 {
            match self.peek() {
                Some(byte) if byte.is_ascii_hexdigit() => {
                    value = (value * 16) + hex_value(byte) as u32;
                    self.bump();
                    count += 1;
                }
                _ => break,
            }
        }

        if count == 0 {
            return Err(ConfigError {
                line,
                message: "bad escape sequence".to_string(),
            });
        }

        buf.push(value as u8);
        Ok(())
    }

    fn read_unquoted_string(&mut self) -> Result<Token, ConfigError> {
        let line = self.line;
        let mut buf = Vec::new();

        while let Some(byte) = self.peek() {
            if byte.is_ascii_whitespace() || matches!(byte, b'{' | b'}' | b'"' | b'#') {
                break;
            }
            if byte == b'/' && self.peek_next() == Some(b'*') {
                break;
            }

            buf.push(byte);
            self.bump();
        }

        let value = String::from_utf8(buf).map_err(|_| ConfigError {
            line,
            message: "invalid utf-8 in token".to_string(),
        })?;

        if let Some(keyword) = keyword_from_str(&value) {
            return Ok(Token {
                kind: TokenKind::Keyword(keyword),
                line,
            });
        }

        Ok(Token {
            kind: TokenKind::String(value),
            line,
        })
    }
}

struct Parser<'a> {
    lexer: Lexer<'a>,
    lookahead: Option<Token>,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            lexer: Lexer::new(input),
            lookahead: None,
        }
    }

    fn parse_system(&mut self) -> Result<LegacyConfig, ConfigError> {
        let mut config = LegacyConfig::default();

        while !self.peek_is(TokenKind::Eof)? {
            let token = self.peek_token()?.clone();
            match token.kind {
                TokenKind::Keyword(Keyword::Default) => {
                    config.sections.push(self.parse_default_section()?);
                }
                TokenKind::Keyword(Keyword::User) => {
                    config.sections.push(self.parse_user_section()?);
                }
                _ => {
                    return Err(self.error("expected 'default' or 'user' section"));
                }
            }
        }

        Ok(config)
    }

    fn parse_user(&mut self) -> Result<UserConfig, ConfigError> {
        let mut rules = Vec::new();

        while !self.peek_is(TokenKind::Eof)? {
            rules.push(self.parse_user_pref_rule()?);
        }

        Ok(UserConfig { rules })
    }

    fn parse_default_section(&mut self) -> Result<UserSection, ConfigError> {
        self.expect_keyword(Keyword::Default)?;
        self.expect(TokenKind::LBrace)?;
        let rules = self.parse_target_rules()?;
        self.expect(TokenKind::RBrace)?;
        Ok(UserSection {
            name: UserName::Default,
            rules,
        })
    }

    fn parse_user_section(&mut self) -> Result<UserSection, ConfigError> {
        self.expect_keyword(Keyword::User)?;
        let name = self.expect_string("expected user name")?;
        self.expect(TokenKind::LBrace)?;
        let rules = self.parse_target_rules()?;
        self.expect(TokenKind::RBrace)?;
        Ok(UserSection {
            name: UserName::Named(name),
            rules,
        })
    }

    fn parse_target_rules(&mut self) -> Result<Vec<Rule>, ConfigError> {
        let mut rules = Vec::new();
        while !self.peek_is(TokenKind::RBrace)? {
            rules.push(self.parse_range_rule()?);
        }

        if rules.is_empty() {
            return Err(self.error("empty section"));
        }

        Ok(rules)
    }

    fn parse_range_rule(&mut self) -> Result<Rule, ConfigError> {
        if self.peek_keyword(Keyword::Default)? {
            self.expect_keyword(Keyword::Default)?;
            self.expect(TokenKind::LBrace)?;
            let statements = self.parse_cap_rule()?;
            self.expect(TokenKind::RBrace)?;
            return Ok(Rule {
                range: RuleRange::Default,
                statements,
            });
        }

        let range = self.parse_range_spec()?;
        self.expect(TokenKind::LBrace)?;
        let statements = self.parse_cap_rule()?;
        self.expect(TokenKind::RBrace)?;
        Ok(Rule {
            range: RuleRange::Spec(range),
            statements,
        })
    }

    fn parse_range_spec(&mut self) -> Result<RangeSpec, ConfigError> {
        let mut spec = RangeSpec::default();
        let mut saw = false;

        loop {
            let keyword = match self.peek_token()?.kind {
                TokenKind::Keyword(keyword) => keyword,
                _ => break,
            };

            match keyword {
                Keyword::To => {
                    self.expect_keyword(Keyword::To)?;
                    let token = self.expect_string("expected destination address")?;
                    if spec.to.is_some() {
                        return Err(self.error("'to' may only be specified once"));
                    }
                    spec.to = Some(parse_address(&token));
                    saw = true;
                }
                Keyword::From => {
                    self.expect_keyword(Keyword::From)?;
                    let token = self.expect_string("expected source address")?;
                    if spec.from.is_some() {
                        return Err(self.error("'from' may only be specified once"));
                    }
                    spec.from = Some(parse_address(&token));
                    saw = true;
                }
                Keyword::Fport => {
                    self.expect_keyword(Keyword::Fport)?;
                    let token = self.expect_string("expected fport range")?;
                    if spec.fport.is_some() {
                        return Err(self.error("'fport' may only be specified once"));
                    }
                    spec.fport = Some(parse_port_range(&token, self.line())?);
                    saw = true;
                }
                Keyword::Lport => {
                    self.expect_keyword(Keyword::Lport)?;
                    let token = self.expect_string("expected lport range")?;
                    if spec.lport.is_some() {
                        return Err(self.error("'lport' may only be specified once"));
                    }
                    spec.lport = Some(parse_port_range(&token, self.line())?);
                    saw = true;
                }
                _ => break,
            }
        }

        if !saw {
            return Err(self.error("expected range specification"));
        }

        Ok(spec)
    }

    fn parse_cap_rule(&mut self) -> Result<Vec<CapStatement>, ConfigError> {
        let mut statements = Vec::new();
        while !self.peek_is(TokenKind::RBrace)? {
            statements.push(self.parse_cap_statement()?);
        }

        if statements.is_empty() {
            return Err(self.error("expected capability statement"));
        }

        Ok(statements)
    }

    fn parse_cap_statement(&mut self) -> Result<CapStatement, ConfigError> {
        if self.peek_keyword(Keyword::Force)? {
            self.expect_keyword(Keyword::Force)?;
            let keyword = self.expect_keyword_any()?;
            return match keyword {
                Keyword::Reply => {
                    let replies = self.parse_reply_list()?;
                    Ok(CapStatement::ForceReply(replies))
                }
                Keyword::Forward => {
                    let host = self.expect_string("expected forward host")?;
                    let port = self.expect_string("expected forward port")?;
                    Ok(CapStatement::ForceForward {
                        host: parse_address(&host),
                        port: parse_port(&port, self.line())?,
                    })
                }
                _ => {
                    let cap = capability_from_keyword(keyword)
                        .ok_or_else(|| self.error("invalid force capability"))?;
                    Ok(CapStatement::ForceCap(cap))
                }
            };
        }

        let action = if self.peek_keyword(Keyword::Allow)? {
            self.expect_keyword(Keyword::Allow)?;
            "allow"
        } else if self.peek_keyword(Keyword::Deny)? {
            self.expect_keyword(Keyword::Deny)?;
            "deny"
        } else {
            return Err(self.error("expected 'allow', 'deny', or 'force'"));
        };

        let keyword = self.expect_keyword_any()?;
        if keyword == Keyword::Forward {
            return Ok(if action == "allow" {
                CapStatement::AllowForward
            } else {
                CapStatement::DenyForward
            });
        }

        let cap = capability_from_keyword(keyword)
            .ok_or_else(|| self.error("invalid capability"))?;

        Ok(if action == "allow" {
            CapStatement::AllowCap(cap)
        } else {
            CapStatement::DenyCap(cap)
        })
    }

    fn parse_user_pref_rule(&mut self) -> Result<UserPrefRule, ConfigError> {
        let range = if self.peek_keyword(Keyword::Global)? {
            self.expect_keyword(Keyword::Global)?;
            UserRange::Global
        } else {
            let spec = self.parse_range_spec()?;
            UserRange::Spec(spec)
        };

        self.expect(TokenKind::LBrace)?;
        let preference = self.parse_user_preference()?;
        self.expect(TokenKind::RBrace)?;

        Ok(UserPrefRule { range, preference })
    }

    fn parse_user_preference(&mut self) -> Result<UserPreference, ConfigError> {
        let keyword = self.expect_keyword_any()?;
        match keyword {
            Keyword::Reply => {
                let replies = self.parse_reply_list()?;
                Ok(UserPreference::Reply(replies))
            }
            Keyword::Forward => {
                let host = self.expect_string("expected forward host")?;
                let port = self.expect_string("expected forward port")?;
                Ok(UserPreference::Forward {
                    host: parse_address(&host),
                    port: parse_port(&port, self.line())?,
                })
            }
            _ => {
                let cap = capability_from_keyword(keyword)
                    .ok_or_else(|| self.error("invalid capability"))?;
                if matches!(cap, Capability::Spoof | Capability::SpoofAll | Capability::SpoofPrivPort)
                {
                    return Err(self.error("spoof capabilities not allowed in user config"));
                }
                Ok(UserPreference::Cap(cap))
            }
        }
    }

    fn parse_reply_list(&mut self) -> Result<Vec<String>, ConfigError> {
        let first = self.expect_string("expected reply string")?;
        let mut replies = vec![first];
        while let TokenKind::String(_) = self.peek_token()?.kind {
            replies.push(self.expect_string("expected reply string")?);
        }
        Ok(replies)
    }

    fn expect(&mut self, expected: TokenKind) -> Result<(), ConfigError> {
        let token = self.next_token()?;
        if token.kind == expected {
            Ok(())
        } else {
            Err(self.error(&format!("expected {:?}", expected)))
        }
    }

    fn expect_keyword(&mut self, expected: Keyword) -> Result<(), ConfigError> {
        let token = self.next_token()?;
        match token.kind {
            TokenKind::Keyword(keyword) if keyword == expected => Ok(()),
            _ => Err(self.error(&format!("expected {:?}", expected))),
        }
    }

    fn expect_keyword_any(&mut self) -> Result<Keyword, ConfigError> {
        let token = self.next_token()?;
        match token.kind {
            TokenKind::Keyword(keyword) => Ok(keyword),
            _ => Err(self.error("expected keyword")),
        }
    }

    fn expect_string(&mut self, message: &str) -> Result<String, ConfigError> {
        let token = self.next_token()?;
        match token.kind {
            TokenKind::String(value) => Ok(value),
            _ => Err(self.error(message)),
        }
    }

    fn peek_is(&mut self, expected: TokenKind) -> Result<bool, ConfigError> {
        Ok(self.peek_token()?.kind == expected)
    }

    fn peek_keyword(&mut self, expected: Keyword) -> Result<bool, ConfigError> {
        Ok(matches!(self.peek_token()?.kind, TokenKind::Keyword(keyword) if keyword == expected))
    }

    fn peek_token(&mut self) -> Result<&Token, ConfigError> {
        if self.lookahead.is_none() {
            self.lookahead = Some(self.lexer.next_token()?);
        }
        Ok(self.lookahead.as_ref().expect("token"))
    }

    fn next_token(&mut self) -> Result<Token, ConfigError> {
        if let Some(token) = self.lookahead.take() {
            Ok(token)
        } else {
            self.lexer.next_token()
        }
    }

    fn error(&self, message: &str) -> ConfigError {
        ConfigError {
            line: self.lexer.line,
            message: message.to_string(),
        }
    }

    fn line(&self) -> usize {
        self.lexer.line
    }
}

fn parse_address(token: &str) -> AddressSpec {
    if let Ok(ip) = token.parse::<IpAddr>() {
        AddressSpec::Ip(ip)
    } else {
        AddressSpec::Host(token.to_string())
    }
}

fn parse_port_range(token: &str, line: usize) -> Result<PortRange, ConfigError> {
    let (min, max) = if let Some((start, end)) = token.split_once(':') {
        let min = if start.is_empty() {
            PORT_MIN
        } else {
            parse_port(start, line)?
        };
        let max = if end.is_empty() {
            PORT_MAX
        } else {
            parse_port(end, line)?
        };
        (min, max)
    } else {
        let port = parse_port(token, line)?;
        (port, port)
    };

    if min > max {
        return Err(ConfigError {
            line,
            message: "port range is invalid".to_string(),
        });
    }

    Ok(PortRange { min, max })
}

fn parse_port(token: &str, line: usize) -> Result<u16, ConfigError> {
    let value = token.parse::<u16>().map_err(|_| ConfigError {
        line,
        message: format!("invalid port: {token}"),
    })?;

    if value < PORT_MIN || value > PORT_MAX {
        return Err(ConfigError {
            line,
            message: format!("port out of range: {token}"),
        });
    }

    Ok(value)
}

fn keyword_from_str(token: &str) -> Option<Keyword> {
    match token.to_ascii_lowercase().as_str() {
        "user" => Some(Keyword::User),
        "default" => Some(Keyword::Default),
        "global" => Some(Keyword::Global),
        "to" => Some(Keyword::To),
        "from" => Some(Keyword::From),
        "fport" => Some(Keyword::Fport),
        "lport" => Some(Keyword::Lport),
        "force" => Some(Keyword::Force),
        "reply" => Some(Keyword::Reply),
        "forward" => Some(Keyword::Forward),
        "allow" => Some(Keyword::Allow),
        "deny" => Some(Keyword::Deny),
        "hide" => Some(Keyword::Hide),
        "random" => Some(Keyword::Random),
        "numeric" => Some(Keyword::Numeric),
        "random_numeric" => Some(Keyword::RandomNumeric),
        "spoof" => Some(Keyword::Spoof),
        "spoof_all" => Some(Keyword::SpoofAll),
        "spoof_privport" => Some(Keyword::SpoofPrivPort),
        _ => None,
    }
}

fn capability_from_keyword(keyword: Keyword) -> Option<Capability> {
    match keyword {
        Keyword::Hide => Some(Capability::Hide),
        Keyword::Random => Some(Capability::Random),
        Keyword::Numeric => Some(Capability::Numeric),
        Keyword::RandomNumeric => Some(Capability::RandomNumeric),
        Keyword::Spoof => Some(Capability::Spoof),
        Keyword::SpoofAll => Some(Capability::SpoofAll),
        Keyword::SpoofPrivPort => Some(Capability::SpoofPrivPort),
        _ => None,
    }
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => 10 + (byte - b'a'),
        b'A'..=b'F' => 10 + (byte - b'A'),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sample_system_config() {
        let input = r#"
# sample

default {
    default {
        deny spoof
        deny spoof_all
        deny spoof_privport
        deny random
        deny random_numeric
        deny numeric
        deny hide
        deny forward
    }
}

user root {
    default {
        force hide
    }
}
"#;

        let config = parse_system_config(input).unwrap();
        assert_eq!(config.sections.len(), 2);

        let default_section = &config.sections[0];
        assert_eq!(default_section.name, UserName::Default);
        assert_eq!(default_section.rules.len(), 1);
        assert!(matches!(default_section.rules[0].range, RuleRange::Default));
        assert_eq!(default_section.rules[0].statements.len(), 8);

        let root_section = &config.sections[1];
        assert_eq!(root_section.name, UserName::Named("root".to_string()));
        assert_eq!(root_section.rules.len(), 1);
        assert!(matches!(root_section.rules[0].range, RuleRange::Default));
        assert_eq!(
            root_section.rules[0].statements,
            vec![CapStatement::ForceCap(Capability::Hide)]
        );
    }

    #[test]
    fn parse_range_spec_with_ports() {
        let input = r#"
user "alice" {
    to 192.0.2.1 from example.com lport 100:200 fport :6667 {
        allow random
    }
}
"#;

        let config = parse_system_config(input).unwrap();
        let section = &config.sections[0];
        let rule = &section.rules[0];
        let range = match &rule.range {
            RuleRange::Spec(spec) => spec,
            _ => panic!("expected spec"),
        };
        assert!(matches!(range.to, Some(AddressSpec::Ip(_))));
        assert!(matches!(range.from, Some(AddressSpec::Host(_))));
        assert_eq!(
            range.lport,
            Some(PortRange {
                min: 100,
                max: 200
            })
        );
        assert_eq!(
            range.fport,
            Some(PortRange {
                min: 1,
                max: 6667
            })
        );
    }

    #[test]
    fn parse_user_preferences() {
        let input = r#"
# user preferences

global { reply "a" "b" }

to 198.51.100.5 lport 5000:6000 {
    random
}
"#;

        let prefs = parse_user_config(input).unwrap();
        assert_eq!(prefs.rules.len(), 2);
        assert!(matches!(prefs.rules[0].range, UserRange::Global));
        assert!(matches!(prefs.rules[1].range, UserRange::Spec(_)));
        assert!(matches!(prefs.rules[1].preference, UserPreference::Cap(Capability::Random)));
    }

    #[test]
    fn user_prefs_reject_spoof() {
        let input = "global { spoof }";
        let err = parse_user_config(input).unwrap_err();
        assert!(err.message.contains("spoof"));
    }

    #[test]
    fn parse_allow_deny_force_statements() {
        let input = r#"
default {
    default {
        allow random
        deny hide
        force numeric
        force reply "alpha" "beta"
        force forward example.com 113
        allow forward
        deny forward
    }
}
"#;

        let config = parse_system_config(input).unwrap();
        let rule = &config.sections[0].rules[0];
        assert_eq!(
            rule.statements,
            vec![
                CapStatement::AllowCap(Capability::Random),
                CapStatement::DenyCap(Capability::Hide),
                CapStatement::ForceCap(Capability::Numeric),
                CapStatement::ForceReply(vec!["alpha".to_string(), "beta".to_string()]),
                CapStatement::ForceForward {
                    host: AddressSpec::Host("example.com".to_string()),
                    port: 113,
                },
                CapStatement::AllowForward,
                CapStatement::DenyForward,
            ]
        );
    }
}
