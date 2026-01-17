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
}
