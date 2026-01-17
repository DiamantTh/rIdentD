# Rust Rewrite Instructions (rIdentD)

## Goal
Build rIdentD, a Rust implementation of oidentd (RFC 1413 Ident daemon) with
IPv4/IPv6, NAT support, forwarding, and per-user capability rules. Behavior
should be compatible with oidentd 3.x.

## Compatibility Targets
- Wire protocol: accept a single line `lport , fport` and reply with
  `lport,fport:USERID:<os>:<reply>\r\n` or `lport,fport:ERROR:<code>\r\n`.
- Error codes: `INVALID-PORT`, `NO-USER`, `HIDDEN-USER`. Support masking to
  `UNKNOWN-ERROR` when configured.
- CLI flags should match oidentd (short/long forms), including: `-a`, `-c`,
  `-C`, `-d`, `-e`, `-f`, `-m`, `-M`, `-P`, `-g`, `-i`, `-I`, `-l`, `-o`,
  `-p`, `-q`, `-S`, `-t`, `-u`, `-v`, `-r`, `-R`, `-h`.
- Logging behavior: syslog by default, stderr when `--nosyslog` or stderr is a
  TTY. `--quiet` suppresses non-critical logs; `--debug` enables debug logs.

## Core Behavior
- Listen on TCP port 113 by default; support multiple bind addresses.
- Parse request, validate ports (1..65535), reply or error without panic.
- Support connection limits and per-request timeout (alarm/timeout).
- Support daemon mode, foreground mode, and inetd/stdio mode.
- Reload configuration on SIGHUP when running as daemon.

## Configuration
Required (legacy format):
- Parse `oidentd.conf` with the existing grammar and semantics:
  - `default { ... }` and `user "<name>" { ... }`
  - Range specs: `to`, `from`, `fport`, `lport`
  - Capabilities: `reply`, `hide`, `random`, `random_numeric`, `numeric`,
    `forward`, plus `spoof`, `spoof_all`, `spoof_privport`
  - `allow`, `deny`, `force` directives
- Parse `oidentd_masq.conf` for NAT static replies:
  `host[/mask] user os`
- User config files: `~/.config/oidentd.conf` (preferred) or `~/.oidentd.conf`,
  read only if owned by the target user. If both exist, use XDG file.

Optional (TOML):
- If adding TOML, make it opt-in (e.g., `--config-format toml` or `.toml` file).
- TOML must be a strict subset of legacy semantics (no new behavior).

## Capabilities and Reply Selection
- System config grants/revokes capabilities; user config can only choose within
  granted capabilities.
- `force` in system config overrides user preferences.
- `reply` may be a list; choose randomly per request.
- `random` and `random_numeric` use non-crypto PRNG; log chosen replies.
- Enforce `spoof`, `spoof_all`, `spoof_privport` rules when replying with a
  username different from the actual user.

## NAT and Forwarding
- NAT support is opt-in.
- Static replies from `oidentd_masq.conf`.
- Forwarding:
  - Gateway: `--forward[=port]` forwards queries to target host.
  - Target servers: `--proxy <host>` accepts forwarded queries.
  - `--masquerade-first` changes preference order.

## OS-Specific UID Lookup
- Provide a trait/abstraction for UID lookup by 4-tuple.
- Linux:
  - Prefer netlink tcpdiag if available.
  - Fallback to `/proc/net/tcp` and `/proc/net/tcp6`.
  - NAT: read `/proc/net/nf_conntrack` or use libnetfilter_conntrack if built.
- BSD:
  - Use sysctl-based lookup (`net.inet.tcp.getcred`, `net.inet6.tcp6.getcred`).

## Security
- Drop privileges after startup (setgid/setuid/initgroups).
- Avoid reading user config unless owned by the user (stat/fstat checks).
- Avoid unsafe formatting; cap reply lengths (max 512).
- Never panic on malformed input; return correct error response.

## Suggested Rust Structure
- `main.rs` (CLI, startup, privilege drop, signal handling)
- `net/` (listener, accept loop, request parsing, timeouts)
- `config/legacy.rs`, `config/toml.rs`
- `caps.rs` (capability evaluation)
- `ident.rs` (response selection)
- `kernel/` (linux.rs, bsd.rs, trait)
- `nat.rs` (masq map + forwarding)
- `util.rs` (logging, safe file open, random)

## Testing
- Unit tests for legacy config parsing (ranges, allow/deny/force).
- Tests for reply selection and spoof rules.
- Protocol tests for request parsing and error handling.
- NAT parsing tests for masks and host matching.
