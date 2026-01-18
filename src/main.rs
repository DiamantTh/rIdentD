use std::collections::VecDeque;
use std::env;
use std::io::{self, BufRead};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ridentd::{config, kernel, net, util};

const DEFAULT_PORT: u16 = 113;

fn main() {
    if let Err(err) = run() {
        eprintln!("ridentd: {err}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let opts = match parse_args() {
        Ok(opts) => opts,
        Err(message) => {
            eprintln!("ridentd: {message}");
            print_usage();
            return Ok(());
        }
    };

    if opts.help {
        print_usage();
        return Ok(());
    }

    if opts.version {
        print_version();
        return Ok(());
    }

    if opts.masquerade_path.is_some() || opts.proxy.is_some() || opts.masquerade_first {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NAT options are handled by ridentd-natd",
        ));
    }

    if opts.inetd {
        return run_inetd();
    }

    load_system_config(&opts)?;

    let addrs = util::build_socket_addrs(&opts.addrs, opts.port)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let os = opts
        .os
        .clone()
        .unwrap_or_else(|| config::Config::default().os);
    let lookup = build_lookup();
    let handler = Arc::new(net::IdentHandler::new(os, lookup));
    let server_config = net::server::ServerConfig {
        addrs,
        timeout: opts.timeout,
        connection_limit: opts.connection_limit,
        max_line_len: opts.max_line_len,
        handler,
    };

    net::server::serve(server_config)
}

fn run_inetd() -> io::Result<()> {
    let stdin = io::stdin();
    let mut handle = stdin.lock();
    let mut line = String::new();
    let bytes = handle.read_line(&mut line)?;
    if bytes == 0 {
        return Ok(());
    }

    let response = net::handle_request_line(&line);
    print!("{response}");
    Ok(())
}

#[derive(Debug)]
struct CliOptions {
    addrs: Vec<String>,
    port: u16,
    inetd: bool,
    timeout: Option<Duration>,
    connection_limit: usize,
    max_line_len: usize,
    help: bool,
    version: bool,
    debug: bool,
    quiet: bool,
    nosyslog: bool,
    foreground: bool,
    masquerade_first: bool,
    config_path: Option<PathBuf>,
    config_format: Option<String>,
    masquerade_path: Option<PathBuf>,
    proxy: Option<String>,
    group: Option<String>,
    inetd_compat: Option<String>,
    log_path: Option<PathBuf>,
    os: Option<String>,
    user: Option<String>,
    error_mask: Option<String>,
    random: Option<String>,
    reply: Option<String>,
}

impl Default for CliOptions {
    fn default() -> Self {
        Self {
            addrs: Vec::new(),
            port: DEFAULT_PORT,
            inetd: false,
            timeout: Some(Duration::from_secs(30)),
            connection_limit: 128,
            max_line_len: 1024,
            help: false,
            version: false,
            debug: false,
            quiet: false,
            nosyslog: false,
            foreground: false,
            masquerade_first: false,
            config_path: None,
            config_format: None,
            masquerade_path: None,
            proxy: None,
            group: None,
            inetd_compat: None,
            log_path: None,
            os: None,
            user: None,
            error_mask: None,
            random: None,
            reply: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValueMode {
    None,
    Required,
    Optional,
}

fn parse_args() -> Result<CliOptions, String> {
    let mut opts = CliOptions::default();
    let mut args: VecDeque<String> = env::args().skip(1).collect();

    while let Some(arg) = args.pop_front() {
        if arg == "--" {
            break;
        }

        if arg.starts_with("--") {
            handle_long_arg(&arg, &mut args, &mut opts)?;
            continue;
        }

        if arg.starts_with('-') {
            handle_short_arg(&arg, &mut args, &mut opts)?;
            continue;
        }

        return Err(format!("unexpected argument: {arg}"));
    }

    Ok(opts)
}

fn handle_long_arg(
    arg: &str,
    args: &mut VecDeque<String>,
    opts: &mut CliOptions,
) -> Result<(), String> {
    let trimmed = arg.trim_start_matches("--");
    let (key, inline_value) = match trimmed.split_once('=') {
        Some((key, value)) => (key, Some(value.to_string())),
        None => (trimmed, None),
    };

    let mode = match key {
        "address" => ValueMode::Required,
        "config" => ValueMode::Required,
        "config-format" => ValueMode::Required,
        "debug" => ValueMode::None,
        "error" => ValueMode::Optional,
        "foreground" => ValueMode::None,
        "masquerade" => ValueMode::Required,
        "masquerade-first" => ValueMode::None,
        "proxy" => ValueMode::Required,
        "group" => ValueMode::Required,
        "inetd" => ValueMode::None,
        "inetd-compat" => ValueMode::Optional,
        "log" => ValueMode::Optional,
        "os" => ValueMode::Required,
        "port" => ValueMode::Required,
        "quiet" => ValueMode::None,
        "nosyslog" => ValueMode::None,
        "timeout" => ValueMode::Required,
        "user" => ValueMode::Required,
        "version" => ValueMode::None,
        "random" => ValueMode::Optional,
        "reply" => ValueMode::Optional,
        "help" => ValueMode::None,
        _ => return Err(format!("unknown option: --{key}")),
    };

    let value = extract_value(mode, inline_value, args, key)?;
    apply_long_option(key, value, opts)
}

fn handle_short_arg(
    arg: &str,
    args: &mut VecDeque<String>,
    opts: &mut CliOptions,
) -> Result<(), String> {
    if arg.len() >= 3 {
        if let Some((flag, value)) = arg.split_once('=') {
            let flag = flag.trim_start_matches('-');
            if flag.len() != 1 {
                return Err(format!("invalid option: {arg}"));
            }
            let mode = short_value_mode(flag.chars().next().unwrap())
                .ok_or_else(|| format!("unknown option: -{flag}"))?;
            let value = extract_value(mode, Some(value.to_string()), args, flag)?;
            return apply_short_option(flag.chars().next().unwrap(), value, opts);
        }

        let flags = arg.trim_start_matches('-');
        if flags.len() > 1 {
            let mut chars = flags.chars().peekable();
            while let Some(flag) = chars.next() {
                let mode = short_value_mode(flag)
                    .ok_or_else(|| format!("unknown option: -{flag}"))?;
                if mode != ValueMode::None {
                    if chars.peek().is_some() {
                        return Err(format!(
                            "option -{flag} requires a value and cannot be grouped"
                        ));
                    }
                    let value = extract_value(mode, None, args, &format!("-{flag}"))?;
                    return apply_short_option(flag, value, opts);
                }
                apply_short_option(flag, None, opts)?;
            }
            return Ok(());
        }
    }

    let flag = arg.trim_start_matches('-');
    let flag = flag
        .chars()
        .next()
        .ok_or_else(|| format!("invalid option: {arg}"))?;
    let mode = short_value_mode(flag).ok_or_else(|| format!("unknown option: -{flag}"))?;
    let value = extract_value(mode, None, args, &format!("-{flag}"))?;
    apply_short_option(flag, value, opts)
}

fn short_value_mode(flag: char) -> Option<ValueMode> {
    match flag {
        'a' => Some(ValueMode::Required),
        'c' => Some(ValueMode::Required),
        'C' => Some(ValueMode::Required),
        'd' => Some(ValueMode::None),
        'e' => Some(ValueMode::Optional),
        'f' => Some(ValueMode::None),
        'm' => Some(ValueMode::Required),
        'M' => Some(ValueMode::None),
        'P' => Some(ValueMode::Required),
        'g' => Some(ValueMode::Required),
        'i' => Some(ValueMode::None),
        'I' => Some(ValueMode::Optional),
        'l' => Some(ValueMode::Optional),
        'o' => Some(ValueMode::Required),
        'p' => Some(ValueMode::Required),
        'q' => Some(ValueMode::None),
        'S' => Some(ValueMode::None),
        't' => Some(ValueMode::Required),
        'u' => Some(ValueMode::Required),
        'v' => Some(ValueMode::None),
        'r' => Some(ValueMode::Optional),
        'R' => Some(ValueMode::Optional),
        'h' => Some(ValueMode::None),
        _ => None,
    }
}

fn extract_value(
    mode: ValueMode,
    inline: Option<String>,
    args: &mut VecDeque<String>,
    flag: &str,
) -> Result<Option<String>, String> {
    match mode {
        ValueMode::None => Ok(None),
        ValueMode::Required => match inline {
            Some(value) => Ok(Some(value)),
            None => args
                .pop_front()
                .map(Some)
                .ok_or_else(|| format!("option {flag} requires a value")),
        },
        ValueMode::Optional => {
            if let Some(value) = inline {
                return Ok(Some(value));
            }
            if let Some(next) = args.front() {
                if !next.starts_with('-') {
                    return Ok(args.pop_front());
                }
            }
            Ok(None)
        }
    }
}

fn apply_long_option(key: &str, value: Option<String>, opts: &mut CliOptions) -> Result<(), String> {
    match key {
        "address" => opts.addrs.push(value.ok_or_else(|| missing_value("--address"))?),
        "config" => opts.config_path = Some(PathBuf::from(value.ok_or_else(|| missing_value("--config"))?)),
        "config-format" => {
            opts.config_format = Some(value.ok_or_else(|| missing_value("--config-format"))?)
        }
        "debug" => opts.debug = true,
        "error" => opts.error_mask = value,
        "foreground" => opts.foreground = true,
        "masquerade" => {
            opts.masquerade_path = Some(PathBuf::from(value.ok_or_else(|| missing_value("--masquerade"))?))
        }
        "masquerade-first" => opts.masquerade_first = true,
        "proxy" => opts.proxy = Some(value.ok_or_else(|| missing_value("--proxy"))?),
        "group" => opts.group = Some(value.ok_or_else(|| missing_value("--group"))?),
        "inetd" => opts.inetd = true,
        "inetd-compat" => opts.inetd_compat = value,
        "log" => opts.log_path = value.map(PathBuf::from),
        "os" => opts.os = Some(value.ok_or_else(|| missing_value("--os"))?),
        "port" => opts.port = parse_u16(&value.ok_or_else(|| missing_value("--port"))?, "--port")?,
        "quiet" => opts.quiet = true,
        "nosyslog" => opts.nosyslog = true,
        "timeout" => opts.timeout = parse_timeout(&value.ok_or_else(|| missing_value("--timeout"))?)?,
        "user" => opts.user = Some(value.ok_or_else(|| missing_value("--user"))?),
        "version" => opts.version = true,
        "random" => opts.random = value,
        "reply" => opts.reply = value,
        "help" => opts.help = true,
        _ => return Err(format!("unknown option: --{key}")),
    }
    Ok(())
}

fn apply_short_option(flag: char, value: Option<String>, opts: &mut CliOptions) -> Result<(), String> {
    match flag {
        'a' => opts.addrs.push(value.ok_or_else(|| missing_value("-a"))?),
        'c' => opts.config_path = Some(PathBuf::from(value.ok_or_else(|| missing_value("-c"))?)),
        'C' => opts.config_format = Some(value.ok_or_else(|| missing_value("-C"))?),
        'd' => opts.debug = true,
        'e' => opts.error_mask = value,
        'f' => opts.foreground = true,
        'm' => opts.masquerade_path = Some(PathBuf::from(value.ok_or_else(|| missing_value("-m"))?)),
        'M' => opts.masquerade_first = true,
        'P' => opts.proxy = Some(value.ok_or_else(|| missing_value("-P"))?),
        'g' => opts.group = Some(value.ok_or_else(|| missing_value("-g"))?),
        'i' => opts.inetd = true,
        'I' => opts.inetd_compat = value,
        'l' => opts.log_path = value.map(PathBuf::from),
        'o' => opts.os = Some(value.ok_or_else(|| missing_value("-o"))?),
        'p' => opts.port = parse_u16(&value.ok_or_else(|| missing_value("-p"))?, "-p")?,
        'q' => opts.quiet = true,
        'S' => opts.nosyslog = true,
        't' => opts.timeout = parse_timeout(&value.ok_or_else(|| missing_value("-t"))?)?,
        'u' => opts.user = Some(value.ok_or_else(|| missing_value("-u"))?),
        'v' => opts.version = true,
        'r' => opts.random = value,
        'R' => opts.reply = value,
        'h' => opts.help = true,
        _ => return Err(format!("unknown option: -{flag}")),
    }
    Ok(())
}

fn missing_value(flag: &str) -> String {
    format!("option {flag} requires a value")
}

fn parse_u16(value: &str, flag: &str) -> Result<u16, String> {
    value
        .parse::<u16>()
        .map_err(|_| format!("invalid value for {flag}: {value}"))
}

fn parse_timeout(value: &str) -> Result<Option<Duration>, String> {
    let seconds = value
        .parse::<u64>()
        .map_err(|_| format!("invalid timeout value: {value}"))?;
    if seconds == 0 {
        Ok(None)
    } else {
        Ok(Some(Duration::from_secs(seconds)))
    }
}

fn load_system_config(opts: &CliOptions) -> io::Result<()> {
    let path = opts
        .config_path
        .clone()
        .unwrap_or_else(config::paths::system_config_path);
    let format = match opts.config_format.as_deref() {
        Some(format) => format,
        None => {
            if path.extension().and_then(|ext| ext.to_str()) == Some("toml") {
                "toml"
            } else {
                "legacy"
            }
        }
    };

    let result = match format {
        "toml" => config::toml::load_toml_config(&path).map(|_| ()),
        "legacy" => config::legacy::load_legacy_config(&path).map(|_| ()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown config format: {format}"),
        )),
    };

    match result {
        Err(err) if err.kind() == io::ErrorKind::NotFound && opts.config_path.is_none() => Ok(()),
        other => other,
    }
}

fn build_lookup() -> Arc<dyn kernel::UidLookup + Send + Sync> {
    #[cfg(target_os = "linux")]
    {
        Arc::new(kernel::linux::LinuxLookup::new())
    }
    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        Arc::new(kernel::bsd::BsdLookup::new())
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    {
        Arc::new(kernel::UnsupportedLookup)
    }
}

fn print_usage() {
    println!(
        "ridentd [-a addr] [-p port] [-i] [-t seconds] [-q] [-d] [-S] [--help]"
    );
}

fn print_version() {
    println!("ridentd 0.1.0");
}
