use std::collections::VecDeque;
use std::env;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ridentd::config::paths;
use ridentd::nat::{MasqueradeHandler, MasqueradeMap};
use ridentd::net::server::ServerConfig;
use ridentd::util;

const DEFAULT_PORT: u16 = 113;

fn main() {
    if let Err(err) = run() {
        eprintln!("ridentd-natd: {err}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let opts = match parse_args() {
        Ok(opts) => opts,
        Err(message) => {
            eprintln!("ridentd-natd: {message}");
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

    let addrs = util::build_socket_addrs(&opts.addrs, opts.port)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let masq_path = opts
        .masquerade_path
        .unwrap_or_else(paths::masquerade_config_path);
    let map = MasqueradeMap::load(&masq_path)?;
    let handler = Arc::new(MasqueradeHandler::new(map));
    let server_config = ServerConfig {
        addrs,
        timeout: opts.timeout,
        connection_limit: opts.connection_limit,
        max_line_len: opts.max_line_len,
        handler,
    };

    ridentd::net::server::serve(server_config)
}

#[derive(Debug)]
struct CliOptions {
    addrs: Vec<String>,
    port: u16,
    timeout: Option<Duration>,
    connection_limit: usize,
    max_line_len: usize,
    masquerade_path: Option<PathBuf>,
    help: bool,
    version: bool,
}

impl Default for CliOptions {
    fn default() -> Self {
        Self {
            addrs: Vec::new(),
            port: DEFAULT_PORT,
            timeout: Some(Duration::from_secs(30)),
            connection_limit: 128,
            max_line_len: 1024,
            masquerade_path: None,
            help: false,
            version: false,
        }
    }
}

fn parse_args() -> Result<CliOptions, String> {
    let mut opts = CliOptions::default();
    let mut args: VecDeque<String> = env::args().skip(1).collect();

    while let Some(arg) = args.pop_front() {
        if arg == "--" {
            break;
        }

        if arg == "-h" || arg == "--help" {
            opts.help = true;
            continue;
        }
        if arg == "-v" || arg == "--version" {
            opts.version = true;
            continue;
        }

        if let Some(value) = arg.strip_prefix("--address=") {
            opts.addrs.push(value.to_string());
            continue;
        }
        if let Some(value) = arg.strip_prefix("--port=") {
            opts.port = parse_u16(value, "--port")?;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--timeout=") {
            opts.timeout = parse_timeout(value)?;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--masquerade=") {
            opts.masquerade_path = Some(PathBuf::from(value));
            continue;
        }
        if let Some(value) = arg.strip_prefix("-a=") {
            opts.addrs.push(value.to_string());
            continue;
        }
        if let Some(value) = arg.strip_prefix("-p=") {
            opts.port = parse_u16(value, "-p")?;
            continue;
        }
        if let Some(value) = arg.strip_prefix("-t=") {
            opts.timeout = parse_timeout(value)?;
            continue;
        }
        if let Some(value) = arg.strip_prefix("-m=") {
            opts.masquerade_path = Some(PathBuf::from(value));
            continue;
        }

        match arg.as_str() {
            "-a" | "--address" => {
                let value = args
                    .pop_front()
                    .ok_or_else(|| format!("option {arg} requires a value"))?;
                opts.addrs.push(value);
            }
            "-p" | "--port" => {
                let value = args
                    .pop_front()
                    .ok_or_else(|| format!("option {arg} requires a value"))?;
                opts.port = parse_u16(&value, &arg)?;
            }
            "-t" | "--timeout" => {
                let value = args
                    .pop_front()
                    .ok_or_else(|| format!("option {arg} requires a value"))?;
                opts.timeout = parse_timeout(&value)?;
            }
            "-m" | "--masquerade" => {
                let value = args
                    .pop_front()
                    .ok_or_else(|| format!("option {arg} requires a value"))?;
                opts.masquerade_path = Some(PathBuf::from(value));
            }
            _ => return Err(format!("unknown option: {arg}")),
        }
    }

    Ok(opts)
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

fn print_usage() {
    println!(
        "ridentd-natd [-a addr] [-p port] [-m file] [-t seconds] [--help]"
    );
}

fn print_version() {
    println!("ridentd-natd 0.1.0");
}
