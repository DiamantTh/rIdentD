use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

use super::handle_request_line;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub addrs: Vec<SocketAddr>,
    pub timeout: Option<Duration>,
    pub connection_limit: usize,
    pub max_line_len: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            addrs: Vec::new(),
            timeout: Some(Duration::from_secs(30)),
            connection_limit: 128,
            max_line_len: 1024,
        }
    }
}

pub fn serve(config: ServerConfig) -> io::Result<()> {
    if config.addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no listen addresses configured",
        ));
    }

    let mut listeners = Vec::new();
    for addr in &config.addrs {
        match TcpListener::bind(addr) {
            Ok(listener) => listeners.push(listener),
            Err(err) => eprintln!("ridentd: failed to bind {addr}: {err}"),
        }
    }

    if listeners.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "unable to bind any listen address",
        ));
    }

    let config = Arc::new(config);
    let active = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    for listener in listeners {
        let config = Arc::clone(&config);
        let active = Arc::clone(&active);
        handles.push(thread::spawn(move || accept_loop(listener, config, active)));
    }

    for handle in handles {
        let _ = handle.join();
    }

    Ok(())
}

fn accept_loop(listener: TcpListener, config: Arc<ServerConfig>, active: Arc<AtomicUsize>) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("ridentd: accept failed: {err}");
                continue;
            }
        };

        if active.load(Ordering::Relaxed) >= config.connection_limit {
            drop(stream);
            continue;
        }

        let guard = ConnectionGuard::new(Arc::clone(&active));
        let config = Arc::clone(&config);
        thread::spawn(move || {
            handle_stream(stream, &config);
            drop(guard);
        });
    }
}

fn handle_stream(mut stream: TcpStream, config: &ServerConfig) {
    let _ = stream.set_read_timeout(config.timeout);
    let _ = stream.set_write_timeout(config.timeout);

    let mut reader = BufReader::new(&mut stream);
    let mut buf = Vec::new();
    let read_result = reader.read_until(b'\n', &mut buf);
    if read_result.is_err() || buf.is_empty() {
        return;
    }

    if buf.len() > config.max_line_len {
        buf.truncate(config.max_line_len);
    }

    let line = String::from_utf8_lossy(&buf);
    let response = handle_request_line(&line);
    let _ = stream.write_all(response.as_bytes());
}

struct ConnectionGuard {
    active: Arc<AtomicUsize>,
}

impl ConnectionGuard {
    fn new(active: Arc<AtomicUsize>) -> Self {
        active.fetch_add(1, Ordering::Relaxed);
        Self { active }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}
