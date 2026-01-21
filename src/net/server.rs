use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use mio::net::TcpListener;
use mio::{Events, Interest, Poll, Token};

use super::{handle_request_line, IdentHandler, RequestHandler};

#[derive(Clone)]
pub struct ServerConfig {
    pub addrs: Vec<SocketAddr>,
    pub timeout: Option<Duration>,
    pub connection_limit: usize,
    pub max_line_len: usize,
    pub handler: Arc<dyn RequestHandler + Send + Sync>,
    pub worker_threads: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            addrs: Vec::new(),
            timeout: Some(Duration::from_secs(30)),
            connection_limit: 128,
            max_line_len: 1024,
            handler: Arc::new(IdentHandler::default()),
            worker_threads: num_cpus::get().max(1),
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
    let mut poll = Poll::new()?;

    for (idx, addr) in config.addrs.iter().enumerate() {
        match TcpListener::bind(*addr) {
            Ok(mut listener) => {
                let token = Token(idx + 1); // reserve Token(0) if needed later
                if let Err(err) = poll
                    .registry()
                    .register(&mut listener, token, Interest::READABLE)
                {
                    eprintln!("ridentd: failed to register listener {addr}: {err}");
                    continue;
                }
                listeners.push((listener, token));
            }
            Err(err) => eprintln!("ridentd: failed to bind {addr}: {err}"),
        }
    }

    if listeners.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "unable to bind any listen address",
        ));
    }

    let active = Arc::new(AtomicUsize::new(0));
    let workers = WorkerPool::new(
        config.worker_threads,
        WorkerSettings {
            timeout: config.timeout,
            max_line_len: config.max_line_len,
            handler: Arc::clone(&config.handler),
        },
        Arc::clone(&active),
    );

    let mut events = Events::with_capacity(128);
    loop {
        poll.poll(&mut events, None)?;

        for event in events.iter() {
            if !event.is_readable() {
                continue;
            }
            if let Some((listener, _)) = listeners
                .iter()
                .find(|(_, token)| token == &event.token())
            {
                accept_ready(
                    listener,
                    &workers,
                    config.connection_limit,
                    &active,
                );
            }
        }
    }
}

fn accept_ready(
    listener: &TcpListener,
    workers: &WorkerPool,
    connection_limit: usize,
    active: &Arc<AtomicUsize>,
) {
    loop {
        match listener.accept() {
            Ok((stream, _addr)) => {
                if active.load(Ordering::Relaxed) >= connection_limit {
                    continue;
                }

                if let Err(err) = stream.set_nodelay(true) {
                    eprintln!("ridentd: failed to set TCP_NODELAY: {err}");
                }

                active.fetch_add(1, Ordering::Relaxed);
                if let Err(err) = workers.submit(stream) {
                    active.fetch_sub(1, Ordering::Relaxed);
                    eprintln!("ridentd: dropped connection: {err}");
                }
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                break;
            }
            Err(err) => {
                eprintln!("ridentd: accept failed: {err}");
                break;
            }
        }
    }
}

struct WorkerPool {
    workers: Vec<Sender<mio::net::TcpStream>>,
    next: AtomicUsize,
}

impl WorkerPool {
    fn new(threads: usize, settings: WorkerSettings, active: Arc<AtomicUsize>) -> Self {
        let threads = threads.max(1);
        let mut workers = Vec::with_capacity(threads);

        for _ in 0..threads {
            let (tx, rx) = mpsc::channel();
            let settings = settings.clone();
            let active = Arc::clone(&active);
            thread::spawn(move || worker_loop(rx, settings, active));
            workers.push(tx);
        }

        Self {
            workers,
            next: AtomicUsize::new(0),
        }
    }

    fn submit(&self, stream: mio::net::TcpStream) -> io::Result<()> {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.workers.len();
        self.workers[idx]
            .send(stream)
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))
    }
}

#[derive(Clone)]
struct WorkerSettings {
    timeout: Option<Duration>,
    max_line_len: usize,
    handler: Arc<dyn RequestHandler + Send + Sync>,
}

fn worker_loop(rx: Receiver<mio::net::TcpStream>, settings: WorkerSettings, active: Arc<AtomicUsize>) {
    for stream in rx {
        handle_stream(stream, &settings);
        active.fetch_sub(1, Ordering::Relaxed);
    }
}

fn handle_stream(stream: mio::net::TcpStream, settings: &WorkerSettings) {
    let std_stream: TcpStream = match mio_to_std(stream) {
        Ok(stream) => stream,
        Err(err) => {
            eprintln!("ridentd: failed to convert stream: {err}");
            return;
        }
    };

    if let Err(err) = std_stream.set_nonblocking(false) {
        eprintln!("ridentd: failed to set blocking mode: {err}");
        return;
    }

    process_stream(std_stream, settings);
}

fn process_stream(mut stream: TcpStream, settings: &WorkerSettings) {
    let _ = stream.set_read_timeout(settings.timeout);
    let _ = stream.set_write_timeout(settings.timeout);

    let mut reader = BufReader::new(&mut stream);
    let mut buf = Vec::new();
    let read_result = reader.read_until(b'\n', &mut buf);
    if read_result.is_err() || buf.is_empty() {
        return;
    }

    if buf.len() > settings.max_line_len {
        buf.truncate(settings.max_line_len);
    }

    let line = String::from_utf8_lossy(&buf);
    let response = match (stream.local_addr(), stream.peer_addr()) {
        (Ok(local), Ok(remote)) => settings.handler.handle(&line, local, remote),
        _ => handle_request_line(&line),
    };
    let _ = stream.write_all(response.as_bytes());
}

#[cfg(unix)]
fn mio_to_std(stream: mio::net::TcpStream) -> io::Result<TcpStream> {
    use std::os::unix::io::{FromRawFd, IntoRawFd};
    let fd = stream.into_raw_fd();
    // Safety: we take ownership of the fd from mio and construct a std stream from it.
    unsafe { Ok(TcpStream::from_raw_fd(fd)) }
}

#[cfg(windows)]
fn mio_to_std(stream: mio::net::TcpStream) -> io::Result<TcpStream> {
    use std::os::windows::io::{FromRawSocket, IntoRawSocket};
    let sock = stream.into_raw_socket();
    unsafe { Ok(TcpStream::from_raw_socket(sock)) }
}
