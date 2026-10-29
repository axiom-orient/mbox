mod resolver;
mod tls;

use self::resolver::resolve_once;
use self::tls::read_client_hello;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;
const IO_TIMEOUT: Duration = Duration::from_millis(100);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const HEADER_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CONNECTIONS: usize = 32;

#[derive(Debug)]
pub struct ProxyRuntime {
    port: u16,
    stop: Arc<AtomicBool>,
    active: Arc<ActiveRegistry>,
    events: Receiver<String>,
    thread: Option<JoinHandle<()>>,
}

impl ProxyRuntime {
    pub fn start(domains: &[String]) -> io::Result<Self> {
        if domains.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "exact network mode requires at least one domain",
            ));
        }
        // Seatbelt's `localhost:<port>` selector covers both loopback address
        // families. Bind both families before the target can start, so an
        // unrelated IPv6 service cannot occupy the permitted port while the
        // proxy only owns IPv4. The listeners use the same handler and policy.
        let ipv6_listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0))?;
        ipv6_listener.set_nonblocking(true)?;
        mark_cloexec(&ipv6_listener)?;
        let port = ipv6_listener.local_addr()?.port();
        let ipv4_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
        ipv4_listener.set_nonblocking(true)?;
        mark_cloexec(&ipv4_listener)?;
        let listeners = vec![ipv4_listener, ipv6_listener];
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(ActiveRegistry::default());
        let (events_tx, events) = mpsc::channel();
        let thread_stop = Arc::clone(&stop);
        let thread_active = Arc::clone(&active);
        let domains = domains.iter().cloned().collect::<BTreeSet<_>>();
        let worker_count = Arc::new(AtomicUsize::new(0));
        let thread = thread::Builder::new()
            .name("mbox-proxy".to_string())
            .spawn(move || {
                proxy_loop(
                    listeners,
                    domains,
                    thread_stop,
                    thread_active,
                    worker_count,
                    events_tx,
                )
            })
            .map_err(|error| {
                io::Error::other(format!("cannot start exact network proxy: {error}"))
            })?;

        Ok(Self {
            port,
            stop,
            active,
            events,
            thread: Some(thread),
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn fatal_error(&self) -> Option<String> {
        self.events.try_recv().ok()
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        self.stop.store(true, Ordering::Release);
        shutdown_active(&self.active);
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        thread
            .join()
            .map_err(|_| io::Error::other("exact network proxy worker panicked"))
    }
}

impl Drop for ProxyRuntime {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn proxy_loop(
    listeners: Vec<TcpListener>,
    domains: BTreeSet<String>,
    stop: Arc<AtomicBool>,
    active: Arc<ActiveRegistry>,
    worker_count: Arc<AtomicUsize>,
    events: Sender<String>,
) {
    let mut workers = Vec::new();
    while !stop.load(Ordering::Acquire) {
        reap_finished_workers(&mut workers, &events, &stop);
        match accept_connection(&listeners) {
            Ok(Some(stream)) => {
                if mark_cloexec(&stream).is_err() {
                    let _ = reject_overflow(stream);
                    continue;
                }
                let Some(permit) = WorkerPermit::try_acquire(&worker_count) else {
                    // Keep the listener responsive under hostile connection
                    // floods. The bounded refusal does not create a worker.
                    let _ = reject_overflow(stream);
                    continue;
                };
                let worker_stop = Arc::clone(&stop);
                let worker_active = Arc::clone(&active);
                let worker_domains = domains.clone();
                let worker = thread::Builder::new()
                    .name("mbox-proxy-connection".to_string())
                    .spawn(move || {
                        handle_client(
                            stream,
                            &worker_domains,
                            &worker_stop,
                            &worker_active,
                            permit,
                        );
                    });
                match worker {
                    Ok(worker) => workers.push(worker),
                    Err(error) => {
                        let _ =
                            events.send(format!("cannot start proxy connection worker: {error}"));
                        stop.store(true, Ordering::Release);
                        break;
                    }
                }
            }
            Ok(None) => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                let _ = events.send(format!("proxy listener failed: {error}"));
                stop.store(true, Ordering::Release);
                break;
            }
        }
    }

    shutdown_active(&active);
    for worker in workers {
        let _ = worker.join();
    }
}

fn accept_connection(listeners: &[TcpListener]) -> io::Result<Option<TcpStream>> {
    for listener in listeners {
        match listener.accept() {
            Ok((stream, _peer)) => return Ok(Some(stream)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

fn reap_finished_workers(
    workers: &mut Vec<JoinHandle<()>>,
    events: &Sender<String>,
    stop: &AtomicBool,
) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            if worker.join().is_err() {
                let _ = events.send("proxy connection worker panicked".to_string());
                stop.store(true, Ordering::Release);
            }
        } else {
            index += 1;
        }
    }
}

fn reject_overflow(mut stream: TcpStream) -> io::Result<()> {
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    respond(&mut stream, "503 Service Unavailable")
}

fn handle_client(
    mut client: TcpStream,
    domains: &BTreeSet<String>,
    stop: &AtomicBool,
    active: &Arc<ActiveRegistry>,
    _permit: WorkerPermit,
) {
    let _ = client.set_read_timeout(Some(IO_TIMEOUT));
    let _ = client.set_write_timeout(Some(IO_TIMEOUT));
    let Ok(_client_lease) = active.register(&client) else {
        return;
    };

    let result = handle_connect(&mut client, domains, stop, active);
    if result.is_err() && !stop.load(Ordering::Acquire) {
        // The client controls the request and network endpoint. Errors are
        // intentionally not logged because headers may contain credentials.
        let _ = respond(&mut client, "502 Bad Gateway");
    }
}

fn handle_connect(
    client: &mut TcpStream,
    domains: &BTreeSet<String>,
    stop: &AtomicBool,
    active: &Arc<ActiveRegistry>,
) -> io::Result<()> {
    let request = match read_request(client, stop) {
        Ok(request) => request,
        Err(_) => {
            let _ = respond(client, "403 Forbidden");
            return Ok(());
        }
    };
    let (host, port) = match parse_connect_request(&request, domains) {
        Ok(value) => value,
        Err(()) => {
            let _ = respond(client, "403 Forbidden");
            return Ok(());
        }
    };

    let addresses = resolve_once(&host, port).map_err(|error| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("exact network name resolution failed: {error}"),
        )
    })?;
    let address = match addresses.first().copied() {
        Some(address) => address,
        None => {
            let _ = respond(client, "403 Forbidden");
            return Ok(());
        }
    };
    let mut upstream = match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
        Ok(stream) => stream,
        Err(_) => {
            let _ = respond(client, "502 Bad Gateway");
            return Ok(());
        }
    };
    upstream.set_read_timeout(Some(IO_TIMEOUT))?;
    upstream.set_write_timeout(Some(IO_TIMEOUT))?;
    mark_cloexec(&upstream)?;
    let _upstream_lease = active.register(&upstream)?;

    respond(client, "200 Connection Established")?;
    let client_hello = match read_client_hello(client, &host) {
        Ok(value) => value,
        Err(error) => {
            let _ = client.shutdown(Shutdown::Both);
            let _ = upstream.shutdown(Shutdown::Both);
            return Err(error);
        }
    };
    upstream.write_all(&client_hello)?;
    let direction_stop = Arc::new(AtomicBool::new(false));
    let mut client_to_upstream = clone_stream(client)?;
    let upstream_to_client = clone_stream(&upstream)?;
    let mut upstream_reader = clone_stream(&upstream)?;
    let mut client_writer = clone_stream(client)?;
    let first_stop = Arc::clone(&direction_stop);
    let second_stop = Arc::clone(&direction_stop);
    let first = thread::Builder::new()
        .name("mbox-proxy-upstream".to_string())
        .spawn(move || {
            copy_direction(&mut client_to_upstream, &mut upstream, &first_stop);
        })?;
    let second = thread::Builder::new()
        .name("mbox-proxy-downstream".to_string())
        .spawn(move || {
            copy_direction(&mut upstream_reader, &mut client_writer, &second_stop);
        });
    let second = match second {
        Ok(second) => second,
        Err(error) => {
            direction_stop.store(true, Ordering::Release);
            let _ = upstream_to_client.shutdown(Shutdown::Both);
            let _ = first.join();
            return Err(error);
        }
    };
    let _ = first.join();
    direction_stop.store(true, Ordering::Release);
    let _ = upstream_to_client.shutdown(Shutdown::Both);
    let _ = second.join();
    Ok(())
}

fn copy_direction(source: &mut TcpStream, destination: &mut TcpStream, stop: &AtomicBool) {
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }
        match source.read(&mut buffer) {
            Ok(0) => {
                let _ = destination.shutdown(Shutdown::Write);
                break;
            }
            Ok(size) => {
                if destination.write_all(&buffer[..size]).is_err() {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
    }
    stop.store(true, Ordering::Release);
    let _ = source.shutdown(Shutdown::Both);
    let _ = destination.shutdown(Shutdown::Both);
}

fn read_request(client: &mut TcpStream, stop: &AtomicBool) -> io::Result<Vec<u8>> {
    let mut request = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 1024];
    let deadline = Instant::now() + HEADER_TIMEOUT;
    while request.len() < MAX_REQUEST_BYTES {
        if stop.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "proxy stopping"));
        }
        match client.read(&mut buffer) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "proxy request ended before headers",
                ));
            }
            Ok(size) => {
                request.extend_from_slice(&buffer[..size]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    return Ok(request);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "proxy request header deadline exceeded",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "proxy request exceeds bounded header size",
    ))
}

fn parse_connect_request(request: &[u8], domains: &BTreeSet<String>) -> Result<(String, u16), ()> {
    let text = std::str::from_utf8(request).map_err(|_| ())?;
    let end = text.find("\r\n\r\n").ok_or(())?;
    if end + 4 != text.len() {
        return Err(());
    }
    let head = &text[..end];
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(())?;
    let mut parts = request_line.split(' ');
    let method = parts.next();
    let authority = parts.next();
    let version = parts.next();
    if method != Some("CONNECT") || version != Some("HTTP/1.1") || parts.next().is_some() {
        return Err(());
    }
    let authority = authority.ok_or(())?;
    let (host, port) = parse_authority(authority)?;
    if port != 443 || !domains.contains(&host) {
        return Err(());
    }

    let mut host_header = None;
    for line in lines {
        if line.len() > MAX_HEADER_LINE_BYTES {
            return Err(());
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(());
        };
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(());
        }
        if name.eq_ignore_ascii_case("host") {
            if host_header.is_some() {
                return Err(());
            }
            host_header = Some(value.trim());
        }
    }
    if let Some(value) = host_header {
        let (header_host, header_port) = parse_authority(value)?;
        if header_host != host || header_port != port {
            return Err(());
        }
    }
    Ok((host, port))
}

fn parse_authority(authority: &str) -> Result<(String, u16), ()> {
    if authority.is_empty() || authority.contains(['[', ']', '/', '@', '?', '#', '%']) {
        return Err(());
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        return Err(());
    };
    if host.contains(':') || host.is_empty() || port.is_empty() {
        return Err(());
    }
    let port = port.parse::<u16>().map_err(|_| ())?;
    let host = host.to_ascii_lowercase();
    if host.parse::<IpAddr>().is_ok() || !valid_dns_name(&host) {
        return Err(());
    }
    Ok((host, port))
}

fn valid_dns_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || value.ends_with('.') {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn respond(stream: &mut TcpStream, status: &str) -> io::Result<()> {
    stream.write_all(
        format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").as_bytes(),
    )
}

#[derive(Debug, Default)]
struct ActiveRegistry {
    next_id: AtomicU64,
    streams: Mutex<BTreeMap<u64, TcpStream>>,
}

struct ActiveLease {
    registry: Arc<ActiveRegistry>,
    id: Option<u64>,
}

impl ActiveRegistry {
    fn register(self: &Arc<Self>, stream: &TcpStream) -> io::Result<ActiveLease> {
        let clone = clone_stream(stream)?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut streams = self
            .streams
            .lock()
            .map_err(|_| io::Error::other("proxy active stream registry poisoned"))?;
        streams.insert(id, clone);
        Ok(ActiveLease {
            registry: Arc::clone(self),
            id: Some(id),
        })
    }
}

impl Drop for ActiveLease {
    fn drop(&mut self) {
        let Some(id) = self.id.take() else {
            return;
        };
        if let Ok(mut streams) = self.registry.streams.lock() {
            streams.remove(&id);
        }
    }
}

fn shutdown_active(active: &Arc<ActiveRegistry>) {
    if let Ok(streams) = active.streams.lock() {
        for stream in streams.values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

fn clone_stream(stream: &TcpStream) -> io::Result<TcpStream> {
    let clone = stream.try_clone()?;
    mark_cloexec(&clone)?;
    Ok(clone)
}

fn mark_cloexec<T: AsRawFd>(descriptor: &T) -> io::Result<()> {
    const F_GETFD: i32 = 1;
    const F_SETFD: i32 = 2;
    const FD_CLOEXEC: i32 = 1;
    unsafe extern "C" {
        fn fcntl(fd: i32, command: i32, ...) -> i32;
    }
    let fd = descriptor.as_raw_fd();
    let flags = unsafe { fcntl(fd, F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { fcntl(fd, F_SETFD, flags | FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct WorkerPermit {
    count: Arc<AtomicUsize>,
}

impl WorkerPermit {
    fn try_acquire(count: &Arc<AtomicUsize>) -> Option<Self> {
        let mut current = count.load(Ordering::Acquire);
        loop {
            if current >= MAX_CONNECTIONS {
                return None;
            }
            match count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(Self {
                        count: Arc::clone(count),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for WorkerPermit {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parse_authority, parse_connect_request, valid_dns_name, ActiveRegistry, WorkerPermit,
        MAX_CONNECTIONS,
    };
    use std::collections::BTreeSet;
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
    use std::sync::Arc;

    #[test]
    fn exact_authority_requires_https_port() {
        assert_eq!(
            parse_authority("API.OpenAI.com:443"),
            Ok(("api.openai.com".to_string(), 443))
        );
        assert!(parse_authority("api.openai.com:80").is_ok());
        assert!(parse_authority("127.0.0.1:443").is_err());
        assert!(parse_authority("[::1]:443").is_err());
        assert!(parse_authority("api.openai.com").is_err());
    }

    #[test]
    fn parser_requires_exact_domain_and_rejects_conflicting_host() {
        let domains = BTreeSet::from(["api.openai.com".to_string()]);
        let request = b"CONNECT API.OPENAI.COM:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n";
        assert_eq!(
            parse_connect_request(request, &domains),
            Ok(("api.openai.com".to_string(), 443))
        );
        let conflicting = b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: other.example:443\r\n\r\n";
        assert!(parse_connect_request(conflicting, &domains).is_err());
        let trailing = b"CONNECT api.openai.com.:443 HTTP/1.1\r\n\r\n";
        assert!(parse_connect_request(trailing, &domains).is_err());
    }

    #[test]
    fn dns_name_rules_are_ascii_and_non_ambiguous() {
        assert!(valid_dns_name("api.openai.com"));
        assert!(valid_dns_name("API.OPENAI.COM"));
        assert!(!valid_dns_name("api.openai.com."));
        assert!(!valid_dns_name("*.openai.com"));
        assert!(!valid_dns_name("api_openai.com"));
        assert!(!valid_dns_name("éxample.com"));
        assert!(!valid_dns_name("-api.openai.com"));
        let _ = (Ipv4Addr::LOCALHOST, Ipv6Addr::LOCALHOST);
    }

    #[test]
    fn worker_cap_and_active_leases_are_bounded_and_raii() {
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let permits = (0..MAX_CONNECTIONS)
            .map(|_| WorkerPermit::try_acquire(&count).unwrap())
            .collect::<Vec<_>>();
        assert!(WorkerPermit::try_acquire(&count).is_none());
        drop(permits);
        assert!(WorkerPermit::try_acquire(&count).is_some());

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).unwrap();
        let (server, _) = listener.accept().unwrap();
        let registry = Arc::new(ActiveRegistry::default());
        let lease = registry.register(&server).unwrap();
        assert_eq!(registry.streams.lock().unwrap().len(), 1);
        drop(lease);
        assert!(registry.streams.lock().unwrap().is_empty());
        drop(client);
    }
}
