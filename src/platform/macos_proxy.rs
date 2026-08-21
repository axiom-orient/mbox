use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
};
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
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);
const TLS_CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_TLS_RECORD_PAYLOAD_BYTES: usize = 16 * 1024;
const MAX_TLS_CLIENT_HELLO_BYTES: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 32;
const MAX_RESOLVER_HELPERS: usize = 2;

static ACTIVE_RESOLVER_HELPERS: AtomicUsize = AtomicUsize::new(0);

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientHelloError {
    Invalid,
    MissingSni,
    DuplicateSni,
    Ech,
    HostMismatch,
    Oversize,
}

#[derive(Debug)]
struct ClientHelloParser {
    expected_host: String,
    wire: Vec<u8>,
    handshake: Vec<u8>,
}

impl ClientHelloParser {
    fn new(expected_host: &str) -> Self {
        Self {
            expected_host: expected_host.to_owned(),
            wire: Vec::with_capacity(4096),
            handshake: Vec::with_capacity(4096),
        }
    }

    fn push_record(&mut self, record: &[u8]) -> Result<bool, ClientHelloError> {
        let payload_length =
            tls_record_payload_length(record.get(..5).ok_or(ClientHelloError::Invalid)?)?;
        let expected_length = 5_usize
            .checked_add(payload_length)
            .ok_or(ClientHelloError::Oversize)?;
        if record.len() != expected_length {
            return Err(ClientHelloError::Invalid);
        }
        let wire_length = self
            .wire
            .len()
            .checked_add(record.len())
            .ok_or(ClientHelloError::Oversize)?;
        if wire_length > MAX_TLS_CLIENT_HELLO_BYTES {
            return Err(ClientHelloError::Oversize);
        }
        self.wire.extend_from_slice(record);
        self.handshake.extend_from_slice(&record[5..]);
        if self.handshake.len() > MAX_TLS_CLIENT_HELLO_BYTES {
            return Err(ClientHelloError::Oversize);
        }
        if self.handshake.len() < 4 {
            return Ok(false);
        }
        if self.handshake[0] != 1 {
            return Err(ClientHelloError::Invalid);
        }
        let message_length = (usize::from(self.handshake[1]) << 16)
            | (usize::from(self.handshake[2]) << 8)
            | usize::from(self.handshake[3]);
        let message_end = 4_usize
            .checked_add(message_length)
            .ok_or(ClientHelloError::Oversize)?;
        if message_end > MAX_TLS_CLIENT_HELLO_BYTES {
            return Err(ClientHelloError::Oversize);
        }
        if self.handshake.len() < message_end {
            return Ok(false);
        }
        validate_client_hello(&self.handshake[..message_end], &self.expected_host)?;
        Ok(true)
    }

    fn into_wire(self) -> Vec<u8> {
        self.wire
    }
}

fn read_client_hello(client: &mut TcpStream, expected_host: &str) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + TLS_CLIENT_HELLO_TIMEOUT;
    let mut parser = ClientHelloParser::new(expected_host);
    loop {
        let mut header = [0_u8; 5];
        read_exact_until(client, &mut header, deadline)?;
        let payload_length = tls_record_payload_length(&header).map_err(client_hello_error)?;
        let record_length = 5_usize
            .checked_add(payload_length)
            .ok_or_else(|| client_hello_error(ClientHelloError::Oversize))?;
        if parser
            .wire
            .len()
            .checked_add(record_length)
            .is_none_or(|length| length > MAX_TLS_CLIENT_HELLO_BYTES)
        {
            return Err(client_hello_error(ClientHelloError::Oversize));
        }
        let mut record = Vec::with_capacity(record_length);
        record.extend_from_slice(&header);
        let mut payload = vec![0_u8; payload_length];
        read_exact_until(client, &mut payload, deadline)?;
        record.extend_from_slice(&payload);
        if parser.push_record(&record).map_err(client_hello_error)? {
            return Ok(parser.into_wire());
        }
    }
}

fn read_exact_until(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TLS ClientHello deadline exceeded",
            ));
        }
        match stream.read(&mut buffer[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TLS ClientHello ended before the first message",
                ));
            }
            Ok(size) => offset += size,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn tls_record_payload_length(header: &[u8]) -> Result<usize, ClientHelloError> {
    if header.len() != 5 || header[0] != 22 || header[1] != 3 || !(1..=4).contains(&header[2]) {
        return Err(ClientHelloError::Invalid);
    }
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if length > MAX_TLS_RECORD_PAYLOAD_BYTES {
        return Err(ClientHelloError::Oversize);
    }
    Ok(length)
}

fn validate_client_hello(message: &[u8], expected_host: &str) -> Result<(), ClientHelloError> {
    if message.len() < 4 || message[0] != 1 {
        return Err(ClientHelloError::Invalid);
    }
    let message_length =
        (usize::from(message[1]) << 16) | (usize::from(message[2]) << 8) | usize::from(message[3]);
    if message_length.checked_add(4) != Some(message.len()) {
        return Err(ClientHelloError::Invalid);
    }
    let body = &message[4..];
    let mut offset = 0;
    take_bytes(body, &mut offset, 2)?;
    take_bytes(body, &mut offset, 32)?;
    let session_id_length = usize::from(read_u8(body, &mut offset)?);
    take_bytes(body, &mut offset, session_id_length)?;
    let cipher_suites_length = usize::from(read_u16(body, &mut offset)?);
    if cipher_suites_length == 0 || cipher_suites_length % 2 != 0 {
        return Err(ClientHelloError::Invalid);
    }
    take_bytes(body, &mut offset, cipher_suites_length)?;
    let compression_methods_length = usize::from(read_u8(body, &mut offset)?);
    if compression_methods_length == 0 {
        return Err(ClientHelloError::Invalid);
    }
    take_bytes(body, &mut offset, compression_methods_length)?;
    let extensions_length = usize::from(read_u16(body, &mut offset)?);
    let extensions_end = offset
        .checked_add(extensions_length)
        .ok_or(ClientHelloError::Invalid)?;
    if extensions_end != body.len() {
        return Err(ClientHelloError::Invalid);
    }

    let mut saw_sni = false;
    while offset < extensions_end {
        let extension_type = read_u16(body, &mut offset)?;
        let extension_length = usize::from(read_u16(body, &mut offset)?);
        let extension = take_bytes(body, &mut offset, extension_length)?;
        if extension_type == 0xfe0d {
            return Err(ClientHelloError::Ech);
        }
        if extension_type == 0 {
            if saw_sni {
                return Err(ClientHelloError::DuplicateSni);
            }
            saw_sni = true;
            validate_sni_extension(extension, expected_host)?;
        }
    }
    if !saw_sni {
        return Err(ClientHelloError::MissingSni);
    }
    Ok(())
}

fn validate_sni_extension(extension: &[u8], expected_host: &str) -> Result<(), ClientHelloError> {
    let mut offset = 0;
    let list_length = usize::from(read_u16(extension, &mut offset)?);
    let list_end = offset
        .checked_add(list_length)
        .ok_or(ClientHelloError::Invalid)?;
    if list_end != extension.len() {
        return Err(ClientHelloError::Invalid);
    }
    let mut names = 0;
    while offset < list_end {
        let name_type = read_u8(extension, &mut offset)?;
        let name_length = usize::from(read_u16(extension, &mut offset)?);
        let name = take_bytes(extension, &mut offset, name_length)?;
        if name_type != 0 || name.is_empty() || names != 0 {
            return Err(if names != 0 {
                ClientHelloError::DuplicateSni
            } else {
                ClientHelloError::Invalid
            });
        }
        let name = std::str::from_utf8(name).map_err(|_| ClientHelloError::Invalid)?;
        if !valid_dns_name(name) {
            return Err(ClientHelloError::Invalid);
        }
        if !name.eq_ignore_ascii_case(expected_host) {
            return Err(ClientHelloError::HostMismatch);
        }
        names += 1;
    }
    if names != 1 {
        return Err(ClientHelloError::MissingSni);
    }
    Ok(())
}

fn take_bytes<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], ClientHelloError> {
    let end = offset
        .checked_add(length)
        .ok_or(ClientHelloError::Invalid)?;
    let result = bytes.get(*offset..end).ok_or(ClientHelloError::Invalid)?;
    *offset = end;
    Ok(result)
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> Result<u8, ClientHelloError> {
    let value = *take_bytes(bytes, offset, 1)?
        .first()
        .ok_or(ClientHelloError::Invalid)?;
    Ok(value)
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> Result<u16, ClientHelloError> {
    let value = take_bytes(bytes, offset, 2)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn client_hello_error(error: ClientHelloError) -> io::Error {
    let kind = match error {
        ClientHelloError::Oversize => io::ErrorKind::InvalidData,
        ClientHelloError::Invalid
        | ClientHelloError::MissingSni
        | ClientHelloError::DuplicateSni
        | ClientHelloError::Ech
        | ClientHelloError::HostMismatch => io::ErrorKind::PermissionDenied,
    };
    io::Error::new(
        kind,
        "TLS ClientHello is not authorized for the CONNECT domain",
    )
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

fn resolve_once(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let host = host.to_string();
    let addresses = resolve_with_timeout_using(host, port, RESOLVE_TIMEOUT, |host, port| {
        (host.as_str(), port)
            .to_socket_addrs()
            .map(|iter| iter.collect())
    })
    .map_err(|error| io::Error::new(io::ErrorKind::TimedOut, error.to_string()))?;
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Ok(Vec::new());
    }
    Ok(addresses)
}

#[derive(Debug)]
enum ResolveError {
    Capacity,
    Timeout,
    Failed(io::Error),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Capacity => formatter.write_str("resolver helper capacity exhausted"),
            Self::Timeout => formatter.write_str("resolver deadline exceeded"),
            Self::Failed(error) => write!(formatter, "resolver failed: {error}"),
        }
    }
}

fn resolve_with_timeout_using<F>(
    host: String,
    port: u16,
    timeout: Duration,
    resolver: F,
) -> Result<Vec<SocketAddr>, ResolveError>
where
    F: FnOnce(String, u16) -> io::Result<Vec<SocketAddr>> + Send + 'static,
{
    if !try_acquire_resolver_helper() {
        return Err(ResolveError::Capacity);
    }
    let resolver_slot = ResolverSlot;
    let (sender, receiver) = mpsc::sync_channel(1);
    let helper = thread::Builder::new()
        .name("mbox-proxy-resolver".to_string())
        .spawn(move || {
            let _resolver_slot = resolver_slot;
            // The slot is deliberately held until the OS resolver returns.
            // A timed-out helper is not joined: process teardown ends a
            // resolver call that the OS has kept stuck beyond its deadline.
            let result = resolver(host, port);
            let _ = sender.send(result);
        });
    if let Err(error) = helper {
        return Err(ResolveError::Failed(error));
    }
    match receiver.recv_timeout(timeout) {
        Ok(Ok(addresses)) => Ok(addresses),
        Ok(Err(error)) => Err(ResolveError::Failed(error)),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(ResolveError::Timeout),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(ResolveError::Failed(io::Error::other(
            "resolver helper disconnected",
        ))),
    }
}

fn try_acquire_resolver_helper() -> bool {
    let mut current = ACTIVE_RESOLVER_HELPERS.load(Ordering::Acquire);
    loop {
        if current >= MAX_RESOLVER_HELPERS {
            return false;
        }
        match ACTIVE_RESOLVER_HELPERS.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

struct ResolverSlot;

impl Drop for ResolverSlot {
    fn drop(&mut self) {
        ACTIVE_RESOLVER_HELPERS.fetch_sub(1, Ordering::AcqRel);
    }
}

pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let value = u32::from_be_bytes(ip.octets());
    [
        (0x0000_0000, 8),  // "this" network
        (0x0a00_0000, 8),  // private
        (0x6440_0000, 10), // shared address space
        (0x7f00_0000, 8),  // loopback
        (0xa9fe_0000, 16), // link-local
        (0xac10_0000, 12), // private
        (0xc000_0000, 24), // IETF protocol assignments
        (0xc000_0200, 24), // TEST-NET-1
        (0xc0a8_0000, 16), // private
        (0xc058_6300, 24), // 6to4 relay anycast
        (0xc612_0000, 15), // benchmarking
        (0xc633_6400, 24), // TEST-NET-2
        (0xcb00_7100, 24), // TEST-NET-3
        (0xe000_0000, 4),  // multicast and reserved
    ]
    .into_iter()
    .all(|(network, prefix)| !prefix_contains_u32(value, network, prefix))
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if ip.to_ipv4_mapped().is_some() {
        // Do not let a resolver or socket API choose a different address
        // family after policy classification. Mapped forms are rejected even
        // when their embedded IPv4 value is public.
        return false;
    }
    // Only the global-unicast allocation is eligible. This excludes all
    // link-local, unique-local, multicast, documentation, transition,
    // benchmarking, and future/special prefixes conservatively.
    if !prefix_contains_ipv6(ip, Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3) {
        return false;
    }
    [
        (Ipv6Addr::UNSPECIFIED, 128),
        (Ipv6Addr::LOCALHOST, 128),
        (Ipv6Addr::UNSPECIFIED, 96), // IPv4-compatible/unspecified space
        (Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0), 96),
        (Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0), 64), // discard-only
        (Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0), 16),
        (Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0), 10), // site-local
        (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 32),
        (Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 0), 32),
        (Ipv6Addr::new(0x2001, 2, 0, 0, 0, 0, 0, 0), 32),
        (Ipv6Addr::new(0x2001, 3, 0, 0, 0, 0, 0, 0), 32),
        (Ipv6Addr::new(0x2001, 4, 0x0112, 0, 0, 0, 0, 0), 48),
        (Ipv6Addr::new(0x2001, 0x0010, 0, 0, 0, 0, 0, 0), 28),
        (Ipv6Addr::new(0x2001, 0x0020, 0, 0, 0, 0, 0, 0), 28),
        (Ipv6Addr::new(0x2001, 0x0030, 0, 0, 0, 0, 0, 0), 28),
        (Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32),
        (Ipv6Addr::new(0x2620, 0x004f, 0x8000, 0, 0, 0, 0, 0), 48),
        (Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16), // 6to4 transition
        (Ipv6Addr::new(0x3ffe, 0, 0, 0, 0, 0, 0, 0), 16), // 6bone
        (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20),
    ]
    .into_iter()
    .all(|(network, prefix)| !prefix_contains_ipv6(ip, network, prefix))
}

fn prefix_contains_u32(value: u32, network: u32, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    value & mask == network & mask
}

fn prefix_contains_ipv6(value: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    let value = u128::from_be_bytes(value.octets());
    let network = u128::from_be_bytes(network.octets());
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    };
    value & mask == network & mask
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
        is_public_ip, parse_authority, parse_connect_request, resolve_with_timeout_using,
        try_acquire_resolver_helper, valid_dns_name, ActiveRegistry, ClientHelloError,
        ClientHelloParser, WorkerPermit, ACTIVE_RESOLVER_HELPERS, MAX_CONNECTIONS,
        MAX_RESOLVER_HELPERS,
    };
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;

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
    fn client_hello_parser_requires_exact_sni_and_handles_record_fragmentation() {
        let message = client_hello_message(&sni_extension("raw.githubusercontent.com"));
        let split = 7;
        let first = tls_record(&message[..split]);
        let second = tls_record(&message[split..]);
        let mut parser = ClientHelloParser::new("raw.githubusercontent.com");
        assert!(!parser.push_record(&first).unwrap());
        assert!(parser.push_record(&second).unwrap());
        let mut expected = first;
        expected.extend_from_slice(&second);
        assert_eq!(parser.into_wire(), expected);

        let mut mismatch = ClientHelloParser::new("raw.githubusercontent.com");
        assert_eq!(
            mismatch.push_record(&tls_record(&client_hello_message(&sni_extension(
                "avatars.githubusercontent.com"
            )))),
            Err(ClientHelloError::HostMismatch)
        );
    }

    #[test]
    fn client_hello_parser_rejects_absent_duplicate_malformed_and_ech_sni() {
        let cases = [
            (client_hello_message(&[]), ClientHelloError::MissingSni),
            (
                client_hello_message(&{
                    let extension = sni_extension("example.com");
                    [extension.clone(), extension].concat()
                }),
                ClientHelloError::DuplicateSni,
            ),
            (
                client_hello_message(&sni_extension_with_hosts(&["example.com", "example.com"])),
                ClientHelloError::DuplicateSni,
            ),
            (
                client_hello_message(&{
                    let mut extension = sni_extension("example.com");
                    extension[4] = 0;
                    extension[5] = 0;
                    extension
                }),
                ClientHelloError::Invalid,
            ),
            (
                client_hello_message(&extension(0xfe0d, &[])),
                ClientHelloError::Ech,
            ),
        ];
        for (message, expected) in cases {
            let mut parser = ClientHelloParser::new("example.com");
            assert_eq!(
                parser.push_record(&tls_record(&message)),
                Err(expected),
                "unexpected ClientHello result for {expected:?}"
            );
        }
    }

    #[test]
    fn client_hello_parser_rejects_record_and_message_bounds() {
        let mut parser = ClientHelloParser::new("example.com");
        let mut plaintext = tls_record(&[0]);
        plaintext[0] = 23;
        assert_eq!(
            parser.push_record(&plaintext),
            Err(ClientHelloError::Invalid)
        );
        assert_eq!(
            parser.push_record(&[22, 3, 3, 0x40, 0x01]),
            Err(ClientHelloError::Oversize)
        );

        let mut oversized = vec![1, 0xff, 0xff, 0xff];
        oversized.resize(4 + 64 * 1024, 0);
        let record = tls_record(&oversized[..16 * 1024]);
        assert_eq!(parser.push_record(&record), Err(ClientHelloError::Oversize));
    }

    fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut value = Vec::with_capacity(4 + data.len());
        value.extend_from_slice(&kind.to_be_bytes());
        value.extend_from_slice(&(u16::try_from(data.len()).unwrap()).to_be_bytes());
        value.extend_from_slice(data);
        value
    }

    fn sni_extension(host: &str) -> Vec<u8> {
        sni_extension_with_hosts(&[host])
    }

    fn sni_extension_with_hosts(hosts: &[&str]) -> Vec<u8> {
        let list_length = hosts.iter().map(|host| 3 + host.len()).sum::<usize>();
        let mut data = Vec::with_capacity(2 + list_length);
        data.extend_from_slice(&(u16::try_from(list_length).unwrap()).to_be_bytes());
        for host in hosts {
            let host = host.as_bytes();
            data.push(0);
            data.extend_from_slice(&(u16::try_from(host.len()).unwrap()).to_be_bytes());
            data.extend_from_slice(host);
        }
        extension(0, &data)
    }

    fn client_hello_message(extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[3, 3]);
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(u16::try_from(extensions.len()).unwrap()).to_be_bytes());
        body.extend_from_slice(extensions);

        let mut message = Vec::with_capacity(4 + body.len());
        message.push(1);
        let length = u32::try_from(body.len()).unwrap();
        message.extend_from_slice(&[
            u8::try_from((length >> 16) & 0xff).unwrap(),
            u8::try_from((length >> 8) & 0xff).unwrap(),
            u8::try_from(length & 0xff).unwrap(),
        ]);
        message.extend_from_slice(&body);
        message
    }

    fn tls_record(payload: &[u8]) -> Vec<u8> {
        let length = u16::try_from(payload.len()).unwrap();
        let mut record = vec![22, 3, 3];
        record.extend_from_slice(&length.to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    #[test]
    fn public_ip_classifier_rejects_private_reserved_and_mapped_ranges() {
        for value in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "192.168.1.1",
            "198.18.0.1",
            "192.88.99.1",
            "192.0.2.1",
            "224.0.0.1",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2001:0::1",
            "64:ff9b::1",
            "3fff::1",
            "100::1",
            "5f00::1",
            "fec0::1",
            "2001:10::1",
            "2001:1f:ffff::1",
            "2001:20::1",
            "2001:2f:ffff::1",
            "2001:30::1",
            "2001:3f:ffff::1",
            "2620:4f:8000::1",
            "2002::1",
            "3ffe::1",
            "::ffff:127.0.0.1",
            "::ffff:8.8.8.8",
        ] {
            assert!(!is_public_ip(value.parse::<IpAddr>().unwrap()), "{value}");
        }
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(is_public_ip("2001:4860:4860::8888".parse().unwrap()));
        assert!(is_public_ip("2001:40::1".parse().unwrap()));
        assert!(is_public_ip("2620:4f:8001::1".parse().unwrap()));
        assert!(!is_public_ip("3ffe:ffff:ffff::1".parse().unwrap()));
        assert!(!is_public_ip("4000::1".parse().unwrap()));
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
    fn resolver_deadline_returns_without_joining_a_stuck_os_call() {
        let started = std::time::Instant::now();
        let result = resolve_with_timeout_using(
            "slow.example".to_string(),
            443,
            Duration::from_millis(5),
            |_host, _port| {
                std::thread::sleep(Duration::from_millis(40));
                Ok(Vec::new())
            },
        );
        assert!(matches!(result, Err(super::ResolveError::Timeout)));
        assert!(started.elapsed() < Duration::from_millis(30));
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(ACTIVE_RESOLVER_HELPERS.load(Ordering::Acquire), 0);
    }

    #[test]
    fn resolver_helper_capacity_is_explicit_and_bounded() {
        let previous = ACTIVE_RESOLVER_HELPERS.swap(MAX_RESOLVER_HELPERS, Ordering::AcqRel);
        assert!(!try_acquire_resolver_helper());
        ACTIVE_RESOLVER_HELPERS.store(previous, Ordering::Release);
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
