use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RESOLVER_HELPERS: usize = 2;

static ACTIVE_RESOLVER_HELPERS: AtomicUsize = AtomicUsize::new(0);

pub(super) fn resolve_once(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
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

fn is_public_ip(ip: IpAddr) -> bool {
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

#[cfg(test)]
mod tests {
    use super::{
        is_public_ip, resolve_with_timeout_using, try_acquire_resolver_helper, ResolveError,
        ACTIVE_RESOLVER_HELPERS, MAX_RESOLVER_HELPERS,
    };
    use std::net::IpAddr;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

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
        assert!(matches!(result, Err(ResolveError::Timeout)));
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
}
