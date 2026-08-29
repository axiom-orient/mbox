use std::env;
use std::ffi::CString;
use std::fs;
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::net::{Ipv6Addr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::RawFd;
use std::os::raw::{c_char, c_int, c_ulong, c_void};
use std::os::unix::ffi::OsStrExt;
use std::process;
use std::thread;
use std::time::Duration;

const EBADF: i32 = 9;
const EPERM: i32 = 1;
const TIOCSCTTY: c_ulong = 0x2000_7461;
const TIOCSTI: c_ulong = 0x8001_7472;
const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;
const PROC_PIDTBSDINFO: c_int = 3;
const PROC_PIDLISTFDS: c_int = 1;
const MAX_FD_SCAN_ENTRIES: usize = 4096;

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcFdInfo {
    proc_fd: i32,
    proc_fdtype: u32,
}

#[repr(C)]
struct ProcBsdInfo {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    pbi_gid: u32,
    pbi_ruid: u32,
    pbi_rgid: u32,
    pbi_svuid: u32,
    pbi_svgid: u32,
    rfu_1: u32,
    pbi_comm: [c_char; 16],
    pbi_name: [c_char; 32],
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
}

#[link(name = "util")]
unsafe extern "C" {
    fn openpty(
        master: *mut c_int,
        slave: *mut c_int,
        name: *mut c_char,
        termios: *const c_void,
        winsize: *const c_void,
    ) -> c_int;
}

#[link(name = "proc")]
unsafe extern "C" {
    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
}

unsafe extern "C" {
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn socketpair(domain: c_int, kind: c_int, protocol: c_int, descriptors: *mut c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn fork() -> c_int;
    fn vfork() -> c_int;
    fn setsid() -> c_int;
    fn execve(path: *const c_char, argv: *const *const c_char, envp: *const *const c_char)
        -> c_int;
    fn posix_spawn(
        pid: *mut c_int,
        path: *const c_char,
        file_actions: *const c_void,
        attributes: *const c_void,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> c_int;
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn _exit(status: c_int) -> !;
}

fn main() -> io::Result<()> {
    let mut args = env::args_os();
    let argv0 = args.next().unwrap_or_else(|| fail("missing argv0"));
    let Some(command) = args.next() else {
        fail("missing probe command");
    };

    let result = match command.to_str() {
        Some("argv") => {
            println!("argv0:{}", argv0.to_string_lossy());
            for (index, value) in args.enumerate() {
                println!("{index}:{}", value.to_string_lossy());
            }
            Ok(())
        }
        Some("env") => {
            let name = args.next().unwrap_or_else(|| fail("missing env name"));
            match env::var_os(name) {
                Some(value) => println!("{}", value.to_string_lossy()),
                None => process::exit(3),
            }
            Ok(())
        }
        Some("fd-open") => {
            let fd = parse_fd(args.next());
            let result = unsafe { fcntl(fd, 1) };
            if result < 0 && io::Error::last_os_error().raw_os_error() == Some(EBADF) {
                println!("CLOSED");
            } else {
                println!("OPEN");
                process::exit(4);
            }
            Ok(())
        }
        Some("stdin") => {
            let mut value = String::new();
            io::stdin().read_to_string(&mut value)?;
            print!("{value}");
            Ok(())
        }
        Some("streams") => {
            println!("STDOUT");
            eprintln!("STDERR");
            Ok(())
        }
        Some("read-file") => {
            let path = args
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing path"))?;
            let value = fs::read_to_string(path)?;
            print!("{value}");
            Ok(())
        }
        Some("remove-file") => {
            let path = args
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing path"))?;
            fs::remove_file(path)
        }
        Some("remove-dir") => {
            let path = args
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing path"))?;
            fs::remove_dir(path)
        }
        Some("rename-file") => {
            let source = args.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing source path")
            })?;
            let destination = args.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing destination path")
            })?;
            fs::rename(source, destination)
        }
        Some("canonicalize-read") => {
            let path = args
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing path"))?;
            let canonical = fs::canonicalize(&path)?;
            let value = fs::read_to_string(canonical)?;
            print!("{value}");
            Ok(())
        }
        Some("process-identity") => {
            let pid = parse_pid(args.next());
            print_process_identity(pid)
        }
        Some("process-fd-count") => {
            let pid = parse_pid(args.next());
            print_process_fd_count(pid)
        }
        Some("tcp-server") => {
            let port_file = args.next().unwrap_or_else(|| fail("missing port file"));
            let listener = TcpListener::bind(("127.0.0.1", 0))?;
            fs::write(&port_file, listener.local_addr()?.port().to_string())?;
            let (mut stream, _) = listener.accept()?;
            stream.write_all(b"ok")?;
            Ok(())
        }
        Some("tcp-connect") => {
            let port = args
                .next()
                .and_then(|value| value.to_str().and_then(|value| value.parse::<u16>().ok()))
                .unwrap_or_else(|| fail("invalid port"));
            let mut stream = TcpStream::connect_timeout(
                &format!("127.0.0.1:{port}").parse().unwrap(),
                Duration::from_secs(2),
            )?;
            let mut value = String::new();
            stream.read_to_string(&mut value)?;
            println!("{value}");
            Ok(())
        }
        Some("tcp-connect6") => {
            let port = parse_port(args.next());
            let mut stream = TcpStream::connect_timeout(
                &format!("[::1]:{port}").parse().unwrap(),
                Duration::from_secs(2),
            )?;
            let mut value = String::new();
            stream.read_to_string(&mut value)?;
            println!("{value}");
            Ok(())
        }
        Some("tcp-bind6") => {
            let port = parse_port(args.next());
            let _listener = TcpListener::bind((Ipv6Addr::LOCALHOST, port))?;
            println!("BOUND");
            Ok(())
        }
        Some("proxy-check6") => {
            let port = parse_port(args.next());
            let mut stream = TcpStream::connect_timeout(
                &format!("[::1]:{port}").parse().unwrap(),
                Duration::from_secs(2),
            )?;
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            stream.write_all(
                b"CONNECT unlisted.example:443 HTTP/1.1\r\nHost: unlisted.example:443\r\n\r\n",
            )?;
            let mut response = [0_u8; 256];
            let size = stream.read(&mut response)?;
            let response = String::from_utf8_lossy(&response[..size]);
            if response.starts_with("HTTP/1.1 403 ") {
                println!("V6-PROXY");
                Ok(())
            } else {
                Err(io::Error::other("IPv6 loopback did not reach exact proxy"))
            }
        }
        Some("tcp-bind") => {
            let _listener = TcpListener::bind(("127.0.0.1", 0))?;
            println!("BOUND");
            Ok(())
        }
        Some("raw-dns") => probe_raw_dns(),
        Some("direct-public-ip") => {
            let address = "93.184.216.34:443".parse().unwrap();
            TcpStream::connect_timeout(&address, Duration::from_secs(2)).map(|_| ())
        }
        Some("proxy-abuse") => probe_proxy_abuse(),
        Some("setsid-escape") => {
            let pid_file = args.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing setsid pid file")
            })?;
            probe_setsid_escape(&pid_file)
        }
        Some("setsid-marker") => {
            let marker = args.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing setsid marker")
            })?;
            probe_setsid_marker(&marker)
        }
        Some("fork-marker") => {
            let marker = args.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing fork marker")
            })?;
            probe_fork_marker(&marker)
        }
        Some("vfork-marker") => {
            let marker = args.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing vfork marker")
            })?;
            probe_vfork_marker(&marker)
        }
        Some("posix-spawn-marker") => {
            let marker = args.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing posix_spawn marker")
            })?;
            probe_posix_spawn_marker(&marker)
        }
        Some("background-marker") => {
            let marker = args.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing background marker")
            })?;
            probe_fork_marker(&marker)
        }
        Some("thread-only") => probe_thread_only(),
        Some("thread-hold") => {
            let seconds = args
                .next()
                .and_then(|value| value.to_str().and_then(|value| value.parse::<u64>().ok()))
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid seconds"))?;
            probe_thread_hold(seconds)
        }
        Some("self-reexec") => {
            let expected_image = args.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing expected image")
            })?;
            let phase = args.next();
            probe_self_reexec(&expected_image, phase.as_deref())
        }
        Some("exec-bash") => {
            let marker = args.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing exec marker")
            })?;
            probe_exec_bash(&marker)
        }
        Some("proxy-hold") => {
            let domain = args
                .next()
                .and_then(|value| value.to_str().map(str::to_string))
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing domain"))?;
            let seconds = args
                .next()
                .and_then(|value| value.to_str().and_then(|value| value.parse::<u64>().ok()))
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid seconds"))?;
            let proxy = env::var("HTTPS_PROXY")
                .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "HTTPS_PROXY missing"))?;
            let endpoint = proxy
                .strip_prefix("http://")
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "unsupported proxy"))?;
            let endpoint = endpoint
                .rsplit_once(':')
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid proxy"))?;
            let proxy_address = format!("{}:{}", endpoint.0, endpoint.1)
                .parse()
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid proxy address")
                })?;
            let mut stream = TcpStream::connect_timeout(&proxy_address, Duration::from_secs(3))?;
            stream.set_read_timeout(Some(Duration::from_secs(3)))?;
            stream.write_all(
                format!("CONNECT {domain}:443 HTTP/1.1\r\nHost: {domain}:443\r\n\r\n").as_bytes(),
            )?;
            let mut response = [0_u8; 256];
            let size = stream.read(&mut response)?;
            let response = String::from_utf8_lossy(&response[..size]);
            if !response.starts_with("HTTP/1.1 200 ") {
                return Err(io::Error::other("proxy did not establish tunnel"));
            }
            println!("READY");
            thread::sleep(Duration::from_secs(seconds));
            Ok(())
        }
        Some("tty-injection") => probe_tty_injection(),
        Some("unix-socketpair") => {
            let mut descriptors: [RawFd; 2] = [-1, -1];
            if unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, descriptors.as_mut_ptr()) } != 0 {
                fail_io("socketpair");
            }
            unsafe {
                close(descriptors[0]);
                close(descriptors[1]);
            }
            println!("OK");
            Ok(())
        }
        Some(other) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown probe command `{other}`"),
        )),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "non-UTF-8 probe command",
        )),
    };

    if let Err(error) = result {
        eprintln!("sandbox-probe: {error}");
        process::exit(1);
    }

    Ok(())
}

fn print_process_identity(pid: c_int) -> io::Result<()> {
    match read_process_identity(pid) {
        Ok((process_id, start_seconds, start_microseconds)) => {
            println!("{process_id}|{start_seconds}|{start_microseconds}");
            Ok(())
        }
        Err(status) => process::exit(status),
    }
}

fn read_process_identity(pid: c_int) -> Result<(u32, u64, u64), i32> {
    let mut info = ProcBsdInfo {
        pbi_flags: 0,
        pbi_status: 0,
        pbi_xstatus: 0,
        pbi_pid: 0,
        pbi_ppid: 0,
        pbi_uid: 0,
        pbi_gid: 0,
        pbi_ruid: 0,
        pbi_rgid: 0,
        pbi_svuid: 0,
        pbi_svgid: 0,
        rfu_1: 0,
        pbi_comm: [0; 16],
        pbi_name: [0; 32],
        pbi_nfiles: 0,
        pbi_pgid: 0,
        pbi_pjobc: 0,
        e_tdev: 0,
        e_tpgid: 0,
        pbi_nice: 0,
        pbi_start_tvsec: 0,
        pbi_start_tvusec: 0,
    };
    let expected_size = size_of::<ProcBsdInfo>() as c_int;
    let result = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            &mut info as *mut ProcBsdInfo as *mut c_void,
            expected_size,
        )
    };
    if result == 0 {
        return Err(3);
    }
    if result != expected_size || info.pbi_pid != pid as u32 {
        return Err(4);
    }
    Ok((info.pbi_pid, info.pbi_start_tvsec, info.pbi_start_tvusec))
}

fn print_process_fd_count(pid: c_int) -> io::Result<()> {
    let mut capacity = 32_usize;
    loop {
        let mut entries = vec![
            ProcFdInfo {
                proc_fd: 0,
                proc_fdtype: 0,
            };
            capacity
        ];
        let buffer_size = (entries.len() * size_of::<ProcFdInfo>()) as c_int;
        let result = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDLISTFDS,
                0,
                entries.as_mut_ptr() as *mut c_void,
                buffer_size,
            )
        };
        if result == 0 {
            process::exit(3);
        }
        if result < 0 {
            process::exit(4);
        }
        let bytes = result as usize;
        let entry_size = size_of::<ProcFdInfo>();
        if bytes % entry_size != 0 {
            process::exit(4);
        }
        let count = bytes / entry_size;
        if bytes < buffer_size as usize {
            println!("{count}");
            break;
        }
        if capacity >= MAX_FD_SCAN_ENTRIES {
            process::exit(4);
        }
        capacity = (capacity * 2).min(MAX_FD_SCAN_ENTRIES);
    }
    Ok(())
}

fn probe_raw_dns() -> io::Result<()> {
    let udp = UdpSocket::bind(("0.0.0.0", 0))
        .and_then(|socket| {
            socket
                .send_to(b"mbox-dns-probe", ("8.8.8.8", 53))
                .map(|_| ())
        })
        .is_ok();
    let tcp = "8.8.8.8:53"
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS endpoint"))
        .and_then(|address| TcpStream::connect_timeout(&address, Duration::from_secs(2)))
        .is_ok();
    if udp || tcp {
        println!("RAW-DNS-ALLOWED");
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("raw DNS attempt results: udp={udp} tcp={tcp}"),
        ))
    }
}

fn proxy_abuse() -> io::Result<()> {
    let proxy = env::var("HTTPS_PROXY")
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "HTTPS_PROXY missing"))?;
    let endpoint = proxy
        .strip_prefix("http://")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "unsupported proxy"))?;
    let endpoint = endpoint
        .rsplit_once(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid proxy"))?;
    let proxy_address = format!("{}:{}", endpoint.0, endpoint.1)
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid proxy address"))?;

    // Hold more partial headers than the worker cap, then reset a second
    // batch. The bounded header deadline must release the held workers.
    let mut held = Vec::new();
    for _ in 0..64 {
        if let Ok(mut stream) = TcpStream::connect_timeout(&proxy_address, Duration::from_secs(2)) {
            let _ = stream.write_all(b"CONNECT example.com:443 HTTP/1.1\r\n");
            held.push(stream);
        }
    }
    for _ in 0..128 {
        if let Ok(mut stream) = TcpStream::connect_timeout(&proxy_address, Duration::from_secs(2)) {
            let _ = stream.write_all(b"CONNECT example.com:443 HTTP/1.1\r\n");
            drop(stream);
        }
    }
    drop(held);
    thread::sleep(Duration::from_secs(3));

    let mut stream = TcpStream::connect_timeout(&proxy_address, Duration::from_secs(3))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")?;
    let mut response = [0_u8; 256];
    let size = stream.read(&mut response)?;
    let response = String::from_utf8_lossy(&response[..size]);
    if response.starts_with("HTTP/1.1 200 ") {
        println!("ABUSE-RECOVERED");
        Ok(())
    } else {
        Err(io::Error::other(
            "proxy did not recover after bounded abuse",
        ))
    }
}

fn probe_proxy_abuse() -> io::Result<()> {
    proxy_abuse()
}

fn probe_setsid_escape(pid_file: &std::ffi::OsStr) -> io::Result<()> {
    let child = unsafe { fork() };
    if child < 0 {
        return Err(io::Error::last_os_error());
    }
    if child == 0 {
        unsafe {
            if setsid() < 0 {
                _exit(10);
            }
            let grandchild = fork();
            if grandchild < 0 {
                _exit(11);
            }
            if grandchild > 0 {
                _exit(0);
            }
        }
        let identity = match read_process_identity(process::id() as c_int) {
            Ok((process_id, start_seconds, start_microseconds)) => {
                format!("{process_id}|{start_seconds}|{start_microseconds}")
            }
            Err(status) => unsafe { _exit(status) },
        };
        fs::write(pid_file, identity)?;
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }

    let mut status = 0;
    if unsafe { waitpid(child, &mut status, 0) } != child {
        return Err(io::Error::last_os_error());
    }
    if status & 0x7f != 0 || (status >> 8) & 0xff != 0 {
        return Err(io::Error::other("setsid escape setup child failed"));
    }
    println!("SETSID-ESCAPE-UNOWNED");
    Ok(())
}

fn probe_setsid_marker(marker: &std::ffi::OsStr) -> io::Result<()> {
    let result = unsafe { setsid() };
    if result < 0 {
        println!("SETSID-DENIED");
        return Ok(());
    }
    fs::write(marker, b"setsid-allowed")?;
    Err(io::Error::other("setsid unexpectedly succeeded"))
}

fn probe_fork_marker(marker: &std::ffi::OsStr) -> io::Result<()> {
    let child = unsafe { fork() };
    if child < 0 {
        println!("FORK-DENIED");
        return Ok(());
    }
    if child == 0 {
        let _ = fs::write(marker, b"fork-allowed");
        unsafe { _exit(0) };
    }
    let mut status = 0;
    if unsafe { waitpid(child, &mut status, 0) } != child {
        return Err(io::Error::last_os_error());
    }
    Err(io::Error::other("fork unexpectedly succeeded"))
}

fn probe_vfork_marker(marker: &std::ffi::OsStr) -> io::Result<()> {
    let child = unsafe { vfork() };
    if child < 0 {
        println!("VFORK-DENIED");
        return Ok(());
    }
    if child == 0 {
        unsafe { _exit(0) };
    }
    let mut status = 0;
    if unsafe { waitpid(child, &mut status, 0) } != child {
        return Err(io::Error::last_os_error());
    }
    fs::write(marker, b"vfork-allowed")?;
    Err(io::Error::other("vfork unexpectedly succeeded"))
}

fn probe_posix_spawn_marker(marker: &std::ffi::OsStr) -> io::Result<()> {
    let path = CString::new("/usr/bin/true").unwrap();
    let argv = [path.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null()];
    let mut child = 0;
    let result = unsafe {
        posix_spawn(
            &mut child,
            path.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            argv.as_ptr(),
            envp.as_ptr(),
        )
    };
    if result != 0 {
        println!("POSIX-SPAWN-DENIED");
        return Ok(());
    }
    let mut status = 0;
    if unsafe { waitpid(child, &mut status, 0) } != child {
        return Err(io::Error::last_os_error());
    }
    fs::write(marker, b"posix-spawn-allowed")?;
    Err(io::Error::other("posix_spawn unexpectedly succeeded"))
}

fn probe_exec_bash(marker: &std::ffi::OsStr) -> io::Result<()> {
    let path = CString::new("/bin/bash").unwrap();
    let option = CString::new("-c").unwrap();
    let script = CString::new("printf exec-bash-allowed > \"$1\"").unwrap();
    let argv0 = CString::new("bash").unwrap();
    let marker =
        CString::new(marker.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "exec marker must be UTF-8")
        })?)
        .unwrap();
    let argv = [
        path.as_ptr(),
        option.as_ptr(),
        script.as_ptr(),
        argv0.as_ptr(),
        marker.as_ptr(),
        std::ptr::null(),
    ];
    let envp = [std::ptr::null()];
    if unsafe { execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) } == 0 {
        unreachable!("execve does not return after success");
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("exec-bash denied: {}", io::Error::last_os_error()),
    ))
}

fn probe_thread_only() -> io::Result<()> {
    thread::spawn(|| {})
        .join()
        .map_err(|_| io::Error::other("thread panicked"))?;
    println!("THREAD-ONLY");
    Ok(())
}

fn probe_thread_hold(seconds: u64) -> io::Result<()> {
    let worker = thread::spawn(move || thread::sleep(Duration::from_secs(seconds)));
    println!("THREAD-HOLD-READY");
    io::stdout().flush()?;
    worker
        .join()
        .map_err(|_| io::Error::other("thread panicked"))
}

fn probe_self_reexec(
    expected_image: &std::ffi::OsStr,
    phase: Option<&std::ffi::OsStr>,
) -> io::Result<()> {
    let executable = fs::canonicalize(env::current_exe()?)?;
    let expected = fs::canonicalize(expected_image)?;
    if executable != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "self-reexec image mismatch: expected `{}`, observed `{}`",
                expected.display(),
                executable.display()
            ),
        ));
    }
    let identity = read_process_identity(process::id() as c_int).map_err(|status| {
        io::Error::other(format!(
            "could not read self-reexec process identity (status {status})"
        ))
    })?;
    let identity = format_identity(identity);
    let after_marker = std::ffi::OsStr::new("--after-self-reexec");

    match phase {
        Some(marker) if marker == after_marker => {
            println!("SELF-REEXEC-AFTER {identity}");
            println!("SELF-REEXEC-IMAGE {}", executable.display());
            io::stdout().flush()
        }
        Some(marker) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown self-reexec phase `{}`", marker.to_string_lossy()),
        )),
        None => {
            println!("SELF-REEXEC-BEFORE {identity}");
            println!("SELF-REEXEC-IMAGE {}", executable.display());
            io::stdout().flush()?;

            let executable = CString::new(executable.as_os_str().as_bytes()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "self-reexec executable path contains NUL",
                )
            })?;
            let command = CString::new("self-reexec").unwrap();
            let expected = CString::new(expected.as_os_str().as_bytes()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "self-reexec expected image contains NUL",
                )
            })?;
            let marker = CString::new(after_marker.as_bytes()).unwrap();
            let argv = [
                executable.as_ptr(),
                command.as_ptr(),
                expected.as_ptr(),
                marker.as_ptr(),
                std::ptr::null(),
            ];
            let envp = [std::ptr::null()];
            let result = unsafe { execve(executable.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "self-reexec denied: {result}: {}",
                    io::Error::last_os_error()
                ),
            ))
        }
    }
}

fn format_identity(identity: (u32, u64, u64)) -> String {
    format!("{}|{}|{}", identity.0, identity.1, identity.2)
}

fn probe_tty_injection() -> io::Result<()> {
    let mut master = -1;
    let mut slave = -1;
    if unsafe {
        openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }

    let pid = unsafe { fork() };
    if pid < 0 {
        let error = io::Error::last_os_error();
        unsafe {
            close(master);
            close(slave);
        }
        return Err(error);
    }

    if pid == 0 {
        unsafe {
            close(master);
            if setsid() < 0 {
                _exit(10);
            }
            if ioctl(slave, TIOCSCTTY, 0_usize) < 0 {
                _exit(11);
            }
            let mut byte = b'x' as c_char;
            let result = ioctl(slave, TIOCSTI, &mut byte as *mut c_char);
            if result == 0 {
                _exit(4);
            }
            let blocked = io::Error::last_os_error().raw_os_error() == Some(EPERM);
            _exit(if blocked { 0 } else { 12 });
        }
    }

    unsafe {
        close(slave);
    }
    let mut status = 0;
    if unsafe { waitpid(pid, &mut status, 0) } != pid {
        let error = io::Error::last_os_error();
        unsafe {
            close(master);
        }
        return Err(error);
    }
    unsafe {
        close(master);
    }
    if status & 0x7f != 0 {
        return Err(io::Error::other(format!(
            "tty-injection child terminated by signal: {status}"
        )));
    }

    match (status >> 8) & 0xff {
        0 => {
            println!("EPERM");
            Ok(())
        }
        4 => {
            println!("ALLOWED");
            process::exit(4);
        }
        code => Err(io::Error::other(format!(
            "tty-injection setup failed with child status {code}"
        ))),
    }
}

fn parse_fd(value: Option<std::ffi::OsString>) -> RawFd {
    value
        .and_then(|value| value.to_str().and_then(|value| value.parse().ok()))
        .unwrap_or_else(|| fail("invalid fd"))
}

fn parse_port(value: Option<std::ffi::OsString>) -> u16 {
    value
        .and_then(|value| value.to_str().and_then(|value| value.parse::<u16>().ok()))
        .unwrap_or_else(|| fail("invalid port"))
}

fn parse_pid(value: Option<std::ffi::OsString>) -> c_int {
    value
        .and_then(|value| value.to_str().and_then(|value| value.parse().ok()))
        .filter(|pid: &c_int| *pid > 0)
        .unwrap_or_else(|| fail("invalid pid"))
}

fn fail(message: &str) -> ! {
    eprintln!("sandbox-probe: {message}");
    process::exit(2);
}

fn fail_io(name: &str) -> ! {
    eprintln!("sandbox-probe: {name}: {}", io::Error::last_os_error());
    process::exit(1);
}
