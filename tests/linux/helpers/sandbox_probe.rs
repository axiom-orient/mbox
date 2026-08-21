#[cfg(target_endian = "big")]
compile_error!("Linux sandbox probe supports only little-endian targets");

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("Linux sandbox probe supports x86_64 and aarch64");

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::os::raw::{c_char, c_int, c_long, c_void};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixDatagram;
use std::process;
use std::thread;
use std::time::Duration;

const EBADF: i32 = 9;
const EPERM: i32 = 1;
const ENOSPC: i32 = 28;
const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;
const SOCK_DGRAM: c_int = 2;
const LOCK_EX: c_int = 2;
const LOCK_NB: c_int = 4;
const TIOCSTI: usize = 0x5412;
const TIOCGWINSZ: usize = 0x5413;
const TIOCLINUX: usize = 0x541c;
const CLONE_NEWUSER: usize = 0x1000_0000;

#[repr(C)]
struct SockAddrUn {
    family: u16,
    path: [c_char; 108],
}

unsafe extern "C" {
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn flock(fd: c_int, operation: c_int) -> c_int;
    fn socketpair(domain: c_int, kind: c_int, protocol: c_int, descriptors: *mut c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn ptrace(request: c_int, pid: c_int, address: *mut c_void, data: *mut c_void) -> c_long;
    fn syscall(number: c_long, ...) -> c_long;
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
        Some("remove-file") => {
            let path = args
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing path"))?;
            fs::remove_file(path)
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
        Some("unix-socketpair") => unix_socketpair_round_trip(),
        Some("unix-socket") => {
            let result =
                unsafe { syscall(SYS_SOCKET, AF_UNIX as usize, SOCK_STREAM as usize, 0_usize) };
            expect_eperm("socket(AF_UNIX)", result)
        }
        Some("unix-dgram-server") => {
            let socket_path = args.next().unwrap_or_else(|| fail("missing socket path"));
            let ready_path = args.next().unwrap_or_else(|| fail("missing ready path"));
            let received_path = args.next().unwrap_or_else(|| fail("missing received path"));
            let stop_path = args.next().unwrap_or_else(|| fail("missing stop path"));
            unix_datagram_server(socket_path, ready_path, received_path, stop_path)
        }
        Some("unix-dgram-sendto") => {
            let socket_path = args.next().unwrap_or_else(|| fail("missing socket path"));
            explicit_destination_sendto_is_blocked(&socket_path)
        }
        Some("sendmsg") => {
            let result = unsafe { syscall(SYS_SENDMSG, usize::MAX, 0_usize, 0_usize) };
            expect_eperm("sendmsg", result)
        }
        Some("recvmsg") => {
            let result = unsafe { syscall(SYS_RECVMSG, usize::MAX, 0_usize, 0_usize) };
            expect_eperm("recvmsg", result)
        }
        Some("tty-injection") => {
            let tiocsti = unsafe { syscall(SYS_IOCTL, usize::MAX, TIOCSTI, 0_usize) };
            expect_eperm("ioctl(TIOCSTI)", tiocsti)?;
            let tioclinux = unsafe { syscall(SYS_IOCTL, usize::MAX, TIOCLINUX, 0_usize) };
            expect_eperm("ioctl(TIOCLINUX)", tioclinux)
        }
        Some("userns-disabled") => {
            let result = unsafe { syscall(SYS_UNSHARE, CLONE_NEWUSER) };
            let error = io::Error::last_os_error();
            if result == -1 && matches!(error.raw_os_error(), Some(EPERM | ENOSPC)) {
                println!("BLOCKED");
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "nested user namespace was not blocked: result={result}, error={error}"
                )))
            }
        }
        Some("tty-query") => {
            let result = unsafe { syscall(SYS_IOCTL, usize::MAX, TIOCGWINSZ, 0_usize) };
            let error = io::Error::last_os_error();
            if result == -1 && error.raw_os_error() == Some(EBADF) {
                println!("ALLOWED");
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "ioctl(TIOCGWINSZ) did not reach the kernel: result={result}, error={error}"
                )))
            }
        }
        Some("ptrace") => {
            let result = unsafe { ptrace(0, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
            expect_eperm("ptrace", result)
        }
        Some("io-uring") => {
            let result = unsafe { syscall(SYS_IO_URING_SETUP, 1_u32, std::ptr::null::<c_void>()) };
            expect_eperm("io_uring_setup", result)
        }
        Some("hold-lock") => {
            let lock_path = args.next().unwrap_or_else(|| fail("missing lock path"));
            let ready_path = args.next().unwrap_or_else(|| fail("missing ready path"));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(lock_path)?;
            if unsafe { flock(file.as_raw_fd(), LOCK_EX) } != 0 {
                fail_io("flock(LOCK_EX)");
            }
            fs::write(ready_path, b"ready\n")?;
            loop {
                thread::sleep(Duration::from_secs(3600));
            }
        }
        Some("try-lock") => {
            let lock_path = args.next().unwrap_or_else(|| fail("missing lock path"));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(lock_path)?;
            if unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) } == 0 {
                println!("LOCKED");
                Ok(())
            } else if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
                println!("BUSY");
                process::exit(4);
            } else {
                Err(io::Error::last_os_error())
            }
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

fn unix_datagram_server(
    socket_path: std::ffi::OsString,
    ready_path: std::ffi::OsString,
    received_path: std::ffi::OsString,
    stop_path: std::ffi::OsString,
) -> io::Result<()> {
    let _ = fs::remove_file(&socket_path);
    let socket = UnixDatagram::bind(&socket_path)?;
    socket.set_nonblocking(true)?;
    fs::write(ready_path, b"ready\n")?;

    let mut buffer = [0_u8; 16];
    loop {
        match socket.recv(&mut buffer) {
            Ok(count) => {
                fs::write(received_path, &buffer[..count])?;
                return Err(io::Error::other(
                    "received a forbidden pathname-socket datagram",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if fs::metadata(&stop_path).is_ok() {
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn unix_socketpair_round_trip() -> io::Result<()> {
    let mut descriptors: [RawFd; 2] = [-1, -1];
    if unsafe { socketpair(AF_UNIX, SOCK_DGRAM, 0, descriptors.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let payload = b"x";
    let written = unsafe {
        syscall(
            SYS_SENDTO,
            descriptors[0] as usize,
            payload.as_ptr(),
            payload.len(),
            0_usize,
            std::ptr::null::<c_void>(),
            0_usize,
        )
    };
    let mut received = [0_u8; 1];
    let read_count = unsafe {
        syscall(
            SYS_RECVFROM,
            descriptors[1] as usize,
            received.as_mut_ptr(),
            received.len(),
            0_usize,
            std::ptr::null_mut::<c_void>(),
            std::ptr::null_mut::<usize>(),
        )
    };
    unsafe {
        close(descriptors[0]);
        close(descriptors[1]);
    }

    if written == 1 && read_count == 1 && received == *payload {
        println!("OK");
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "connected socketpair round trip failed: written={written}, read={read_count}"
        )))
    }
}

fn explicit_destination_sendto_is_blocked(socket_path: &std::ffi::OsStr) -> io::Result<()> {
    let path_bytes = socket_path.as_bytes();
    if path_bytes.len() >= 108 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unix socket path is too long",
        ));
    }

    let mut descriptors: [RawFd; 2] = [-1, -1];
    if unsafe { socketpair(AF_UNIX, SOCK_DGRAM, 0, descriptors.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut address = SockAddrUn {
        family: AF_UNIX as u16,
        path: [0; 108],
    };
    for (destination, source) in address.path.iter_mut().zip(path_bytes.iter().copied()) {
        *destination = source as c_char;
    }
    let address_length = std::mem::size_of::<u16>() + path_bytes.len() + 1;
    let payload = b"x";
    let result = unsafe {
        syscall(
            SYS_SENDTO,
            descriptors[0] as usize,
            payload.as_ptr(),
            payload.len(),
            0_usize,
            &address as *const SockAddrUn,
            address_length,
        )
    };
    let error = io::Error::last_os_error();
    unsafe {
        close(descriptors[0]);
        close(descriptors[1]);
    }

    if result == -1 && error.raw_os_error() == Some(EPERM) {
        println!("EPERM");
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "sendto to pathname Unix socket was not blocked: result={result}, error={error}"
        )))
    }
}

fn parse_fd(value: Option<std::ffi::OsString>) -> RawFd {
    value
        .and_then(|value| value.to_str().and_then(|value| value.parse().ok()))
        .unwrap_or_else(|| fail("invalid fd"))
}

fn expect_eperm(name: &str, result: c_long) -> io::Result<()> {
    let error = io::Error::last_os_error();
    if result == -1 && error.raw_os_error() == Some(EPERM) {
        println!("EPERM");
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{name} was not blocked with EPERM: result={result}, error={error}"
        )))
    }
}

fn fail(message: &str) -> ! {
    eprintln!("sandbox-probe: {message}");
    process::exit(2);
}

fn fail_io(name: &str) -> ! {
    eprintln!("sandbox-probe: {name}: {}", io::Error::last_os_error());
    process::exit(1);
}

#[cfg(target_arch = "x86_64")]
const SYS_IOCTL: c_long = 16;
#[cfg(target_arch = "x86_64")]
const SYS_UNSHARE: c_long = 272;
#[cfg(target_arch = "aarch64")]
const SYS_IOCTL: c_long = 29;
#[cfg(target_arch = "aarch64")]
const SYS_UNSHARE: c_long = 97;

#[cfg(target_arch = "x86_64")]
const SYS_SOCKET: c_long = 41;
#[cfg(target_arch = "aarch64")]
const SYS_SOCKET: c_long = 198;

#[cfg(target_arch = "x86_64")]
const SYS_SENDTO: c_long = 44;
#[cfg(target_arch = "aarch64")]
const SYS_SENDTO: c_long = 206;

#[cfg(target_arch = "x86_64")]
const SYS_RECVFROM: c_long = 45;
#[cfg(target_arch = "aarch64")]
const SYS_RECVFROM: c_long = 207;

#[cfg(target_arch = "x86_64")]
const SYS_SENDMSG: c_long = 46;
#[cfg(target_arch = "aarch64")]
const SYS_SENDMSG: c_long = 211;

#[cfg(target_arch = "x86_64")]
const SYS_RECVMSG: c_long = 47;
#[cfg(target_arch = "aarch64")]
const SYS_RECVMSG: c_long = 212;

#[cfg(target_arch = "x86_64")]
const SYS_IO_URING_SETUP: c_long = 425;
#[cfg(target_arch = "aarch64")]
const SYS_IO_URING_SETUP: c_long = 425;
