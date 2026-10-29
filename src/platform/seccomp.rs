use super::fd;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::raw::{c_int, c_long, c_uint};

#[cfg(target_endian = "big")]
compile_error!("mbox Linux seccomp supports only little-endian targets");
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("mbox Linux seccomp supports x86_64 and aarch64");

const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
#[cfg(any(test, target_arch = "x86_64"))]
const BPF_JGE: u16 = 0x30;
const BPF_K: u16 = 0x00;

const SECCOMP_DATA_NR: u32 = 0;
const SECCOMP_DATA_ARCH: u32 = 4;
const SECCOMP_DATA_ARGS: u32 = 16;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const EPERM: u32 = 1;
const AF_UNIX: u32 = 1;
const TIOCSTI: u32 = 0x5412;
#[cfg(test)]
const TIOCGWINSZ: u32 = 0x5413;
const TIOCLINUX: u32 = 0x541c;
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

const MFD_ALLOW_SEALING: c_uint = 0x0002;
const F_ADD_SEALS: c_int = 1033;
const F_SEAL_SEAL: c_int = 0x0001;
const F_SEAL_SHRINK: c_int = 0x0002;
const F_SEAL_GROW: c_int = 0x0004;
const F_SEAL_WRITE: c_int = 0x0008;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
}

pub fn create_filter_file(network_enabled: bool) -> io::Result<File> {
    let program = filter_program(network_enabled);
    let name = CString::new("mbox-seccomp").expect("constant contains no NUL");
    let descriptor = unsafe { syscall(SYS_MEMFD_CREATE, name.as_ptr(), MFD_ALLOW_SEALING) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut file = unsafe { File::from_raw_fd(descriptor as c_int) };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            program.as_ptr().cast::<u8>(),
            program.len() * size_of::<SockFilter>(),
        )
    };
    file.write_all(bytes)?;
    file.seek(SeekFrom::Start(0))?;

    let fd = file.as_raw_fd();
    fd::make_inheritable(fd)?;

    let seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
    if unsafe { fcntl(fd, F_ADD_SEALS, seals) } < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(file)
}

fn filter_program(network_enabled: bool) -> Vec<SockFilter> {
    let mut program = vec![
        load(SECCOMP_DATA_ARCH),
        jump_equal(AUDIT_ARCH, 1, 0),
        ret(SECCOMP_RET_KILL_PROCESS),
    ];

    #[cfg(target_arch = "x86_64")]
    program.extend([
        load(SECCOMP_DATA_NR),
        jump_ge(X32_SYSCALL_BIT, 0, 1),
        ret(errno(EPERM)),
    ]);

    program.push(load(SECCOMP_DATA_NR));

    for syscall in baseline_denied().iter().copied() {
        deny_number(&mut program, syscall);
    }
    deny_tty_injection(&mut program);

    if !network_enabled {
        for syscall in network_denied().iter().copied() {
            deny_number(&mut program, syscall);
        }

        restrict_sendto_destination(&mut program);
        restrict_socketpair_family(&mut program);
    }

    program.push(ret(SECCOMP_RET_ALLOW));
    program
}

fn deny_number(program: &mut Vec<SockFilter>, syscall: u32) {
    program.push(jump_equal(syscall, 0, 1));
    program.push(ret(errno(EPERM)));
}

fn deny_tty_injection(program: &mut Vec<SockFilter>) {
    program.push(jump_equal(SYS_IOCTL, 0, 4));
    program.push(load(seccomp_argument(1)));
    program.push(jump_equal(TIOCSTI, 1, 0));
    program.push(jump_equal(TIOCLINUX, 0, 1));
    program.push(ret(errno(EPERM)));
    program.push(load(SECCOMP_DATA_NR));
}

fn restrict_sendto_destination(program: &mut Vec<SockFilter>) {
    // Preserve send(2) semantics for already-connected anonymous socketpairs,
    // while denying sendto(2) with an explicit destination address. The latter
    // could otherwise target a pathname Unix socket mounted read-only from the
    // host. seccomp arguments are u64, so both pointer words must be zero.
    program.push(jump_equal(SYS_SENDTO, 0, 6));
    program.push(load(seccomp_argument(4)));
    program.push(jump_equal(0, 1, 0));
    program.push(ret(errno(EPERM)));
    program.push(load(seccomp_argument_high(4)));
    program.push(jump_equal(0, 1, 0));
    program.push(ret(errno(EPERM)));
    program.push(load(SECCOMP_DATA_NR));
}

fn restrict_socketpair_family(program: &mut Vec<SockFilter>) {
    program.push(jump_equal(SYS_SOCKETPAIR, 0, 3));
    program.push(load(seccomp_argument(0)));
    program.push(jump_equal(AF_UNIX, 1, 0));
    program.push(ret(errno(EPERM)));
}

const fn seccomp_argument(index: u32) -> u32 {
    SECCOMP_DATA_ARGS + index * 8
}

const fn seccomp_argument_high(index: u32) -> u32 {
    seccomp_argument(index) + 4
}

const fn load(offset: u32) -> SockFilter {
    SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: offset,
    }
}

const fn jump_equal(value: u32, jump_true: u8, jump_false: u8) -> SockFilter {
    SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: jump_true,
        jf: jump_false,
        k: value,
    }
}

#[cfg(target_arch = "x86_64")]
const fn jump_ge(value: u32, jump_true: u8, jump_false: u8) -> SockFilter {
    SockFilter {
        code: BPF_JMP | BPF_JGE | BPF_K,
        jt: jump_true,
        jf: jump_false,
        k: value,
    }
}

const fn ret(action: u32) -> SockFilter {
    SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: action,
    }
}

const fn errno(value: u32) -> u32 {
    SECCOMP_RET_ERRNO | (value & 0x0000_ffff)
}

fn baseline_denied() -> &'static [u32] {
    &[
        SYS_PTRACE,
        SYS_PROCESS_VM_READV,
        SYS_PROCESS_VM_WRITEV,
        SYS_IO_URING_SETUP,
        SYS_IO_URING_ENTER,
        SYS_IO_URING_REGISTER,
    ]
}

fn network_denied() -> &'static [u32] {
    &[
        SYS_SOCKET,
        SYS_CONNECT,
        SYS_ACCEPT,
        SYS_ACCEPT4,
        SYS_BIND,
        SYS_LISTEN,
        SYS_SENDMSG,
        SYS_RECVMSG,
        SYS_SENDMMSG,
        SYS_RECVMMSG,
    ]
}

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

#[cfg(target_arch = "x86_64")]
const SYS_MEMFD_CREATE: c_long = 319;
#[cfg(target_arch = "aarch64")]
const SYS_MEMFD_CREATE: c_long = 279;

#[cfg(target_arch = "x86_64")]
mod numbers {
    pub const IOCTL: u32 = 16;
    pub const SOCKET: u32 = 41;
    pub const CONNECT: u32 = 42;
    pub const ACCEPT: u32 = 43;
    pub const SENDTO: u32 = 44;
    #[cfg(test)]
    pub const RECVFROM: u32 = 45;
    pub const SENDMSG: u32 = 46;
    pub const RECVMSG: u32 = 47;
    #[cfg(test)]
    pub const SHUTDOWN: u32 = 48;
    pub const BIND: u32 = 49;
    pub const LISTEN: u32 = 50;
    pub const SOCKETPAIR: u32 = 53;
    pub const PTRACE: u32 = 101;
    pub const ACCEPT4: u32 = 288;
    pub const RECVMMSG: u32 = 299;
    pub const PROCESS_VM_READV: u32 = 310;
    pub const PROCESS_VM_WRITEV: u32 = 311;
    pub const SENDMMSG: u32 = 307;
    pub const IO_URING_SETUP: u32 = 425;
    pub const IO_URING_ENTER: u32 = 426;
    pub const IO_URING_REGISTER: u32 = 427;
}

#[cfg(target_arch = "aarch64")]
mod numbers {
    pub const IOCTL: u32 = 29;
    pub const PTRACE: u32 = 117;
    pub const SOCKET: u32 = 198;
    pub const SOCKETPAIR: u32 = 199;
    pub const BIND: u32 = 200;
    pub const LISTEN: u32 = 201;
    pub const ACCEPT: u32 = 202;
    pub const CONNECT: u32 = 203;
    pub const SENDTO: u32 = 206;
    #[cfg(test)]
    pub const RECVFROM: u32 = 207;
    pub const SENDMSG: u32 = 211;
    pub const RECVMSG: u32 = 212;
    #[cfg(test)]
    pub const SHUTDOWN: u32 = 210;
    pub const ACCEPT4: u32 = 242;
    pub const RECVMMSG: u32 = 243;
    pub const PROCESS_VM_READV: u32 = 270;
    pub const PROCESS_VM_WRITEV: u32 = 271;
    pub const SENDMMSG: u32 = 269;
    pub const IO_URING_SETUP: u32 = 425;
    pub const IO_URING_ENTER: u32 = 426;
    pub const IO_URING_REGISTER: u32 = 427;
}

use numbers::{
    ACCEPT as SYS_ACCEPT, ACCEPT4 as SYS_ACCEPT4, BIND as SYS_BIND, CONNECT as SYS_CONNECT,
    IOCTL as SYS_IOCTL, IO_URING_ENTER as SYS_IO_URING_ENTER,
    IO_URING_REGISTER as SYS_IO_URING_REGISTER, IO_URING_SETUP as SYS_IO_URING_SETUP,
    LISTEN as SYS_LISTEN, PROCESS_VM_READV as SYS_PROCESS_VM_READV,
    PROCESS_VM_WRITEV as SYS_PROCESS_VM_WRITEV, PTRACE as SYS_PTRACE, RECVMMSG as SYS_RECVMMSG,
    RECVMSG as SYS_RECVMSG, SENDMMSG as SYS_SENDMMSG, SENDMSG as SYS_SENDMSG, SENDTO as SYS_SENDTO,
    SOCKET as SYS_SOCKET, SOCKETPAIR as SYS_SOCKETPAIR,
};
#[cfg(test)]
use numbers::{RECVFROM as SYS_RECVFROM, SHUTDOWN as SYS_SHUTDOWN};

#[cfg(test)]
mod tests;
