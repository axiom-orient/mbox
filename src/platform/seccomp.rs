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
mod tests {
    use super::*;

    fn evaluate(program: &[SockFilter], arch: u32, syscall: u32, arguments: [u64; 6]) -> u32 {
        let mut accumulator = 0_u32;
        let mut pc = 0_usize;
        while pc < program.len() {
            let instruction = program[pc];
            match instruction.code {
                code if code == BPF_LD | BPF_W | BPF_ABS => {
                    accumulator = match instruction.k {
                        SECCOMP_DATA_ARCH => arch,
                        SECCOMP_DATA_NR => syscall,
                        offset if offset >= SECCOMP_DATA_ARGS => {
                            let relative = offset - SECCOMP_DATA_ARGS;
                            let index = (relative / 8) as usize;
                            match relative % 8 {
                                0 => arguments[index] as u32,
                                4 => (arguments[index] >> 32) as u32,
                                byte => panic!("unaligned argument load at byte {byte}"),
                            }
                        }
                        offset => panic!("unexpected load offset {offset}"),
                    };
                    pc += 1;
                }
                code if code == BPF_JMP | BPF_JEQ | BPF_K => {
                    pc += 1 + if accumulator == instruction.k {
                        instruction.jt as usize
                    } else {
                        instruction.jf as usize
                    };
                }
                code if code == BPF_JMP | BPF_JGE | BPF_K => {
                    pc += 1 + if accumulator >= instruction.k {
                        instruction.jt as usize
                    } else {
                        instruction.jf as usize
                    };
                }
                code if code == BPF_RET | BPF_K => return instruction.k,
                code => panic!("unexpected instruction {code:#x}"),
            }
        }
        panic!("filter terminated without an action")
    }

    fn action(program: &[SockFilter], syscall: u32, arguments: [u64; 6]) -> u32 {
        evaluate(program, AUDIT_ARCH, syscall, arguments)
    }

    #[test]
    fn filter_struct_is_kernel_wire_size() {
        assert_eq!(size_of::<SockFilter>(), 8);
    }

    #[test]
    fn baseline_is_always_enforced() {
        for network in [false, true] {
            let program = filter_program(network);
            assert_eq!(action(&program, SYS_PTRACE, [0; 6]), errno(EPERM));
            assert_eq!(action(&program, SYS_IO_URING_SETUP, [0; 6]), errno(EPERM));
            assert_eq!(
                action(&program, SYS_IOCTL, [0, TIOCSTI as u64, 0, 0, 0, 0]),
                errno(EPERM)
            );
            assert_eq!(
                action(&program, SYS_IOCTL, [0, TIOCLINUX as u64, 0, 0, 0, 0]),
                errno(EPERM)
            );
            assert_eq!(
                action(&program, SYS_IOCTL, [0, TIOCGWINSZ as u64, 0, 0, 0, 0]),
                SECCOMP_RET_ALLOW
            );
        }
    }

    #[test]
    fn restricted_network_preserves_only_connected_anonymous_unix_ipc() {
        let program = filter_program(false);
        assert_eq!(
            action(&program, SYS_SOCKET, [AF_UNIX as u64, 0, 0, 0, 0, 0]),
            errno(EPERM)
        );
        assert_eq!(
            action(&program, SYS_SOCKETPAIR, [AF_UNIX as u64, 0, 0, 0, 0, 0]),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            action(&program, SYS_SOCKETPAIR, [2, 0, 0, 0, 0, 0]),
            errno(EPERM)
        );
        assert_eq!(action(&program, SYS_CONNECT, [0; 6]), errno(EPERM));
        assert_eq!(action(&program, SYS_SENDMSG, [0; 6]), errno(EPERM));
        assert_eq!(action(&program, SYS_RECVMSG, [0; 6]), errno(EPERM));

        // send(2) is implemented as sendto(2) with a null destination. Keep it
        // usable for connected socketpairs, but reject any explicit address.
        assert_eq!(action(&program, SYS_SENDTO, [0; 6]), SECCOMP_RET_ALLOW);
        assert_eq!(
            action(&program, SYS_SENDTO, [0, 0, 0, 0, 0x1000, 0]),
            errno(EPERM)
        );
        assert_eq!(
            action(&program, SYS_SENDTO, [0, 0, 0, 0, 1_u64 << 32, 0]),
            errno(EPERM)
        );
        assert_eq!(action(&program, SYS_RECVFROM, [0; 6]), SECCOMP_RET_ALLOW);
        assert_eq!(action(&program, SYS_SHUTDOWN, [0; 6]), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn enabled_network_allows_socket_and_message_io() {
        let program = filter_program(true);
        assert_eq!(
            action(&program, SYS_SOCKET, [2, 0, 0, 0, 0, 0]),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(action(&program, SYS_SENDMSG, [0; 6]), SECCOMP_RET_ALLOW);
        assert_eq!(action(&program, SYS_RECVMSG, [0; 6]), SECCOMP_RET_ALLOW);
        assert_eq!(
            action(&program, SYS_SENDTO, [0, 0, 0, 0, 0x1000, 0]),
            SECCOMP_RET_ALLOW
        );
    }

    #[test]
    fn wrong_architecture_is_killed() {
        let program = filter_program(true);
        assert_eq!(
            evaluate(&program, AUDIT_ARCH ^ 1, 0, [0; 6]),
            SECCOMP_RET_KILL_PROCESS
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_syscalls_are_rejected() {
        let program = filter_program(true);
        assert_eq!(action(&program, X32_SYSCALL_BIT, [0; 6]), errno(EPERM));
    }

    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }

    unsafe extern "C" {
        fn fork() -> i32;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn prctl(option: i32, ...) -> i32;
        fn close(fd: i32) -> i32;
        fn _exit(status: i32) -> !;
    }

    const PR_SET_NO_NEW_PRIVS: i32 = 38;
    const PR_SET_SECCOMP: i32 = 22;
    const SECCOMP_MODE_FILTER: usize = 2;
    const AF_INET: usize = 2;
    const SOCK_STREAM: usize = 1;
    const SOCK_DGRAM: usize = 2;
    const EBADF: i32 = 9;

    fn run_kernel_child(network_enabled: bool, child_check: unsafe fn() -> bool) {
        let program = filter_program(network_enabled);
        let pid = unsafe { fork() };
        assert!(pid >= 0, "fork failed: {}", io::Error::last_os_error());

        if pid == 0 {
            let setup = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1_usize, 0_usize, 0_usize, 0_usize) };
            if setup != 0 {
                unsafe { _exit(2) };
            }

            let filter = SockFprog {
                len: program.len() as u16,
                filter: program.as_ptr(),
            };
            let setup = unsafe {
                prctl(
                    PR_SET_SECCOMP,
                    SECCOMP_MODE_FILTER,
                    &filter as *const SockFprog,
                    0_usize,
                    0_usize,
                )
            };
            if setup != 0 {
                unsafe { _exit(3) };
            }

            let passed = unsafe { child_check() };
            unsafe { _exit(if passed { 0 } else { 4 }) };
        }

        let mut status = 0_i32;
        assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(
            status & 0x7f,
            0,
            "seccomp kernel child was terminated by a signal: {status}"
        );
        assert_eq!(
            (status >> 8) & 0xff,
            0,
            "seccomp kernel child failed with raw wait status {status}"
        );
    }

    unsafe fn ptrace_and_tty_injection_are_eperm() -> bool {
        let ptrace = unsafe { syscall(SYS_PTRACE as c_long, 0_usize, 0_usize, 0_usize, 0_usize) };
        let ptrace_blocked =
            ptrace == -1 && io::Error::last_os_error().raw_os_error() == Some(EPERM as i32);

        let tiocsti =
            unsafe { syscall(SYS_IOCTL as c_long, usize::MAX, TIOCSTI as usize, 0_usize) };
        let tiocsti_blocked =
            tiocsti == -1 && io::Error::last_os_error().raw_os_error() == Some(EPERM as i32);

        let tioclinux =
            unsafe { syscall(SYS_IOCTL as c_long, usize::MAX, TIOCLINUX as usize, 0_usize) };
        let tioclinux_blocked =
            tioclinux == -1 && io::Error::last_os_error().raw_os_error() == Some(EPERM as i32);

        ptrace_blocked && tiocsti_blocked && tioclinux_blocked
    }

    unsafe fn restricted_network_policy_is_exact() -> bool {
        let socket = unsafe { syscall(SYS_SOCKET as c_long, AF_INET, SOCK_STREAM, 0_usize) };
        let socket_blocked =
            socket == -1 && io::Error::last_os_error().raw_os_error() == Some(EPERM as i32);

        let sendmsg = unsafe { syscall(SYS_SENDMSG as c_long, usize::MAX, 0_usize, 0_usize) };
        let sendmsg_blocked =
            sendmsg == -1 && io::Error::last_os_error().raw_os_error() == Some(EPERM as i32);

        let recvmsg = unsafe { syscall(SYS_RECVMSG as c_long, usize::MAX, 0_usize, 0_usize) };
        let recvmsg_blocked =
            recvmsg == -1 && io::Error::last_os_error().raw_os_error() == Some(EPERM as i32);

        let null_sendto = unsafe {
            syscall(
                SYS_SENDTO as c_long,
                usize::MAX,
                0_usize,
                0_usize,
                0_usize,
                0_usize,
                0_usize,
            )
        };
        let null_sendto_reached_kernel =
            null_sendto == -1 && io::Error::last_os_error().raw_os_error() == Some(EBADF);

        let destination_sendto = unsafe {
            syscall(
                SYS_SENDTO as c_long,
                usize::MAX,
                0_usize,
                0_usize,
                0_usize,
                1_usize,
                1_usize,
            )
        };
        let destination_sendto_blocked = destination_sendto == -1
            && io::Error::last_os_error().raw_os_error() == Some(EPERM as i32);

        let recvfrom = unsafe {
            syscall(
                SYS_RECVFROM as c_long,
                usize::MAX,
                0_usize,
                0_usize,
                0_usize,
                0_usize,
                0_usize,
            )
        };
        let recvfrom_reached_kernel =
            recvfrom == -1 && io::Error::last_os_error().raw_os_error() == Some(EBADF);

        let mut descriptors = [-1_i32; 2];
        let pair = unsafe {
            syscall(
                SYS_SOCKETPAIR as c_long,
                AF_UNIX as usize,
                SOCK_DGRAM,
                0_usize,
                descriptors.as_mut_ptr(),
            )
        };
        let socketpair_round_trip = if pair == 0 {
            let payload = b"x";
            let sent = unsafe {
                syscall(
                    SYS_SENDTO as c_long,
                    descriptors[0] as usize,
                    payload.as_ptr(),
                    payload.len(),
                    0_usize,
                    0_usize,
                    0_usize,
                )
            };
            let mut received = [0_u8; 1];
            let read = unsafe {
                syscall(
                    SYS_RECVFROM as c_long,
                    descriptors[1] as usize,
                    received.as_mut_ptr(),
                    received.len(),
                    0_usize,
                    0_usize,
                    0_usize,
                )
            };
            unsafe {
                close(descriptors[0]);
                close(descriptors[1]);
            }
            sent == 1 && read == 1 && received == *payload
        } else {
            false
        };

        socket_blocked
            && sendmsg_blocked
            && recvmsg_blocked
            && null_sendto_reached_kernel
            && destination_sendto_blocked
            && recvfrom_reached_kernel
            && socketpair_round_trip
    }

    #[test]
    fn kernel_enforces_baseline_filter() {
        run_kernel_child(true, ptrace_and_tty_injection_are_eperm);
    }

    #[test]
    fn kernel_enforces_restricted_network_filter() {
        run_kernel_child(false, restricted_network_policy_is_exact);
    }
}
