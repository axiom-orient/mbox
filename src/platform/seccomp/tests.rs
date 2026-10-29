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

    let tiocsti = unsafe { syscall(SYS_IOCTL as c_long, usize::MAX, TIOCSTI as usize, 0_usize) };
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
    let destination_sendto_blocked =
        destination_sendto == -1 && io::Error::last_os_error().raw_os_error() == Some(EPERM as i32);

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
