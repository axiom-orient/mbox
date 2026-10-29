use super::super::macos_proxy::ProxyRuntime;
use std::io;
use std::os::raw::{c_int, c_long, c_uint, c_ulong, c_void};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicU8, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const SIGINT: c_int = 2;
const SIGQUIT: c_int = 3;
const SIGHUP: c_int = 1;
const SIGTERM: c_int = 15;
const SIGKILL: c_int = 9;
const SIGTTOU: c_int = 22;
const SIG_BLOCK: c_int = 1;
const SIG_SETMASK: c_int = 3;
const WAIT_P_PID: c_int = 1;
const WAIT_WNOHANG: c_int = 1;
const WAIT_WEXITED: c_int = 4;
const WAIT_WNOWAIT: c_int = 0x20;
const STDIN_FD: c_int = 0;
const SIGNAL_INT: u8 = 1;
const SIGNAL_QUIT: u8 = 2;
const SIGNAL_HUP: u8 = 4;
const SIGNAL_TERM: u8 = 8;
const TERM_GRACE: Duration = Duration::from_secs(2);
const KILL_GRACE: Duration = Duration::from_secs(2);

static PENDING_SIGNALS: AtomicU8 = AtomicU8::new(0);

unsafe extern "C" {
    fn signal(signal: c_int, handler: usize) -> usize;
    fn kill(process: c_int, signal: c_int) -> c_int;
    fn isatty(fd: c_int) -> c_int;
    fn tcgetpgrp(fd: c_int) -> c_int;
    fn tcsetpgrp(fd: c_int, group: c_int) -> c_int;
    fn sigemptyset(set: *mut u32) -> c_int;
    fn sigaddset(set: *mut u32, signal: c_int) -> c_int;
    fn sigprocmask(how: c_int, set: *const u32, old_set: *mut u32) -> c_int;
    fn waitid(id_type: c_int, id: c_int, info: *mut SigInfo, options: c_int) -> c_int;
}

#[repr(C)]
struct SigInfo {
    si_signo: c_int,
    si_errno: c_int,
    si_code: c_int,
    si_pid: c_int,
    si_uid: c_uint,
    si_status: c_int,
    si_addr: *mut c_void,
    si_value: SigVal,
    si_band: c_long,
    _padding: [c_ulong; 7],
}

#[repr(C)]
union SigVal {
    sival_int: c_int,
    sival_ptr: *mut c_void,
}

extern "C" fn supervisor_signal_handler(signal: c_int) {
    let bit = match signal {
        SIGINT => SIGNAL_INT,
        SIGQUIT => SIGNAL_QUIT,
        SIGHUP => SIGNAL_HUP,
        SIGTERM => SIGNAL_TERM,
        _ => 0,
    };
    if bit != 0 {
        PENDING_SIGNALS.fetch_or(bit, Ordering::Relaxed);
    }
}

unsafe extern "C" {
    fn getpgrp() -> c_int;
    fn setpgid(pid: c_int, pgid: c_int) -> c_int;
}

pub(in crate::platform) fn establish_process_group_leader() -> io::Result<()> {
    let expected = std::process::id() as c_int;
    if unsafe { getpgrp() } != expected && unsafe { setpgid(0, 0) } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "strict mode could not establish process-group leader custody for pid {expected}: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    let observed = unsafe { getpgrp() };
    if observed != expected {
        return Err(io::Error::other(format!(
            "strict mode process-group custody mismatch: pid {expected}, pgid {observed}"
        )));
    }
    Ok(())
}

pub(in crate::platform) fn run_supervised(
    mut command: Command,
    mut proxy: ProxyRuntime,
) -> io::Result<ExitStatus> {
    let _signals = SignalGuard::install()?;
    // process_group(0) requests an atomic child-side process-group setup from
    // Command::spawn. Unlike pre_exec, it performs no Rust allocation or
    // filesystem access in a multithreaded post-fork child.
    command.process_group(0);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = proxy.shutdown();
            return Err(error);
        }
    };
    let pid = child.id() as c_int;

    let foreground = match ForegroundGuard::handoff(pid) {
        Ok(guard) => guard,
        Err(error) => {
            let _ = terminate_group(&mut child, pid, SIGKILL);
            let _ = proxy.shutdown();
            return Err(error);
        }
    };

    let mut target_status = None;
    let mut proxy_failure = None;
    loop {
        match child_exit_observed(pid) {
            Ok(true) => {
                // WNOWAIT leaves the leader waitable while its process group
                // is cleaned. Only then reap it, preventing PGID reuse from
                // targeting an unrelated process group.
                cleanup_group(pid);
                target_status = Some(child.wait()?);
                break;
            }
            Ok(false) => {}
            Err(error) => {
                let _ = terminate_group(&mut child, pid, SIGKILL);
                proxy_failure = Some(format!("target wait failed: {error}"));
                break;
            }
        }
        if let Some(error) = proxy.fatal_error() {
            let _ = terminate_group(&mut child, pid, SIGTERM);
            proxy_failure = Some(error);
            break;
        }
        if let Some(signal) = pending_signal() {
            match terminate_group(&mut child, pid, signal) {
                Ok(status) => target_status = Some(status),
                Err(error) => {
                    let _ = terminate_group(&mut child, pid, SIGKILL);
                    proxy_failure = Some(format!("target signal cleanup failed: {error}"));
                }
            }
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let proxy_result = proxy.shutdown();
    drop(foreground);

    if let Some(error) = proxy_failure {
        if let Err(shutdown_error) = proxy_result {
            return Err(io::Error::other(format!(
                "exact network proxy failed: {error}; cleanup failed: {shutdown_error}"
            )));
        }
        return Err(io::Error::other(format!(
            "exact network proxy failed: {error}"
        )));
    }
    proxy_result?;
    target_status.ok_or_else(|| io::Error::other("supervised target ended without a status"))
}

fn pending_signal() -> Option<c_int> {
    let flags = PENDING_SIGNALS.swap(0, Ordering::Relaxed);
    if flags & SIGNAL_INT != 0 {
        Some(SIGINT)
    } else if flags & SIGNAL_QUIT != 0 {
        Some(SIGQUIT)
    } else if flags & SIGNAL_HUP != 0 {
        Some(SIGHUP)
    } else if flags & SIGNAL_TERM != 0 {
        Some(SIGTERM)
    } else {
        None
    }
}

fn terminate_group(child: &mut Child, pid: c_int, signal: c_int) -> io::Result<ExitStatus> {
    if unsafe { kill(-pid, signal) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(3) {
            let _ = child.kill();
        }
    }

    let deadline = Instant::now() + TERM_GRACE;
    loop {
        if child_exit_observed(pid)? {
            cleanup_group(pid);
            return child.wait();
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let _ = unsafe { kill(-pid, SIGKILL) };
    let kill_deadline = Instant::now() + KILL_GRACE;
    loop {
        if child_exit_observed(pid)? {
            cleanup_group(pid);
            return child.wait();
        }
        if Instant::now() >= kill_deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "target did not exit after bounded SIGKILL observation",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn child_exit_observed(pid: c_int) -> io::Result<bool> {
    let mut info = SigInfo {
        si_signo: 0,
        si_errno: 0,
        si_code: 0,
        si_pid: 0,
        si_uid: 0,
        si_status: 0,
        si_addr: std::ptr::null_mut(),
        si_value: SigVal { sival_int: 0 },
        si_band: 0,
        _padding: [0; 7],
    };
    let result = unsafe {
        waitid(
            WAIT_P_PID,
            pid,
            &mut info,
            WAIT_WEXITED | WAIT_WNOHANG | WAIT_WNOWAIT,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info.si_pid == pid)
}

fn cleanup_group(pid: c_int) {
    let _ = unsafe { kill(-pid, SIGTERM) };
    thread::sleep(Duration::from_millis(50));
    let _ = unsafe { kill(-pid, SIGKILL) };
}

struct SignalGuard {
    previous: [(c_int, usize); 4],
    previous_mask: u32,
    mask: u32,
}

impl SignalGuard {
    fn install() -> io::Result<Self> {
        let signals = [SIGINT, SIGQUIT, SIGHUP, SIGTERM];
        let mask = signal_mask(&signals)?;
        let mut previous_mask = 0;
        if unsafe { sigprocmask(SIG_BLOCK, &mask, &mut previous_mask) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // Clear before installing handlers. A signal delivered immediately
        // after this point is recorded by the new handler and cannot be
        // erased by a post-install reset.
        PENDING_SIGNALS.store(0, Ordering::Relaxed);
        let mut previous = [(0, 0); 4];
        for (index, signal_number) in signals.into_iter().enumerate() {
            let old = unsafe {
                signal(
                    signal_number,
                    supervisor_signal_handler as *const () as usize,
                )
            };
            if old == usize::MAX {
                let error = io::Error::last_os_error();
                for (restored_signal, restored_handler) in previous.into_iter().take(index) {
                    unsafe {
                        signal(restored_signal, restored_handler);
                    }
                }
                let _ = unsafe { sigprocmask(SIG_SETMASK, &previous_mask, std::ptr::null_mut()) };
                return Err(error);
            }
            previous[index] = (signal_number, old);
        }
        if unsafe { sigprocmask(SIG_SETMASK, &previous_mask, std::ptr::null_mut()) } != 0 {
            let error = io::Error::last_os_error();
            for (signal_number, handler) in previous {
                unsafe {
                    signal(signal_number, handler);
                }
            }
            return Err(error);
        }
        Ok(Self {
            previous,
            previous_mask,
            mask,
        })
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        let _ = unsafe { sigprocmask(SIG_BLOCK, &self.mask, std::ptr::null_mut()) };
        for (signal_number, handler) in self.previous {
            unsafe {
                signal(signal_number, handler);
            }
        }
        PENDING_SIGNALS.store(0, Ordering::Relaxed);
        let _ = unsafe { sigprocmask(SIG_SETMASK, &self.previous_mask, std::ptr::null_mut()) };
    }
}

fn signal_mask(signals: &[c_int]) -> io::Result<u32> {
    let mut mask = 0;
    if unsafe { sigemptyset(&mut mask) } != 0 {
        return Err(io::Error::last_os_error());
    }
    for signal_number in signals {
        if unsafe { sigaddset(&mut mask, *signal_number) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(mask)
}

struct ForegroundGuard {
    original_group: Option<c_int>,
}

impl ForegroundGuard {
    fn handoff(target_group: c_int) -> io::Result<Self> {
        if unsafe { isatty(STDIN_FD) } != 1 {
            return Ok(Self {
                original_group: None,
            });
        }
        let original_group = unsafe { tcgetpgrp(STDIN_FD) };
        if original_group < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { tcsetpgrp(STDIN_FD, target_group) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            original_group: Some(original_group),
        })
    }
}

impl Drop for ForegroundGuard {
    fn drop(&mut self) {
        if let Some(group) = self.original_group {
            // mbox is in the background group while the target owns the tty.
            // Block SIGTTOU around restoration so the cleanup itself cannot
            // stop the supervisor before it returns the terminal.
            let mask = signal_mask(&[SIGTTOU]).ok();
            let mut previous_mask = 0;
            let blocked = if let Some(mask) = mask {
                unsafe { sigprocmask(SIG_BLOCK, &mask, &mut previous_mask) == 0 }
            } else {
                false
            };
            let _ = unsafe { tcsetpgrp(STDIN_FD, group) };
            if blocked {
                let _ = unsafe { sigprocmask(SIG_SETMASK, &previous_mask, std::ptr::null_mut()) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        supervisor_signal_handler, SigInfo, SignalGuard, PENDING_SIGNALS, SIGNAL_TERM, SIGTERM,
    };
    use std::mem::{align_of, size_of};

    #[test]
    fn waitid_siginfo_layout_matches_darwin_arm64_abi() {
        assert_eq!(size_of::<SigInfo>(), 104);
        assert_eq!(align_of::<SigInfo>(), 8);
    }

    #[test]
    fn signal_install_clear_precedes_handler_recording() {
        PENDING_SIGNALS.store(SIGNAL_TERM, std::sync::atomic::Ordering::Relaxed);
        let guard = SignalGuard::install().unwrap();
        assert_eq!(
            PENDING_SIGNALS.load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        supervisor_signal_handler(SIGTERM);
        assert_eq!(
            PENDING_SIGNALS.load(std::sync::atomic::Ordering::Relaxed),
            SIGNAL_TERM
        );
        drop(guard);
    }
}
