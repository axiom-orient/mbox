use super::macos_proxy::ProxyRuntime;
use super::PreparedCommand;
use crate::plan::{AccessKind, AccessRoot, ExecutionPlan, NetworkPolicy};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io;
use std::os::raw::{c_int, c_long, c_uint, c_ulong, c_void};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::FileExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicU8, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const BASH: &str = "/bin/bash";
const RUNNER: &str = r#"exec -a "$1" "$2" "${@:3}""#;
const BASE_POLICY: &str = include_str!("macos_base.sbpl");
const PLATFORM_POLICY: &str = include_str!("macos_platform.sbpl");
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
    fn geteuid() -> u32;
    fn getpgrp() -> c_int;
    fn setpgid(pid: c_int, pgid: c_int) -> c_int;
}

pub fn establish_process_group_leader() -> io::Result<()> {
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

pub fn prepare(plan: &ExecutionPlan) -> io::Result<PreparedCommand> {
    validate_system_executable(Path::new(SANDBOX_EXEC))?;
    if plan.no_child_processes {
        if matches!(plan.network, NetworkPolicy::ExactDomains(_)) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "`--no-child-processes` cannot be combined with macOS `--allow-net`; setup aborted",
            ));
        }
        validate_native_executable(&plan.program)?;
    } else {
        validate_system_executable(Path::new(BASH))?;
    }

    let mut writes = plan.writes.clone();
    if let Some(tmp) = &plan.tmp {
        validate_private_tmp(tmp)?;
        writes.push(AccessRoot {
            path: tmp.clone(),
            kind: AccessKind::Directory,
        });
    }

    // The exact proxy creates listener/worker sockets after this point. Close
    // ambient descriptors first so no pre-existing descriptor can be
    // inherited by those threads or the target. Newly-created sockets carry
    // CLOEXEC in macos_proxy; no filesystem/allocator work runs after fork.
    if matches!(plan.network, NetworkPolicy::ExactDomains(_)) {
        super::fd::close_inherited(&[])?;
    }
    let mut proxy = match &plan.network {
        NetworkPolicy::ExactDomains(domains) => Some(ProxyRuntime::start(domains)?),
        _ => None,
    };
    let proxy_port = proxy.as_ref().map(ProxyRuntime::port);
    let policy = compile_policy(
        &plan.reads,
        &writes,
        &plan.deny_writes,
        &plan.program,
        &plan.network,
        proxy_port,
        plan.no_child_processes,
    );
    let mut command = Command::new(SANDBOX_EXEC);
    command.env_clear();
    for (name, value) in &plan.environment {
        command.env(name, value);
    }
    if let Some(port) = proxy_port {
        let proxy = format!("http://127.0.0.1:{port}");
        for name in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            command.env(name, &proxy);
        }
        for name in ["ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"] {
            command.env_remove(name);
        }
    }
    if let Some(tmp) = &plan.tmp {
        command.env("TMPDIR", tmp);
    }
    command.env("PWD", &plan.cwd);
    command.current_dir(&plan.cwd);

    command.arg("-p").arg(policy);
    add_definitions(&mut command, "READ", &plan.reads);
    add_definitions(&mut command, "WRITE", &writes);
    add_definitions(&mut command, "DENY_WRITE", &plan.deny_writes);
    command.arg(definition("EXECUTABLE", &plan.program));
    command.arg("--");
    if plan.no_child_processes {
        // Strict mode intentionally does not enter the Bash positional
        // runner. The canonical executable becomes argv[0]; preserving a
        // caller spelling here would require a second launcher or exec.
        command.arg(&plan.program).args(&plan.arguments);
    } else {
        command
            .arg(BASH)
            .arg("--noprofile")
            .arg("--norc")
            .arg("-c")
            .arg(RUNNER)
            .arg("mbox-runner")
            .arg(&plan.argv0)
            .arg(&plan.program)
            .args(&plan.arguments);
    }

    let prepared = PreparedCommand::new(command);
    Ok(match proxy.take() {
        Some(proxy) => prepared.with_supervisor(proxy),
        None if plan.no_child_processes => prepared.with_process_group_leader(),
        None => prepared,
    })
}

pub fn run_supervised(mut command: Command, mut proxy: ProxyRuntime) -> io::Result<ExitStatus> {
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

fn compile_policy(
    reads: &[AccessRoot],
    writes: &[AccessRoot],
    deny_writes: &[AccessRoot],
    executable: &Path,
    network: &NetworkPolicy,
    proxy_port: Option<u16>,
    no_child_processes: bool,
) -> String {
    let mut policy = String::new();
    policy.push_str(BASE_POLICY);
    policy.push('\n');
    policy.push_str(PLATFORM_POLICY);
    policy.push('\n');

    for (index, root) in reads.iter().enumerate() {
        append_access(
            &mut policy,
            "file-read* file-test-existence file-map-executable",
            "READ",
            index,
            root.kind,
        );
    }
    for (index, root) in writes.iter().enumerate() {
        append_access(
            &mut policy,
            "file-read* file-test-existence file-write*",
            "WRITE",
            index,
            root.kind,
        );
    }

    if matches!(network, NetworkPolicy::Native) {
        policy.push_str(
            r#"
; Explicit full native network access.
(allow network-outbound)
(allow network-inbound)
(allow network-bind)
(allow mach-lookup
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.networkd")
  (global-name "com.apple.ocspd")
  (global-name "com.apple.trustd")
  (global-name "com.apple.trustd.agent")
  (global-name "com.apple.SystemConfiguration.DNSConfiguration")
  (global-name "com.apple.SystemConfiguration.configd"))
"#,
        );
    } else if let Some(port) = proxy_port {
        policy.push_str(&format!(
            r#"
; Exact HTTPS egress is available only through the parent-owned loopback proxy.
(allow network-outbound (remote ip "localhost:{port}"))
"#
        ));
    }

    // A writable parent is not permission to replace or unlink the command
    // image. Reassert the exact canonical executable after all dynamic grants.
    debug_assert!(executable.is_absolute());
    policy.push_str(
        r#"
(allow file-read* file-test-existence file-map-executable
  (literal (param "EXECUTABLE")))
(deny file-write* (literal (param "EXECUTABLE")))
"#,
    );

    for (index, root) in deny_writes.iter().enumerate() {
        let key = format!("DENY_WRITE_{index}");
        let selector = match root.kind {
            AccessKind::File => format!(r#"(literal (param "{key}"))"#),
            AccessKind::Directory => format!(r#"(subpath (param "{key}"))"#),
        };
        policy.push_str(&format!(
            "\n; Final write subtraction.\n(deny file-write* {selector})\n"
        ));
    }

    // A shared terminal is an explicit I/O channel, not permission to inject
    // bytes into the host shell's input queue. Keep normal tty ioctls but
    // subtract Darwin TIOCSTI (_IOW('t', 114, char) = 0x80017472) last.
    policy.push_str(
        r#"
(deny file-ioctl (ioctl-command #x80017472))
; Hardlink creation can otherwise create a writable alias for a protected
; inode after planning. Callers may still write ordinary sibling files.
(deny file-link)
"#,
    );

    if no_child_processes {
        // These rules are deliberately final. The base profile keeps normal
        // mode compatible with shell/toolchain subprocesses, while strict
        // mode subtracts every fork and every exec of another image. The
        // exact EXECUTABLE remains allowed for the initial launch and a
        // self-reexec of that same image.
        policy.push_str(
            r#"
; Strict exact-execution mode: no target-created children or other-image exec.
(deny process-fork)
(deny process-exec)
(allow process-exec (literal (param "EXECUTABLE")))
"#,
        );
    }

    policy
}

fn append_access(
    policy: &mut String,
    operations: &str,
    prefix: &str,
    index: usize,
    kind: AccessKind,
) {
    let key = format!("{prefix}_{index}");
    policy.push_str(&format!(
        "\n(allow file-read-metadata file-test-existence (path-ancestors (param \"{key}\")))\n"
    ));
    let selector = match kind {
        AccessKind::File => format!(r#"(literal (param "{key}"))"#),
        AccessKind::Directory => format!(r#"(subpath (param "{key}"))"#),
    };
    policy.push_str(&format!("\n(allow {operations} {selector})\n"));
}

fn add_definitions(command: &mut Command, prefix: &str, roots: &[AccessRoot]) {
    for (index, root) in roots.iter().enumerate() {
        let key = format!("{prefix}_{index}");
        command.arg(definition(&key, &root.path));
    }
}

fn definition(key: &str, path: &Path) -> OsString {
    let mut bytes = format!("-D{key}=").into_bytes();
    bytes.extend_from_slice(path.as_os_str().as_bytes());
    OsString::from_vec(bytes)
}

fn validate_private_tmp(path: &Path) -> io::Result<()> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "temporary directory `{}` is not accessible: {error}",
                path.display()
            ),
        )
    })?;
    let metadata = fs::metadata(&canonical)?;
    let effective_uid = unsafe { geteuid() };
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "temporary path `{}` is not a directory",
                canonical.display()
            ),
        ));
    }
    if metadata.uid() != effective_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "temporary directory `{}` is not owned by the invoking user",
                canonical.display()
            ),
        ));
    }
    if metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "temporary directory `{}` must have mode 0700",
                canonical.display()
            ),
        ));
    }
    Ok(())
}

fn validate_system_executable(path: &Path) -> io::Result<()> {
    let canonical = fs::canonicalize(path)?;
    if canonical != path {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("system launcher `{}` must not be a symlink", path.display()),
        ));
    }
    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode();
    if !metadata.is_file() || metadata.uid() != 0 || mode & 0o111 == 0 || mode & 0o6022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "system launcher `{}` is not a trusted root-owned executable",
                path.display()
            ),
        ));
    }

    let mut current = path.parent();
    while let Some(parent) = current {
        let metadata = fs::metadata(parent)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "system launcher parent `{}` must be a root-owned directory not writable by group or others",
                    parent.display()
                ),
            ));
        }
        current = parent.parent();
    }

    Ok(())
}

fn validate_native_executable(path: &Path) -> io::Result<()> {
    let link_metadata = fs::symlink_metadata(path)?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "strict target `{}` must be a regular native Mach-O executable",
                path.display()
            ),
        ));
    }
    if link_metadata.permissions().mode() & 0o111 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("strict target `{}` is not executable", path.display()),
        ));
    }

    let file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let (slice_offset, slice_size) = select_native_slice(&file, file_len).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "strict target `{}` is not a structurally valid native Mach-O: {error}",
                path.display()
            ),
        )
    })?;
    validate_thin_slice(&file, file_len, slice_offset, slice_size)
}

const MH_EXECUTE: u32 = 0x2;
const LC_UNIXTHREAD: u32 = 0x5;
const LC_MAIN: u32 = 0x8000_0028;
#[cfg(target_arch = "x86_64")]
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const FAT_ARCH_SIZE_32: u64 = 20;
const FAT_ARCH_SIZE_64: u64 = 32;
const MAX_FAT_ARCHES: u32 = 256;
const MAX_LOAD_COMMANDS: u32 = 4096;
const MAX_LOAD_COMMAND_BYTES: u64 = 64 * 1024 * 1024;
const HOST_BYTE_ORDER: ByteOrder = ByteOrder::Little;

#[cfg(target_arch = "aarch64")]
const HOST_CPU_TYPE: u32 = CPU_TYPE_ARM64;
#[cfg(target_arch = "x86_64")]
const HOST_CPU_TYPE: u32 = CPU_TYPE_X86_64;

#[cfg(target_arch = "aarch64")]
const HOST_THREAD_STATE_FLAVOR: u32 = 6; // ARM_THREAD_STATE64
#[cfg(target_arch = "aarch64")]
const HOST_THREAD_STATE_COUNT: u32 = 68; // ARM_THREAD_STATE64_COUNT
#[cfg(target_arch = "x86_64")]
const HOST_THREAD_STATE_FLAVOR: u32 = 4; // x86_THREAD_STATE64
#[cfg(target_arch = "x86_64")]
const HOST_THREAD_STATE_COUNT: u32 = 42; // x86_THREAD_STATE64_COUNT

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ByteOrder {
    Big,
    Little,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MachMagic {
    Thin32(ByteOrder),
    Thin64(ByteOrder),
    Fat32(ByteOrder),
    Fat64(ByteOrder),
}

#[derive(Clone, Copy, Debug)]
struct FatSlice {
    offset: u64,
    size: u64,
}

fn select_native_slice(file: &File, file_len: u64) -> io::Result<(u64, u64)> {
    let magic_bytes = read_bytes(file, 0, 4)?;
    let magic = [
        magic_bytes[0],
        magic_bytes[1],
        magic_bytes[2],
        magic_bytes[3],
    ];
    let Some(kind) = parse_mach_magic(magic) else {
        return invalid_image("unknown Mach-O magic");
    };
    match kind {
        MachMagic::Thin32(_) | MachMagic::Thin64(_) => Ok((0, file_len)),
        MachMagic::Fat32(order) => select_fat_slice(file, file_len, order, false),
        MachMagic::Fat64(order) => select_fat_slice(file, file_len, order, true),
    }
}

fn select_fat_slice(
    file: &File,
    file_len: u64,
    order: ByteOrder,
    is_fat64: bool,
) -> io::Result<(u64, u64)> {
    const FAT_HEADER_SIZE: u64 = 8;
    let count = read_u32(file, 4, order)?;
    if count == 0 || count > MAX_FAT_ARCHES {
        return invalid_image("fat architecture count is zero or exceeds the bounded limit");
    }
    let entry_size = if is_fat64 {
        FAT_ARCH_SIZE_64
    } else {
        FAT_ARCH_SIZE_32
    };
    let table_size = u64::from(count)
        .checked_mul(entry_size)
        .ok_or_else(|| invalid_error("fat architecture table size overflow"))?;
    let table_end = FAT_HEADER_SIZE
        .checked_add(table_size)
        .ok_or_else(|| invalid_error("fat architecture table end overflow"))?;
    if table_end > file_len {
        return invalid_image("fat architecture table is truncated");
    }

    let mut slices: Vec<FatSlice> = Vec::with_capacity(count as usize);
    let mut selected = None;
    for index in 0..count {
        let entry_offset = FAT_HEADER_SIZE + u64::from(index) * entry_size;
        let bytes = read_bytes(file, entry_offset, entry_size as usize)?;
        let cputype = read_u32_from(&bytes, 0, order)?;
        let slice_offset = if is_fat64 {
            read_u64_from(&bytes, 8, order)?
        } else {
            u64::from(read_u32_from(&bytes, 8, order)?)
        };
        let slice_size = if is_fat64 {
            read_u64_from(&bytes, 16, order)?
        } else {
            u64::from(read_u32_from(&bytes, 12, order)?)
        };
        let align = if is_fat64 {
            read_u32_from(&bytes, 24, order)?
        } else {
            read_u32_from(&bytes, 16, order)?
        };
        if is_fat64 && read_u32_from(&bytes, 28, order)? != 0 {
            return invalid_image("fat64 architecture reserved field is nonzero");
        }
        if align >= 64 {
            return invalid_image("fat slice alignment exponent is out of range");
        }
        let alignment = 1_u64 << align;
        if slice_offset % alignment != 0 {
            return invalid_image("fat slice offset violates its alignment");
        }
        if slice_size == 0 {
            return invalid_image("fat slice has zero size");
        }
        if slice_offset < table_end {
            return invalid_image("fat slice overlaps the architecture table");
        }
        let slice_end = slice_offset
            .checked_add(slice_size)
            .ok_or_else(|| invalid_error("fat slice offset plus size overflows"))?;
        if slice_end > file_len {
            return invalid_image("fat slice is outside the file");
        }
        for previous in &slices {
            let previous_end = previous
                .offset
                .checked_add(previous.size)
                .ok_or_else(|| invalid_error("fat slice range overflow"))?;
            if slice_offset < previous_end && previous.offset < slice_end {
                return invalid_image("fat slices overlap");
            }
        }
        let slice = FatSlice {
            offset: slice_offset,
            size: slice_size,
        };
        if cputype == HOST_CPU_TYPE && selected.is_none() {
            selected = Some((slice_offset, slice_size));
        }
        slices.push(slice);
    }

    let Some((slice_offset, slice_size)) = selected else {
        return invalid_image("fat file has no executable slice for the current host CPU");
    };
    // The loop above checks all table/range invariants. Validate only the
    // kernel-selected host CPU slice; other architecture slices are not
    // candidates for this invocation.
    Ok((slice_offset, slice_size))
}

fn validate_thin_slice(
    file: &File,
    file_len: u64,
    slice_offset: u64,
    slice_size: u64,
) -> io::Result<()> {
    let slice_end = slice_offset
        .checked_add(slice_size)
        .ok_or_else(|| invalid_error("Mach-O slice range overflow"))?;
    if slice_end > file_len {
        return invalid_image("Mach-O slice is outside the file");
    }
    let magic_bytes = read_bytes(file, slice_offset, 4)?;
    let magic = [
        magic_bytes[0],
        magic_bytes[1],
        magic_bytes[2],
        magic_bytes[3],
    ];
    let Some(kind) = parse_mach_magic(magic) else {
        return invalid_image("selected slice is not a thin Mach-O image");
    };
    let (order, is64) = match kind {
        MachMagic::Thin32(order) => (order, false),
        MachMagic::Thin64(order) => (order, true),
        MachMagic::Fat32(_) | MachMagic::Fat64(_) => {
            return invalid_image("selected slice is a nested fat Mach-O image")
        }
    };
    if order != HOST_BYTE_ORDER {
        return invalid_image("big-endian Mach-O is not executable on the current host");
    }
    let header_size = if is64 { 32_u64 } else { 28_u64 };
    if slice_size < header_size {
        return invalid_image("Mach-O header is truncated");
    }
    if !is64 {
        return invalid_image("32-bit Mach-O is not executable for the current 64-bit host");
    }
    let header = read_bytes(file, slice_offset, header_size as usize)?;
    let cputype = read_u32_from(&header, 4, order)?;
    if cputype != HOST_CPU_TYPE {
        return invalid_image("Mach-O CPU type does not match the current host");
    }
    let filetype = read_u32_from(&header, 12, order)?;
    if filetype != MH_EXECUTE {
        return invalid_image("Mach-O file type is not MH_EXECUTE");
    }
    let ncmds = read_u32_from(&header, 16, order)?;
    let sizeofcmds = u64::from(read_u32_from(&header, 20, order)?);
    if ncmds == 0 || ncmds > MAX_LOAD_COMMANDS {
        return invalid_image("Mach-O load-command count is zero or exceeds the bounded limit");
    }
    if sizeofcmds == 0 || sizeofcmds > MAX_LOAD_COMMAND_BYTES {
        return invalid_image(
            "Mach-O load-command byte count is zero or exceeds the bounded limit",
        );
    }
    let commands_start = slice_offset
        .checked_add(header_size)
        .ok_or_else(|| invalid_error("Mach-O load-command offset overflow"))?;
    let commands_end = commands_start
        .checked_add(sizeofcmds)
        .ok_or_else(|| invalid_error("Mach-O load-command range overflow"))?;
    if commands_end > slice_end {
        return invalid_image("Mach-O load-command region is outside the selected slice");
    }

    let mut cursor = commands_start;
    let mut has_entry = false;
    for _ in 0..ncmds {
        if cursor.checked_add(8).is_none_or(|end| end > commands_end) {
            return invalid_image("Mach-O load-command header is truncated");
        }
        let command = read_bytes(file, cursor, 8)?;
        let cmd = read_u32_from(&command, 0, order)?;
        let cmdsize = u64::from(read_u32_from(&command, 4, order)?);
        let command_alignment = if is64 { 8 } else { 4 };
        if cmdsize < 8 || cmdsize % command_alignment != 0 {
            return invalid_image("Mach-O load-command size is too small or unaligned");
        }
        let next = cursor
            .checked_add(cmdsize)
            .ok_or_else(|| invalid_error("Mach-O load-command range overflow"))?;
        if next > commands_end {
            return invalid_image("Mach-O load command exceeds the bounded command region");
        }
        if cmd == LC_MAIN {
            if cmdsize < 24 {
                return invalid_image("LC_MAIN command is truncated");
            }
            let entry_offset = cursor
                .checked_add(8)
                .ok_or_else(|| invalid_error("LC_MAIN entry offset overflow"))?;
            let entry = read_u64(file, entry_offset, order)?;
            if entry >= slice_size {
                return invalid_image("LC_MAIN entry offset is outside the selected slice");
            }
            has_entry = true;
        } else if cmd == LC_UNIXTHREAD {
            validate_unixthread(file, cursor, cmdsize, order)?;
            has_entry = true;
        }
        cursor = next;
    }
    if cursor != commands_end {
        return invalid_image("Mach-O load-command progression does not consume sizeofcmds");
    }
    if !has_entry {
        return invalid_image("Mach-O has no LC_MAIN or valid LC_UNIXTHREAD entry command");
    }
    Ok(())
}

fn validate_unixthread(
    file: &File,
    command_offset: u64,
    command_size: u64,
    order: ByteOrder,
) -> io::Result<()> {
    if command_size < 16 {
        return invalid_image("LC_UNIXTHREAD command is truncated");
    }
    let state_header_offset = command_offset
        .checked_add(8)
        .ok_or_else(|| invalid_error("LC_UNIXTHREAD state header offset overflow"))?;
    let header = read_bytes(file, state_header_offset, 8)?;
    let flavor = read_u32_from(&header, 0, order)?;
    let count = read_u32_from(&header, 4, order)?;
    if flavor != HOST_THREAD_STATE_FLAVOR || count != HOST_THREAD_STATE_COUNT {
        return invalid_image("LC_UNIXTHREAD does not contain the current host thread state");
    }
    let state_bytes = u64::from(count)
        .checked_mul(4)
        .ok_or_else(|| invalid_error("LC_UNIXTHREAD state size overflow"))?;
    let required = 16_u64
        .checked_add(state_bytes)
        .ok_or_else(|| invalid_error("LC_UNIXTHREAD command size overflow"))?;
    if required > command_size {
        return invalid_image("LC_UNIXTHREAD thread state exceeds command size");
    }
    Ok(())
}

fn read_bytes(file: &File, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0_u8; len];
    let mut read = 0_usize;
    while read < len {
        let position = offset
            .checked_add(read as u64)
            .ok_or_else(|| invalid_error("Mach-O positioned-read offset overflow"))?;
        let count = file.read_at(&mut bytes[read..], position)?;
        if count == 0 {
            return invalid_image("Mach-O positioned read reached EOF");
        }
        read += count;
    }
    Ok(bytes)
}

fn read_u32(file: &File, offset: u64, order: ByteOrder) -> io::Result<u32> {
    let bytes = read_bytes(file, offset, 4)?;
    read_u32_from(&bytes, 0, order)
}

fn read_u64(file: &File, offset: u64, order: ByteOrder) -> io::Result<u64> {
    let bytes = read_bytes(file, offset, 8)?;
    read_u64_from(&bytes, 0, order)
}

fn read_u32_from(bytes: &[u8], offset: usize, order: ByteOrder) -> io::Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| invalid_error("Mach-O byte-slice offset overflow"))?;
    let Some(value) = bytes.get(offset..end) else {
        return invalid_image("Mach-O byte-slice read is outside the bounded buffer");
    };
    let array = [value[0], value[1], value[2], value[3]];
    Ok(match order {
        ByteOrder::Big => u32::from_be_bytes(array),
        ByteOrder::Little => u32::from_le_bytes(array),
    })
}

fn read_u64_from(bytes: &[u8], offset: usize, order: ByteOrder) -> io::Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| invalid_error("Mach-O byte-slice offset overflow"))?;
    let Some(value) = bytes.get(offset..end) else {
        return invalid_image("Mach-O byte-slice read is outside the bounded buffer");
    };
    let array = [
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ];
    Ok(match order {
        ByteOrder::Big => u64::from_be_bytes(array),
        ByteOrder::Little => u64::from_le_bytes(array),
    })
}

fn invalid_image<T>(message: &str) -> io::Result<T> {
    Err(invalid_error(message))
}

fn invalid_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn parse_mach_magic(magic: [u8; 4]) -> Option<MachMagic> {
    Some(match magic {
        [0xfe, 0xed, 0xfa, 0xce] => MachMagic::Thin32(ByteOrder::Big),
        [0xce, 0xfa, 0xed, 0xfe] => MachMagic::Thin32(ByteOrder::Little),
        [0xfe, 0xed, 0xfa, 0xcf] => MachMagic::Thin64(ByteOrder::Big),
        [0xcf, 0xfa, 0xed, 0xfe] => MachMagic::Thin64(ByteOrder::Little),
        // Apple SDK mach_header_64/fat_header documents the on-disk fat
        // header and architecture table as big-endian. The CIGAM byte
        // sequences are host-read swap constants, not alternate on-disk
        // encodings accepted by this native strict preflight.
        [0xca, 0xfe, 0xba, 0xbe] => MachMagic::Fat32(ByteOrder::Big),
        [0xca, 0xfe, 0xba, 0xbf] => MachMagic::Fat64(ByteOrder::Big),
        _ => return None,
    })
}

#[cfg(test)]
fn is_macho_magic(magic: [u8; 4]) -> bool {
    parse_mach_magic(magic).is_some()
}

#[cfg(test)]
mod tests {
    use super::{
        compile_policy, definition, is_macho_magic, supervisor_signal_handler,
        validate_native_executable, ByteOrder, SigInfo, SignalGuard, HOST_CPU_TYPE, LC_MAIN,
        MH_EXECUTE, PENDING_SIGNALS, SIGNAL_TERM, SIGTERM,
    };
    use crate::plan::{AccessKind, AccessRoot, ExecutionPlan, NetworkPolicy};
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::mem::{align_of, size_of};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static IMAGE_TEST_ID: AtomicUsize = AtomicUsize::new(0);

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32, order: ByteOrder) {
        let encoded = match order {
            ByteOrder::Big => value.to_be_bytes(),
            ByteOrder::Little => value.to_le_bytes(),
        };
        bytes[offset..offset + 4].copy_from_slice(&encoded);
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64, order: ByteOrder) {
        let encoded = match order {
            ByteOrder::Big => value.to_be_bytes(),
            ByteOrder::Little => value.to_le_bytes(),
        };
        bytes[offset..offset + 8].copy_from_slice(&encoded);
    }

    fn thin_image(
        order: ByteOrder,
        cpu: u32,
        filetype: u32,
        commands: &[u8],
        ncmds: u32,
        sizeofcmds: u32,
    ) -> Vec<u8> {
        let mut image = vec![0_u8; 32 + commands.len()];
        let magic = match order {
            ByteOrder::Big => [0xfe, 0xed, 0xfa, 0xcf],
            ByteOrder::Little => [0xcf, 0xfa, 0xed, 0xfe],
        };
        image[..4].copy_from_slice(&magic);
        put_u32(&mut image, 4, cpu, order);
        put_u32(&mut image, 8, 0, order);
        put_u32(&mut image, 12, filetype, order);
        put_u32(&mut image, 16, ncmds, order);
        put_u32(&mut image, 20, sizeofcmds, order);
        put_u32(&mut image, 24, 0, order);
        put_u32(&mut image, 28, 0, order);
        image[32..].copy_from_slice(commands);
        image
    }

    fn valid_thin_image() -> Vec<u8> {
        let mut main = vec![0_u8; 24];
        put_u32(&mut main, 0, LC_MAIN, ByteOrder::Little);
        put_u32(&mut main, 4, 24, ByteOrder::Little);
        put_u64(&mut main, 8, 32, ByteOrder::Little);
        put_u64(&mut main, 16, 0, ByteOrder::Little);
        thin_image(
            ByteOrder::Little,
            HOST_CPU_TYPE,
            MH_EXECUTE,
            &main,
            1,
            main.len() as u32,
        )
    }

    fn image_path(label: &str, image: &[u8]) -> PathBuf {
        let id = IMAGE_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "mbox-native-image-{label}-{}-{id}",
            std::process::id()
        ));
        fs::write(&path, image).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    fn assert_invalid_image(label: &str, image: &[u8]) {
        let path = image_path(label, image);
        let result = validate_native_executable(&path);
        fs::remove_file(&path).unwrap();
        assert!(result.is_err(), "{label} unexpectedly passed preflight");
    }

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

    #[test]
    fn policy_distinguishes_files_from_directories() {
        let reads = vec![
            AccessRoot {
                path: PathBuf::from("/a/file"),
                kind: AccessKind::File,
            },
            AccessRoot {
                path: PathBuf::from("/a/dir"),
                kind: AccessKind::Directory,
            },
        ];
        let policy = compile_policy(
            &reads,
            &[],
            &[],
            Path::new("/a/program"),
            &NetworkPolicy::Denied,
            None,
            false,
        );
        assert!(policy.contains(r#"(literal (param "READ_0"))"#));
        assert!(policy.contains(r#"(subpath (param "READ_1"))"#));
        assert!(policy.contains(
            r#"(allow file-read-metadata file-test-existence (path-ancestors (param "READ_0")))"#
        ));
        assert!(!policy.contains("(allow network-outbound)"));
    }

    #[test]
    fn dynamic_roots_allow_only_ancestor_metadata_for_canonicalization() {
        let policy = compile_policy(
            &[AccessRoot {
                path: PathBuf::from("/external/nested/file"),
                kind: AccessKind::File,
            }],
            &[AccessRoot {
                path: PathBuf::from("/external/output"),
                kind: AccessKind::Directory,
            }],
            &[],
            Path::new("/a/program"),
            &NetworkPolicy::Denied,
            None,
            false,
        );

        for key in ["READ_0", "WRITE_0"] {
            assert!(policy.contains(&format!(
                "(allow file-read-metadata file-test-existence (path-ancestors (param \"{key}\")))"
            )));
        }
        assert!(!policy.contains("(allow file-read-data (path-ancestors"));
    }

    #[test]
    fn policy_does_not_grant_ambient_user_filesystem_access() {
        let policy = compile_policy(
            &[],
            &[],
            &[],
            Path::new("/a/program"),
            &NetworkPolicy::Denied,
            None,
            false,
        );
        assert!(policy.contains(
            r#"(allow file-read-data file-read-metadata file-test-existence (literal "/"))"#
        ));
        assert!(!policy.contains(r#"(subpath "/")"#));
        for forbidden in [
            r#"(subpath "/Applications")"#,
            r#"(subpath "/opt/homebrew")"#,
            r#"(subpath "/usr/local")"#,
            r#"(subpath "/usr")"#,
            r#"com.apple.app-sandbox.read"#,
            r#"com.apple.app-sandbox.read-write"#,
        ] {
            assert!(
                !policy.contains(forbidden),
                "ambient macOS authority returned: {forbidden}"
            );
        }
    }

    #[test]
    fn policy_subtracts_executable_write_after_dynamic_write_grants() {
        let executable = Path::new("/workspace/tool");
        let policy = compile_policy(
            &[],
            &[AccessRoot {
                path: PathBuf::from("/workspace"),
                kind: AccessKind::Directory,
            }],
            &[],
            executable,
            &NetworkPolicy::Denied,
            None,
            false,
        );
        let write_grant = policy
            .rfind("(allow file-read* file-test-existence file-write*")
            .unwrap();
        let executable_deny = policy
            .rfind(r#"(deny file-write* (literal (param "EXECUTABLE")))"#)
            .unwrap();
        assert!(executable_deny > write_grant);
    }

    #[test]
    fn policy_subtracts_terminal_input_injection_after_tty_grants() {
        let policy = compile_policy(
            &[],
            &[],
            &[],
            Path::new("/a/program"),
            &NetworkPolicy::Denied,
            None,
            false,
        );
        let tty_grant = policy.find("file-write* file-ioctl").unwrap();
        let tiocsti_deny = policy
            .rfind("(deny file-ioctl (ioctl-command #x80017472))")
            .unwrap();
        assert!(tiocsti_deny > tty_grant);
    }

    #[test]
    fn exact_network_policy_allows_only_parent_loopback_port() {
        let policy = compile_policy(
            &[],
            &[],
            &[],
            Path::new("/a/program"),
            &NetworkPolicy::ExactDomains(vec!["api.openai.com".into()]),
            Some(43127),
            false,
        );
        assert!(policy.contains(r#"(allow network-outbound (remote ip "localhost:43127"))"#));
        assert!(!policy.contains("(allow network-inbound)"));
        assert!(!policy.contains("(allow network-bind)"));
    }

    #[test]
    fn strict_policy_denies_children_and_allows_only_exact_target_exec() {
        let policy = compile_policy(
            &[],
            &[],
            &[],
            Path::new("/workspace/tool"),
            &NetworkPolicy::Denied,
            None,
            true,
        );
        let deny_fork = policy.rfind("(deny process-fork)").unwrap();
        let deny_exec = policy.rfind("(deny process-exec)").unwrap();
        let allow_exec = policy
            .rfind(r#"(allow process-exec (literal (param "EXECUTABLE")))"#)
            .unwrap();
        assert!(deny_fork > policy.rfind("(allow process-fork)").unwrap());
        assert!(deny_exec > policy.rfind("(allow process-exec)").unwrap());
        assert!(allow_exec > deny_exec);
    }

    #[test]
    fn recognizes_native_mach_and_on_disk_big_endian_fat_magic() {
        for magic in [
            [0xfe, 0xed, 0xfa, 0xce],
            [0xce, 0xfa, 0xed, 0xfe],
            [0xfe, 0xed, 0xfa, 0xcf],
            [0xcf, 0xfa, 0xed, 0xfe],
            [0xca, 0xfe, 0xba, 0xbe],
            [0xca, 0xfe, 0xba, 0xbf],
        ] {
            assert!(is_macho_magic(magic));
        }
        for cigam in [[0xbe, 0xba, 0xfe, 0xca], [0xbf, 0xba, 0xfe, 0xca]] {
            assert!(!is_macho_magic(cigam));
        }
        assert!(!is_macho_magic(*b"#! /"));
        assert!(!is_macho_magic(*b"ELF\0"));
    }

    #[test]
    fn accepts_a_structurally_valid_native_thin_image() {
        let path = image_path("valid-thin", &valid_thin_image());
        validate_native_executable(&path).unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_truncated_headers_and_magic_only_images() {
        assert_invalid_image("magic-only", &[0xcf, 0xfa, 0xed, 0xfe]);
        let mut truncated_64 = vec![0_u8; 31];
        truncated_64[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        assert_invalid_image("truncated-64", &truncated_64);
        let mut truncated_32 = vec![0_u8; 27];
        truncated_32[..4].copy_from_slice(&[0xce, 0xfa, 0xed, 0xfe]);
        assert_invalid_image("truncated-32", &truncated_32);
    }

    #[test]
    fn rejects_wrong_host_cpu_filetype_and_endian() {
        let mut wrong_cpu = valid_thin_image();
        put_u32(&mut wrong_cpu, 4, 7, ByteOrder::Little);
        assert_invalid_image("wrong-cpu", &wrong_cpu);

        let mut wrong_filetype = valid_thin_image();
        put_u32(&mut wrong_filetype, 12, 6, ByteOrder::Little);
        assert_invalid_image("wrong-filetype", &wrong_filetype);

        let big_endian = thin_image(
            ByteOrder::Big,
            HOST_CPU_TYPE,
            MH_EXECUTE,
            &valid_thin_image()[32..],
            1,
            24,
        );
        assert_invalid_image("wrong-endian", &big_endian);

        let mut wrong_width = valid_thin_image();
        wrong_width[..4].copy_from_slice(&[0xce, 0xfa, 0xed, 0xfe]);
        assert_invalid_image("wrong-width", &wrong_width);

        let mut thin32_host_cpu = thin_image(
            ByteOrder::Little,
            HOST_CPU_TYPE,
            MH_EXECUTE,
            &valid_thin_image()[32..],
            1,
            24,
        );
        thin32_host_cpu[..4].copy_from_slice(&[0xce, 0xfa, 0xed, 0xfe]);
        assert_invalid_image("thin32-host-cpu", &thin32_host_cpu);
    }

    #[test]
    fn rejects_load_command_bounds_size_alignment_and_missing_entry() {
        let mut out_of_bounds = valid_thin_image();
        put_u32(&mut out_of_bounds, 20, 32, ByteOrder::Little);
        assert_invalid_image("load-region-bounds", &out_of_bounds);

        let mut short_command = valid_thin_image();
        put_u32(&mut short_command, 36, 4, ByteOrder::Little);
        assert_invalid_image("load-command-short", &short_command);

        let mut unaligned_command = valid_thin_image();
        put_u32(&mut unaligned_command, 36, 10, ByteOrder::Little);
        assert_invalid_image("load-command-unaligned", &unaligned_command);

        let mut unaligned_64_command = valid_thin_image();
        put_u32(&mut unaligned_64_command, 36, 12, ByteOrder::Little);
        assert_invalid_image("load-command-64-alignment", &unaligned_64_command);

        let mut no_entry_command = vec![0_u8; 8];
        put_u32(&mut no_entry_command, 0, 1, ByteOrder::Little);
        put_u32(&mut no_entry_command, 4, 8, ByteOrder::Little);
        let no_entry = thin_image(
            ByteOrder::Little,
            HOST_CPU_TYPE,
            MH_EXECUTE,
            &no_entry_command,
            1,
            8,
        );
        assert_invalid_image("missing-entry", &no_entry);

        let mut short_main = valid_thin_image();
        put_u32(&mut short_main, 36, 16, ByteOrder::Little);
        assert_invalid_image("short-main", &short_main);

        let mut short_thread = vec![0_u8; 16];
        put_u32(&mut short_thread, 0, 5, ByteOrder::Little);
        put_u32(&mut short_thread, 4, 16, ByteOrder::Little);
        put_u32(&mut short_thread, 8, 6, ByteOrder::Little);
        put_u32(&mut short_thread, 12, 68, ByteOrder::Little);
        let thread = thin_image(
            ByteOrder::Little,
            HOST_CPU_TYPE,
            MH_EXECUTE,
            &short_thread,
            1,
            16,
        );
        assert_invalid_image("short-unixthread", &thread);
    }

    fn fat32_image_with_magic_and_order(
        magic: [u8; 4],
        order: ByteOrder,
        entries: &[(u32, u32, u32, u32)],
        file_len: usize,
    ) -> Vec<u8> {
        let table_end = 8 + entries.len() * 20;
        let mut image = vec![0_u8; file_len.max(table_end)];
        image[..4].copy_from_slice(&magic);
        put_u32(&mut image, 4, entries.len() as u32, order);
        for (index, (cpu, offset, size, align)) in entries.iter().enumerate() {
            let at = 8 + index * 20;
            put_u32(&mut image, at, *cpu, order);
            put_u32(&mut image, at + 4, 0, order);
            put_u32(&mut image, at + 8, *offset, order);
            put_u32(&mut image, at + 12, *size, order);
            put_u32(&mut image, at + 16, *align, order);
        }
        image
    }

    fn fat32_image(entries: &[(u32, u32, u32, u32)], file_len: usize) -> Vec<u8> {
        fat32_image_with_magic_and_order(
            [0xca, 0xfe, 0xba, 0xbe],
            ByteOrder::Big,
            entries,
            file_len,
        )
    }

    fn fat64_image_with_magic_and_order(
        magic: [u8; 4],
        order: ByteOrder,
        cpu: u32,
        offset: u64,
        payload: &[u8],
        reserved: u32,
    ) -> Vec<u8> {
        let mut image = vec![0_u8; offset as usize + payload.len()];
        image[..4].copy_from_slice(&magic);
        put_u32(&mut image, 4, 1, order);
        put_u32(&mut image, 8, cpu, order);
        put_u32(&mut image, 12, 0, order);
        put_u64(&mut image, 16, offset, order);
        put_u64(&mut image, 24, payload.len() as u64, order);
        put_u32(&mut image, 32, 12, order);
        put_u32(&mut image, 36, reserved, order);
        image[offset as usize..].copy_from_slice(payload);
        image
    }

    #[test]
    fn rejects_malformed_fat_tables_slices_overlap_and_no_host_slice() {
        assert_invalid_image("fat-truncated", &[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1]);

        let no_host = fat32_image(&[(7, 0x1000, 1, 12)], 0x1001);
        assert_invalid_image("fat-no-host", &no_host);

        let out_of_range = fat32_image(&[(HOST_CPU_TYPE, 0x1000, 0x100, 12)], 0x1001);
        assert_invalid_image("fat-out-of-range", &out_of_range);

        let unaligned = fat32_image(&[(HOST_CPU_TYPE, 0x1001, 1, 12)], 0x1002);
        assert_invalid_image("fat-unaligned", &unaligned);

        let overlap = fat32_image(
            &[(HOST_CPU_TYPE, 0x1000, 0x100, 12), (7, 0x1080, 0x100, 7)],
            0x1180,
        );
        assert_invalid_image("fat-overlap", &overlap);

        let fat64 = fat64_image_with_magic_and_order(
            [0xca, 0xfe, 0xba, 0xbf],
            ByteOrder::Big,
            HOST_CPU_TYPE,
            0x1000,
            &[0],
            1,
        );
        assert_invalid_image("fat64-reserved", &fat64);

        let payload = valid_thin_image();
        let cigam32 = fat32_image_with_magic_and_order(
            [0xbe, 0xba, 0xfe, 0xca],
            ByteOrder::Little,
            &[(HOST_CPU_TYPE, 0x1000, payload.len() as u32, 12)],
            0x1000 + payload.len(),
        );
        assert_invalid_image("fat32-cigam", &cigam32);

        let cigam64 = fat64_image_with_magic_and_order(
            [0xbf, 0xba, 0xfe, 0xca],
            ByteOrder::Little,
            HOST_CPU_TYPE,
            0x1000,
            &payload,
            0,
        );
        assert_invalid_image("fat64-cigam", &cigam64);
    }

    #[test]
    fn accepts_a_structurally_valid_fat_host_slice() {
        let payload = valid_thin_image();
        let offset = 0x1000_u32;
        let mut image = fat32_image(
            &[(HOST_CPU_TYPE, offset, payload.len() as u32, 12)],
            offset as usize + payload.len(),
        );
        image[offset as usize..].copy_from_slice(&payload);
        let path = image_path("valid-fat", &image);
        validate_native_executable(&path).unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn deny_write_subtraction_is_after_write_grants_and_executable_rules() {
        let protected = AccessRoot {
            path: PathBuf::from("/workspace/.git"),
            kind: AccessKind::Directory,
        };
        let policy = compile_policy(
            &[],
            &[AccessRoot {
                path: PathBuf::from("/workspace"),
                kind: AccessKind::Directory,
            }],
            &[protected],
            Path::new("/workspace/tool"),
            &NetworkPolicy::Denied,
            None,
            false,
        );
        let write_grant = policy
            .find("(allow file-read* file-test-existence file-write*")
            .unwrap();
        let subtraction = policy
            .rfind(r#"(deny file-write* (subpath (param "DENY_WRITE_0")))"#)
            .unwrap();
        assert!(subtraction > write_grant);
    }

    #[test]
    fn prepare_sets_native_working_directory() {
        let plan = ExecutionPlan {
            program: PathBuf::from("/bin/bash"),
            argv0: OsString::from("/bin/bash"),
            arguments: Vec::new(),
            cwd: std::env::current_dir().unwrap(),
            reads: Vec::new(),
            writes: Vec::new(),
            tmp: None,
            environment: BTreeMap::new(),
            network: NetworkPolicy::Denied,
            deny_writes: Vec::new(),
            no_child_processes: false,
        };
        let prepared = super::prepare(&plan).unwrap();
        let current_dir = prepared.command.get_current_dir().map(Path::to_path_buf);
        assert_eq!(current_dir, Some(plan.cwd));
    }

    #[test]
    fn definition_keeps_path_out_of_policy_text() {
        assert_eq!(
            definition("READ_0", Path::new("/tmp/a b")),
            "-DREAD_0=/tmp/a b"
        );
    }
}
