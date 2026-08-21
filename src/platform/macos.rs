use super::macos_proxy::ProxyRuntime;
use super::PreparedCommand;
use crate::plan::{AccessKind, AccessRoot, ExecutionPlan};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::raw::{c_int, c_long, c_uint, c_ulong, c_void};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
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
}

pub fn prepare(plan: &ExecutionPlan) -> io::Result<PreparedCommand> {
    validate_system_executable(Path::new(SANDBOX_EXEC))?;
    validate_system_executable(Path::new(BASH))?;

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
    if !plan.allow_net.is_empty() {
        super::fd::close_inherited(&[])?;
    }
    let mut proxy = if plan.allow_net.is_empty() {
        None
    } else {
        Some(ProxyRuntime::start(&plan.allow_net)?)
    };
    let proxy_port = proxy.as_ref().map(ProxyRuntime::port);
    let policy = compile_policy(
        &plan.reads,
        &writes,
        &plan.deny_writes,
        &plan.program,
        plan.network,
        proxy_port,
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
    command
        .arg("--")
        .arg(BASH)
        .arg("--noprofile")
        .arg("--norc")
        .arg("-c")
        .arg(RUNNER)
        .arg("mbox-runner")
        .arg(&plan.argv0)
        .arg(&plan.program)
        .args(&plan.arguments);

    let prepared = PreparedCommand::new(command);
    Ok(match proxy.take() {
        Some(proxy) => prepared.with_supervisor(proxy),
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
    network: bool,
    proxy_port: Option<u16>,
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

    if network {
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

#[cfg(test)]
mod tests {
    use super::{
        compile_policy, definition, supervisor_signal_handler, SigInfo, SignalGuard,
        PENDING_SIGNALS, SIGNAL_TERM, SIGTERM,
    };
    use crate::plan::{AccessKind, AccessRoot, ExecutionPlan};
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::mem::{align_of, size_of};
    use std::path::{Path, PathBuf};

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
        let policy = compile_policy(&reads, &[], &[], Path::new("/a/program"), false, None);
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
            false,
            None,
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
        let policy = compile_policy(&[], &[], &[], Path::new("/a/program"), false, None);
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
            false,
            None,
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
        let policy = compile_policy(&[], &[], &[], Path::new("/a/program"), false, None);
        let tty_grant = policy.find("file-write* file-ioctl").unwrap();
        let tiocsti_deny = policy
            .rfind("(deny file-ioctl (ioctl-command #x80017472))")
            .unwrap();
        assert!(tiocsti_deny > tty_grant);
    }

    #[test]
    fn exact_network_policy_allows_only_parent_loopback_port() {
        let policy = compile_policy(&[], &[], &[], Path::new("/a/program"), false, Some(43127));
        assert!(policy.contains(r#"(allow network-outbound (remote ip "localhost:43127"))"#));
        assert!(!policy.contains("(allow network-inbound)"));
        assert!(!policy.contains("(allow network-bind)"));
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
            false,
            None,
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
            network: false,
            allow_net: Vec::new(),
            deny_writes: Vec::new(),
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
