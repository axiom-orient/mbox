mod macho;
mod policy;
mod supervisor;

use self::macho::validate_native_executable;
use self::policy::{add_definitions, compile_policy, definition};
pub(super) use self::supervisor::{establish_process_group_leader, run_supervised};
use super::macos_proxy::ProxyRuntime;
use super::PreparedCommand;
use crate::plan::{AccessKind, AccessRoot, ExecutionPlan, NetworkPolicy};
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const BASH: &str = "/bin/bash";
const RUNNER: &str = r#"exec -a "$1" "$2" "${@:3}""#;
unsafe extern "C" {
    fn geteuid() -> u32;
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
    use crate::plan::{ExecutionPlan, NetworkPolicy};
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

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
}
