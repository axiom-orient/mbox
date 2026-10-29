mod bwrap;
mod mounts;

use self::bwrap::{trusted_bwrap, validate_bwrap_version};
use self::mounts::{prepare_mounts, MountSetup};
use super::fd;
use super::seccomp;
use super::PreparedCommand;
use crate::plan::{ExecutionPlan, NetworkPolicy};
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::process::Command;

pub fn prepare(plan: &ExecutionPlan) -> io::Result<PreparedCommand> {
    if plan.no_child_processes {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "`--no-child-processes` is supported only on macOS; Linux setup aborted",
        ));
    }
    if matches!(plan.network, NetworkPolicy::ExactDomains(_)) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "`--allow-net` exact-domain egress is not implemented on Linux; setup aborted",
        ));
    }
    if !plan.deny_writes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "`--deny-write` native subtraction is not implemented on Linux; setup aborted",
        ));
    }
    if plan.tmp.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--tmp is only supported on macOS",
        ));
    }

    // Bubblewrap's version preflight is itself a child process. Close ambient
    // descriptors before that spawn so no capability beyond stdin/out/err can
    // cross even the trusted-launcher probe. Mount and seccomp descriptors are
    // created afterwards and explicitly preserved for the final exec.
    fd::close_inherited(&[])?;

    let bwrap = trusted_bwrap()?;
    validate_bwrap_version(&bwrap)?;
    let mount_setup = prepare_mounts(plan)?;
    let filter = seccomp::create_filter_file(matches!(plan.network, NetworkPolicy::Native))?;
    let filter_fd = filter.as_raw_fd();

    let mut command = Command::new(bwrap);
    command.env_clear();
    command.env("PATH", "/usr/bin:/bin");
    command.args(compile_args(plan, filter_fd, &mount_setup));

    let mut prepared = PreparedCommand::new(command).keep_file(filter);
    for mount in mount_setup.mounts {
        prepared = prepared.keep_file(mount.file);
    }
    Ok(prepared)
}

fn compile_args(plan: &ExecutionPlan, filter_fd: RawFd, mount_setup: &MountSetup) -> Vec<OsString> {
    let mut args = Vec::new();

    push(&mut args, "--die-with-parent");
    push(&mut args, "--unshare-user");
    push(&mut args, "--disable-userns");
    push(&mut args, "--unshare-pid");
    push(&mut args, "--unshare-ipc");
    push(&mut args, "--unshare-uts");
    if !matches!(plan.network, NetworkPolicy::Native) {
        push(&mut args, "--unshare-net");
    }
    push_pair(&mut args, "--cap-drop", "ALL");
    push(&mut args, "--clearenv");

    push_pair(&mut args, "--tmpfs", "/");
    push_pair(&mut args, "--dev", "/dev");
    push_pair(&mut args, "--proc", "/proc");
    push_pair(&mut args, "--tmpfs", "/tmp");
    push_pair(&mut args, "--tmpfs", "/dev/shm");

    for (target, destination) in &mount_setup.symlinks {
        push(&mut args, "--symlink");
        args.push(target.clone());
        args.push(destination.as_os_str().to_os_string());
    }
    for mount in &mount_setup.mounts {
        push(
            &mut args,
            if mount.read_only {
                "--ro-bind-fd"
            } else {
                "--bind-fd"
            },
        );
        args.push(OsString::from(mount.file.as_raw_fd().to_string()));
        args.push(mount.destination.as_os_str().to_os_string());
    }

    push_pair(&mut args, "--remount-ro", "/");
    push_pair_os(&mut args, OsStr::new("--chdir"), plan.cwd.as_os_str());

    for (name, value) in &plan.environment {
        push(&mut args, "--setenv");
        args.push(name.clone());
        args.push(value.clone());
    }
    push_pair(&mut args, "--setenv", "TMPDIR");
    args.push(OsString::from("/tmp"));

    push_pair(&mut args, "--seccomp", &filter_fd.to_string());
    push(&mut args, "--argv0");
    args.push(plan.argv0.clone());
    push(&mut args, "--");
    args.push(plan.program.as_os_str().to_os_string());
    args.extend(plan.arguments.iter().cloned());

    args
}

fn push(args: &mut Vec<OsString>, value: &str) {
    args.push(OsString::from(value));
}

fn push_pair(args: &mut Vec<OsString>, left: &str, right: &str) {
    push(args, left);
    push(args, right);
}

fn push_pair_os(args: &mut Vec<OsString>, left: &OsStr, right: &OsStr) {
    args.push(left.to_os_string());
    args.push(right.to_os_string());
}
