mod fd;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod macos_proxy;
#[cfg(target_os = "linux")]
mod seccomp;

use crate::plan::ExecutionPlan;
use std::fs::File;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

pub struct PreparedCommand {
    command: Command,
    preserve_fds: Vec<RawFd>,
    _resources: Vec<File>,
    #[cfg(target_os = "macos")]
    supervisor: Option<macos_proxy::ProxyRuntime>,
}

impl PreparedCommand {
    pub fn new(command: Command) -> Self {
        Self {
            command,
            preserve_fds: Vec::new(),
            _resources: Vec::new(),
            #[cfg(target_os = "macos")]
            supervisor: None,
        }
    }

    #[cfg(target_os = "macos")]
    pub fn with_supervisor(mut self, supervisor: macos_proxy::ProxyRuntime) -> Self {
        self.supervisor = Some(supervisor);
        self
    }

    #[cfg(target_os = "linux")]
    pub fn keep_file(mut self, file: File) -> Self {
        self.preserve_fds.push(file.as_raw_fd());
        self._resources.push(file);
        self
    }

    pub fn exec(mut self) -> io::Result<std::process::ExitStatus> {
        #[cfg(target_os = "macos")]
        if let Some(supervisor) = self.supervisor.take() {
            return macos::run_supervised(self.command, supervisor);
        }

        fd::close_inherited(&self.preserve_fds)?;

        Err(self.command.exec())
    }
}

pub fn prepare(plan: &ExecutionPlan) -> io::Result<PreparedCommand> {
    #[cfg(target_os = "linux")]
    {
        linux::prepare(plan)
    }
    #[cfg(target_os = "macos")]
    {
        macos::prepare(plan)
    }
}
