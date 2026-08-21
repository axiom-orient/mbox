#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("mbox supports only Linux and macOS");

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
compile_error!("mbox Linux seccomp supports x86_64 and aarch64");

mod cli;
mod plan;
mod platform;

use std::os::unix::process::ExitStatusExt;
use std::process;

const EXIT_CLI: i32 = 2;
const EXIT_SETUP: i32 = 125;

fn main() {
    let action = match cli::parse(std::env::args_os()) {
        Ok(action) => action,
        Err(error) => fail(EXIT_CLI, &error),
    };

    match action {
        cli::Action::Help => {
            print!("{}", cli::HELP);
        }
        cli::Action::Version => {
            println!("mbox {}", env!("CARGO_PKG_VERSION"));
        }
        cli::Action::Run(request) => {
            let plan = match plan::ExecutionPlan::build(*request) {
                Ok(plan) => plan,
                Err(error) => fail(EXIT_SETUP, &error),
            };
            let prepared = match platform::prepare(&plan) {
                Ok(prepared) => prepared,
                Err(error) => fail(EXIT_SETUP, &error.to_string()),
            };

            match prepared.exec() {
                Ok(status) => {
                    if let Some(code) = status.code() {
                        process::exit(code);
                    }
                    if let Some(signal) = status.signal() {
                        process::exit(128 + signal);
                    }
                    fail(EXIT_SETUP, "native target ended without an exit status");
                }
                Err(error) => fail(
                    EXIT_SETUP,
                    &format!("failed to enter the native sandbox: {error}"),
                ),
            }
        }
    }
}

fn fail(code: i32, message: &str) -> ! {
    eprintln!("mbox: {message}");
    process::exit(code);
}
