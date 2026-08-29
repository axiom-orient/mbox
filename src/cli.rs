use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

pub const HELP: &str = concat!(
    "mbox ",
    env!("CARGO_PKG_VERSION"),
    "\n\
Run one command in the native macOS or Linux sandbox.

USAGE:
    mbox [OPTIONS] -- COMMAND [ARG...]

OPTIONS:
    --cwd PATH          Run from PATH. Default: current directory.
    --read PATH         Add an existing read-only file or directory. Repeatable.
    --write PATH        Add an existing writable file or directory. Repeatable.
    --tmp PATH          Use an existing caller-owned 0700 temporary directory on macOS.
    --network           Allow the native network. Default: denied.
    --allow-net DOMAIN  Allow HTTPS CONNECT to one exact ASCII DNS name. Repeatable.
    --deny-write PATH   Subtract write authority at PATH. Repeatable.
    --no-child-processes  On macOS, run one native Mach-O without child/other-image exec authority.
    --env NAME          Pass one existing environment variable. Repeatable.
    --set-env NAME=VAL  Set one environment variable. Repeatable.
    --inherit-env       Pass all non-reserved, non-launcher environment variables.
    -h, --help          Print this help.
    -V, --version       Print the version.

The `--` separator is mandatory. Paths are resolved once to canonical paths.
On macOS, `--tmp` is optional; when omitted, the target has no TMPDIR or
temporary write authority. Linux rejects `--tmp` and uses anonymous `/tmp`.
There are no profiles, configuration files, compatibility aliases, or fallbacks.
"
);

#[derive(Debug, Clone)]
pub struct Request {
    pub cwd: Option<PathBuf>,
    pub reads: Vec<PathBuf>,
    pub writes: Vec<PathBuf>,
    pub tmp: Option<PathBuf>,
    pub network: bool,
    pub allow_net: Vec<OsString>,
    pub deny_writes: Vec<PathBuf>,
    pub no_child_processes: bool,
    pub env_names: Vec<OsString>,
    pub env_overrides: Vec<(OsString, OsString)>,
    pub inherit_env: bool,
    pub command: Vec<OsString>,
}

#[derive(Debug, Clone)]
pub enum Action {
    Help,
    Version,
    Run(Box<Request>),
}

pub fn parse<I>(args: I) -> Result<Action, String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let _program = args.next();

    let mut request = Request {
        cwd: None,
        reads: Vec::new(),
        writes: Vec::new(),
        tmp: None,
        network: false,
        allow_net: Vec::new(),
        deny_writes: Vec::new(),
        no_child_processes: false,
        env_names: Vec::new(),
        env_overrides: Vec::new(),
        inherit_env: false,
        command: Vec::new(),
    };

    while let Some(argument) = args.next() {
        if argument == OsStr::new("--") {
            request.command.extend(args);
            if request.command.is_empty() {
                return Err("missing COMMAND after `--`".to_string());
            }
            if request.network && !request.allow_net.is_empty() {
                return Err("`--network` cannot be combined with `--allow-net`".to_string());
            }
            return Ok(Action::Run(Box::new(request)));
        }

        match argument.to_str() {
            Some("-h" | "--help") => return Ok(Action::Help),
            Some("-V" | "--version") => return Ok(Action::Version),
            Some("--cwd") => {
                set_once_path(&mut request.cwd, next_value(&mut args, "--cwd")?, "--cwd")?;
            }
            Some("--read") => {
                request
                    .reads
                    .push(PathBuf::from(next_value(&mut args, "--read")?));
            }
            Some("--write") => {
                request
                    .writes
                    .push(PathBuf::from(next_value(&mut args, "--write")?));
            }
            Some("--tmp") => {
                set_once_path(&mut request.tmp, next_value(&mut args, "--tmp")?, "--tmp")?;
            }
            Some("--network") => request.network = true,
            Some("--allow-net") => request
                .allow_net
                .push(next_value(&mut args, "--allow-net")?),
            Some("--deny-write") => request
                .deny_writes
                .push(PathBuf::from(next_value(&mut args, "--deny-write")?)),
            Some("--no-child-processes") => request.no_child_processes = true,
            Some("--env") => request.env_names.push(next_value(&mut args, "--env")?),
            Some("--set-env") => {
                let value = next_value(&mut args, "--set-env")?;
                request.env_overrides.push(split_assignment(value)?);
            }
            Some("--inherit-env") => request.inherit_env = true,
            Some(option) if option.starts_with('-') => {
                return Err(format!("unknown option `{option}`"));
            }
            Some(value) => {
                return Err(format!(
                    "unexpected argument `{value}` before `--`; the separator is mandatory"
                ));
            }
            None => {
                return Err("non-UTF-8 option name before `--` is not supported".to_string());
            }
        }
    }

    Err("missing mandatory `-- COMMAND`".to_string())
}

fn next_value<I>(args: &mut I, option: &str) -> Result<OsString, String>
where
    I: Iterator<Item = OsString>,
{
    args.next()
        .ok_or_else(|| format!("missing value for `{option}`"))
}

fn set_once_path(slot: &mut Option<PathBuf>, value: OsString, option: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("`{option}` may be specified only once"));
    }
    *slot = Some(PathBuf::from(value));
    Ok(())
}

#[cfg(unix)]
fn split_assignment(value: OsString) -> Result<(OsString, OsString), String> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let bytes = value.as_os_str().as_bytes();
    let Some(index) = bytes.iter().position(|byte| *byte == b'=') else {
        return Err("`--set-env` requires NAME=VALUE".to_string());
    };
    if index == 0 {
        return Err("`--set-env` requires a non-empty NAME".to_string());
    }

    Ok((
        OsString::from_vec(bytes[..index].to_vec()),
        OsString::from_vec(bytes[index + 1..].to_vec()),
    ))
}

#[cfg(test)]
mod tests {
    use super::{parse, Action, HELP};
    use std::ffi::OsString;
    use std::path::PathBuf;

    fn argv(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn help_uses_package_version() {
        let expected = format!("mbox {}", env!("CARGO_PKG_VERSION"));
        assert_eq!(HELP.lines().next(), Some(expected.as_str()));
    }

    #[test]
    fn requires_separator() {
        let error = parse(argv(&["mbox", "echo"])).unwrap_err();
        assert!(error.contains("separator"));
    }

    #[test]
    fn preserves_command_arguments() {
        let Action::Run(request) = parse(argv(&["mbox", "--", "printf", "%s", "a b"])).unwrap()
        else {
            panic!("expected run");
        };
        assert_eq!(request.command, argv(&["printf", "%s", "a b"]));
    }

    #[test]
    fn parses_all_policy_inputs() {
        let Action::Run(request) = parse(argv(&[
            "mbox",
            "--cwd",
            ".",
            "--read",
            "a",
            "--write",
            "b",
            "--tmp",
            "tmp",
            "--allow-net",
            "api.openai.com",
            "--deny-write",
            ".git",
            "--env",
            "TERM",
            "--set-env",
            "MODE=test",
            "--inherit-env",
            "--",
            "true",
        ]))
        .unwrap() else {
            panic!("expected run");
        };
        assert_eq!(request.allow_net, argv(&["api.openai.com"]));
        assert_eq!(request.deny_writes, vec![PathBuf::from(".git")]);
        assert!(request.inherit_env);
        assert_eq!(request.reads.len(), 1);
        assert_eq!(request.writes.len(), 1);
        assert_eq!(request.tmp, Some("tmp".into()));
        assert_eq!(request.env_names, argv(&["TERM"]));
        assert_eq!(request.env_overrides[0].0, "MODE");
        assert_eq!(request.env_overrides[0].1, "test");
        assert!(!request.no_child_processes);
    }

    #[test]
    fn parses_strict_no_child_processes_mode() {
        let Action::Run(request) = parse(argv(&[
            "mbox",
            "--no-child-processes",
            "--",
            "/usr/bin/true",
        ]))
        .unwrap() else {
            panic!("expected run");
        };
        assert!(request.no_child_processes);
    }

    #[test]
    fn rejects_duplicate_cwd() {
        let error = parse(argv(&["mbox", "--cwd", ".", "--cwd", ".", "--", "true"])).unwrap_err();
        assert!(error.contains("only once"));
    }

    #[test]
    fn rejects_full_network_and_exact_domains_together() {
        let error = parse(argv(&[
            "mbox",
            "--network",
            "--allow-net",
            "api.openai.com",
            "--",
            "true",
        ]))
        .unwrap_err();
        assert!(error.contains("cannot be combined"));
    }
}
