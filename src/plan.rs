mod environment;
mod roots;

use self::environment::{build_environment, resolve_program};
use self::roots::{
    access_root, canonical_directory, deny_write_root, minimize_roots,
    reject_hardlinked_regular_file, reject_hardlinks_under, AuthorityIndex,
};
use crate::cli::{NetworkRequest, Request};
use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccessKind {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccessRoot {
    pub path: PathBuf,
    pub kind: AccessKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPolicy {
    Denied,
    Native,
    ExactDomains(Vec<String>),
}

#[derive(Debug)]
pub struct ExecutionPlan {
    pub program: PathBuf,
    pub argv0: OsString,
    pub arguments: Vec<OsString>,
    pub cwd: PathBuf,
    pub reads: Vec<AccessRoot>,
    pub writes: Vec<AccessRoot>,
    pub tmp: Option<PathBuf>,
    pub environment: BTreeMap<OsString, OsString>,
    pub network: NetworkPolicy,
    pub deny_writes: Vec<AccessRoot>,
    pub no_child_processes: bool,
}

impl ExecutionPlan {
    pub fn build(request: Request) -> Result<Self, String> {
        let network = match &request.network {
            NetworkRequest::Denied => NetworkPolicy::Denied,
            NetworkRequest::Native => NetworkPolicy::Native,
            NetworkRequest::ExactDomains(domains) => {
                if domains.is_empty() {
                    return Err("exact-domain network requires a domain".into());
                }
                NetworkPolicy::ExactDomains(
                    domains
                        .iter()
                        .map(|d| normalize_domain(d))
                        .collect::<Result<_, _>>()?,
                )
            }
        };
        let process_cwd = env::current_dir()
            .map_err(|error| format!("cannot read current directory: {error}"))?;
        let cwd_input = request.cwd.as_deref().unwrap_or(&process_cwd);
        let cwd = canonical_directory(cwd_input, &process_cwd, "working directory")?;

        let environment = build_environment(&request, &cwd)?;
        let argv0 = request
            .command
            .first()
            .cloned()
            .ok_or_else(|| "missing command".to_string())?;
        let program = resolve_program(&argv0, &cwd, &environment)?;
        reject_hardlinked_regular_file(&program, "selected executable")?;
        let arguments = request.command.into_iter().skip(1).collect();

        let tmp = request
            .tmp
            .as_deref()
            .map(|path| canonical_directory(path, &cwd, "temporary directory"))
            .transpose()?;

        let mut reads = Vec::with_capacity(request.reads.len() + 2);
        reads.push(access_root(&cwd, &cwd, "working directory")?);
        reads.push(access_root(&program, &cwd, "command")?);
        for path in &request.reads {
            reads.push(access_root(path, &cwd, "read path")?);
        }

        let mut writes = Vec::with_capacity(request.writes.len());
        for path in &request.writes {
            let root = access_root(path, &cwd, "write path")?;
            if root.path.parent().is_none() {
                return Err("writable filesystem root `/` is forbidden".to_string());
            }
            writes.push(root);
        }

        let writes = minimize_roots(writes);

        let mut deny_writes = Vec::with_capacity(request.deny_writes.len());
        for path in &request.deny_writes {
            deny_writes.push(deny_write_root(path, &cwd)?);
        }
        let deny_writes = minimize_roots(deny_writes);
        for root in &deny_writes {
            reject_hardlinks_under(root)?;
        }

        let write_index = AuthorityIndex::new(&writes);
        reads.retain(|read| !write_index.covers(&read.path));
        let reads = minimize_roots(reads);

        Ok(Self {
            program,
            argv0,
            arguments,
            cwd,
            reads,
            writes,
            tmp,
            environment,
            network,
            deny_writes,
            no_child_processes: request.no_child_processes,
        })
    }
}

fn normalize_domain(value: &OsStr) -> Result<String, String> {
    let Some(value) = value.to_str() else {
        return Err("`--allow-net` domains must be ASCII DNS names".to_string());
    };
    if value.is_empty() || !value.is_ascii() {
        return Err(format!("invalid exact network domain `{value}`"));
    }
    if value.ends_with('.') {
        return Err(format!(
            "exact network domain `{value}` must not have a trailing dot"
        ));
    }
    if value.parse::<IpAddr>().is_ok()
        || value.contains(['/', ':', '@', '*', '?', '#', '%'])
        || value
            .chars()
            .any(|character| character.is_ascii_whitespace())
    {
        return Err(format!(
            "exact network domain `{value}` must be a DNS name, not an IP, URL, wildcard, or port"
        ));
    }
    if value.len() > 253 {
        return Err(format!(
            "exact network domain `{value}` is longer than 253 bytes"
        ));
    }

    for label in value.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("invalid exact network domain `{value}`"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("invalid exact network domain `{value}`"));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(format!("invalid exact network domain `{value}`"));
        }
    }

    Ok(value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::environment::{is_launcher_sensitive, is_platform_owned};
    use super::{
        minimize_roots, normalize_domain, reject_hardlinked_regular_file, AccessKind, AccessRoot,
        ExecutionPlan,
    };
    use crate::cli::{NetworkRequest, Request};
    use std::ffi::OsStr;
    use std::fs;
    use std::path::PathBuf;

    fn directory(path: &str) -> AccessRoot {
        AccessRoot {
            path: PathBuf::from(path),
            kind: AccessKind::Directory,
        }
    }

    fn file(path: &str) -> AccessRoot {
        AccessRoot {
            path: PathBuf::from(path),
            kind: AccessKind::File,
        }
    }

    #[test]
    fn ancestor_directory_removes_descendants() {
        assert_eq!(
            minimize_roots(vec![file("/a/b/file"), directory("/a"), directory("/a/b")]),
            vec![directory("/a")]
        );
    }

    #[test]
    fn sibling_files_are_preserved() {
        assert_eq!(
            minimize_roots(vec![file("/a/b"), file("/a/c")]),
            vec![file("/a/b"), file("/a/c")]
        );
    }

    #[test]
    fn large_root_set_does_not_need_pairwise_comparison() {
        let roots = (0..10_000)
            .map(|index| file(&format!("/workspace/{index}/file")))
            .collect();
        assert_eq!(minimize_roots(roots).len(), 10_000);
    }

    #[test]
    fn launcher_and_platform_environment_is_not_delegated() {
        assert!(is_launcher_sensitive("LD_PRELOAD"));
        assert!(is_launcher_sensitive("DYLD_INSERT_LIBRARIES"));
        assert!(is_launcher_sensitive("BASH_ENV"));
        assert!(is_platform_owned("PWD"));
        assert!(is_platform_owned("TMPDIR"));
        assert!(!is_launcher_sensitive("RUST_LOG"));
    }

    #[test]
    fn executable_parent_is_not_an_implicit_read_authority() {
        let command_input = PathBuf::from("/bin/sh");
        let command = fs::canonicalize(&command_input).unwrap();
        let parent = command.parent().unwrap().to_path_buf();
        let plan = ExecutionPlan::build(Request {
            cwd: Some(std::env::current_dir().unwrap()),
            reads: Vec::new(),
            writes: Vec::new(),
            tmp: None,
            network: NetworkRequest::Denied,
            deny_writes: Vec::new(),
            no_child_processes: true,
            env_names: Vec::new(),
            env_overrides: Vec::new(),
            inherit_env: false,
            command: vec![command_input.into_os_string()],
        })
        .unwrap();

        assert!(plan.no_child_processes);
        assert!(plan.reads.iter().any(|root| root.path == command));
        assert!(!plan.reads.iter().any(|root| root.path == parent));
    }

    #[test]
    fn exact_domain_normalization_is_ascii_case_sensitive_only() {
        assert_eq!(
            normalize_domain(OsStr::new("API.OpenAI.COM")).unwrap(),
            "api.openai.com"
        );
        for value in [
            "api.openai.com.",
            "*.openai.com",
            "api.openai.com:443",
            "127.0.0.1",
            "[::1]",
            "api_openai.com",
            "-api.openai.com",
            "api.-openai.com",
            "éxample.com",
        ] {
            assert!(normalize_domain(OsStr::new(value)).is_err(), "{value}");
        }
    }

    #[test]
    fn nonexistent_deny_write_leaf_is_resolved_against_canonical_parent() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mbox-deny-write-{nonce}"));
        fs::create_dir(&root).unwrap();
        let plan = ExecutionPlan::build(Request {
            cwd: Some(root.clone()),
            reads: Vec::new(),
            writes: vec![root.clone()],
            tmp: None,
            network: NetworkRequest::Denied,
            deny_writes: vec![PathBuf::from(".git")],
            no_child_processes: false,
            env_names: Vec::new(),
            env_overrides: Vec::new(),
            inherit_env: false,
            command: vec![PathBuf::from("/usr/bin/true").into_os_string()],
        })
        .unwrap();
        assert_eq!(
            plan.deny_writes[0].path,
            fs::canonicalize(&root).unwrap().join(".git")
        );
        assert_eq!(plan.deny_writes[0].kind, AccessKind::Directory);
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn hardlinked_protected_file_is_rejected_before_launch() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mbox-hardlink-{nonce}"));
        fs::create_dir(&root).unwrap();
        let source = root.join("protected");
        let alias = root.join("alias");
        fs::write(&source, b"data").unwrap();
        fs::hard_link(&source, &alias).unwrap();
        let result = reject_hardlinked_regular_file(&source, "test protected file");
        assert!(result.is_err());
        fs::remove_file(alias).unwrap();
        fs::remove_file(source).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
