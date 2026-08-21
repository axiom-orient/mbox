use crate::cli::Request;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::net::IpAddr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

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
    pub network: bool,
    pub allow_net: Vec<String>,
    pub deny_writes: Vec<AccessRoot>,
}

impl ExecutionPlan {
    pub fn build(request: Request) -> Result<Self, String> {
        if request.network && !request.allow_net.is_empty() {
            return Err("`--network` cannot be combined with `--allow-net`".to_string());
        }
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

        let allow_net = request
            .allow_net
            .iter()
            .map(|domain| normalize_domain(domain))
            .collect::<Result<Vec<_>, _>>()?;

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
            network: request.network,
            allow_net,
            deny_writes,
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

    let mut labels = value.split('.');
    if labels.clone().count() == 0 {
        return Err(format!("invalid exact network domain `{value}`"));
    }
    for label in &mut labels {
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

fn deny_write_root(path: &Path, base: &Path) -> Result<AccessRoot, String> {
    let absolute = absolute_from(path, base);
    match fs::symlink_metadata(&absolute) {
        Ok(link_metadata) => {
            if link_metadata.file_type().is_symlink() {
                return Err(format!(
                    "deny-write path `{}` must not be a symlink",
                    absolute.display()
                ));
            }
            let canonical = fs::canonicalize(&absolute).map_err(|error| {
                format!(
                    "deny-write path `{}` is not accessible: {error}",
                    absolute.display()
                )
            })?;
            let metadata = fs::metadata(&canonical).map_err(|error| {
                format!(
                    "cannot inspect deny-write path `{}`: {error}",
                    canonical.display()
                )
            })?;
            let kind = if metadata.is_file() {
                AccessKind::File
            } else if metadata.is_dir() {
                AccessKind::Directory
            } else {
                return Err(format!(
                    "deny-write path `{}` must be a regular file or directory",
                    canonical.display()
                ));
            };
            Ok(AccessRoot {
                path: canonical,
                kind,
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let name = absolute.file_name().ok_or_else(|| {
                format!(
                    "deny-write path `{}` must name a file or directory",
                    absolute.display()
                )
            })?;
            if name == OsStr::new(".") || name == OsStr::new("..") {
                return Err(format!(
                    "deny-write path `{}` must name a file or directory",
                    absolute.display()
                ));
            }
            let parent = absolute.parent().ok_or_else(|| {
                format!(
                    "deny-write path `{}` has no existing parent",
                    absolute.display()
                )
            })?;
            let canonical_parent = fs::canonicalize(parent).map_err(|error| {
                format!(
                    "parent of deny-write path `{}` is not accessible: {error}",
                    absolute.display()
                )
            })?;
            let metadata = fs::metadata(&canonical_parent).map_err(|error| {
                format!(
                    "cannot inspect parent of deny-write path `{}`: {error}",
                    absolute.display()
                )
            })?;
            if !metadata.is_dir() {
                return Err(format!(
                    "parent of deny-write path `{}` is not a directory",
                    absolute.display()
                ));
            }
            Ok(AccessRoot {
                path: canonical_parent.join(name),
                // A nonexistent path may later become either a file or a
                // directory. Subpath semantics protect both the leaf and
                // anything created beneath it.
                kind: AccessKind::Directory,
            })
        }
        Err(error) => Err(format!(
            "deny-write path `{}` is not accessible: {error}",
            absolute.display()
        )),
    }
}

fn reject_hardlinks_under(root: &AccessRoot) -> Result<(), String> {
    match fs::symlink_metadata(&root.path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "cannot inspect deny-write path `{}` for hardlinks: {error}",
                root.path.display()
            ));
        }
    }
    match root.kind {
        AccessKind::File => reject_hardlinked_regular_file(&root.path, "deny-write file"),
        AccessKind::Directory => reject_hardlinks_directory(&root.path),
    }
}

fn reject_hardlinks_directory(path: &Path) -> Result<(), String> {
    let entries = fs::read_dir(path).map_err(|error| {
        format!(
            "cannot inspect deny-write directory `{}` for hardlinks: {error}",
            path.display()
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "cannot inspect deny-write directory `{}` for hardlinks: {error}",
                path.display()
            )
        })?;
        let child = entry.path();
        let metadata = fs::symlink_metadata(&child).map_err(|error| {
            format!(
                "cannot inspect protected path `{}` for hardlinks: {error}",
                child.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "deny-write directory `{}` contains symlink `{}`; inode identity is not stable",
                path.display(),
                child.display()
            ));
        }
        if metadata.is_dir() {
            reject_hardlinks_directory(&child)?;
        } else if metadata.is_file() && metadata.nlink() > 1 {
            return Err(format!(
                "deny-write path `{}` contains hardlinked regular file `{}` ({} links)",
                path.display(),
                child.display(),
                metadata.nlink()
            ));
        }
    }
    Ok(())
}

fn reject_hardlinked_regular_file(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "cannot inspect {label} `{}` for hardlinks: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "{label} `{}` must not be a symlink",
            path.display()
        ));
    }
    if metadata.is_file() && metadata.nlink() > 1 {
        return Err(format!(
            "{label} `{}` has {} hardlinks; inode identity cannot be pinned",
            path.display(),
            metadata.nlink()
        ));
    }
    Ok(())
}

fn canonical_directory(path: &Path, base: &Path, label: &str) -> Result<PathBuf, String> {
    let absolute = absolute_from(path, base);
    let canonical = fs::canonicalize(&absolute).map_err(|error| {
        format!(
            "{label} `{}` is not accessible: {error}",
            absolute.display()
        )
    })?;
    let metadata = fs::metadata(&canonical)
        .map_err(|error| format!("cannot inspect {label} `{}`: {error}", canonical.display()))?;
    if !metadata.is_dir() {
        return Err(format!(
            "{label} `{}` is not a directory",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn access_root(path: &Path, base: &Path, label: &str) -> Result<AccessRoot, String> {
    let absolute = absolute_from(path, base);
    let canonical = fs::canonicalize(&absolute).map_err(|error| {
        format!(
            "{label} `{}` is not accessible: {error}",
            absolute.display()
        )
    })?;
    let metadata = fs::metadata(&canonical)
        .map_err(|error| format!("cannot inspect {label} `{}`: {error}", canonical.display()))?;
    let kind = if metadata.is_file() {
        AccessKind::File
    } else if metadata.is_dir() {
        AccessKind::Directory
    } else {
        return Err(format!(
            "{label} `{}` must be a regular file or directory",
            canonical.display()
        ));
    };
    Ok(AccessRoot {
        path: canonical,
        kind,
    })
}

fn absolute_from(path: &Path, base: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn resolve_program(
    argv0: &OsStr,
    cwd: &Path,
    environment: &BTreeMap<OsString, OsString>,
) -> Result<PathBuf, String> {
    let token = Path::new(argv0);
    if argv0.as_bytes().contains(&b'/') {
        return executable_path(&absolute_from(token, cwd), argv0);
    }

    let search = environment
        .iter()
        .find(|(name, _)| name.as_os_str() == OsStr::new("PATH"))
        .map(|(_, value)| value.clone())
        .unwrap_or_else(|| OsString::from("/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"));

    for directory in env::split_paths(&search) {
        let candidate = if directory.is_absolute() {
            directory.join(token)
        } else {
            cwd.join(directory).join(token)
        };
        if let Ok(path) = executable_path(&candidate, argv0) {
            return Ok(path);
        }
    }

    Err(format!(
        "command `{}` was not found as an executable in PATH",
        argv0.to_string_lossy()
    ))
}

fn executable_path(candidate: &Path, argv0: &OsStr) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(candidate).map_err(|_| {
        format!(
            "command `{}` does not resolve to an existing file",
            argv0.to_string_lossy()
        )
    })?;
    let metadata = fs::metadata(&canonical)
        .map_err(|error| format!("cannot inspect command `{}`: {error}", canonical.display()))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(format!(
            "command `{}` is not an executable regular file",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn build_environment(
    request: &Request,
    cwd: &Path,
) -> Result<BTreeMap<OsString, OsString>, String> {
    let host: Vec<(OsString, OsString)> = env::vars_os().collect();
    let mut result = BTreeMap::new();

    if request.inherit_env {
        for (name, value) in &host {
            let name_text = checked_env_name(name)?;
            if is_platform_owned(name_text) || is_launcher_sensitive(name_text) {
                continue;
            }
            result.insert(name.clone(), value.clone());
        }
    } else {
        const DEFAULTS: &[&str] = &[
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "SHELL",
            "TERM",
            "COLORTERM",
            "LANG",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        ];
        for (name, value) in &host {
            let Some(name_text) = name.to_str() else {
                continue;
            };
            if (DEFAULTS.contains(&name_text) || name_text.starts_with("LC_"))
                && !is_platform_owned(name_text)
                && !is_launcher_sensitive(name_text)
            {
                result.insert(name.clone(), value.clone());
            }
        }
    }

    for name in &request.env_names {
        let name_text = checked_env_name(name)?;
        reject_explicit_env(name_text)?;
        let value = host
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.clone())
            .ok_or_else(|| format!("environment variable `{name_text}` does not exist"))?;
        result.insert(name.clone(), value);
    }

    for (name, value) in &request.env_overrides {
        let name_text = checked_env_name(name)?;
        reject_explicit_env(name_text)?;
        result.insert(name.clone(), value.clone());
    }

    result
        .entry(OsString::from("PATH"))
        .or_insert_with(|| OsString::from("/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"));
    result.insert(OsString::from("PWD"), cwd.as_os_str().to_os_string());
    result.remove(OsStr::new("OLDPWD"));
    result.remove(OsStr::new("TMPDIR"));

    Ok(result)
}

fn checked_env_name(name: &OsStr) -> Result<&str, String> {
    let Some(name) = name.to_str() else {
        return Err("environment variable names must be UTF-8 ASCII identifiers".to_string());
    };
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err("environment variable name is empty".to_string());
    };
    if !(first == '_' || first.is_ascii_alphabetic())
        || !chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
    {
        return Err(format!("invalid environment variable name `{name}`"));
    }
    Ok(name)
}

fn reject_explicit_env(name: &str) -> Result<(), String> {
    if is_platform_owned(name) {
        return Err(format!(
            "environment variable `{name}` is owned by mbox and cannot be supplied"
        ));
    }
    if is_launcher_sensitive(name) {
        return Err(format!(
            "environment variable `{name}` can alter a native launcher and is forbidden"
        ));
    }
    Ok(())
}

fn is_platform_owned(name: &str) -> bool {
    matches!(name, "PWD" | "OLDPWD" | "TMPDIR")
}

fn is_launcher_sensitive(name: &str) -> bool {
    name.starts_with("LD_")
        || name.starts_with("DYLD_")
        || matches!(
            name,
            "BASH_ENV" | "ENV" | "SHELLOPTS" | "BASHOPTS" | "CDPATH" | "GLOBIGNORE"
        )
}

fn minimize_roots(mut roots: Vec<AccessRoot>) -> Vec<AccessRoot> {
    roots.sort_by(|left, right| {
        depth(&left.path)
            .cmp(&depth(&right.path))
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.kind.cmp(&right.kind))
    });
    roots.dedup();

    let mut accepted = Vec::with_capacity(roots.len());
    let mut directories = BTreeSet::new();
    for root in roots {
        if has_directory_ancestor(&root.path, &directories) {
            continue;
        }
        if root.kind == AccessKind::Directory {
            directories.insert(root.path.clone());
        }
        accepted.push(root);
    }
    accepted
}

struct AuthorityIndex {
    exact: BTreeSet<PathBuf>,
    directories: BTreeSet<PathBuf>,
}

impl AuthorityIndex {
    fn new(roots: &[AccessRoot]) -> Self {
        let exact = roots.iter().map(|root| root.path.clone()).collect();
        let directories = roots
            .iter()
            .filter(|root| root.kind == AccessKind::Directory)
            .map(|root| root.path.clone())
            .collect();
        Self { exact, directories }
    }

    fn covers(&self, path: &Path) -> bool {
        if self.exact.contains(path) {
            return true;
        }
        has_directory_ancestor(path, &self.directories)
    }
}

fn has_directory_ancestor(path: &Path, directories: &BTreeSet<PathBuf>) -> bool {
    let mut current = path.parent();
    while let Some(parent) = current {
        if directories.contains(parent) {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn depth(path: &Path) -> usize {
    path.components().count()
}

#[cfg(test)]
mod tests {
    use super::{
        is_launcher_sensitive, is_platform_owned, minimize_roots, normalize_domain,
        reject_hardlinked_regular_file, AccessKind, AccessRoot, ExecutionPlan,
    };
    use crate::cli::Request;
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
            network: false,
            allow_net: Vec::new(),
            deny_writes: Vec::new(),
            env_names: Vec::new(),
            env_overrides: Vec::new(),
            inherit_env: false,
            command: vec![command_input.into_os_string()],
        })
        .unwrap();

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
            network: false,
            allow_net: Vec::new(),
            deny_writes: vec![PathBuf::from(".git")],
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
