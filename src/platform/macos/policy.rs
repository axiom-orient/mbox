use crate::plan::{AccessKind, AccessRoot, NetworkPolicy};
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::process::Command;

const BASE_POLICY: &str = include_str!("../macos_base.sbpl");
const PLATFORM_POLICY: &str = include_str!("../macos_platform.sbpl");

pub(super) fn compile_policy(
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
        let selector = selector(&key, root.kind);
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
    let selector = selector(&key, kind);
    policy.push_str(&format!("\n(allow {operations} {selector})\n"));
}

fn selector(key: &str, kind: AccessKind) -> String {
    match kind {
        AccessKind::File => format!(r#"(literal (param "{key}"))"#),
        AccessKind::Directory => format!(r#"(subpath (param "{key}"))"#),
    }
}

pub(super) fn add_definitions(command: &mut Command, prefix: &str, roots: &[AccessRoot]) {
    for (index, root) in roots.iter().enumerate() {
        let key = format!("{prefix}_{index}");
        command.arg(definition(&key, &root.path));
    }
}

pub(super) fn definition(key: &str, path: &Path) -> OsString {
    let mut bytes = format!("-D{key}=").into_bytes();
    bytes.extend_from_slice(path.as_os_str().as_bytes());
    OsString::from_vec(bytes)
}

#[cfg(test)]
mod tests {
    use super::{compile_policy, definition};
    use crate::plan::{AccessKind, AccessRoot, NetworkPolicy};
    use std::path::{Path, PathBuf};

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
    fn definition_keeps_path_out_of_policy_text() {
        assert_eq!(
            definition("READ_0", Path::new("/tmp/a b")),
            "-DREAD_0=/tmp/a b"
        );
    }
}
