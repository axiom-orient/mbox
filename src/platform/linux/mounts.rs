use super::super::fd;
use crate::plan::{AccessKind, AccessRoot, ExecutionPlan, NetworkPolicy};
use std::collections::BTreeSet;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::raw::{c_char, c_int};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

// Runtime roots contain operating-system code and data, not user-managed
// `/usr/local`. Commands or toolchains installed outside these roots must add
// their supporting directories explicitly with `--read`.
const RUNTIME_PATHS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/usr/libexec",
    "/usr/share",
    "/usr/include",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/nix/store",
    "/run/current-system/sw",
];

// These individual files keep common dynamically linked CLI tools usable
// without exposing the complete host `/etc`. Unusual host configuration must
// be delegated explicitly with `--read`.
const COMPATIBILITY_PATHS: &[&str] = &[
    "/etc/ld.so.cache",
    "/etc/nsswitch.conf",
    "/etc/passwd",
    "/etc/group",
    "/etc/localtime",
    "/etc/alternatives",
];

// Resolver and trust-store data is ambient only when native network authority
// is explicitly enabled. Local/offline tools can request individual paths with
// `--read` instead.
const NETWORK_PATHS: &[&str] = &[
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/gai.conf",
    "/etc/host.conf",
    "/etc/protocols",
    "/etc/services",
    "/etc/ssl",
    "/etc/pki",
    "/etc/ca-certificates",
    "/var/lib/ca-certificates",
    "/var/lib/ssl",
];

const O_CLOEXEC: c_int = 0o2_000_000;
const O_DIRECTORY: c_int = 0o200_000;
const O_NOFOLLOW: c_int = 0o400_000;
const O_PATH: c_int = 0o10_000_000;

unsafe extern "C" {
    fn open(path: *const c_char, flags: c_int, ...) -> c_int;
    fn openat(directory: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
}

pub(super) struct MountHandle {
    pub(super) file: File,
    pub(super) destination: PathBuf,
    pub(super) read_only: bool,
}

#[derive(Default)]
pub(super) struct MountSetup {
    pub(super) symlinks: Vec<(OsString, PathBuf)>,
    pub(super) mounts: Vec<MountHandle>,
}

pub(super) fn prepare_mounts(plan: &ExecutionPlan) -> io::Result<MountSetup> {
    let mut setup = MountSetup::default();
    let mut read_directories = BTreeSet::new();

    for path in RUNTIME_PATHS.iter().chain(COMPATIBILITY_PATHS) {
        add_system_path(&mut setup, &mut read_directories, Path::new(path))?;
    }
    if matches!(plan.network, NetworkPolicy::Native) {
        for path in NETWORK_PATHS {
            add_system_path(&mut setup, &mut read_directories, Path::new(path))?;
        }
    }

    // Mount readable parents before writable descendants. Bubblewrap applies
    // mount operations in argument order, so a later writable child remains
    // visible while a later parent mount would hide it.
    for root in &plan.reads {
        add_read_path(&mut setup, &mut read_directories, &root.path, root.kind)?;
    }
    for root in &plan.writes {
        add_mount(&mut setup, root, false)?;
    }

    // Reassert the exact executable as read-only after writable parents. This
    // pins the validated executable without hiding unrelated writable children.
    add_exact_mount(
        &mut setup,
        &AccessRoot {
            path: plan.program.clone(),
            kind: AccessKind::File,
        },
        true,
    )?;

    Ok(setup)
}

fn add_system_path(
    setup: &mut MountSetup,
    read_directories: &mut BTreeSet<PathBuf>,
    path: &Path,
) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };

    if metadata.file_type().is_symlink() {
        let target = fs::read_link(path)?;
        setup
            .symlinks
            .push((target.into_os_string(), path.to_path_buf()));

        let canonical = fs::canonicalize(path)?;
        let kind = access_kind(&canonical, "system path")?;
        add_read_path(setup, read_directories, &canonical, kind)
    } else if metadata.is_dir() {
        add_read_path(setup, read_directories, path, AccessKind::Directory)
    } else if metadata.is_file() {
        add_read_path(setup, read_directories, path, AccessKind::File)
    } else {
        Ok(())
    }
}

fn add_read_path(
    setup: &mut MountSetup,
    read_directories: &mut BTreeSet<PathBuf>,
    path: &Path,
    kind: AccessKind,
) -> io::Result<()> {
    if covered_by_directory(path, read_directories) {
        return Ok(());
    }

    add_mount(
        setup,
        &AccessRoot {
            path: path.to_path_buf(),
            kind,
        },
        true,
    )?;
    if kind == AccessKind::Directory {
        read_directories.insert(path.to_path_buf());
    }
    Ok(())
}

fn add_exact_mount(setup: &mut MountSetup, root: &AccessRoot, read_only: bool) -> io::Result<()> {
    if setup
        .mounts
        .iter()
        .rev()
        .any(|mount| mount.destination == root.path && mount.read_only == read_only)
    {
        return Ok(());
    }
    add_mount(setup, root, read_only)
}

fn add_mount(setup: &mut MountSetup, root: &AccessRoot, read_only: bool) -> io::Result<()> {
    let file = open_pinned_path(&root.path, root.kind)?;
    setup.mounts.push(MountHandle {
        file,
        destination: root.path.clone(),
        read_only,
    });
    Ok(())
}

fn open_pinned_path(path: &Path, expected_kind: AccessKind) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("mount source `{}` is not absolute", path.display()),
        ));
    }

    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("mount source `{}` has no filesystem root", path.display()),
        ));
    }

    let mut current = open_absolute_root()?;
    let mut remaining = components.peekable();
    while let Some(component) = remaining.next() {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("mount source `{}` is not canonical", path.display()),
            ));
        };
        let final_component = remaining.peek().is_none();
        let require_directory = !final_component || expected_kind == AccessKind::Directory;
        current = open_child(&current, name, require_directory)?;
    }

    let metadata = current.metadata()?;
    let valid = match expected_kind {
        AccessKind::File => metadata.is_file(),
        AccessKind::Directory => metadata.is_dir(),
    };
    if !valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "mount source `{}` changed type after validation",
                path.display()
            ),
        ));
    }

    fd::make_inheritable(current.as_raw_fd())?;
    Ok(current)
}

fn open_absolute_root() -> io::Result<File> {
    let root = CString::new("/").expect("constant contains no NUL");
    let descriptor = unsafe { open(root.as_ptr(), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) };
    file_from_descriptor(descriptor, "cannot pin filesystem root")
}

fn open_child(parent: &File, name: &OsStr, directory: bool) -> io::Result<File> {
    let name = CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "mount source component contains NUL",
        )
    })?;
    let mut flags = O_PATH | O_NOFOLLOW | O_CLOEXEC;
    if directory {
        flags |= O_DIRECTORY;
    }
    let descriptor = unsafe { openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    file_from_descriptor(descriptor, "cannot pin mount source component")
}

fn file_from_descriptor(descriptor: RawFd, context: &str) -> io::Result<File> {
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(error.kind(), format!("{context}: {error}")));
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn access_kind(path: &Path, label: &str) -> io::Result<AccessKind> {
    let metadata = fs::metadata(path)?;
    if metadata.is_dir() {
        Ok(AccessKind::Directory)
    } else if metadata.is_file() {
        Ok(AccessKind::File)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} `{}` has unsupported type", path.display()),
        ))
    }
}

fn covered_by_directory(path: &Path, directories: &BTreeSet<PathBuf>) -> bool {
    let mut current = Some(path);
    while let Some(candidate) = current {
        if directories.contains(candidate) {
            return true;
        }
        current = candidate.parent();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::super::compile_args;
    use super::{
        covered_by_directory, open_pinned_path, prepare_mounts, MountHandle, MountSetup,
        COMPATIBILITY_PATHS, NETWORK_PATHS, RUNTIME_PATHS,
    };
    use crate::plan::{AccessKind, AccessRoot, ExecutionPlan, NetworkPolicy};
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn mounted_directory_covers_descendants_only() {
        let directories = BTreeSet::from([PathBuf::from("/usr")]);
        assert!(covered_by_directory(Path::new("/usr/bin/sh"), &directories));
        assert!(!covered_by_directory(Path::new("/home/user"), &directories));
    }

    #[test]
    fn ambient_system_paths_do_not_expose_complete_etc() {
        for path in RUNTIME_PATHS
            .iter()
            .chain(COMPATIBILITY_PATHS.iter())
            .chain(NETWORK_PATHS.iter())
        {
            assert_ne!(*path, "/etc");
        }
        assert!(NETWORK_PATHS.contains(&"/etc/resolv.conf"));
        assert!(!COMPATIBILITY_PATHS.contains(&"/etc/resolv.conf"));
        assert!(!RUNTIME_PATHS.iter().any(|path| path.starts_with("/etc")));
        assert!(!RUNTIME_PATHS.contains(&"/usr"));
        assert!(!RUNTIME_PATHS
            .iter()
            .any(|path| path.starts_with("/usr/local")));
    }

    #[test]
    fn pinned_mount_source_does_not_follow_a_replacement_path() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("mbox-pinned-mount-{}-{nonce}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let source = directory.join("source");
        let moved = directory.join("moved");
        fs::write(&source, b"original").unwrap();

        let pinned = open_pinned_path(&source, AccessKind::File).unwrap();
        let pinned_metadata = pinned.metadata().unwrap();
        fs::rename(&source, &moved).unwrap();
        fs::write(&source, b"replacement").unwrap();

        let moved_metadata = fs::metadata(&moved).unwrap();
        let replacement_metadata = fs::metadata(&source).unwrap();
        assert_eq!(
            (pinned_metadata.dev(), pinned_metadata.ino()),
            (moved_metadata.dev(), moved_metadata.ino())
        );
        assert_ne!(
            (pinned_metadata.dev(), pinned_metadata.ino()),
            (replacement_metadata.dev(), replacement_metadata.ino())
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn writable_descendant_is_mounted_after_readable_parent() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("mbox-mount-order-{}-{nonce}", std::process::id()));
        let writable = root.join("writable");
        fs::create_dir_all(&writable).unwrap();
        let program = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let root = fs::canonicalize(&root).unwrap();
        let writable = fs::canonicalize(&writable).unwrap();
        let plan = ExecutionPlan {
            program: program.clone(),
            argv0: OsString::from("true"),
            arguments: Vec::new(),
            cwd: root.clone(),
            reads: vec![AccessRoot {
                path: root.clone(),
                kind: AccessKind::Directory,
            }],
            writes: vec![AccessRoot {
                path: writable.clone(),
                kind: AccessKind::Directory,
            }],
            tmp: None,
            environment: BTreeMap::new(),
            network: NetworkPolicy::Denied,
            deny_writes: Vec::new(),
            no_child_processes: false,
        };

        let setup = prepare_mounts(&plan).unwrap();
        let parent = setup
            .mounts
            .iter()
            .position(|mount| mount.destination == root && mount.read_only)
            .unwrap();
        let child = setup
            .mounts
            .iter()
            .position(|mount| mount.destination == writable && !mount.read_only)
            .unwrap();
        assert!(
            parent < child,
            "readable parent must precede writable child"
        );
        assert!(!setup.mounts[child + 1..]
            .iter()
            .any(|mount| mount.destination == root));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn compiled_linux_contract_uses_pinned_mounts_and_keeps_terminal_session() {
        let cwd = fs::canonicalize(".").unwrap();
        let program = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let mount_setup = MountSetup {
            symlinks: Vec::new(),
            mounts: vec![MountHandle {
                file: open_pinned_path(&cwd, AccessKind::Directory).unwrap(),
                destination: cwd.clone(),
                read_only: true,
            }],
        };
        let plan = ExecutionPlan {
            program: program.clone(),
            argv0: OsString::from("true"),
            arguments: Vec::new(),
            cwd: cwd.clone(),
            reads: vec![
                AccessRoot {
                    path: cwd,
                    kind: AccessKind::Directory,
                },
                AccessRoot {
                    path: program,
                    kind: AccessKind::File,
                },
            ],
            writes: Vec::new(),
            tmp: None,
            environment: BTreeMap::new(),
            network: NetworkPolicy::Denied,
            deny_writes: Vec::new(),
            no_child_processes: false,
        };
        let args = compile_args(&plan, 9, &mount_setup);
        assert!(args.iter().any(|arg| arg == "--unshare-net"));
        assert!(args.iter().any(|arg| arg == "--disable-userns"));
        assert!(args.iter().any(|arg| arg == "--seccomp"));
        assert!(args.iter().any(|arg| arg == "--ro-bind-fd"));
        assert!(args.iter().any(|arg| arg == "--remount-ro"));
        assert!(!args.iter().any(|arg| arg == "--new-session"));
        assert!(!args.iter().any(|arg| arg == "--ro-bind"));
    }
}
