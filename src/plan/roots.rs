use super::{AccessKind, AccessRoot};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub(super) fn deny_write_root(path: &Path, base: &Path) -> Result<AccessRoot, String> {
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

pub(super) fn reject_hardlinks_under(root: &AccessRoot) -> Result<(), String> {
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

pub(super) fn reject_hardlinked_regular_file(path: &Path, label: &str) -> Result<(), String> {
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

pub(super) fn canonical_directory(
    path: &Path,
    base: &Path,
    label: &str,
) -> Result<PathBuf, String> {
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

pub(super) fn access_root(path: &Path, base: &Path, label: &str) -> Result<AccessRoot, String> {
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

pub(super) fn absolute_from(path: &Path, base: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

pub(super) fn minimize_roots(mut roots: Vec<AccessRoot>) -> Vec<AccessRoot> {
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

pub(super) struct AuthorityIndex {
    exact: BTreeSet<PathBuf>,
    directories: BTreeSet<PathBuf>,
}

impl AuthorityIndex {
    pub(super) fn new(roots: &[AccessRoot]) -> Self {
        let exact = roots.iter().map(|root| root.path.clone()).collect();
        let directories = roots
            .iter()
            .filter(|root| root.kind == AccessKind::Directory)
            .map(|root| root.path.clone())
            .collect();
        Self { exact, directories }
    }

    pub(super) fn covers(&self, path: &Path) -> bool {
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
