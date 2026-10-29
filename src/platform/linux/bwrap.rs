use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

const BWRAP_CANDIDATES: &[&str] = &["/usr/bin/bwrap", "/bin/bwrap"];
const MIN_BWRAP_VERSION: Version = Version::new(0, 10, 0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Version {
    major: u32,
    minor: u32,
    patch: u32,
}

impl Version {
    const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

pub(super) fn trusted_bwrap() -> io::Result<PathBuf> {
    for candidate in BWRAP_CANDIDATES {
        let candidate = Path::new(candidate);
        if !candidate.exists() {
            continue;
        }
        let canonical = fs::canonicalize(candidate)?;
        validate_root_owned_executable(&canonical)?;
        return Ok(canonical);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "trusted Bubblewrap was not found at /usr/bin/bwrap or /bin/bwrap",
    ))
}

fn validate_root_owned_executable(path: &Path) -> io::Result<()> {
    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode();
    if !metadata.is_file()
        || metadata.uid() != 0
        || mode & 0o111 == 0
        || mode & 0o022 != 0
        || mode & 0o6000 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "Bubblewrap `{}` must be a non-setuid, non-setgid, root-owned executable not writable by group or others",
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
                    "Bubblewrap parent `{}` must be a root-owned directory not writable by group or others",
                    parent.display()
                ),
            ));
        }
        current = parent.parent();
    }

    Ok(())
}

pub(super) fn validate_bwrap_version(path: &Path) -> io::Result<()> {
    let output = Command::new(path)
        .arg("--version")
        .env_clear()
        .env("LC_ALL", "C")
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "Bubblewrap `{}` could not report its version",
            path.display()
        )));
    }

    let stdout = String::from_utf8(output.stdout).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Bubblewrap `{}` returned a non-UTF-8 version",
                path.display()
            ),
        )
    })?;
    let version = parse_bwrap_version(&stdout).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Bubblewrap `{}` returned an unrecognized version: {}",
                path.display(),
                stdout.trim()
            ),
        )
    })?;
    if version < MIN_BWRAP_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "Bubblewrap {}.{}.{} is too old; mbox requires 0.10.0 or newer",
                version.major, version.minor, version.patch
            ),
        ));
    }
    Ok(())
}

fn parse_bwrap_version(value: &str) -> Option<Version> {
    value.split_whitespace().find_map(parse_version_token)
}

fn parse_version_token(value: &str) -> Option<Version> {
    let value = value.strip_prefix('v').unwrap_or(value);
    let mut components = value.split('.');
    let major = parse_numeric_prefix(components.next()?)?;
    let minor = parse_numeric_prefix(components.next()?)?;
    let patch = parse_numeric_prefix(components.next()?)?;
    Some(Version::new(major, minor, patch))
}

fn parse_numeric_prefix(value: &str) -> Option<u32> {
    let digits: String = value
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_bwrap_version, Version};

    #[test]
    fn supported_bubblewrap_versions_are_parsed() {
        assert_eq!(
            parse_bwrap_version("bubblewrap 0.10.0\n"),
            Some(Version::new(0, 10, 0))
        );
        assert_eq!(
            parse_bwrap_version("bwrap v0.11.2\n"),
            Some(Version::new(0, 11, 2))
        );
        assert_eq!(
            parse_bwrap_version("bubblewrap 0.10.0-1~deb13u1\n"),
            Some(Version::new(0, 10, 0))
        );
        assert!(Version::new(0, 9, 0) < super::MIN_BWRAP_VERSION);
        assert_eq!(parse_bwrap_version("unknown\n"), None);
    }
}
