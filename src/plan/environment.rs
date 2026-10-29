use super::roots::absolute_from;
use crate::cli::Request;
use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

pub(super) fn resolve_program(
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
        .unwrap_or_else(|| OsString::from(DEFAULT_PATH));

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

pub(super) fn build_environment(
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
        .or_insert_with(|| OsString::from(DEFAULT_PATH));
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

pub(super) fn is_platform_owned(name: &str) -> bool {
    matches!(name, "PWD" | "OLDPWD" | "TMPDIR")
}

pub(super) fn is_launcher_sensitive(name: &str) -> bool {
    name.starts_with("LD_")
        || name.starts_with("DYLD_")
        || matches!(
            name,
            "BASH_ENV" | "ENV" | "SHELLOPTS" | "BASHOPTS" | "CDPATH" | "GLOBIGNORE"
        )
}
