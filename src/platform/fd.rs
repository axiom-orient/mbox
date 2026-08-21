use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::fd::RawFd;
use std::path::Path;

const EBADF: i32 = 9;

unsafe extern "C" {
    fn close(fd: i32) -> i32;
}

#[cfg(target_os = "linux")]
const F_GETFD: i32 = 1;
#[cfg(target_os = "linux")]
const F_SETFD: i32 = 2;
#[cfg(target_os = "linux")]
const FD_CLOEXEC: i32 = 1;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn fcntl(fd: i32, command: i32, ...) -> i32;
}

pub fn close_inherited(preserve: &[RawFd]) -> io::Result<()> {
    let preserve: BTreeSet<RawFd> = preserve.iter().copied().collect();
    let descriptors = descriptor_snapshot()?;

    for descriptor in descriptors {
        if descriptor <= 2 || preserve.contains(&descriptor) {
            continue;
        }
        let result = unsafe { close(descriptor) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(EBADF) {
                return Err(io::Error::new(
                    error.kind(),
                    format!("cannot close inherited file descriptor {descriptor}: {error}"),
                ));
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn make_inheritable(descriptor: RawFd) -> io::Result<()> {
    let flags = unsafe { fcntl(descriptor, F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { fcntl(descriptor, F_SETFD, flags & !FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn descriptor_snapshot() -> io::Result<Vec<RawFd>> {
    for directory in [Path::new("/proc/self/fd"), Path::new("/dev/fd")] {
        match read_descriptors(directory) {
            Ok(descriptors) => return Ok(descriptors),
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "neither /proc/self/fd nor /dev/fd is available",
    ))
}

fn read_descriptors(directory: &Path) -> io::Result<Vec<RawFd>> {
    let mut descriptors = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if let Ok(descriptor) = name.parse::<RawFd>() {
            descriptors.push(descriptor);
        }
    }
    Ok(descriptors)
}

#[cfg(test)]
mod tests {
    use super::descriptor_snapshot;

    #[test]
    fn descriptor_snapshot_contains_only_nonnegative_numbers() {
        let descriptors = descriptor_snapshot().unwrap();
        assert!(descriptors.iter().all(|descriptor| *descriptor >= 0));
    }
}
