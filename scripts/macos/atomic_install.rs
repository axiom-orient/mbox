#![deny(unsafe_op_in_unsafe_fn)]

//! Small, Darwin-only release installer.
//!
//! This program is separate from the mbox runtime. The release protocol
//! builds it from this checked-in source, then uses it only after the two
//! clean builds and the native contract have passed. All filesystem mutation
//! is relative to a held, verified release-directory fd. The destination is
//! replaced only by renameat, never written in place.

use std::ffi::{CString, OsStr};
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const DESTINATION_NAME: &str = "mbox";
const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 128 * 1024;
const MAX_TEMP_NAME_ATTEMPTS: u32 = 32;

const AT_FDCWD: RawFd = -2;
const O_WRONLY: i32 = 0x0000_0001;
const O_NONBLOCK: i32 = 0x0000_0004;
const O_CREAT: i32 = 0x0000_0200;
const O_EXCL: i32 = 0x0000_0800;
const O_NOFOLLOW: i32 = 0x0000_0100;
const O_DIRECTORY: i32 = 0x0010_0000;
const O_CLOEXEC: i32 = 0x0100_0000;

#[link(name = "System")]
unsafe extern "C" {
    fn openat(dirfd: RawFd, path: *const i8, flags: i32, mode: u16) -> RawFd;
    fn renameat(olddirfd: RawFd, oldpath: *const i8, newdirfd: RawFd, newpath: *const i8) -> i32;
    fn unlinkat(dirfd: RawFd, path: *const i8, flags: i32) -> i32;
    fn fchmod(fd: RawFd, mode: u16) -> i32;
    fn fsync(fd: RawFd) -> i32;
    fn geteuid() -> u32;
    fn getpid() -> i32;
}

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    nlink: u64,
    mode: u32,
    len: u64,
}

impl Identity {
    fn from_metadata(metadata: &Metadata) -> Self {
        // Every caller obtains this Metadata from File::metadata(), which is
        // fstat(2) against an already-held descriptor rather than a path
        // lookup. No post-open identity check uses path-based metadata.
        use std::os::unix::fs::MetadataExt;
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            nlink: metadata.nlink(),
            mode: metadata.mode(),
            len: metadata.len(),
        }
    }
}

fn io_failure(operation: &str) -> String {
    format!("{operation}: {}", io::Error::last_os_error())
}

fn c_string(value: &OsStr, label: &str) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| format!("{label} contains NUL"))
}

fn canonical_argument(path: &Path, label: &str) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(format!("{label} must be absolute"));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("could not canonicalize {label}: {error}"))?;
    if canonical != path {
        return Err(format!(
            "{label} must already be canonical and symlink-free"
        ));
    }
    Ok(canonical)
}

fn validate_directory(directory: &File) -> Result<Identity> {
    let metadata = directory
        .metadata()
        .map_err(|error| format!("could not stat release directory: {error}"))?;
    let identity = Identity::from_metadata(&metadata);
    let mode = identity.mode & 0o7777;
    if !metadata.is_dir() {
        return Err("release path is not a directory".into());
    }
    if identity.uid != unsafe { geteuid() } {
        return Err("release directory owner mismatch".into());
    }
    if mode & 0o022 != 0 || mode & 0o700 != 0o700 {
        return Err("release directory has unsafe permissions".into());
    }
    Ok(identity)
}

fn validate_regular(
    metadata: &Metadata,
    label: &str,
    directory: Identity,
    require_executable: bool,
) -> Result<Identity> {
    let identity = Identity::from_metadata(metadata);
    let mode = identity.mode & 0o7777;
    if !metadata.is_file() {
        return Err(format!("{label} is not a regular file"));
    }
    if identity.uid != unsafe { geteuid() } {
        return Err(format!("{label} owner mismatch"));
    }
    if identity.dev != directory.dev {
        return Err(format!("{label} is on a different filesystem"));
    }
    if identity.nlink != 1 {
        return Err(format!("{label} must have exactly one hard link"));
    }
    if mode & 0o022 != 0 {
        return Err(format!("{label} is group/other writable"));
    }
    if require_executable && mode & 0o111 == 0 {
        return Err(format!("{label} is not executable"));
    }
    Ok(identity)
}

fn open_release_directory(path: &Path) -> Result<File> {
    let path = c_string(path.as_os_str(), "release directory")?;
    let fd = unsafe {
        openat(
            AT_FDCWD,
            path.as_ptr().cast(),
            O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io_failure("open verified release directory"));
    }
    // SAFETY: fd is the unique descriptor returned by openat and is now owned
    // by this File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_source(path: &Path) -> Result<File> {
    let path = c_string(path.as_os_str(), "source artifact")?;
    let fd = unsafe { openat(AT_FDCWD, path.as_ptr().cast(), O_NOFOLLOW | O_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io_failure("open verified source artifact"));
    }
    // SAFETY: fd is the unique descriptor returned by openat and is now owned
    // by this File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_existing_destination(directory: &File) -> Result<Option<File>> {
    let name = CString::new(DESTINATION_NAME).expect("constant destination name");
    let fd = unsafe {
        openat(
            directory.as_raw_fd(),
            name.as_ptr().cast(),
            O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(format!(
            "open existing destination without following it: {error}"
        ));
    }
    // SAFETY: fd is the unique descriptor returned by openat and is now owned
    // by this File.
    Ok(Some(unsafe { File::from_raw_fd(fd) }))
}

fn open_unique_temp(directory: &File) -> Result<(File, CString)> {
    let pid = unsafe { getpid() };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before Unix epoch: {error}"))?;
    let base = format!(
        ".mbox.atomic.{pid}.{}.{}",
        now.as_secs(),
        now.subsec_nanos()
    );
    for attempt in 0..MAX_TEMP_NAME_ATTEMPTS {
        let name = CString::new(format!("{base}.{attempt}")).expect("generated temp name");
        let fd = unsafe {
            openat(
                directory.as_raw_fd(),
                name.as_ptr().cast(),
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                0o600,
            )
        };
        if fd >= 0 {
            // SAFETY: fd is the unique descriptor returned by openat and is
            // now owned by this File.
            return Ok((unsafe { File::from_raw_fd(fd) }, name));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(format!("create unique release temp file: {error}"));
        }
    }
    Err("could not create a unique release temp file".into())
}

struct TempGuard {
    directory_fd: RawFd,
    name: CString,
    active: bool,
}

impl TempGuard {
    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = unsafe { unlinkat(self.directory_fd, self.name.as_ptr().cast(), 0) };
        }
    }
}

fn sync_file(file: &File, label: &str) -> Result<()> {
    if unsafe { fsync(file.as_raw_fd()) } != 0 {
        return Err(io_failure(label));
    }
    Ok(())
}

fn set_executable(file: &File) -> Result<()> {
    if unsafe { fchmod(file.as_raw_fd(), 0o755) } != 0 {
        return Err(io_failure("set installed artifact mode"));
    }
    Ok(())
}

fn copy_checked(source: &mut File, destination: &mut File, expected: Identity) -> Result<Identity> {
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut total = 0_u64;
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|error| format!("read release artifact: {error}"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| "release artifact size overflow".to_string())?;
        if total > MAX_ARTIFACT_BYTES {
            return Err("release artifact exceeds bounded copy size".into());
        }
        destination
            .write_all(&buffer[..read])
            .map_err(|error| format!("write release temp artifact: {error}"))?;
    }
    set_executable(destination)?;
    sync_file(destination, "fsync release temp artifact")?;

    let source_after = Identity::from_metadata(
        &source
            .metadata()
            .map_err(|error| format!("re-stat release artifact: {error}"))?,
    );
    if source_after != expected {
        return Err("release artifact changed while it was copied".into());
    }
    let temp = Identity::from_metadata(
        &destination
            .metadata()
            .map_err(|error| format!("re-stat release temp artifact: {error}"))?,
    );
    if !destination_matches(temp, expected.dev, total, 0o755) {
        return Err("release temp artifact identity or mode is unsafe".into());
    }
    Ok(temp)
}

fn destination_matches(identity: Identity, device: u64, length: u64, mode: u32) -> bool {
    identity.dev == device
        && identity.uid == unsafe { geteuid() }
        && identity.nlink == 1
        && identity.len == length
        && identity.mode & 0o7777 == mode
}

fn rename_temp(directory: &File, temp: &CString) -> Result<()> {
    let destination = CString::new(DESTINATION_NAME).expect("constant destination name");
    if unsafe {
        renameat(
            directory.as_raw_fd(),
            temp.as_ptr().cast(),
            directory.as_raw_fd(),
            destination.as_ptr().cast(),
        )
    } != 0
    {
        return Err(io_failure("atomically rename release artifact"));
    }
    Ok(())
}

fn verify_installed(directory: &File, expected: Identity) -> Result<()> {
    let destination = open_existing_destination(directory)?
        .ok_or_else(|| "installed release artifact disappeared".to_string())?;
    let actual = Identity::from_metadata(
        &destination
            .metadata()
            .map_err(|error| format!("stat installed release artifact: {error}"))?,
    );
    if actual != expected {
        return Err("installed release artifact identity changed after rename".into());
    }
    if !destination_matches(actual, expected.dev, expected.len, 0o755) {
        return Err("installed release artifact has unsafe final metadata".into());
    }
    Ok(())
}

fn install(source_path: &Path, release_path: &Path) -> Result<()> {
    let source_path = canonical_argument(source_path, "source artifact")?;
    let release_path = canonical_argument(release_path, "release directory")?;
    let directory = open_release_directory(&release_path)?;
    let directory_identity = validate_directory(&directory)?;
    let mut source = open_source(&source_path)?;
    let source_identity = validate_regular(
        &source
            .metadata()
            .map_err(|error| format!("stat source artifact: {error}"))?,
        "source artifact",
        directory_identity,
        true,
    )?;

    if let Some(destination) = open_existing_destination(&directory)? {
        validate_regular(
            &destination
                .metadata()
                .map_err(|error| format!("stat existing destination: {error}"))?,
            "existing destination",
            directory_identity,
            true,
        )?;
    }

    let (mut temporary, temporary_name) = open_unique_temp(&directory)?;
    let mut temporary_guard = TempGuard {
        directory_fd: directory.as_raw_fd(),
        name: temporary_name.clone(),
        active: true,
    };
    let temporary_identity = copy_checked(&mut source, &mut temporary, source_identity)?;
    rename_temp(&directory, &temporary_name)?;
    temporary_guard.disarm();
    sync_file(&directory, "fsync release directory")?;
    verify_installed(&directory, temporary_identity)
}

fn usage() -> ! {
    eprintln!("usage: mbox-atomic-install SOURCE_ARTIFACT RELEASE_DIRECTORY");
    std::process::exit(2);
}

fn main() {
    let arguments: Vec<_> = std::env::args_os().collect();
    if arguments.len() != 3 {
        usage();
    }
    let result = install(Path::new(&arguments[1]), Path::new(&arguments[2]));
    if let Err(error) = result {
        eprintln!("mbox-atomic-install: FAIL: {error}");
        std::process::exit(1);
    }
    println!("mbox-atomic-install: installed {DESTINATION_NAME}");
}
