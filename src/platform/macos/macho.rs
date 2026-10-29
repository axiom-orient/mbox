use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::path::Path;

pub(super) fn validate_native_executable(path: &Path) -> io::Result<()> {
    let link_metadata = fs::symlink_metadata(path)?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "strict target `{}` must be a regular native Mach-O executable",
                path.display()
            ),
        ));
    }
    if link_metadata.permissions().mode() & 0o111 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("strict target `{}` is not executable", path.display()),
        ));
    }

    let file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let (slice_offset, slice_size) = select_native_slice(&file, file_len).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "strict target `{}` is not a structurally valid native Mach-O: {error}",
                path.display()
            ),
        )
    })?;
    validate_thin_slice(&file, file_len, slice_offset, slice_size)
}

const MH_EXECUTE: u32 = 0x2;
const LC_UNIXTHREAD: u32 = 0x5;
const LC_MAIN: u32 = 0x8000_0028;
#[cfg(target_arch = "x86_64")]
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const FAT_ARCH_SIZE_32: u64 = 20;
const FAT_ARCH_SIZE_64: u64 = 32;
const MAX_FAT_ARCHES: u32 = 256;
const MAX_LOAD_COMMANDS: u32 = 4096;
const MAX_LOAD_COMMAND_BYTES: u64 = 64 * 1024 * 1024;
const HOST_BYTE_ORDER: ByteOrder = ByteOrder::Little;

#[cfg(target_arch = "aarch64")]
const HOST_CPU_TYPE: u32 = CPU_TYPE_ARM64;
#[cfg(target_arch = "x86_64")]
const HOST_CPU_TYPE: u32 = CPU_TYPE_X86_64;

#[cfg(target_arch = "aarch64")]
const HOST_THREAD_STATE_FLAVOR: u32 = 6; // ARM_THREAD_STATE64
#[cfg(target_arch = "aarch64")]
const HOST_THREAD_STATE_COUNT: u32 = 68; // ARM_THREAD_STATE64_COUNT
#[cfg(target_arch = "x86_64")]
const HOST_THREAD_STATE_FLAVOR: u32 = 4; // x86_THREAD_STATE64
#[cfg(target_arch = "x86_64")]
const HOST_THREAD_STATE_COUNT: u32 = 42; // x86_THREAD_STATE64_COUNT

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ByteOrder {
    Big,
    Little,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MachMagic {
    Thin32(ByteOrder),
    Thin64(ByteOrder),
    Fat32(ByteOrder),
    Fat64(ByteOrder),
}

#[derive(Clone, Copy, Debug)]
struct FatSlice {
    offset: u64,
    size: u64,
}

fn select_native_slice(file: &File, file_len: u64) -> io::Result<(u64, u64)> {
    let magic_bytes = read_bytes(file, 0, 4)?;
    let magic = [
        magic_bytes[0],
        magic_bytes[1],
        magic_bytes[2],
        magic_bytes[3],
    ];
    let Some(kind) = parse_mach_magic(magic) else {
        return invalid_image("unknown Mach-O magic");
    };
    match kind {
        MachMagic::Thin32(_) | MachMagic::Thin64(_) => Ok((0, file_len)),
        MachMagic::Fat32(order) => select_fat_slice(file, file_len, order, false),
        MachMagic::Fat64(order) => select_fat_slice(file, file_len, order, true),
    }
}

fn select_fat_slice(
    file: &File,
    file_len: u64,
    order: ByteOrder,
    is_fat64: bool,
) -> io::Result<(u64, u64)> {
    const FAT_HEADER_SIZE: u64 = 8;
    let count = read_u32(file, 4, order)?;
    if count == 0 || count > MAX_FAT_ARCHES {
        return invalid_image("fat architecture count is zero or exceeds the bounded limit");
    }
    let entry_size = if is_fat64 {
        FAT_ARCH_SIZE_64
    } else {
        FAT_ARCH_SIZE_32
    };
    let table_size = u64::from(count)
        .checked_mul(entry_size)
        .ok_or_else(|| invalid_error("fat architecture table size overflow"))?;
    let table_end = FAT_HEADER_SIZE
        .checked_add(table_size)
        .ok_or_else(|| invalid_error("fat architecture table end overflow"))?;
    if table_end > file_len {
        return invalid_image("fat architecture table is truncated");
    }

    let mut slices: Vec<FatSlice> = Vec::with_capacity(count as usize);
    let mut selected = None;
    for index in 0..count {
        let entry_offset = FAT_HEADER_SIZE + u64::from(index) * entry_size;
        let bytes = read_bytes(file, entry_offset, entry_size as usize)?;
        let cputype = read_u32_from(&bytes, 0, order)?;
        let slice_offset = if is_fat64 {
            read_u64_from(&bytes, 8, order)?
        } else {
            u64::from(read_u32_from(&bytes, 8, order)?)
        };
        let slice_size = if is_fat64 {
            read_u64_from(&bytes, 16, order)?
        } else {
            u64::from(read_u32_from(&bytes, 12, order)?)
        };
        let align = if is_fat64 {
            read_u32_from(&bytes, 24, order)?
        } else {
            read_u32_from(&bytes, 16, order)?
        };
        if is_fat64 && read_u32_from(&bytes, 28, order)? != 0 {
            return invalid_image("fat64 architecture reserved field is nonzero");
        }
        if align >= 64 {
            return invalid_image("fat slice alignment exponent is out of range");
        }
        let alignment = 1_u64 << align;
        if slice_offset % alignment != 0 {
            return invalid_image("fat slice offset violates its alignment");
        }
        if slice_size == 0 {
            return invalid_image("fat slice has zero size");
        }
        if slice_offset < table_end {
            return invalid_image("fat slice overlaps the architecture table");
        }
        let slice_end = slice_offset
            .checked_add(slice_size)
            .ok_or_else(|| invalid_error("fat slice offset plus size overflows"))?;
        if slice_end > file_len {
            return invalid_image("fat slice is outside the file");
        }
        for previous in &slices {
            let previous_end = previous
                .offset
                .checked_add(previous.size)
                .ok_or_else(|| invalid_error("fat slice range overflow"))?;
            if slice_offset < previous_end && previous.offset < slice_end {
                return invalid_image("fat slices overlap");
            }
        }
        let slice = FatSlice {
            offset: slice_offset,
            size: slice_size,
        };
        if cputype == HOST_CPU_TYPE && selected.is_none() {
            selected = Some((slice_offset, slice_size));
        }
        slices.push(slice);
    }

    let Some((slice_offset, slice_size)) = selected else {
        return invalid_image("fat file has no executable slice for the current host CPU");
    };
    // The loop above checks all table/range invariants. Validate only the
    // kernel-selected host CPU slice; other architecture slices are not
    // candidates for this invocation.
    Ok((slice_offset, slice_size))
}

fn validate_thin_slice(
    file: &File,
    file_len: u64,
    slice_offset: u64,
    slice_size: u64,
) -> io::Result<()> {
    let slice_end = slice_offset
        .checked_add(slice_size)
        .ok_or_else(|| invalid_error("Mach-O slice range overflow"))?;
    if slice_end > file_len {
        return invalid_image("Mach-O slice is outside the file");
    }
    let magic_bytes = read_bytes(file, slice_offset, 4)?;
    let magic = [
        magic_bytes[0],
        magic_bytes[1],
        magic_bytes[2],
        magic_bytes[3],
    ];
    let Some(kind) = parse_mach_magic(magic) else {
        return invalid_image("selected slice is not a thin Mach-O image");
    };
    let (order, is64) = match kind {
        MachMagic::Thin32(order) => (order, false),
        MachMagic::Thin64(order) => (order, true),
        MachMagic::Fat32(_) | MachMagic::Fat64(_) => {
            return invalid_image("selected slice is a nested fat Mach-O image")
        }
    };
    if order != HOST_BYTE_ORDER {
        return invalid_image("big-endian Mach-O is not executable on the current host");
    }
    let header_size = if is64 { 32_u64 } else { 28_u64 };
    if slice_size < header_size {
        return invalid_image("Mach-O header is truncated");
    }
    if !is64 {
        return invalid_image("32-bit Mach-O is not executable for the current 64-bit host");
    }
    let header = read_bytes(file, slice_offset, header_size as usize)?;
    let cputype = read_u32_from(&header, 4, order)?;
    if cputype != HOST_CPU_TYPE {
        return invalid_image("Mach-O CPU type does not match the current host");
    }
    let filetype = read_u32_from(&header, 12, order)?;
    if filetype != MH_EXECUTE {
        return invalid_image("Mach-O file type is not MH_EXECUTE");
    }
    let ncmds = read_u32_from(&header, 16, order)?;
    let sizeofcmds = u64::from(read_u32_from(&header, 20, order)?);
    if ncmds == 0 || ncmds > MAX_LOAD_COMMANDS {
        return invalid_image("Mach-O load-command count is zero or exceeds the bounded limit");
    }
    if sizeofcmds == 0 || sizeofcmds > MAX_LOAD_COMMAND_BYTES {
        return invalid_image(
            "Mach-O load-command byte count is zero or exceeds the bounded limit",
        );
    }
    let commands_start = slice_offset
        .checked_add(header_size)
        .ok_or_else(|| invalid_error("Mach-O load-command offset overflow"))?;
    let commands_end = commands_start
        .checked_add(sizeofcmds)
        .ok_or_else(|| invalid_error("Mach-O load-command range overflow"))?;
    if commands_end > slice_end {
        return invalid_image("Mach-O load-command region is outside the selected slice");
    }

    let mut cursor = commands_start;
    let mut has_entry = false;
    for _ in 0..ncmds {
        if cursor.checked_add(8).is_none_or(|end| end > commands_end) {
            return invalid_image("Mach-O load-command header is truncated");
        }
        let command = read_bytes(file, cursor, 8)?;
        let cmd = read_u32_from(&command, 0, order)?;
        let cmdsize = u64::from(read_u32_from(&command, 4, order)?);
        let command_alignment = if is64 { 8 } else { 4 };
        if cmdsize < 8 || cmdsize % command_alignment != 0 {
            return invalid_image("Mach-O load-command size is too small or unaligned");
        }
        let next = cursor
            .checked_add(cmdsize)
            .ok_or_else(|| invalid_error("Mach-O load-command range overflow"))?;
        if next > commands_end {
            return invalid_image("Mach-O load command exceeds the bounded command region");
        }
        if cmd == LC_MAIN {
            if cmdsize < 24 {
                return invalid_image("LC_MAIN command is truncated");
            }
            let entry_offset = cursor
                .checked_add(8)
                .ok_or_else(|| invalid_error("LC_MAIN entry offset overflow"))?;
            let entry = read_u64(file, entry_offset, order)?;
            if entry >= slice_size {
                return invalid_image("LC_MAIN entry offset is outside the selected slice");
            }
            has_entry = true;
        } else if cmd == LC_UNIXTHREAD {
            validate_unixthread(file, cursor, cmdsize, order)?;
            has_entry = true;
        }
        cursor = next;
    }
    if cursor != commands_end {
        return invalid_image("Mach-O load-command progression does not consume sizeofcmds");
    }
    if !has_entry {
        return invalid_image("Mach-O has no LC_MAIN or valid LC_UNIXTHREAD entry command");
    }
    Ok(())
}

fn validate_unixthread(
    file: &File,
    command_offset: u64,
    command_size: u64,
    order: ByteOrder,
) -> io::Result<()> {
    if command_size < 16 {
        return invalid_image("LC_UNIXTHREAD command is truncated");
    }
    let state_header_offset = command_offset
        .checked_add(8)
        .ok_or_else(|| invalid_error("LC_UNIXTHREAD state header offset overflow"))?;
    let header = read_bytes(file, state_header_offset, 8)?;
    let flavor = read_u32_from(&header, 0, order)?;
    let count = read_u32_from(&header, 4, order)?;
    if flavor != HOST_THREAD_STATE_FLAVOR || count != HOST_THREAD_STATE_COUNT {
        return invalid_image("LC_UNIXTHREAD does not contain the current host thread state");
    }
    let state_bytes = u64::from(count)
        .checked_mul(4)
        .ok_or_else(|| invalid_error("LC_UNIXTHREAD state size overflow"))?;
    let required = 16_u64
        .checked_add(state_bytes)
        .ok_or_else(|| invalid_error("LC_UNIXTHREAD command size overflow"))?;
    if required > command_size {
        return invalid_image("LC_UNIXTHREAD thread state exceeds command size");
    }
    Ok(())
}

fn read_bytes(file: &File, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0_u8; len];
    let mut read = 0_usize;
    while read < len {
        let position = offset
            .checked_add(read as u64)
            .ok_or_else(|| invalid_error("Mach-O positioned-read offset overflow"))?;
        let count = file.read_at(&mut bytes[read..], position)?;
        if count == 0 {
            return invalid_image("Mach-O positioned read reached EOF");
        }
        read += count;
    }
    Ok(bytes)
}

fn read_u32(file: &File, offset: u64, order: ByteOrder) -> io::Result<u32> {
    let bytes = read_bytes(file, offset, 4)?;
    read_u32_from(&bytes, 0, order)
}

fn read_u64(file: &File, offset: u64, order: ByteOrder) -> io::Result<u64> {
    let bytes = read_bytes(file, offset, 8)?;
    read_u64_from(&bytes, 0, order)
}

fn read_u32_from(bytes: &[u8], offset: usize, order: ByteOrder) -> io::Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| invalid_error("Mach-O byte-slice offset overflow"))?;
    let Some(value) = bytes.get(offset..end) else {
        return invalid_image("Mach-O byte-slice read is outside the bounded buffer");
    };
    let array = [value[0], value[1], value[2], value[3]];
    Ok(match order {
        ByteOrder::Big => u32::from_be_bytes(array),
        ByteOrder::Little => u32::from_le_bytes(array),
    })
}

fn read_u64_from(bytes: &[u8], offset: usize, order: ByteOrder) -> io::Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| invalid_error("Mach-O byte-slice offset overflow"))?;
    let Some(value) = bytes.get(offset..end) else {
        return invalid_image("Mach-O byte-slice read is outside the bounded buffer");
    };
    let array = [
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ];
    Ok(match order {
        ByteOrder::Big => u64::from_be_bytes(array),
        ByteOrder::Little => u64::from_le_bytes(array),
    })
}

fn invalid_image<T>(message: &str) -> io::Result<T> {
    Err(invalid_error(message))
}

fn invalid_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn parse_mach_magic(magic: [u8; 4]) -> Option<MachMagic> {
    Some(match magic {
        [0xfe, 0xed, 0xfa, 0xce] => MachMagic::Thin32(ByteOrder::Big),
        [0xce, 0xfa, 0xed, 0xfe] => MachMagic::Thin32(ByteOrder::Little),
        [0xfe, 0xed, 0xfa, 0xcf] => MachMagic::Thin64(ByteOrder::Big),
        [0xcf, 0xfa, 0xed, 0xfe] => MachMagic::Thin64(ByteOrder::Little),
        // Apple SDK mach_header_64/fat_header documents the on-disk fat
        // header and architecture table as big-endian. The CIGAM byte
        // sequences are host-read swap constants, not alternate on-disk
        // encodings accepted by this native strict preflight.
        [0xca, 0xfe, 0xba, 0xbe] => MachMagic::Fat32(ByteOrder::Big),
        [0xca, 0xfe, 0xba, 0xbf] => MachMagic::Fat64(ByteOrder::Big),
        _ => return None,
    })
}

#[cfg(test)]
fn is_macho_magic(magic: [u8; 4]) -> bool {
    parse_mach_magic(magic).is_some()
}

#[cfg(test)]
mod tests {
    use super::{
        is_macho_magic, validate_native_executable, ByteOrder, HOST_CPU_TYPE, LC_MAIN, MH_EXECUTE,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static IMAGE_TEST_ID: AtomicUsize = AtomicUsize::new(0);

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32, order: ByteOrder) {
        let encoded = match order {
            ByteOrder::Big => value.to_be_bytes(),
            ByteOrder::Little => value.to_le_bytes(),
        };
        bytes[offset..offset + 4].copy_from_slice(&encoded);
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64, order: ByteOrder) {
        let encoded = match order {
            ByteOrder::Big => value.to_be_bytes(),
            ByteOrder::Little => value.to_le_bytes(),
        };
        bytes[offset..offset + 8].copy_from_slice(&encoded);
    }

    fn thin_image(
        order: ByteOrder,
        cpu: u32,
        filetype: u32,
        commands: &[u8],
        ncmds: u32,
        sizeofcmds: u32,
    ) -> Vec<u8> {
        let mut image = vec![0_u8; 32 + commands.len()];
        let magic = match order {
            ByteOrder::Big => [0xfe, 0xed, 0xfa, 0xcf],
            ByteOrder::Little => [0xcf, 0xfa, 0xed, 0xfe],
        };
        image[..4].copy_from_slice(&magic);
        put_u32(&mut image, 4, cpu, order);
        put_u32(&mut image, 8, 0, order);
        put_u32(&mut image, 12, filetype, order);
        put_u32(&mut image, 16, ncmds, order);
        put_u32(&mut image, 20, sizeofcmds, order);
        put_u32(&mut image, 24, 0, order);
        put_u32(&mut image, 28, 0, order);
        image[32..].copy_from_slice(commands);
        image
    }

    fn valid_thin_image() -> Vec<u8> {
        let mut main = vec![0_u8; 24];
        put_u32(&mut main, 0, LC_MAIN, ByteOrder::Little);
        put_u32(&mut main, 4, 24, ByteOrder::Little);
        put_u64(&mut main, 8, 32, ByteOrder::Little);
        put_u64(&mut main, 16, 0, ByteOrder::Little);
        thin_image(
            ByteOrder::Little,
            HOST_CPU_TYPE,
            MH_EXECUTE,
            &main,
            1,
            main.len() as u32,
        )
    }

    fn image_path(label: &str, image: &[u8]) -> PathBuf {
        let id = IMAGE_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "mbox-native-image-{label}-{}-{id}",
            std::process::id()
        ));
        fs::write(&path, image).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    fn assert_invalid_image(label: &str, image: &[u8]) {
        let path = image_path(label, image);
        let result = validate_native_executable(&path);
        fs::remove_file(&path).unwrap();
        assert!(result.is_err(), "{label} unexpectedly passed preflight");
    }

    #[test]
    fn recognizes_native_mach_and_on_disk_big_endian_fat_magic() {
        for magic in [
            [0xfe, 0xed, 0xfa, 0xce],
            [0xce, 0xfa, 0xed, 0xfe],
            [0xfe, 0xed, 0xfa, 0xcf],
            [0xcf, 0xfa, 0xed, 0xfe],
            [0xca, 0xfe, 0xba, 0xbe],
            [0xca, 0xfe, 0xba, 0xbf],
        ] {
            assert!(is_macho_magic(magic));
        }
        for cigam in [[0xbe, 0xba, 0xfe, 0xca], [0xbf, 0xba, 0xfe, 0xca]] {
            assert!(!is_macho_magic(cigam));
        }
        assert!(!is_macho_magic(*b"#! /"));
        assert!(!is_macho_magic(*b"ELF\0"));
    }

    #[test]
    fn accepts_a_structurally_valid_native_thin_image() {
        let path = image_path("valid-thin", &valid_thin_image());
        validate_native_executable(&path).unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_truncated_headers_and_magic_only_images() {
        assert_invalid_image("magic-only", &[0xcf, 0xfa, 0xed, 0xfe]);
        let mut truncated_64 = vec![0_u8; 31];
        truncated_64[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        assert_invalid_image("truncated-64", &truncated_64);
        let mut truncated_32 = vec![0_u8; 27];
        truncated_32[..4].copy_from_slice(&[0xce, 0xfa, 0xed, 0xfe]);
        assert_invalid_image("truncated-32", &truncated_32);
    }

    #[test]
    fn rejects_wrong_host_cpu_filetype_and_endian() {
        let mut wrong_cpu = valid_thin_image();
        put_u32(&mut wrong_cpu, 4, 7, ByteOrder::Little);
        assert_invalid_image("wrong-cpu", &wrong_cpu);

        let mut wrong_filetype = valid_thin_image();
        put_u32(&mut wrong_filetype, 12, 6, ByteOrder::Little);
        assert_invalid_image("wrong-filetype", &wrong_filetype);

        let big_endian = thin_image(
            ByteOrder::Big,
            HOST_CPU_TYPE,
            MH_EXECUTE,
            &valid_thin_image()[32..],
            1,
            24,
        );
        assert_invalid_image("wrong-endian", &big_endian);

        let mut wrong_width = valid_thin_image();
        wrong_width[..4].copy_from_slice(&[0xce, 0xfa, 0xed, 0xfe]);
        assert_invalid_image("wrong-width", &wrong_width);

        let mut thin32_host_cpu = thin_image(
            ByteOrder::Little,
            HOST_CPU_TYPE,
            MH_EXECUTE,
            &valid_thin_image()[32..],
            1,
            24,
        );
        thin32_host_cpu[..4].copy_from_slice(&[0xce, 0xfa, 0xed, 0xfe]);
        assert_invalid_image("thin32-host-cpu", &thin32_host_cpu);
    }

    #[test]
    fn rejects_load_command_bounds_size_alignment_and_missing_entry() {
        let mut out_of_bounds = valid_thin_image();
        put_u32(&mut out_of_bounds, 20, 32, ByteOrder::Little);
        assert_invalid_image("load-region-bounds", &out_of_bounds);

        let mut short_command = valid_thin_image();
        put_u32(&mut short_command, 36, 4, ByteOrder::Little);
        assert_invalid_image("load-command-short", &short_command);

        let mut unaligned_command = valid_thin_image();
        put_u32(&mut unaligned_command, 36, 10, ByteOrder::Little);
        assert_invalid_image("load-command-unaligned", &unaligned_command);

        let mut unaligned_64_command = valid_thin_image();
        put_u32(&mut unaligned_64_command, 36, 12, ByteOrder::Little);
        assert_invalid_image("load-command-64-alignment", &unaligned_64_command);

        let mut no_entry_command = vec![0_u8; 8];
        put_u32(&mut no_entry_command, 0, 1, ByteOrder::Little);
        put_u32(&mut no_entry_command, 4, 8, ByteOrder::Little);
        let no_entry = thin_image(
            ByteOrder::Little,
            HOST_CPU_TYPE,
            MH_EXECUTE,
            &no_entry_command,
            1,
            8,
        );
        assert_invalid_image("missing-entry", &no_entry);

        let mut short_main = valid_thin_image();
        put_u32(&mut short_main, 36, 16, ByteOrder::Little);
        assert_invalid_image("short-main", &short_main);

        let mut short_thread = vec![0_u8; 16];
        put_u32(&mut short_thread, 0, 5, ByteOrder::Little);
        put_u32(&mut short_thread, 4, 16, ByteOrder::Little);
        put_u32(&mut short_thread, 8, 6, ByteOrder::Little);
        put_u32(&mut short_thread, 12, 68, ByteOrder::Little);
        let thread = thin_image(
            ByteOrder::Little,
            HOST_CPU_TYPE,
            MH_EXECUTE,
            &short_thread,
            1,
            16,
        );
        assert_invalid_image("short-unixthread", &thread);
    }

    fn fat32_image_with_magic_and_order(
        magic: [u8; 4],
        order: ByteOrder,
        entries: &[(u32, u32, u32, u32)],
        file_len: usize,
    ) -> Vec<u8> {
        let table_end = 8 + entries.len() * 20;
        let mut image = vec![0_u8; file_len.max(table_end)];
        image[..4].copy_from_slice(&magic);
        put_u32(&mut image, 4, entries.len() as u32, order);
        for (index, (cpu, offset, size, align)) in entries.iter().enumerate() {
            let at = 8 + index * 20;
            put_u32(&mut image, at, *cpu, order);
            put_u32(&mut image, at + 4, 0, order);
            put_u32(&mut image, at + 8, *offset, order);
            put_u32(&mut image, at + 12, *size, order);
            put_u32(&mut image, at + 16, *align, order);
        }
        image
    }

    fn fat32_image(entries: &[(u32, u32, u32, u32)], file_len: usize) -> Vec<u8> {
        fat32_image_with_magic_and_order(
            [0xca, 0xfe, 0xba, 0xbe],
            ByteOrder::Big,
            entries,
            file_len,
        )
    }

    fn fat64_image_with_magic_and_order(
        magic: [u8; 4],
        order: ByteOrder,
        cpu: u32,
        offset: u64,
        payload: &[u8],
        reserved: u32,
    ) -> Vec<u8> {
        let mut image = vec![0_u8; offset as usize + payload.len()];
        image[..4].copy_from_slice(&magic);
        put_u32(&mut image, 4, 1, order);
        put_u32(&mut image, 8, cpu, order);
        put_u32(&mut image, 12, 0, order);
        put_u64(&mut image, 16, offset, order);
        put_u64(&mut image, 24, payload.len() as u64, order);
        put_u32(&mut image, 32, 12, order);
        put_u32(&mut image, 36, reserved, order);
        image[offset as usize..].copy_from_slice(payload);
        image
    }

    #[test]
    fn rejects_malformed_fat_tables_slices_overlap_and_no_host_slice() {
        assert_invalid_image("fat-truncated", &[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1]);

        let no_host = fat32_image(&[(7, 0x1000, 1, 12)], 0x1001);
        assert_invalid_image("fat-no-host", &no_host);

        let out_of_range = fat32_image(&[(HOST_CPU_TYPE, 0x1000, 0x100, 12)], 0x1001);
        assert_invalid_image("fat-out-of-range", &out_of_range);

        let unaligned = fat32_image(&[(HOST_CPU_TYPE, 0x1001, 1, 12)], 0x1002);
        assert_invalid_image("fat-unaligned", &unaligned);

        let overlap = fat32_image(
            &[(HOST_CPU_TYPE, 0x1000, 0x100, 12), (7, 0x1080, 0x100, 7)],
            0x1180,
        );
        assert_invalid_image("fat-overlap", &overlap);

        let fat64 = fat64_image_with_magic_and_order(
            [0xca, 0xfe, 0xba, 0xbf],
            ByteOrder::Big,
            HOST_CPU_TYPE,
            0x1000,
            &[0],
            1,
        );
        assert_invalid_image("fat64-reserved", &fat64);

        let payload = valid_thin_image();
        let cigam32 = fat32_image_with_magic_and_order(
            [0xbe, 0xba, 0xfe, 0xca],
            ByteOrder::Little,
            &[(HOST_CPU_TYPE, 0x1000, payload.len() as u32, 12)],
            0x1000 + payload.len(),
        );
        assert_invalid_image("fat32-cigam", &cigam32);

        let cigam64 = fat64_image_with_magic_and_order(
            [0xbf, 0xba, 0xfe, 0xca],
            ByteOrder::Little,
            HOST_CPU_TYPE,
            0x1000,
            &payload,
            0,
        );
        assert_invalid_image("fat64-cigam", &cigam64);
    }

    #[test]
    fn accepts_a_structurally_valid_fat_host_slice() {
        let payload = valid_thin_image();
        let offset = 0x1000_u32;
        let mut image = fat32_image(
            &[(HOST_CPU_TYPE, offset, payload.len() as u32, 12)],
            offset as usize + payload.len(),
        );
        image[offset as usize..].copy_from_slice(&payload);
        let path = image_path("valid-fat", &image);
        validate_native_executable(&path).unwrap();
        fs::remove_file(path).unwrap();
    }
}
