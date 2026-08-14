use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub fn read_game_relative_file(
    game_root: &Path,
    relative_path: &str,
    max_bytes: u64,
) -> io::Result<Vec<u8>> {
    let mut file = open_file_beneath(game_root, relative_path)?;
    let before = file.metadata()?;
    if !before.file_type().is_file() {
        return Err(unsafe_entry("final path component is not a regular file"));
    }
    if before.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            "file exceeds the safe read limit",
        ));
    }

    let capacity = usize::try_from(before.len())
        .map_err(|_| io::Error::new(io::ErrorKind::FileTooLarge, "file is too large to read"))?;
    let mut contents = Vec::with_capacity(capacity);
    file.by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut contents)?;
    if contents.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            "file exceeds the safe read limit",
        ));
    }
    let after = file.metadata()?;
    if contents.len() as u64 != before.len() || after.len() != before.len() {
        return Err(changed_file("file changed while it was being read"));
    }
    Ok(contents)
}

pub fn replace_game_relative_file(
    game_root: &Path,
    relative_path: &str,
    expected_size: u64,
    expected_sha256: &str,
    replacement: &[u8],
) -> io::Result<()> {
    if expected_sha256.len() != 64 || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid_path(
            "expected SHA-256 is not a 64-digit hex digest",
        ));
    }
    let components = validated_relative_components(relative_path)?;
    platform::replace_file_beneath(
        game_root,
        &components,
        expected_size,
        expected_sha256,
        replacement,
    )
}

fn validated_relative_components(relative_path: &str) -> io::Result<Vec<&str>> {
    if relative_path.is_empty() {
        return Err(invalid_path("empty relative file path"));
    }
    relative_path
        .split('/')
        .map(|component| {
            if component.is_empty() || matches!(component, "." | "..") {
                return Err(invalid_path("relative file path has an invalid component"));
            }
            if component.contains(['\\', ':', '\0']) {
                return Err(invalid_path(
                    "relative file path contains an alternate separator, stream, or NUL",
                ));
            }
            Ok(component)
        })
        .collect()
}

fn validate_expected_file(
    file: &File,
    expected_size: u64,
    expected_sha256: &str,
) -> io::Result<()> {
    let before = file.metadata()?;
    if !before.file_type().is_file() {
        return Err(unsafe_entry("final path component is not a regular file"));
    }
    if before.len() != expected_size {
        return Err(changed_file("file size differs from the expected size"));
    }

    let mut reader = file;
    let mut hasher = Sha256::new();
    let mut bytes_read = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes_read = bytes_read
            .checked_add(count as u64)
            .ok_or_else(|| changed_file("file size overflowed while hashing"))?;
        if bytes_read > expected_size {
            return Err(changed_file("file grew while it was being hashed"));
        }
        hasher.update(&buffer[..count]);
    }

    let after = file.metadata()?;
    if bytes_read != expected_size || after.len() != expected_size {
        return Err(changed_file("file changed while it was being hashed"));
    }
    let actual_sha256 = format!("{:x}", hasher.finalize());
    if !actual_sha256.eq_ignore_ascii_case(expected_sha256) {
        return Err(changed_file(
            "file SHA-256 differs from the expected digest",
        ));
    }
    Ok(())
}

fn temporary_filename() -> String {
    let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!(".rrmm-{}-{sequence:016x}.tmp", std::process::id())
}

fn invalid_path(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn unsafe_entry(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.into())
}

fn changed_file(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Component;

    pub(crate) fn open_file_beneath(game_root: &Path, relative_path: &str) -> io::Result<File> {
        let components = validated_relative_components(relative_path)?;
        let (directory, filename) = open_parent_beneath(game_root, &components)?;
        open_regular_file_at(&directory, &filename)
    }

    pub(super) fn replace_file_beneath(
        game_root: &Path,
        components: &[&str],
        expected_size: u64,
        expected_sha256: &str,
        replacement: &[u8],
    ) -> io::Result<()> {
        let (directory, filename) = open_parent_beneath(game_root, components)?;
        let original = open_regular_file_at(&directory, &filename)?;
        validate_expected_file(&original, expected_size, expected_sha256)?;
        let original_metadata = original.metadata()?;

        let (mut temporary, temporary_name) =
            create_temporary_at(&directory, original_metadata.permissions().mode() & 0o777)?;
        let prepared = (|| {
            temporary.write_all(replacement)?;
            temporary.sync_all()?;

            let current = open_regular_file_at(&directory, &filename)?;
            let current_metadata = current.metadata()?;
            if current_metadata.dev() != original_metadata.dev()
                || current_metadata.ino() != original_metadata.ino()
            {
                return Err(changed_file("file identity changed before replacement"));
            }
            validate_expected_file(&current, expected_size, expected_sha256)?;

            // SAFETY: both names are NUL-terminated and both directory descriptors remain live.
            let renamed = unsafe {
                libc::renameat(
                    directory.as_raw_fd(),
                    temporary_name.as_ptr(),
                    directory.as_raw_fd(),
                    filename.as_ptr(),
                )
            };
            if renamed != 0 {
                return Err(io::Error::last_os_error());
            }
            directory.sync_all()?;
            Ok(())
        })();

        if prepared.is_err() {
            unlink_at(&directory, &temporary_name);
        }
        prepared
    }

    fn open_parent_beneath(game_root: &Path, components: &[&str]) -> io::Result<(File, CString)> {
        let mut directory = open_game_root(game_root)?;
        let Some((filename, parents)) = components.split_last() else {
            return Err(invalid_path("empty relative file path"));
        };
        for component in parents {
            let component = c_string(component, "file path component contains NUL")?;
            directory = open_directory_at(&directory, &component)?;
        }
        Ok((directory, c_string(filename, "filename contains NUL")?))
    }

    fn open_game_root(game_root: &Path) -> io::Result<File> {
        if !game_root.is_absolute() {
            return Err(invalid_path("game root must be absolute"));
        }
        let filesystem_root = c"/";
        // SAFETY: filesystem_root is NUL-terminated and flags require no variadic mode argument.
        let root_fd = unsafe {
            libc::open(
                filesystem_root.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if root_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: root_fd is newly owned after a successful open.
        let mut directory = unsafe { File::from_raw_fd(root_fd) };
        for component in game_root.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(component) => {
                    let component = CString::new(component.as_bytes())
                        .map_err(|_| invalid_path("game root component contains NUL"))?;
                    directory = open_directory_at(&directory, &component)?;
                }
                Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                    return Err(invalid_path("game root has an invalid component"));
                }
            }
        }
        Ok(directory)
    }

    fn open_directory_at(directory: &File, component: &CStr) -> io::Result<File> {
        // SAFETY: component is NUL-terminated, dirfd is live, and no mode argument is required.
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        owned_file(descriptor)
    }

    fn open_regular_file_at(directory: &File, filename: &CStr) -> io::Result<File> {
        // SAFETY: filename is NUL-terminated, dirfd is live, and no mode argument is required.
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                filename.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        let file = owned_file(descriptor)?;
        if !file.metadata()?.file_type().is_file() {
            return Err(unsafe_entry("final path component is not a regular file"));
        }
        Ok(file)
    }

    fn create_temporary_at(directory: &File, mode: u32) -> io::Result<(File, CString)> {
        for _ in 0..128 {
            let name = CString::new(temporary_filename()).expect("generated name contains no NUL");
            // SAFETY: name is NUL-terminated, dirfd is live, and O_CREAT supplies the mode argument.
            let descriptor = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    mode as libc::mode_t,
                )
            };
            if descriptor >= 0 {
                // SAFETY: descriptor is newly owned after successful openat.
                let file = unsafe { File::from_raw_fd(descriptor) };
                if let Err(error) = file.set_permissions(std::fs::Permissions::from_mode(mode)) {
                    drop(file);
                    unlink_at(directory, &name);
                    return Err(error);
                }
                return Ok((file, name));
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(error);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique temporary filename",
        ))
    }

    fn unlink_at(directory: &File, filename: &CStr) {
        // SAFETY: filename is NUL-terminated and dirfd remains live.
        unsafe {
            libc::unlinkat(directory.as_raw_fd(), filename.as_ptr(), 0);
        }
    }

    fn owned_file(descriptor: i32) -> io::Result<File> {
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: descriptor is newly owned after a successful open/openat.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }

    fn c_string(value: &str, message: &'static str) -> io::Result<CString> {
        CString::new(value).map_err(|_| invalid_path(message))
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::OsStr;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::mem::{offset_of, size_of, size_of_val, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr;
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_DISPOSITION_DELETE, FILE_DISPOSITION_INFORMATION_EX,
        FILE_DISPOSITION_POSIX_SEMANTICS, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
        FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_RENAME_POSIX_SEMANTICS,
        FILE_RENAME_REPLACE_IF_EXISTS, FILE_SYNCHRONOUS_IO_NONALERT, FileDispositionInformationEx,
        FileRenameInformationEx, NtCreateFile, NtSetInformationFile,
    };
    use windows_sys::Win32::Foundation::{
        GENERIC_READ, GENERIC_WRITE, HANDLE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError,
        UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_TYPE_DISK, FileAttributeTagInfo,
        GetFileInformationByHandleEx, GetFileType, SYNCHRONIZE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    pub(crate) fn open_file_beneath(game_root: &Path, relative_path: &str) -> io::Result<File> {
        let components = wide_components(&validated_relative_components(relative_path)?)?;
        let (directory, filename) = open_parent_beneath(game_root, &components)?;
        let file = open_component(
            &directory,
            &filename,
            GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            SHARE_ALL,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        )?;
        validate_handle(&file, false, "final path component")?;
        Ok(file)
    }

    pub(super) fn replace_file_beneath(
        game_root: &Path,
        components: &[&str],
        expected_size: u64,
        expected_sha256: &str,
        replacement: &[u8],
    ) -> io::Result<()> {
        let components = wide_components(components)?;
        let (directory, filename) = open_parent_beneath(game_root, &components)?;
        let original = open_component(
            &directory,
            &filename,
            GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        )?;
        validate_handle(&original, false, "final path component")?;
        validate_expected_file(&original, expected_size, expected_sha256)?;

        let mut temporary = create_temporary_at(&directory)?;
        let prepared = (|| {
            temporary.write_all(replacement)?;
            temporary.sync_all()?;
            rename_replacing_at(&temporary, &directory, &filename)
        })();
        if prepared.is_err() {
            mark_for_deletion(&temporary);
        }
        prepared
    }

    fn wide_components(components: &[&str]) -> io::Result<Vec<Vec<u16>>> {
        components
            .iter()
            .map(|component| {
                let wide: Vec<_> = OsStr::new(component).encode_wide().collect();
                if size_of_val(wide.as_slice()) > u16::MAX as usize {
                    return Err(invalid_path("relative file path component is too long"));
                }
                Ok(wide)
            })
            .collect()
    }

    fn open_parent_beneath(
        game_root: &Path,
        components: &[Vec<u16>],
    ) -> io::Result<(File, Vec<u16>)> {
        if !game_root.is_absolute() {
            return Err(invalid_path("game root must be absolute"));
        }
        let mut options = OpenOptions::new();
        options
            .access_mode(FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE)
            .share_mode(SHARE_ALL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        let mut directory = options.open(game_root)?;
        validate_handle(&directory, true, "game root")?;

        let Some((filename, parents)) = components.split_last() else {
            return Err(invalid_path("empty relative file path"));
        };
        for component in parents {
            let child = open_component(
                &directory,
                component,
                FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
                SHARE_ALL,
                FILE_OPEN,
                FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE,
            )?;
            validate_handle(&child, true, "path component")?;
            directory = child;
        }
        Ok((directory, filename.clone()))
    }

    fn open_component(
        directory: &File,
        component: &[u16],
        desired_access: u32,
        share_access: u32,
        disposition: u32,
        options: u32,
    ) -> io::Result<File> {
        let byte_len = u16::try_from(size_of_val(component))
            .map_err(|_| invalid_path("relative file path component is too long"))?;
        let name = UNICODE_STRING {
            Length: byte_len,
            MaximumLength: byte_len,
            Buffer: component.as_ptr().cast_mut(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: directory.as_raw_handle() as HANDLE,
            ObjectName: &name,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: ptr::null(),
            SecurityQualityOfService: ptr::null(),
        };
        let mut handle: HANDLE = ptr::null_mut();
        // SAFETY: output pointers are valid, names remain live, and RootDirectory is owned.
        let status = unsafe {
            let mut io_status: IO_STATUS_BLOCK = zeroed();
            NtCreateFile(
                &mut handle,
                desired_access,
                &attributes,
                &mut io_status,
                ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                share_access,
                disposition,
                options,
                ptr::null(),
                0,
            )
        };
        status_file(status, handle)
    }

    fn create_temporary_at(directory: &File) -> io::Result<File> {
        for _ in 0..128 {
            let name: Vec<_> = OsStr::new(&temporary_filename()).encode_wide().collect();
            match open_component(
                directory,
                &name,
                GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
                FILE_SHARE_READ,
                FILE_CREATE,
                FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            ) {
                Ok(file) => {
                    validate_handle(&file, false, "temporary file")?;
                    return Ok(file);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique temporary filename",
        ))
    }

    fn rename_replacing_at(file: &File, directory: &File, filename: &[u16]) -> io::Result<()> {
        let filename_bytes = u32::try_from(size_of_val(filename))
            .map_err(|_| invalid_path("relative file path component is too long"))?;
        let information_bytes = offset_of!(FILE_RENAME_INFORMATION, FileName)
            .checked_add(filename_bytes as usize)
            .ok_or_else(|| invalid_path("rename information is too large"))?;
        let slots = information_bytes.div_ceil(size_of::<FILE_RENAME_INFORMATION>());
        let mut storage = vec![FILE_RENAME_INFORMATION::default(); slots.max(1)];
        let information = &mut storage[0];
        information.Anonymous.Flags = FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS;
        information.RootDirectory = directory.as_raw_handle() as HANDLE;
        information.FileNameLength = filename_bytes;
        // SAFETY: storage includes the flexible filename bytes and both slices are non-overlapping.
        unsafe {
            ptr::copy_nonoverlapping(
                filename.as_ptr(),
                information.FileName.as_mut_ptr(),
                filename.len(),
            );
        }

        // FILE_RENAME_POSIX_SEMANTICS permits replacing the validated target while its handle
        // remains open and continues to deny competing writers/deleters.
        let status = unsafe {
            let mut io_status: IO_STATUS_BLOCK = zeroed();
            NtSetInformationFile(
                file.as_raw_handle() as HANDLE,
                &mut io_status,
                storage.as_ptr().cast(),
                information_bytes as u32,
                FileRenameInformationEx,
            )
        };
        status_result(status)
    }

    fn mark_for_deletion(file: &File) {
        let information = FILE_DISPOSITION_INFORMATION_EX {
            Flags: FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS,
        };
        // SAFETY: information has the size supplied and the file handle remains live.
        unsafe {
            let mut io_status: IO_STATUS_BLOCK = zeroed();
            NtSetInformationFile(
                file.as_raw_handle() as HANDLE,
                &mut io_status,
                (&information as *const FILE_DISPOSITION_INFORMATION_EX).cast(),
                size_of::<FILE_DISPOSITION_INFORMATION_EX>() as u32,
                FileDispositionInformationEx,
            );
        }
    }

    fn validate_handle(file: &File, expect_directory: bool, role: &str) -> io::Result<()> {
        let handle = file.as_raw_handle() as HANDLE;
        // SAFETY: handle remains live for the duration of the query.
        if unsafe { GetFileType(handle) } != FILE_TYPE_DISK {
            return Err(unsafe_entry(format!("{role} is not a disk file")));
        }
        let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
        // SAFETY: info is writable for the supplied size and handle remains live.
        let queried = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileAttributeTagInfo,
                (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        };
        if queried == 0 {
            return Err(io::Error::last_os_error());
        }
        if info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(unsafe_entry(format!("{role} is a reparse point")));
        }
        if info.FileAttributes & FILE_ATTRIBUTE_DEVICE != 0 {
            return Err(unsafe_entry(format!("{role} is a device")));
        }
        let is_directory = info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        if is_directory != expect_directory {
            return Err(unsafe_entry(if expect_directory {
                format!("{role} is not a directory")
            } else {
                format!("{role} is not a regular file")
            }));
        }
        Ok(())
    }

    fn status_file(status: i32, handle: HANDLE) -> io::Result<File> {
        status_result(status)?;
        if handle.is_null() {
            return Err(io::Error::other(
                "NtCreateFile succeeded without returning a handle",
            ));
        }
        // SAFETY: handle is newly owned after successful NtCreateFile and is transferred to File.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    fn status_result(status: i32) -> io::Result<()> {
        if status < 0 {
            // SAFETY: conversion accepts any NTSTATUS returned by the NT file APIs.
            let code = unsafe { RtlNtStatusToDosError(status) };
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use super::*;

    pub(crate) fn open_file_beneath(_game_root: &Path, _relative_path: &str) -> io::Result<File> {
        Err(unsupported())
    }

    pub(super) fn replace_file_beneath(
        _game_root: &Path,
        _components: &[&str],
        _expected_size: u64,
        _expected_sha256: &str,
        _replacement: &[u8],
    ) -> io::Result<()> {
        Err(unsupported())
    }

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "safe component-relative file access is not implemented on this platform",
        )
    }
}

pub(crate) use platform::open_file_beneath;

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::{open_file_beneath, read_game_relative_file, replace_game_relative_file};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::Read;
    use tempfile::TempDir;

    #[test]
    fn replaces_a_normal_nested_file() {
        let root = TempDir::new().unwrap();
        fs::create_dir_all(root.path().join("one/two")).unwrap();
        let path = root.path().join("one/two/file.txt");
        fs::write(&path, b"original").unwrap();

        replace_game_relative_file(
            root.path(),
            "one/two/file.txt",
            8,
            &digest(b"original"),
            b"replacement",
        )
        .unwrap();

        assert_eq!(fs::read(path).unwrap(), b"replacement");
    }

    #[test]
    fn rejects_a_divergent_hash_without_changing_the_original() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("file.txt");
        fs::write(&path, b"original").unwrap();

        let error = replace_game_relative_file(
            root.path(),
            "file.txt",
            8,
            &digest(b"different"),
            b"replacement",
        )
        .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(fs::read(path).unwrap(), b"original");
    }

    #[test]
    fn preserves_the_original_when_preparation_fails() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("file.txt");
        fs::write(&path, b"original").unwrap();

        assert!(
            replace_game_relative_file(
                root.path(),
                "file.txt",
                7,
                &digest(b"original"),
                b"replacement",
            )
            .is_err()
        );
        assert_eq!(fs::read(path).unwrap(), b"original");
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn rejects_invalid_components_and_a_final_directory() {
        let root = TempDir::new().unwrap();
        fs::create_dir(root.path().join("directory")).unwrap();

        for path in [
            "",
            "/file",
            "../file",
            "one/./file",
            "one\\file",
            "file:stream",
        ] {
            assert!(
                open_file_beneath(root.path(), path).is_err(),
                "accepted {path:?}"
            );
        }
        assert!(open_file_beneath(root.path(), "directory").is_err());
    }

    #[test]
    fn opens_a_normal_nested_file() {
        let root = TempDir::new().unwrap();
        fs::create_dir_all(root.path().join("one/two")).unwrap();
        fs::write(root.path().join("one/two/file.txt"), b"safe").unwrap();

        let mut file = open_file_beneath(root.path(), "one/two/file.txt").unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();

        assert_eq!(content, "safe");
    }

    #[test]
    fn reads_a_normal_file_with_a_hard_limit() {
        let root = TempDir::new().unwrap();
        fs::write(root.path().join("file.txt"), b"safe").unwrap();

        assert_eq!(
            read_game_relative_file(root.path(), "file.txt", 4).unwrap(),
            b"safe"
        );
        assert_eq!(
            read_game_relative_file(root.path(), "file.txt", 3)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::FileTooLarge
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_file_and_directory_symlinks_without_touching_their_targets() {
        use std::os::unix::fs::symlink;

        let root = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let outside_file = outside.path().join("outside.txt");
        fs::write(&outside_file, b"outside").unwrap();
        symlink(&outside_file, root.path().join("linked.txt")).unwrap();
        symlink(outside.path(), root.path().join("linked-dir")).unwrap();

        assert!(
            replace_game_relative_file(
                root.path(),
                "linked.txt",
                7,
                &digest(b"outside"),
                b"replacement",
            )
            .is_err()
        );
        assert!(
            replace_game_relative_file(
                root.path(),
                "linked-dir/outside.txt",
                7,
                &digest(b"outside"),
                b"replacement",
            )
            .is_err()
        );
        assert_eq!(fs::read(outside_file).unwrap(), b"outside");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlink_as_the_game_root() {
        use std::os::unix::fs::symlink;

        let parent = TempDir::new().unwrap();
        let actual = TempDir::new().unwrap();
        fs::write(actual.path().join("file.txt"), b"outside").unwrap();
        let linked_root = parent.path().join("linked-root");
        symlink(actual.path(), &linked_root).unwrap();

        assert!(
            replace_game_relative_file(
                &linked_root,
                "file.txt",
                7,
                &digest(b"outside"),
                b"replacement",
            )
            .is_err()
        );
        assert_eq!(
            fs::read(actual.path().join("file.txt")).unwrap(),
            b"outside"
        );
    }

    #[cfg(windows)]
    #[test]
    fn rejects_file_and_directory_reparse_points_without_touching_their_targets() {
        use std::io::ErrorKind;
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let root = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let outside_file = outside.path().join("outside.txt");
        fs::write(&outside_file, b"outside").unwrap();
        if !create_symlink_or_skip(|| symlink_file(&outside_file, root.path().join("linked.txt"))) {
            return;
        }
        if !create_symlink_or_skip(|| symlink_dir(outside.path(), root.path().join("linked-dir"))) {
            return;
        }

        assert!(
            replace_game_relative_file(
                root.path(),
                "linked.txt",
                7,
                &digest(b"outside"),
                b"replacement",
            )
            .is_err()
        );
        assert!(
            replace_game_relative_file(
                root.path(),
                "linked-dir/outside.txt",
                7,
                &digest(b"outside"),
                b"replacement",
            )
            .is_err()
        );
        assert_eq!(fs::read(outside_file).unwrap(), b"outside");

        fn create_symlink_or_skip(create: impl FnOnce() -> std::io::Result<()>) -> bool {
            match create() {
                Ok(()) => true,
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::PermissionDenied | ErrorKind::Unsupported
                    ) =>
                {
                    false
                }
                Err(error) => panic!("failed to create test reparse point: {error}"),
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn rejects_a_reparse_point_as_the_game_root() {
        use std::io::ErrorKind;
        use std::os::windows::fs::symlink_dir;

        let parent = TempDir::new().unwrap();
        let actual = TempDir::new().unwrap();
        fs::write(actual.path().join("file.txt"), b"outside").unwrap();
        let linked_root = parent.path().join("linked-root");
        if let Err(error) = symlink_dir(actual.path(), &linked_root) {
            if matches!(
                error.kind(),
                ErrorKind::PermissionDenied | ErrorKind::Unsupported
            ) {
                return;
            }
            panic!("failed to create test reparse point: {error}");
        }

        assert!(
            replace_game_relative_file(
                &linked_root,
                "file.txt",
                7,
                &digest(b"outside"),
                b"replacement",
            )
            .is_err()
        );
        assert_eq!(
            fs::read(actual.path().join("file.txt")).unwrap(),
            b"outside"
        );
    }

    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
}
