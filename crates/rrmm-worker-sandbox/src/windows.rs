#![allow(unsafe_op_in_unsafe_fn)]

//! Windows sandbox broker for parser workers.
//!
//! The parser instance is created in a unique, ephemeral AppContainer profile with no capabilities.
//! Windows still grants AppContainers read access to the OS runtime resources needed to load a
//! process; selected data files are the only additional read ACLs, and staging directories are the
//! only additional write ACLs. The profile and its private storage are deleted after every run.
//! Windows has no hard equivalents of `RLIMIT_NOFILE` or `RLIMIT_FSIZE`; a trusted broker watchdog
//! terminates the Job Object when handle or write-I/O accounting exceeds policy. CPU, committed
//! memory, and process count are hard Job Object limits.

use crate::SandboxPolicy;
use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::io::{Read, Write};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::thread;
use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, GetLastError, HANDLE, HANDLE_FLAG_INHERIT, LocalFree,
    SetHandleInformation, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, REVOKE_ACCESS, SE_FILE_OBJECT,
    SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, FreeSid, GetTokenInformation, PSID, SECURITY_ATTRIBUTES,
    SECURITY_CAPABILITIES, SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_DUPLICATE, TOKEN_QUERY,
    TokenCapabilities, TokenIsAppContainer,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD,
    FILE_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_TRAVERSE,
};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOB_OBJECT_LIMIT_PROCESS_TIME,
    JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicAndIoAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
use windows_sys::Win32::System::SystemServices::{
    JOB_OBJECT_QUERY, PROCESS_MITIGATION_CHILD_PROCESS_POLICY,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateEventW, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetExitCodeProcess, GetProcessHandleCount, GetProcessMitigationPolicy,
    InitializeProcThreadAttributeList, OpenProcessToken,
    PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, ProcessChildProcessPolicy, ResumeThread, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, SetEvent, TerminateProcess, UpdateProcThreadAttribute, WaitForMultipleObjects,
    WaitForSingleObject,
};
use windows_sys::Win32::System::WindowsProgramming::PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;

const CHILD_ARGUMENT_PREFIX: &str = "--rrmm-windows-sandbox-child=";
const READY_ARGUMENT_PREFIX: &str = "--rrmm-windows-sandbox-ready=";
const WATCHDOG_INTERVAL_MS: u32 = 10;
const CHILD_READY_TIMEOUT_MS: u32 = 10_000;
const SANDBOX_TERMINATED_EXIT_CODE: u32 = 0x5252_4d4d;
const MAX_ACL_CLEANUP_ENTRIES: usize = 1_000_000;

#[derive(Debug)]
pub struct WindowsSandboxRun {
    pub stdout: Vec<u8>,
    pub exit_code: u32,
}

pub fn is_windows_sandbox_child() -> bool {
    child_job_handle().is_some()
}

pub fn verify_windows_sandbox_before_parsing() -> Result<(), String> {
    let job = child_job_handle().ok_or_else(|| {
        "Windows sandbox child marker is missing; request was not processed".to_owned()
    })?;
    verify_app_container_token()?;
    verify_child_process_mitigation()?;
    verify_job_membership(job)?;
    let limits = query_job_limits(job)?;
    let required = JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_TIME
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    if limits.BasicLimitInformation.LimitFlags & required != required
        || limits.BasicLimitInformation.ActiveProcessLimit != 1
    {
        return Err("Windows sandbox Job Object is missing mandatory limits".to_owned());
    }
    Ok(())
}

pub fn signal_windows_sandbox_ready() -> Result<(), String> {
    let ready = child_ready_handle().ok_or_else(|| {
        "Windows sandbox readiness marker is missing; request was not processed".to_owned()
    })?;
    if unsafe { SetEvent(ready) } == 0 {
        return Err(last_error("failed to signal Windows sandbox readiness"));
    }
    Ok(())
}

pub(crate) fn verify_windows_sandbox_policy(policy: &SandboxPolicy) -> Result<(), String> {
    verify_windows_sandbox_before_parsing()?;
    let job = child_job_handle().expect("verified child marker");
    let limits = query_job_limits(job)?;
    let requested_cpu = cpu_limit_100ns(policy.max_cpu_seconds);
    let requested_memory = usize::try_from(policy.max_address_space_bytes)
        .map_err(|_| "Windows sandbox memory limit exceeds this architecture".to_owned())?;
    if limits.BasicLimitInformation.PerProcessUserTimeLimit != requested_cpu
        || limits.ProcessMemoryLimit != requested_memory
    {
        return Err("Windows sandbox Job Object limits do not match the request".to_owned());
    }
    Ok(())
}

pub fn run_windows_sandboxed_worker(
    policy: &SandboxPolicy,
    request: &[u8],
) -> Result<WindowsSandboxRun, String> {
    if is_windows_sandbox_child() {
        return Err("a sandbox child cannot broker another worker".to_owned());
    }
    let canonical = CanonicalPolicy::new(policy)?;
    let mut app_container = AppContainerProfile::new()?;
    let executable = canonical_file(
        &std::env::current_exe()
            .map_err(|error| format!("failed to locate worker executable: {error}"))?,
        "worker executable",
    )?;
    let executable_directory = executable
        .parent()
        .ok_or_else(|| "worker executable has no parent directory".to_owned())?;
    let mut grants = vec![
        AclGrant::new(
            executable_directory,
            app_container.sid,
            FILE_GENERIC_READ | FILE_TRAVERSE,
            0,
        )?,
        AclGrant::new(
            &executable,
            app_container.sid,
            FILE_GENERIC_READ | FILE_EXECUTE,
            0,
        )?,
    ];
    for path in &canonical.read_files {
        grants.push(AclGrant::new(
            path,
            app_container.sid,
            FILE_GENERIC_READ,
            0,
        )?);
    }
    for path in &canonical.write_directories {
        grants.push(AclGrant::new(
            path,
            app_container.sid,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_DELETE_CHILD | FILE_TRAVERSE | DELETE,
            SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        )?);
    }

    let result = unsafe {
        launch_child(
            policy,
            request,
            app_container.sid,
            &executable,
            executable_directory,
        )
    };
    let acl_cleanup = grants
        .iter_mut()
        .rev()
        .try_for_each(AclGrant::restore)
        .and_then(|()| {
            canonical
                .write_directories
                .iter()
                .try_for_each(|path| revoke_descendant_access(path, app_container.sid))
        });
    let profile_cleanup = app_container.delete();
    match (result, acl_cleanup, profile_cleanup) {
        (Ok(run), Ok(()), Ok(())) => Ok(run),
        (Err(error), Ok(()), Ok(())) => Err(error),
        (result, acl_cleanup, profile_cleanup) => {
            let mut failures = Vec::new();
            if let Err(error) = result {
                failures.push(error);
            }
            if let Err(error) = acl_cleanup {
                failures.push(format!(
                    "failed to restore temporary Windows sandbox ACL: {error}"
                ));
            }
            if let Err(error) = profile_cleanup {
                failures.push(error);
            }
            Err(failures.join("; "))
        }
    }
}

fn revoke_descendant_access(root: &Path, sid: PSID) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;

    let mut pending = vec![root.to_path_buf()];
    let mut descendants = Vec::new();
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory).map_err(|error| {
            format!(
                "failed to inspect sandbox output {} during ACL cleanup: {error}",
                directory.display()
            )
        })?;
        for entry in entries {
            let path = entry
                .map_err(|error| format!("failed to enumerate sandbox output: {error}"))?
                .path();
            let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
                format!(
                    "failed to inspect sandbox output {} during ACL cleanup: {error}",
                    path.display()
                )
            })?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                let removal = if metadata.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0 {
                    std::fs::remove_dir(&path)
                } else {
                    std::fs::remove_file(&path)
                };
                removal.map_err(|error| {
                    format!(
                        "failed to remove unexpected reparse point {}: {error}",
                        path.display()
                    )
                })?;
                continue;
            }
            if metadata.is_dir() {
                pending.push(path.clone());
            }
            descendants.push(path);
            if descendants.len() > MAX_ACL_CLEANUP_ENTRIES {
                return Err(
                    "sandbox output contains too many paths for safe ACL cleanup".to_owned(),
                );
            }
        }
    }
    descendants
        .iter()
        .rev()
        .try_for_each(|path| revoke_acl(path, sid))
}

fn revoke_acl(path: &Path, sid: PSID) -> Result<(), String> {
    let path = wide(path.as_os_str());
    let mut old_dacl = null_mut();
    let mut security_descriptor = null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut old_dacl,
            null_mut(),
            &mut security_descriptor,
        )
    };
    if status != 0 {
        return Err(format!(
            "failed to read output ACL for cleanup: Windows error {status}"
        ));
    }
    let access = EXPLICIT_ACCESS_W {
        grfAccessMode: REVOKE_ACCESS,
        Trustee: TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.cast(),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut updated_dacl = null_mut();
    let status = unsafe { SetEntriesInAclW(1, &access, old_dacl, &mut updated_dacl) };
    if status == 0 {
        let set_status = unsafe {
            SetNamedSecurityInfoW(
                path.as_ptr() as *mut u16,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                updated_dacl,
                null_mut(),
            )
        };
        unsafe {
            LocalFree(updated_dacl.cast());
            LocalFree(security_descriptor.cast());
        }
        if set_status != 0 {
            return Err(format!(
                "failed to remove AppContainer output access: Windows error {set_status}"
            ));
        }
        Ok(())
    } else {
        unsafe {
            LocalFree(security_descriptor.cast());
        }
        Err(format!(
            "failed to build cleaned output ACL: Windows error {status}"
        ))
    }
}

struct CanonicalPolicy {
    read_files: Vec<PathBuf>,
    write_directories: Vec<PathBuf>,
}

impl CanonicalPolicy {
    fn new(policy: &SandboxPolicy) -> Result<Self, String> {
        let read_files = policy
            .read_files
            .iter()
            .map(|path| canonical_file(path, "input"))
            .collect::<Result<Vec<_>, _>>()?;
        let write_directories = policy
            .write_directories
            .iter()
            .map(|path| canonical_directory(path, "output"))
            .collect::<Result<Vec<_>, _>>()?;
        for input in &read_files {
            for output in &write_directories {
                if windows_path_starts_with(input, output)
                    || windows_path_starts_with(output, input)
                {
                    return Err(format!(
                        "Windows sandbox input and output overlap: {} and {}",
                        input.display(),
                        output.display()
                    ));
                }
            }
        }
        Ok(Self {
            read_files,
            write_directories,
        })
    }
}

fn canonical_file(path: &Path, kind: &str) -> Result<PathBuf, String> {
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        format!(
            "failed to resolve Windows sandbox {kind} {}: {error}",
            path.display()
        )
    })?;
    let metadata = std::fs::metadata(&canonical).map_err(|error| {
        format!(
            "failed to inspect Windows sandbox {kind} {}: {error}",
            canonical.display()
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "Windows sandbox {kind} must be a file: {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn canonical_directory(path: &Path, kind: &str) -> Result<PathBuf, String> {
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        format!(
            "failed to resolve Windows sandbox {kind} {}: {error}",
            path.display()
        )
    })?;
    let metadata = std::fs::metadata(&canonical).map_err(|error| {
        format!(
            "failed to inspect Windows sandbox {kind} {}: {error}",
            canonical.display()
        )
    })?;
    if !metadata.is_dir() {
        return Err(format!(
            "Windows sandbox {kind} must be a directory: {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn windows_path_starts_with(path: &Path, base: &Path) -> bool {
    let path = path.to_string_lossy().to_lowercase();
    let base = base.to_string_lossy().to_lowercase();
    path == base
        || path
            .strip_prefix(&base)
            .is_some_and(|rest| rest.starts_with(['\\', '/']))
}

struct AppContainerProfile {
    name: Vec<u16>,
    sid: PSID,
    deleted: bool,
}

impl AppContainerProfile {
    fn new() -> Result<Self, String> {
        // AppContainer monikers are limited to 64 characters. The fixed-width hexadecimal
        // process/nonce suffix stays well below that limit while remaining unique per launch.
        let name = wide(format!(
            "RetroRewind.RrmmWorker.{:08x}.{:016x}",
            std::process::id(),
            monotonic_nonce()
        ));
        let display_name = wide("RR Mod Manager parser worker");
        let description = wide("Ephemeral sandbox for untrusted archive parsing");
        let mut sid = null_mut();
        let result = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                display_name.as_ptr(),
                description.as_ptr(),
                null(),
                0,
                &mut sid,
            )
        };
        if result < 0 || sid.is_null() {
            return Err(format!(
                "failed to create an ephemeral AppContainer profile: HRESULT 0x{:08x}",
                result as u32
            ));
        }
        Ok(Self {
            name,
            sid,
            deleted: false,
        })
    }

    fn delete(&mut self) -> Result<(), String> {
        if self.deleted {
            return Ok(());
        }
        let result = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) };
        if result < 0 {
            return Err(format!(
                "failed to delete the ephemeral AppContainer profile: HRESULT 0x{:08x}",
                result as u32
            ));
        }
        self.deleted = true;
        Ok(())
    }
}

impl Drop for AppContainerProfile {
    fn drop(&mut self) {
        let _ = self.delete();
        unsafe {
            FreeSid(self.sid);
        }
    }
}

fn monotonic_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (time as u64) ^ COUNTER.fetch_add(1, Ordering::Relaxed)
}

struct AclGrant {
    path: Vec<u16>,
    original_dacl: *mut windows_sys::Win32::Security::ACL,
    security_descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
    restored: bool,
}

impl AclGrant {
    fn new(path: &Path, sid: PSID, permissions: u32, inheritance: u32) -> Result<Self, String> {
        let display_path = path.display().to_string();
        let path = wide(path.as_os_str());
        let mut original_dacl = null_mut();
        let mut security_descriptor = null_mut();
        let status = unsafe {
            GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut original_dacl,
                null_mut(),
                &mut security_descriptor,
            )
        };
        if status != 0 {
            return Err(format!(
                "Windows sandbox failed to read the ACL for {display_path}: Windows error {status}"
            ));
        }
        let trustee = TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.cast(),
            ..Default::default()
        };
        let access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: permissions,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: inheritance,
            Trustee: trustee,
        };
        let mut updated_dacl = null_mut();
        let status = unsafe { SetEntriesInAclW(1, &access, original_dacl, &mut updated_dacl) };
        if status != 0 {
            unsafe {
                LocalFree(security_descriptor.cast());
            }
            return Err(format!(
                "Windows sandbox failed to build the ACL for {display_path}: Windows error {status}"
            ));
        }
        let status = unsafe {
            SetNamedSecurityInfoW(
                path.as_ptr() as *mut u16,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                updated_dacl,
                null_mut(),
            )
        };
        unsafe {
            LocalFree(updated_dacl.cast());
        }
        if status != 0 {
            unsafe {
                LocalFree(security_descriptor.cast());
            }
            return Err(format!(
                "Windows sandbox failed to grant AppContainer access to {display_path}: Windows error {status}"
            ));
        }
        Ok(Self {
            path,
            original_dacl,
            security_descriptor,
            restored: false,
        })
    }

    fn restore(&mut self) -> Result<(), String> {
        if self.restored {
            return Ok(());
        }
        let status = unsafe {
            SetNamedSecurityInfoW(
                self.path.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                self.original_dacl,
                null_mut(),
            )
        };
        if status != 0 {
            return Err(format!("Windows error {status}"));
        }
        self.restored = true;
        Ok(())
    }
}

impl Drop for AclGrant {
    fn drop(&mut self) {
        let _ = self.restore();
        unsafe {
            LocalFree(self.security_descriptor.cast());
        }
    }
}

unsafe fn launch_child(
    policy: &SandboxPolicy,
    request: &[u8],
    app_container_sid: PSID,
    executable: &Path,
    executable_directory: &Path,
) -> Result<WindowsSandboxRun, String> {
    let job = OwnedHandle::new(CreateJobObjectW(null(), null()))
        .ok_or_else(|| last_error("failed to create Windows sandbox Job Object"))?;
    configure_job(job.0, policy)?;
    let query_job = duplicate_query_handle(job.0)?;
    let (child_stdin, parent_stdin) = create_pipe_pair(true)?;
    let (parent_stdout, child_stdout) = create_pipe_pair(false)?;
    let ready = create_inheritable_event()?;

    // PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY requires a pointer to a DWORD. Using a
    // pointer-sized value makes cbSize 8 on Windows x64 and UpdateProcThreadAttribute rejects it
    // with ERROR_BAD_LENGTH (24).
    let child_policy: u32 = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
    let mut security_capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: app_container_sid,
        Capabilities: null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let inherited_handles = [child_stdin.0, child_stdout.0, query_job.0, ready.0];
    let mut attributes = AttributeList::new(3)?;
    attributes.update(
        "AppContainer security capabilities",
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
        (&mut security_capabilities as *mut SECURITY_CAPABILITIES).cast(),
        size_of::<SECURITY_CAPABILITIES>(),
    )?;
    attributes.update(
        "child-process policy",
        PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY as usize,
        (&child_policy as *const u32).cast(),
        size_of::<u32>(),
    )?;
    const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
    attributes.update(
        "inherited handle list",
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        inherited_handles.as_ptr().cast(),
        size_of_val(&inherited_handles),
    )?;

    let executable_wide = wide(executable.as_os_str());
    let executable_directory_wide = wide(executable_directory.as_os_str());
    let environment = sanitized_environment()?;
    let mut command_line = wide(format!(
        "\"{}\" {CHILD_ARGUMENT_PREFIX}{} {READY_ARGUMENT_PREFIX}{}",
        executable.display(),
        query_job.0 as usize,
        ready.0 as usize
    ));
    let mut startup: STARTUPINFOEXW = zeroed();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = child_stdin.0;
    startup.StartupInfo.hStdOutput = child_stdout.0;
    startup.StartupInfo.hStdError = child_stdout.0;
    startup.lpAttributeList = attributes.0;
    let mut process: PROCESS_INFORMATION = zeroed();
    if CreateProcessW(
        executable_wide.as_ptr(),
        command_line.as_mut_ptr(),
        null(),
        null(),
        1,
        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
        environment.as_ptr().cast(),
        executable_directory_wide.as_ptr(),
        &startup.StartupInfo,
        &mut process,
    ) == 0
    {
        return Err(last_error("failed to create AppContainer worker"));
    }
    let process_handle = OwnedHandle(process.hProcess);
    let thread_handle = OwnedHandle(process.hThread);
    drop(child_stdin);
    drop(child_stdout);
    drop(query_job);
    if AssignProcessToJobObject(job.0, process_handle.0) == 0 {
        let error = last_error("failed to assign suspended worker to its Job Object");
        TerminateProcess(process_handle.0, SANDBOX_TERMINATED_EXIT_CODE);
        return Err(error);
    }

    let parent_stdout = parent_stdout.into_raw() as usize;
    let reader = thread::spawn(move || {
        let mut output = Vec::new();
        let mut file = File::from_raw_handle(parent_stdout as *mut c_void);
        file.read_to_end(&mut output).map(|_| output)
    });
    let mut input = File::from_raw_handle(parent_stdin.into_raw());
    if ResumeThread(thread_handle.0) == u32::MAX {
        return Err(last_error("failed to resume sandboxed worker"));
    }
    wait_for_child_ready(ready.0, process_handle.0)?;
    let mut baseline_handles = 0;
    if GetProcessHandleCount(process_handle.0, &mut baseline_handles) == 0 {
        return Err(last_error(
            "failed to establish the Windows sandbox handle baseline",
        ));
    }
    drop(ready);
    input
        .write_all(request)
        .map_err(|error| format!("failed to send request to sandboxed worker: {error}"))?;
    drop(input);

    let watchdog_result = monitor_child(job.0, process_handle.0, policy, baseline_handles);
    if let Err(error) = watchdog_result {
        TerminateJobObject(job.0, SANDBOX_TERMINATED_EXIT_CODE);
        WaitForSingleObject(process_handle.0, 5_000);
        let _ = reader.join();
        return Err(error);
    }
    let mut exit_code = 0;
    if GetExitCodeProcess(process_handle.0, &mut exit_code) == 0 {
        return Err(last_error("failed to read sandboxed worker exit code"));
    }
    let stdout = reader
        .join()
        .map_err(|_| "sandboxed worker output reader panicked".to_owned())?
        .map_err(|error| format!("failed to read sandboxed worker output: {error}"))?;
    Ok(WindowsSandboxRun { stdout, exit_code })
}

unsafe fn wait_for_child_ready(ready: HANDLE, process: HANDLE) -> Result<(), String> {
    let handles = [ready, process];
    match WaitForMultipleObjects(
        handles.len() as u32,
        handles.as_ptr(),
        0,
        CHILD_READY_TIMEOUT_MS,
    ) {
        WAIT_OBJECT_0 => Ok(()),
        status if status == WAIT_OBJECT_0 + 1 => {
            Err("Windows sandbox worker exited before confirming isolation".to_owned())
        }
        WAIT_TIMEOUT => Err("Windows sandbox worker did not become ready in time".to_owned()),
        WAIT_FAILED => Err(last_error("failed to wait for Windows sandbox readiness")),
        status => Err(format!(
            "unexpected Windows sandbox readiness wait status {status}"
        )),
    }
}

unsafe fn configure_job(job: HANDLE, policy: &SandboxPolicy) -> Result<(), String> {
    let memory = usize::try_from(policy.max_address_space_bytes)
        .map_err(|_| "Windows sandbox memory limit exceeds this architecture".to_owned())?;
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_TIME
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    limits.BasicLimitInformation.PerProcessUserTimeLimit = cpu_limit_100ns(policy.max_cpu_seconds);
    limits.ProcessMemoryLimit = memory;
    if SetInformationJobObject(
        job,
        JobObjectExtendedLimitInformation,
        (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
        size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
    ) == 0
    {
        return Err(last_error("failed to configure Windows sandbox limits"));
    }
    Ok(())
}

unsafe fn monitor_child(
    job: HANDLE,
    process: HANDLE,
    policy: &SandboxPolicy,
    baseline_handles: u32,
) -> Result<(), String> {
    loop {
        let completed = match WaitForSingleObject(process, WATCHDOG_INTERVAL_MS) {
            WAIT_OBJECT_0 => true,
            WAIT_TIMEOUT => false,
            WAIT_FAILED => return Err(last_error("failed to wait for sandboxed worker")),
            status => return Err(format!("unexpected Windows wait status {status}")),
        };
        if !completed {
            let mut handles = 0;
            if GetProcessHandleCount(process, &mut handles) == 0 {
                return Err(last_error("failed to inspect sandboxed worker handles"));
            }
            let additional_handles = handles.saturating_sub(baseline_handles);
            if u64::from(additional_handles) > policy.max_open_files {
                return Err(format!(
                    "Windows sandbox additional-handle limit exceeded: {additional_handles} > {}",
                    policy.max_open_files
                ));
            }
        }
        let accounting = query_job_accounting(job)?;
        if accounting.IoInfo.WriteTransferCount > policy.max_output_bytes {
            return Err(format!(
                "Windows sandbox output limit exceeded: {} > {}",
                accounting.IoInfo.WriteTransferCount, policy.max_output_bytes
            ));
        }
        if completed {
            return Ok(());
        }
    }
}

unsafe fn create_pipe_pair(child_reads: bool) -> Result<(OwnedHandle, OwnedHandle), String> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let mut read = null_mut();
    let mut write = null_mut();
    if CreatePipe(&mut read, &mut write, &attributes, 0) == 0 {
        return Err(last_error("failed to create worker protocol pipe"));
    }
    let read = OwnedHandle(read);
    let write = OwnedHandle(write);
    let parent = if child_reads { write.0 } else { read.0 };
    if SetHandleInformation(parent, HANDLE_FLAG_INHERIT, 0) == 0 {
        return Err(last_error("failed to secure worker protocol pipe"));
    }
    Ok((read, write))
}

unsafe fn create_inheritable_event() -> Result<OwnedHandle, String> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    OwnedHandle::new(CreateEventW(&attributes, 1, 0, null()))
        .ok_or_else(|| last_error("failed to create Windows sandbox readiness event"))
}

unsafe fn duplicate_query_handle(job: HANDLE) -> Result<OwnedHandle, String> {
    let process = GetCurrentProcess();
    let mut duplicate = null_mut();
    if DuplicateHandle(
        process,
        job,
        process,
        &mut duplicate,
        JOB_OBJECT_QUERY,
        1,
        0,
    ) == 0
    {
        return Err(last_error("failed to create read-only Job Object handle"));
    }
    Ok(OwnedHandle(duplicate))
}

fn verify_app_container_token() -> Result<(), String> {
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(last_error("failed to open worker token"));
        }
        let token = OwnedHandle(token);
        let mut app_container = 0u32;
        let mut returned = 0;
        if GetTokenInformation(
            token.0,
            TokenIsAppContainer,
            (&mut app_container as *mut u32).cast(),
            size_of::<u32>() as u32,
            &mut returned,
        ) == 0
            || app_container == 0
        {
            return Err("worker token is not an AppContainer token".to_owned());
        }
        let mut required = 0;
        GetTokenInformation(token.0, TokenCapabilities, null_mut(), 0, &mut required);
        if required < size_of::<u32>() as u32 {
            return Err("failed to inspect AppContainer capabilities".to_owned());
        }
        let mut buffer = vec![0u8; required as usize];
        if GetTokenInformation(
            token.0,
            TokenCapabilities,
            buffer.as_mut_ptr().cast(),
            required,
            &mut returned,
        ) == 0
        {
            return Err(last_error("failed to inspect AppContainer capabilities"));
        }
        let group_count = buffer.as_ptr().cast::<u32>().read_unaligned();
        if group_count != 0 {
            return Err("worker AppContainer unexpectedly has network capabilities".to_owned());
        }
    }
    Ok(())
}

fn verify_child_process_mitigation() -> Result<(), String> {
    unsafe {
        let mut policy: PROCESS_MITIGATION_CHILD_PROCESS_POLICY = zeroed();
        if GetProcessMitigationPolicy(
            GetCurrentProcess(),
            ProcessChildProcessPolicy,
            (&mut policy as *mut PROCESS_MITIGATION_CHILD_PROCESS_POLICY).cast(),
            size_of::<PROCESS_MITIGATION_CHILD_PROCESS_POLICY>(),
        ) == 0
        {
            return Err(last_error("failed to inspect child-process mitigation"));
        }
        if policy.Anonymous.Flags & PROCESS_CREATION_CHILD_PROCESS_RESTRICTED == 0 {
            return Err("worker child-process creation is not prohibited".to_owned());
        }
    }
    Ok(())
}

fn verify_job_membership(job: HANDLE) -> Result<(), String> {
    unsafe {
        let mut in_job = 0;
        if IsProcessInJob(GetCurrentProcess(), job, &mut in_job) == 0 {
            return Err(last_error("failed to verify worker Job Object"));
        }
        if in_job == 0 {
            return Err("worker is not assigned to the expected Job Object".to_owned());
        }
    }
    Ok(())
}

fn query_job_limits(job: HANDLE) -> Result<JOBOBJECT_EXTENDED_LIMIT_INFORMATION, String> {
    unsafe {
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
        if QueryInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            null_mut(),
        ) == 0
        {
            return Err(last_error("failed to inspect Windows sandbox limits"));
        }
        Ok(limits)
    }
}

unsafe fn query_job_accounting(
    job: HANDLE,
) -> Result<JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION, String> {
    let mut accounting: JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION = zeroed();
    if QueryInformationJobObject(
        job,
        JobObjectBasicAndIoAccountingInformation,
        (&mut accounting as *mut JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION).cast(),
        size_of::<JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION>() as u32,
        null_mut(),
    ) == 0
    {
        return Err(last_error("failed to inspect Windows sandbox I/O"));
    }
    Ok(accounting)
}

fn cpu_limit_100ns(seconds: u64) -> i64 {
    seconds.saturating_mul(10_000_000).min(i64::MAX as u64) as i64
}

fn child_job_handle() -> Option<HANDLE> {
    std::env::args_os().find_map(|argument| {
        let argument = argument.to_string_lossy();
        argument
            .strip_prefix(CHILD_ARGUMENT_PREFIX)
            .and_then(|value| value.parse::<isize>().ok())
            .map(|value| value as HANDLE)
    })
}

fn child_ready_handle() -> Option<HANDLE> {
    child_argument_handle(READY_ARGUMENT_PREFIX)
}

fn child_argument_handle(prefix: &str) -> Option<HANDLE> {
    std::env::args_os().find_map(|argument| {
        let argument = argument.to_string_lossy();
        argument
            .strip_prefix(prefix)
            .and_then(|value| value.parse::<isize>().ok())
            .map(|value| value as HANDLE)
    })
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn sanitized_environment() -> Result<Vec<u16>, String> {
    // AppContainer process creation rewrites LOCALAPPDATA, TEMP, and TMP to the profile's private
    // storage. CreateProcessW fails with ERROR_ENVVAR_NOT_FOUND if those source variables are
    // absent. The trusted broker itself is launched with an empty environment, so retrieve the
    // current user's canonical environment directly from Userenv and retain only non-secret paths
    // needed to initialize and load the worker.
    const ALLOWED: &[&str] = &[
        "APPDATA",
        "LOCALAPPDATA",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    ];
    const REQUIRED: &[&str] = &["LOCALAPPDATA", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE"];
    let defaults = default_user_environment()?;
    let mut entries = defaults
        .entries()?
        .into_iter()
        .filter(|entry| {
            environment_name(entry).is_some_and(|name| {
                ALLOWED
                    .iter()
                    .any(|allowed| name.eq_ignore_ascii_case(allowed))
            })
        })
        .collect::<Vec<_>>();
    let windows_directory = windows_directory()?;
    set_environment_entry(&mut entries, "SystemRoot", &windows_directory);
    set_environment_entry(&mut entries, "WINDIR", &windows_directory);
    let missing = REQUIRED
        .iter()
        .filter(|required| {
            !entries.iter().any(|entry| {
                environment_name(entry).is_some_and(|name| name.eq_ignore_ascii_case(required))
            })
        })
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "failed to construct AppContainer environment; unavailable variables: {}",
            missing.join(", ")
        ));
    }
    entries.sort_unstable_by_key(|entry| {
        environment_name(entry)
            .unwrap_or_default()
            .to_ascii_lowercase()
    });
    let mut block = Vec::new();
    for entry in entries {
        block.extend(entry);
        block.push(0);
    }
    block.push(0);
    if block.len() == 1 {
        block.push(0);
    }
    Ok(block)
}

fn set_environment_entry(entries: &mut Vec<Vec<u16>>, name: &str, value: &OsStr) {
    entries.retain(|entry| {
        !environment_name(entry).is_some_and(|existing| existing.eq_ignore_ascii_case(name))
    });
    let mut entry = OsStr::new(name).encode_wide().collect::<Vec<_>>();
    entry.push(b'=' as u16);
    entry.extend(value.encode_wide());
    entries.push(entry);
}

fn environment_name(entry: &[u16]) -> Option<String> {
    let separator = entry
        .iter()
        .position(|character| *character == b'=' as u16)?;
    (separator > 0).then(|| String::from_utf16_lossy(&entry[..separator]))
}

fn windows_directory() -> Result<std::ffi::OsString, String> {
    let mut buffer = vec![0u16; 260];
    loop {
        let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if length == 0 {
            return Err(last_error("failed to locate the Windows system directory"));
        }
        let length = length as usize;
        if length < buffer.len() {
            buffer.truncate(length);
            return Ok(std::ffi::OsString::from_wide(&buffer));
        }
        buffer.resize(length.saturating_add(1), 0);
    }
}

struct UserEnvironment(*mut c_void);

impl UserEnvironment {
    fn entries(&self) -> Result<Vec<Vec<u16>>, String> {
        const MAX_ENVIRONMENT_CODE_UNITS: usize = 1_048_576;
        let mut entries = Vec::new();
        let mut offset = 0usize;
        unsafe {
            while offset < MAX_ENVIRONMENT_CODE_UNITS {
                let start = self.0.cast::<u16>().add(offset);
                if *start == 0 {
                    return Ok(entries);
                }
                let mut length = 0usize;
                while offset + length < MAX_ENVIRONMENT_CODE_UNITS && *start.add(length) != 0 {
                    length += 1;
                }
                if offset + length == MAX_ENVIRONMENT_CODE_UNITS {
                    break;
                }
                entries.push(std::slice::from_raw_parts(start, length).to_vec());
                offset += length + 1;
            }
        }
        Err("Windows user environment exceeds the safe parser limit".to_owned())
    }
}

impl Drop for UserEnvironment {
    fn drop(&mut self) {
        unsafe {
            DestroyEnvironmentBlock(self.0);
        }
    }
}

fn default_user_environment() -> Result<UserEnvironment, String> {
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut token,
        ) == 0
        {
            return Err(last_error(
                "failed to open the broker token for AppContainer environment creation",
            ));
        }
        let token = OwnedHandle(token);
        let mut environment = null_mut();
        if CreateEnvironmentBlock(&mut environment, token.0, 0) == 0 || environment.is_null() {
            return Err(last_error(
                "failed to create a clean Windows user environment for AppContainer",
            ));
        }
        Ok(UserEnvironment(environment))
    }
}

fn last_error(context: &str) -> String {
    format!("{context}: Windows error {}", unsafe { GetLastError() })
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> Option<Self> {
        (!handle.is_null()).then_some(Self(handle))
    }

    fn into_raw(mut self) -> *mut c_void {
        let handle = self.0;
        self.0 = null_mut();
        handle.cast()
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct AttributeList(windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST);

impl AttributeList {
    unsafe fn new(count: u32) -> Result<Self, String> {
        let mut bytes = 0;
        InitializeProcThreadAttributeList(null_mut(), count, 0, &mut bytes);
        if bytes == 0 {
            return Err(last_error("failed to size process attribute list"));
        }
        let memory = LocalFreeBuffer::new(bytes);
        if memory.0.is_null() {
            return Err("failed to allocate process attribute list".to_owned());
        }
        if InitializeProcThreadAttributeList(memory.0.cast(), count, 0, &mut bytes) == 0 {
            return Err(last_error("failed to initialize process attribute list"));
        }
        let pointer = memory.0.cast();
        std::mem::forget(memory);
        Ok(Self(pointer))
    }

    unsafe fn update(
        &mut self,
        context: &str,
        attribute: usize,
        value: *const c_void,
        bytes: usize,
    ) -> Result<(), String> {
        if UpdateProcThreadAttribute(self.0, 0, attribute, value, bytes, null_mut(), null()) == 0 {
            return Err(last_error(&format!(
                "failed to configure process security attribute ({context})"
            )));
        }
        Ok(())
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.0);
            drop(LocalFreeBuffer(self.0.cast()));
        }
    }
}

struct LocalFreeBuffer(*mut c_void);

impl LocalFreeBuffer {
    unsafe fn new(bytes: usize) -> Self {
        use windows_sys::Win32::System::Memory::{LMEM_FIXED, LocalAlloc};
        Self(LocalAlloc(LMEM_FIXED, bytes))
    }
}

impl Drop for LocalFreeBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_process_is_not_accepted_as_a_sandbox_child() {
        assert!(verify_windows_sandbox_before_parsing().is_err());
    }

    #[test]
    fn path_overlap_check_is_case_insensitive_and_component_aware() {
        assert!(windows_path_starts_with(
            Path::new(r"C:\Staging\file"),
            Path::new(r"c:\staging")
        ));
        assert!(!windows_path_starts_with(
            Path::new(r"C:\StagingElsewhere\file"),
            Path::new(r"c:\staging")
        ));
    }

    #[test]
    fn app_container_moniker_fits_the_windows_limit() {
        let name = format!("RetroRewind.RrmmWorker.{:08x}.{:016x}", u32::MAX, u64::MAX);
        assert!(name.len() <= 64);
    }
}
