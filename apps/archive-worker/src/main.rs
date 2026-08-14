use rrmm_archive::{ArchiveWorkerRequest, execute_worker_request};
use rrmm_worker_sandbox::{SandboxPolicy, apply_worker_sandbox};
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process::ExitCode;

#[cfg(windows)]
use rrmm_worker_sandbox::{
    is_windows_sandbox_child, run_windows_sandboxed_worker, signal_windows_sandbox_ready,
    verify_windows_sandbox_before_parsing,
};

const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
const MAX_WINDOWS_OUTPUT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const RESPONSE_OUTPUT_ALLOWANCE: u64 = 16 * 1024 * 1024;

fn main() -> ExitCode {
    #[cfg(windows)]
    if is_windows_sandbox_child() {
        if let Err(error) = verify_windows_sandbox_before_parsing() {
            return write_error(error);
        }
        if let Err(error) = signal_windows_sandbox_ready() {
            return write_error(error);
        }
    }

    let mut input = Vec::new();
    let read_result = io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut input);
    if let Err(error) = read_result {
        return write_error(format!("failed to read request: {error}"));
    }
    if input.len() as u64 > MAX_REQUEST_BYTES {
        return write_error("worker request exceeds 1 MiB".to_owned());
    }
    let request: ArchiveWorkerRequest = match serde_json::from_slice(&input) {
        Ok(request) => request,
        Err(error) => return write_error(format!("invalid worker request: {error}")),
    };
    if let Err(error) = prepare_request_paths(&request) {
        return write_error(error);
    }
    let policy = archive_sandbox_policy(&request);
    #[cfg(windows)]
    if !is_windows_sandbox_child() {
        return broker_archive_worker(&policy, &input);
    }
    let sandboxed = match apply_worker_sandbox(&policy) {
        Ok(true) => true,
        Ok(false) => {
            return write_error(
                "worker sandbox was not enforced; request was not processed".to_owned(),
            );
        }
        Err(error) => return write_error(error),
    };
    let mut response = execute_worker_request(request);
    response.sandboxed = sandboxed;
    match serde_json::to_writer(io::stdout().lock(), &response) {
        Ok(()) if response.ok => ExitCode::SUCCESS,
        Ok(()) => ExitCode::FAILURE,
        Err(_) => ExitCode::FAILURE,
    }
}

fn prepare_request_paths(request: &ArchiveWorkerRequest) -> Result<(), String> {
    let ArchiveWorkerRequest::Extract { staging, .. } = request else {
        return Ok(());
    };
    match fs::symlink_metadata(staging) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(format!(
                    "staging must be a real directory: {}",
                    staging.display()
                ));
            }
            let mut entries = fs::read_dir(staging)
                .map_err(|error| format!("failed to inspect staging: {error}"))?;
            if entries.next().is_some() {
                return Err(format!("staging must be empty: {}", staging.display()));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(staging)
                .map_err(|error| format!("failed to create staging: {error}"))?;
        }
        Err(error) => return Err(format!("failed to inspect staging: {error}")),
    }
    set_private_directory(staging)
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("failed to secure staging permissions: {error}"))
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn archive_sandbox_policy(request: &ArchiveWorkerRequest) -> SandboxPolicy {
    let (archive, limits) = match request {
        ArchiveWorkerRequest::Preflight { archive, limits }
        | ArchiveWorkerRequest::Extract {
            archive, limits, ..
        } => (archive, limits),
    };
    let write_directories = match request {
        ArchiveWorkerRequest::Preflight { .. } => Vec::new(),
        ArchiveWorkerRequest::Extract { staging, .. } => vec![staging.clone()],
    };
    SandboxPolicy {
        read_files: vec![archive.clone()],
        write_directories,
        max_cpu_seconds: processing_seconds(archive),
        max_output_file_bytes: limits.max_file_bytes,
        max_output_bytes: limits
            .max_expanded_bytes
            .min(MAX_WINDOWS_OUTPUT_BYTES)
            .saturating_add(RESPONSE_OUTPUT_ALLOWANCE),
        ..SandboxPolicy::default()
    }
}

#[cfg(windows)]
fn broker_archive_worker(policy: &SandboxPolicy, input: &[u8]) -> ExitCode {
    let run = match run_windows_sandboxed_worker(policy, input) {
        Ok(run) => run,
        Err(error) => return write_error(error),
    };
    let response: rrmm_archive::ArchiveWorkerResponse = match serde_json::from_slice(&run.stdout) {
        Ok(response) => response,
        Err(error) => {
            return write_error(format!(
                "sandboxed archive worker returned invalid JSON (exit {}): {error}",
                run.exit_code
            ));
        }
    };
    if response.ok != (run.exit_code == 0) || (response.ok && !response.sandboxed) {
        return write_error("sandboxed archive worker returned inconsistent status".to_owned());
    }
    match serde_json::to_writer(io::stdout().lock(), &response) {
        Ok(()) if response.ok => ExitCode::SUCCESS,
        Ok(()) => ExitCode::FAILURE,
        Err(_) => ExitCode::FAILURE,
    }
}

fn processing_seconds(path: &Path) -> u64 {
    const GIB: u64 = 1024 * 1024 * 1024;
    let gibibytes = fs::metadata(path)
        .map(|metadata| metadata.len().div_ceil(GIB))
        .unwrap_or(0);
    300_u64.saturating_add(gibibytes.saturating_mul(300))
}

fn write_error(error: String) -> ExitCode {
    let response = rrmm_archive::ArchiveWorkerResponse {
        ok: false,
        sandboxed: false,
        preflight: None,
        extraction: None,
        error: Some(error),
    };
    let _ = serde_json::to_writer(io::stdout().lock(), &response);
    ExitCode::FAILURE
}
