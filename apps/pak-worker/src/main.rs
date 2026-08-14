use rrmm_pak::{PakWorkerRequest, PakWorkerResponse, execute_worker_request};
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
const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

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
    if let Err(error) = io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut input)
    {
        return write_error(format!("failed to read request: {error}"));
    }
    if input.len() as u64 > MAX_REQUEST_BYTES {
        return write_error("worker request exceeds 1 MiB".to_owned());
    }
    let request: PakWorkerRequest = match serde_json::from_slice(&input) {
        Ok(request) => request,
        Err(error) => return write_error(format!("invalid worker request: {error}")),
    };
    let policy = pak_sandbox_policy(&request);
    #[cfg(windows)]
    if !is_windows_sandbox_child() {
        return broker_pak_worker(&policy, &input);
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

fn pak_sandbox_policy(request: &PakWorkerRequest) -> SandboxPolicy {
    let pak = match request {
        PakWorkerRequest::Fingerprint { pak, .. } | PakWorkerRequest::Inspect { pak, .. } => pak,
    };
    SandboxPolicy {
        read_files: vec![pak.clone()],
        max_cpu_seconds: processing_seconds(pak),
        max_output_bytes: MAX_RESPONSE_BYTES,
        ..SandboxPolicy::default()
    }
}

#[cfg(windows)]
fn broker_pak_worker(policy: &SandboxPolicy, input: &[u8]) -> ExitCode {
    let run = match run_windows_sandboxed_worker(policy, input) {
        Ok(run) => run,
        Err(error) => return write_error(error),
    };
    let response: PakWorkerResponse = match serde_json::from_slice(&run.stdout) {
        Ok(response) => response,
        Err(error) => {
            return write_error(format!(
                "sandboxed PAK worker returned invalid JSON (exit {}): {error}",
                run.exit_code
            ));
        }
    };
    if response.ok != (run.exit_code == 0) || (response.ok && !response.sandboxed) {
        return write_error("sandboxed PAK worker returned inconsistent status".to_owned());
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
    let response = PakWorkerResponse {
        ok: false,
        sandboxed: false,
        inventory: None,
        member_digests: Vec::new(),
        index_metadata_sha256: None,
        error: Some(error),
    };
    let _ = serde_json::to_writer(io::stdout().lock(), &response);
    ExitCode::FAILURE
}
