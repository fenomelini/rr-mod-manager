use std::path::PathBuf;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{
    WindowsSandboxRun, is_windows_sandbox_child, run_windows_sandboxed_worker,
    signal_windows_sandbox_ready, verify_windows_sandbox_before_parsing,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPolicy {
    pub read_files: Vec<PathBuf>,
    pub write_directories: Vec<PathBuf>,
    pub max_cpu_seconds: u64,
    pub max_address_space_bytes: u64,
    pub max_output_file_bytes: u64,
    pub max_output_bytes: u64,
    pub max_open_files: u64,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            read_files: Vec::new(),
            write_directories: Vec::new(),
            max_cpu_seconds: 120,
            max_address_space_bytes: 2 * 1024 * 1024 * 1024,
            max_output_file_bytes: 0,
            max_output_bytes: 8 * 1024 * 1024 * 1024,
            max_open_files: 64,
        }
    }
}

#[cfg(target_os = "linux")]
pub fn apply_worker_sandbox(policy: &SandboxPolicy) -> Result<bool, String> {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
        RulesetAttr, RulesetCreatedAttr, RulesetStatus, make_bitflags,
    };
    use std::fs;

    apply_resource_limits(policy)?;
    let abi = ABI::V4;
    let write_access = make_bitflags!(AccessFs::{
        ReadFile | ReadDir | WriteFile | RemoveDir | RemoveFile | MakeDir | MakeReg | Refer | Truncate
    });
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|error| format!("failed to configure filesystem sandbox: {error}"))?
        .handle_access(AccessNet::from_all(abi))
        .map_err(|error| format!("failed to configure network sandbox: {error}"))?
        .create()
        .map_err(|error| format!("failed to create Linux sandbox: {error}"))?;

    for path in &policy.read_files {
        let path = fs::canonicalize(path).map_err(|error| {
            format!(
                "failed to resolve sandbox input {}: {error}",
                path.display()
            )
        })?;
        let descriptor = PathFd::new(&path)
            .map_err(|error| format!("failed to open sandbox input {}: {error}", path.display()))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(descriptor, AccessFs::ReadFile))
            .map_err(|error| format!("failed to allow input reads: {error}"))?;
    }
    for path in &policy.write_directories {
        let path = fs::canonicalize(path).map_err(|error| {
            format!(
                "failed to resolve sandbox output {}: {error}",
                path.display()
            )
        })?;
        let descriptor = PathFd::new(&path).map_err(|error| {
            format!("failed to open sandbox output {}: {error}", path.display())
        })?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(descriptor, write_access))
            .map_err(|error| format!("failed to allow output access: {error}"))?;
    }

    let status = ruleset
        .restrict_self()
        .map_err(|error| format!("failed to activate Linux sandbox: {error}"))?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(format!("Linux sandbox was not fully enforced: {status:?}"));
    }
    verify_linux_sandbox_denials()?;
    Ok(true)
}

#[cfg(target_os = "linux")]
fn apply_resource_limits(policy: &SandboxPolicy) -> Result<(), String> {
    use rlimit::Resource;

    set_resource_limit(Resource::CORE, 0)?;
    set_resource_limit(Resource::CPU, policy.max_cpu_seconds)?;
    set_resource_limit(Resource::FSIZE, policy.max_output_file_bytes)?;
    set_resource_limit(Resource::NOFILE, policy.max_open_files)?;
    set_resource_limit(Resource::AS, policy.max_address_space_bytes)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_resource_limit(resource: rlimit::Resource, requested: u64) -> Result<(), String> {
    let (_, hard) = resource
        .get()
        .map_err(|error| format!("failed to read {resource:?} limit: {error}"))?;
    let limit = if hard == rlimit::INFINITY {
        requested
    } else {
        requested.min(hard)
    };
    resource
        .set(limit, limit)
        .map_err(|error| format!("failed to set {resource:?} limit: {error}"))
}

#[cfg(target_os = "linux")]
fn verify_linux_sandbox_denials() -> Result<(), String> {
    use std::fs::File;
    use std::io;
    use std::net::{Ipv4Addr, TcpStream};

    match File::open("/proc/self/status") {
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
        Err(error) => {
            return Err(format!(
                "failed to verify Linux filesystem sandbox denial: {error}"
            ));
        }
        Ok(_) => return Err("Linux filesystem sandbox did not deny an outside read".to_owned()),
    }
    match TcpStream::connect((Ipv4Addr::LOCALHOST, 9)) {
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(()),
        Err(error) => Err(format!(
            "failed to verify Linux network sandbox denial: {error}"
        )),
        Ok(_) => Err("Linux network sandbox did not deny a TCP connection".to_owned()),
    }
}

#[cfg(windows)]
pub fn apply_worker_sandbox(policy: &SandboxPolicy) -> Result<bool, String> {
    windows::verify_windows_sandbox_policy(policy)?;
    Ok(true)
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn apply_worker_sandbox(_policy: &SandboxPolicy) -> Result<bool, String> {
    Err("worker sandbox is unavailable on this platform; request was not processed".to_owned())
}
