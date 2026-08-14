use rrmm_archive::{PathPolicyError, sha256_path, validate_entry_path};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

const MAX_DEPLOYMENT_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileIdentity {
    pub bytes: u64,
    pub modified_ns: i64,
    pub changed_ns: Option<i64>,
    pub device_id: Option<u64>,
    pub file_id: Option<u64>,
}

impl FileIdentity {
    pub fn stable_for_cache(&self) -> bool {
        self.changed_ns.is_some() && self.device_id.is_some() && self.file_id.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSource {
    pub identity: FileIdentity,
    pub sha256: String,
}

pub fn file_identity(path: &Path) -> Result<FileIdentity, DeployError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| DeployError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(DeployError::InvalidSource(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(FileIdentity {
            bytes: metadata.len(),
            modified_ns: metadata
                .mtime()
                .saturating_mul(1_000_000_000)
                .saturating_add(metadata.mtime_nsec()),
            changed_ns: Some(
                metadata
                    .ctime()
                    .saturating_mul(1_000_000_000)
                    .saturating_add(metadata.ctime_nsec()),
            ),
            device_id: Some(metadata.dev()),
            file_id: Some(metadata.ino()),
        })
    }
    #[cfg(windows)]
    {
        windows_file_identity(path, &metadata)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let modified_ns = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_nanos().min(i64::MAX as u128) as i64)
            .unwrap_or_default();
        Ok(FileIdentity {
            bytes: metadata.len(),
            modified_ns,
            changed_ns: None,
            device_id: None,
            file_id: None,
        })
    }
}

#[cfg(windows)]
fn windows_file_identity(
    path: &Path,
    path_metadata: &fs::Metadata,
) -> Result<FileIdentity, DeployError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandle,
        GetFileInformationByHandleEx,
    };

    let file = File::open(path).map_err(|source| DeployError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let handle = file.as_raw_handle();
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` belongs to the live `file`, and `information` is a
    // correctly sized writable output buffer for this Win32 call.
    if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0 {
        return Ok(unstable_file_identity(path_metadata));
    }

    let bytes = ((information.nFileSizeHigh as u64) << 32) | information.nFileSizeLow as u64;
    let file_id = ((information.nFileIndexHigh as u64) << 32) | information.nFileIndexLow as u64;
    let mut basic = FILE_BASIC_INFO::default();
    // SAFETY: `handle` belongs to the live `file`, and `basic` is a correctly
    // sized writable output buffer for `FileBasicInfo`.
    let has_basic_info = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            (&mut basic as *mut FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } != 0;
    if !has_basic_info || basic.ChangeTime <= 0 {
        return Ok(FileIdentity {
            bytes,
            modified_ns: windows_filetime_ns(
                information.ftLastWriteTime.dwHighDateTime,
                information.ftLastWriteTime.dwLowDateTime,
            ),
            changed_ns: None,
            device_id: Some(information.dwVolumeSerialNumber as u64),
            file_id: Some(file_id),
        });
    }

    Ok(FileIdentity {
        bytes,
        modified_ns: basic.LastWriteTime.saturating_mul(100),
        changed_ns: Some(basic.ChangeTime.saturating_mul(100)),
        device_id: Some(information.dwVolumeSerialNumber as u64),
        file_id: Some(file_id),
    })
}

#[cfg(windows)]
fn windows_filetime_ns(high: u32, low: u32) -> i64 {
    let ticks = ((high as u64) << 32) | low as u64;
    i64::try_from(ticks).unwrap_or(i64::MAX).saturating_mul(100)
}

#[cfg(windows)]
fn unstable_file_identity(metadata: &fs::Metadata) -> FileIdentity {
    let modified_ns = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos().min(i64::MAX as u128) as i64)
        .unwrap_or_default();
    FileIdentity {
        bytes: metadata.len(),
        modified_ns,
        changed_ns: None,
        device_id: None,
        file_id: None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentFile {
    pub source: PathBuf,
    pub relative_path: String,
    pub bytes: u64,
    pub sha256: String,
    #[serde(default)]
    pub package_id: Option<String>,
    #[serde(default)]
    pub package_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentExternalFile {
    pub original_relative_path: String,
    pub source_relative_path: String,
    pub target_relative_path: String,
    pub bytes: u64,
    pub sha256: String,
    #[serde(default)]
    pub owner_id: Option<String>,
    #[serde(default)]
    pub owner_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentExternalMove {
    pub source_relative_path: String,
    pub target_relative_path: String,
    pub bytes: u64,
    pub sha256: String,
    #[serde(default)]
    pub owner_id: Option<String>,
    #[serde(default)]
    pub owner_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedFile {
    pub relative_path: String,
    pub bytes: u64,
    pub sha256: String,
    pub displaced_unmanaged: Option<DisplacedFile>,
    #[serde(default)]
    pub package_id: Option<String>,
    #[serde(default)]
    pub package_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisplacedFile {
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderedExternalFile {
    pub original_relative_path: String,
    pub current_relative_path: String,
    pub bytes: u64,
    pub sha256: String,
    #[serde(default)]
    pub owner_id: Option<String>,
    #[serde(default)]
    pub owner_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentReceipt {
    pub schema_version: u32,
    pub profile_id: String,
    pub game_root: PathBuf,
    pub files: Vec<OwnedFile>,
    #[serde(default)]
    pub external_files: Vec<OrderedExternalFile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentChangeKind {
    Create,
    ReplaceManaged,
    ReplaceUnmanaged,
    AdoptIdenticalUnmanaged,
    RemoveManaged,
    RestoreUnmanaged,
    UnchangedManaged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentChange {
    pub relative_path: String,
    pub kind: DeploymentChangeKind,
    pub previous_sha256: Option<String>,
    pub next_sha256: Option<String>,
    #[serde(default)]
    pub owner_id: Option<String>,
    #[serde(default)]
    pub owner_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedFileRestoreApproval {
    pub relative_path: String,
    pub expected_sha256: String,
    pub current_sha256: Option<String>,
    pub restore_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum DeploymentBlocker {
    GameRunning,
    UnmanagedPath {
        relative_path: String,
        identical: bool,
    },
    PathCollision {
        planned_path: String,
        existing_path: String,
    },
    ManagedFileMissing {
        relative_path: String,
    },
    ManagedFileDrifted {
        relative_path: String,
        expected_sha256: String,
        actual_sha256: String,
    },
    UnsafeFilesystemEntry {
        relative_path: String,
        detail: String,
    },
    ExternalTargetOccupied {
        relative_path: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentPlan {
    pub schema_version: u32,
    pub transaction_id: String,
    pub installation_id: String,
    pub profile_id: String,
    pub game_root: PathBuf,
    pub state_root: PathBuf,
    pub files: Vec<DeploymentFile>,
    pub external_files: Vec<DeploymentExternalFile>,
    pub external_moves: Vec<DeploymentExternalMove>,
    pub allow_unmanaged: bool,
    #[serde(default)]
    pub managed_file_restore_approvals: Vec<ManagedFileRestoreApproval>,
    pub changes: Vec<DeploymentChange>,
    pub blockers: Vec<DeploymentBlocker>,
    pub previous_receipt: Option<DeploymentReceipt>,
    pub target_receipt: DeploymentReceipt,
}

impl DeploymentPlan {
    pub fn ready(&self) -> bool {
        self.blockers.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentRequest {
    pub transaction_id: String,
    pub installation_id: String,
    pub profile_id: String,
    pub game_root: PathBuf,
    pub state_root: PathBuf,
    pub files: Vec<DeploymentFile>,
    #[serde(default)]
    pub external_files: Vec<DeploymentExternalFile>,
    pub allow_unmanaged: bool,
    pub game_running: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentBoundary {
    JournalDurable,
    ExternalSourcesStaged,
    OperationApplied(usize),
    FilesVerified,
    ReceiptWritten,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationReport {
    pub transaction_id: String,
    pub installation_id: String,
    pub profile_id: String,
    pub receipt_path: PathBuf,
    pub changed_files: usize,
    pub backup_hashes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryReport {
    pub transaction_id: String,
    pub action: RecoveryAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    RolledBack,
    CleanedCommitted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryStatus {
    ManagedMatch,
    ManagedDrifted,
    ManagedMissing,
    Unmanaged,
    UnmanagedCollision,
    UnsafeLink,
    SpecialEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameFileInventoryEntry {
    pub relative_path: String,
    pub status: InventoryStatus,
    pub bytes: Option<u64>,
    pub actual_sha256: Option<String>,
    pub expected_sha256: Option<String>,
    pub collision_with: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameFileInventoryReport {
    pub game_root: PathBuf,
    pub managed_match_count: usize,
    pub managed_drift_count: usize,
    pub managed_missing_count: usize,
    pub unmanaged_count: usize,
    pub collision_count: usize,
    pub unsafe_count: usize,
    pub entries: Vec<GameFileInventoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DeploymentJournal {
    schema_version: u32,
    transaction_id: String,
    installation_id: String,
    game_root: PathBuf,
    state_root: PathBuf,
    changes: Vec<DeploymentChange>,
    #[serde(default)]
    external_moves: Vec<DeploymentExternalMove>,
    previous_receipt: Option<DeploymentReceipt>,
    target_receipt: DeploymentReceipt,
}

struct DeploymentLock {
    file: File,
}

impl Drop for DeploymentLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[derive(Debug, Error)]
pub enum DeployError {
    #[error("invalid {field} identifier: {value}")]
    InvalidIdentifier { field: &'static str, value: String },
    #[error("invalid deployment path '{path}': {source}")]
    InvalidPath {
        path: String,
        source: PathPolicyError,
    },
    #[error(
        "deployment paths collide after cross-platform normalization: '{first}' and '{second}'"
    )]
    PlannedCollision { first: String, second: String },
    #[error("deployment path is both a file and a directory prefix: '{first}' and '{second}'")]
    PrefixCollision { first: String, second: String },
    #[error("deployment source is not a regular file: {0}")]
    InvalidSource(PathBuf),
    #[error("external deployment path is owned by RRMM: {0}")]
    ExternalOwnedPath(String),
    #[error(
        "deployment source metadata differs for {path}: expected {expected_bytes} bytes and {expected_sha256}, got {actual_bytes} bytes and {actual_sha256}"
    )]
    SourceChanged {
        path: PathBuf,
        expected_bytes: u64,
        expected_sha256: String,
        actual_bytes: u64,
        actual_sha256: String,
    },
    #[error("receipt is invalid: {0}")]
    InvalidReceipt(String),
    #[error("deployment I/O failed at {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("deployment hashing failed for {path}: {detail}")]
    Hash { path: PathBuf, detail: String },
    #[error("deployment plan is blocked")]
    PlanBlocked,
    #[error("deployment plan changed during final validation")]
    PlanChanged,
    #[error("managed file restoration approval is no longer exact for '{0}'")]
    ManagedFileApprovalChanged(String),
    #[error("game is running; deployment and recovery are blocked")]
    GameRunning,
    #[error("deployment transaction already exists: {0}")]
    TransactionExists(String),
    #[error("another deployment operation is active")]
    DeploymentBusy,
    #[error("incomplete deployment journals must be recovered before applying a new plan")]
    PendingRecovery,
    #[error("deployment state root is unsafe: {0}")]
    UnsafeStateRoot(String),
    #[error("deployment JSON failed at {path}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("recovery stopped because '{path}' changed outside RRMM")]
    RecoveryDrift { path: String },
    #[error("injected deployment failure at {0:?}")]
    InjectedFailure(DeploymentBoundary),
}

pub fn plan_deployment(
    request: DeploymentRequest,
    previous_receipt: Option<&DeploymentReceipt>,
) -> Result<DeploymentPlan, DeployError> {
    plan_deployment_internal(request, previous_receipt, Vec::new(), None)
}

pub fn plan_deployment_with_approvals(
    request: DeploymentRequest,
    previous_receipt: Option<&DeploymentReceipt>,
    managed_file_restore_approvals: Vec<ManagedFileRestoreApproval>,
) -> Result<DeploymentPlan, DeployError> {
    plan_deployment_internal(
        request,
        previous_receipt,
        managed_file_restore_approvals,
        None,
    )
}

pub fn plan_deployment_with_verified_sources(
    request: DeploymentRequest,
    previous_receipt: Option<&DeploymentReceipt>,
    managed_file_restore_approvals: Vec<ManagedFileRestoreApproval>,
    verified_sources: &BTreeMap<PathBuf, VerifiedSource>,
) -> Result<DeploymentPlan, DeployError> {
    plan_deployment_internal(
        request,
        previous_receipt,
        managed_file_restore_approvals,
        Some(verified_sources),
    )
}

fn plan_deployment_internal(
    request: DeploymentRequest,
    previous_receipt: Option<&DeploymentReceipt>,
    managed_file_restore_approvals: Vec<ManagedFileRestoreApproval>,
    verified_sources: Option<&BTreeMap<PathBuf, VerifiedSource>>,
) -> Result<DeploymentPlan, DeployError> {
    validate_identifier("transaction", &request.transaction_id)?;
    validate_identifier("installation", &request.installation_id)?;
    validate_identifier("profile", &request.profile_id)?;
    let game_root = canonical_directory(&request.game_root)?;
    let mut files = normalize_files(request.files)?;
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    verify_sources(&files, verified_sources)?;
    let mut external_files = normalize_external_files(request.external_files)?;
    external_files.sort_by(|left, right| {
        left.source_relative_path
            .cmp(&right.source_relative_path)
            .then_with(|| left.target_relative_path.cmp(&right.target_relative_path))
    });

    let previous_receipt = previous_receipt
        .map(|receipt| validate_receipt(receipt, &game_root))
        .transpose()?;
    let owned = previous_receipt
        .as_ref()
        .map(receipt_map)
        .unwrap_or_default();
    let relevant_paths = files
        .iter()
        .map(|file| file.relative_path.as_str())
        .chain(owned.values().map(|file| file.relative_path.as_str()))
        .chain(external_files.iter().flat_map(|file| {
            [
                file.source_relative_path.as_str(),
                file.target_relative_path.as_str(),
            ]
        }))
        .collect::<BTreeSet<_>>();
    let existing = inventory_existing_scoped(&game_root, &relevant_paths)?;
    let desired_paths: BTreeSet<_> = files
        .iter()
        .map(|file| file.relative_path.as_str())
        .collect();
    let desired_by_path: BTreeMap<_, _> = files
        .iter()
        .map(|file| (file.relative_path.as_str(), file))
        .collect();
    let approvals = validate_restore_approvals(managed_file_restore_approvals)?;
    let mut consumed_approvals = BTreeSet::new();
    let mut blockers = Vec::new();
    let mut changes = Vec::new();
    let mut displaced_by_path = BTreeMap::new();
    let mut present_owned_paths = BTreeSet::new();
    let mut observed_managed = BTreeMap::new();

    validate_external_plan_paths(&external_files, &files, &owned, &mut blockers)?;
    verify_external_sources(&game_root, &external_files, verified_sources)?;
    inspect_external_targets(&game_root, &external_files, &existing, &mut blockers)?;

    if request.game_running {
        blockers.push(DeploymentBlocker::GameRunning);
    }

    {
        let mut inspection = ManagedInspection {
            game_root: &game_root,
            approvals: &approvals,
            consumed_approvals: &mut consumed_approvals,
            blockers: &mut blockers,
            observed: &mut observed_managed,
            verified_files: verified_sources,
        };
        for current in owned.values() {
            if inspect_managed_file(
                current,
                desired_by_path.get(current.relative_path.as_str()).copied(),
                &mut inspection,
            )? {
                present_owned_paths.insert(current.relative_path.as_str());
            }
        }
    }

    for file in &files {
        let destination = game_root.join(path_from_normalized(&file.relative_path));
        inspect_parent_chain(&game_root, &file.relative_path, &mut blockers)?;
        inspect_existing_collisions(&file.relative_path, &existing, &mut blockers)?;

        let previous = match observed_managed.get(&file.relative_path) {
            Some(previous) => previous.clone(),
            None => inspect_file(
                &destination,
                &file.relative_path,
                &mut blockers,
                verified_sources,
            )?,
        };
        let owner = owned.get(&file.relative_path);
        let displaced = match (owner, &previous) {
            (Some(owner), _) => owner.displaced_unmanaged.clone(),
            (None, Some((_bytes, sha256))) if sha256 == &file.sha256 => None,
            (None, Some((bytes, sha256))) => Some(DisplacedFile {
                bytes: *bytes,
                sha256: sha256.clone(),
            }),
            (None, None) => None,
        };
        displaced_by_path.insert(file.relative_path.clone(), displaced);
        let (kind, previous_sha256) = match previous {
            None => (DeploymentChangeKind::Create, None),
            Some((_, actual_sha256)) if owner.is_some() && actual_sha256 == file.sha256 => {
                (DeploymentChangeKind::UnchangedManaged, Some(actual_sha256))
            }
            Some((_, actual_sha256)) if owner.is_some() => {
                (DeploymentChangeKind::ReplaceManaged, Some(actual_sha256))
            }
            Some((_, actual_sha256)) if actual_sha256 == file.sha256 => (
                DeploymentChangeKind::AdoptIdenticalUnmanaged,
                Some(actual_sha256),
            ),
            Some((_, actual_sha256)) => {
                if !request.allow_unmanaged {
                    blockers.push(DeploymentBlocker::UnmanagedPath {
                        relative_path: file.relative_path.clone(),
                        identical: false,
                    });
                }
                (DeploymentChangeKind::ReplaceUnmanaged, Some(actual_sha256))
            }
        };
        changes.push(DeploymentChange {
            relative_path: file.relative_path.clone(),
            kind,
            previous_sha256,
            next_sha256: Some(file.sha256.clone()),
            owner_id: file.package_id.clone(),
            owner_name: file.package_name.clone(),
        });
    }

    for current in owned.values() {
        if !desired_paths.contains(current.relative_path.as_str())
            && present_owned_paths.contains(current.relative_path.as_str())
        {
            let (kind, next_sha256) = match &current.displaced_unmanaged {
                Some(displaced) => (
                    DeploymentChangeKind::RestoreUnmanaged,
                    Some(displaced.sha256.clone()),
                ),
                None => (DeploymentChangeKind::RemoveManaged, None),
            };
            changes.push(DeploymentChange {
                relative_path: current.relative_path.clone(),
                kind,
                previous_sha256: Some(current.sha256.clone()),
                next_sha256,
                owner_id: current.package_id.clone(),
                owner_name: current.package_name.clone(),
            });
        }
    }
    changes.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    blockers.sort_by_key(blocker_sort_key);
    blockers.dedup();
    if let Some(path) = approvals
        .keys()
        .find(|path| !consumed_approvals.contains(path.as_str()))
    {
        return Err(DeployError::ManagedFileApprovalChanged(path.clone()));
    }

    let target_receipt = DeploymentReceipt {
        schema_version: 1,
        profile_id: request.profile_id.clone(),
        game_root: game_root.clone(),
        files: files
            .iter()
            .map(|file| OwnedFile {
                relative_path: file.relative_path.clone(),
                bytes: file.bytes,
                sha256: file.sha256.clone(),
                displaced_unmanaged: displaced_by_path
                    .remove(&file.relative_path)
                    .unwrap_or(None),
                package_id: file.package_id.clone(),
                package_name: file.package_name.clone(),
            })
            .collect(),
        external_files: external_files
            .iter()
            .map(|file| OrderedExternalFile {
                original_relative_path: file.original_relative_path.clone(),
                current_relative_path: file.target_relative_path.clone(),
                bytes: file.bytes,
                sha256: file.sha256.clone(),
                owner_id: file.owner_id.clone(),
                owner_name: file.owner_name.clone(),
            })
            .collect(),
    };
    let external_moves = external_files
        .iter()
        .filter(|file| file.source_relative_path != file.target_relative_path)
        .map(|file| DeploymentExternalMove {
            source_relative_path: file.source_relative_path.clone(),
            target_relative_path: file.target_relative_path.clone(),
            bytes: file.bytes,
            sha256: file.sha256.clone(),
            owner_id: file.owner_id.clone(),
            owner_name: file.owner_name.clone(),
        })
        .collect();
    Ok(DeploymentPlan {
        schema_version: 2,
        transaction_id: request.transaction_id,
        installation_id: request.installation_id,
        profile_id: request.profile_id,
        game_root,
        state_root: request.state_root,
        files,
        external_files,
        external_moves,
        allow_unmanaged: request.allow_unmanaged,
        managed_file_restore_approvals: approvals.into_values().collect(),
        changes,
        blockers,
        previous_receipt,
        target_receipt,
    })
}

pub fn activate_deployment<F>(
    plan: &DeploymentPlan,
    game_running: F,
) -> Result<ActivationReport, DeployError>
where
    F: Fn() -> bool,
{
    activate_with_failpoint(plan, game_running, |_| Ok(()))
}

/// Applies a plan that was retained from preview after the caller revalidated its
/// file identities. Unlike `activate_deployment`, this does not rebuild the plan.
pub fn activate_prepared_deployment<F>(
    plan: &DeploymentPlan,
    game_running: F,
) -> Result<ActivationReport, DeployError>
where
    F: Fn() -> bool,
{
    activate_prepared_with_failpoint(plan, game_running, |_| Ok(()))
}

pub fn recover_incomplete<F>(
    state_root: &Path,
    game_running: F,
) -> Result<Vec<RecoveryReport>, DeployError>
where
    F: Fn() -> bool,
{
    if game_running() {
        return Err(DeployError::GameRunning);
    }
    let state_root = prepare_state_root(state_root, None)?;
    let _lock = acquire_deployment_lock(&state_root)?;
    let journals_root = state_root.join("journals");
    match fs::read_dir(&journals_root) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(DeployError::Io {
                path: journals_root,
                source,
            });
        }
    }
    let mut journals = Vec::new();
    for entry in fs::read_dir(&journals_root).map_err(|source| DeployError::Io {
        path: journals_root.clone(),
        source,
    })? {
        let entry = entry.map_err(|source| DeployError::Io {
            path: journals_root.clone(),
            source,
        })?;
        let file_type = entry.file_type().map_err(|source| DeployError::Io {
            path: entry.path(),
            source,
        })?;
        if file_type.is_symlink() {
            return Err(DeployError::UnsafeStateRoot(format!(
                "journal is a filesystem link: {}",
                entry.path().display()
            )));
        }
        if file_type.is_file()
            && entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "json")
        {
            journals.push(entry.path());
        }
    }
    journals.sort();

    let mut reports = Vec::with_capacity(journals.len());
    for journal_path in journals {
        if game_running() {
            return Err(DeployError::GameRunning);
        }
        let journal: DeploymentJournal = read_json(&journal_path)?;
        if journal_path.file_stem().and_then(|name| name.to_str()) != Some(&journal.transaction_id)
        {
            return Err(DeployError::UnsafeStateRoot(format!(
                "journal filename does not match transaction: {}",
                journal_path.display()
            )));
        }
        validate_journal(&journal, &state_root)?;
        let marker = commit_marker_path(&state_root, &journal.transaction_id);
        let action = if marker.is_file() {
            cleanup_transaction(&journal, &journal_path, &marker)?;
            RecoveryAction::CleanedCommitted
        } else {
            rollback_journal(&journal)?;
            remove_file_if_exists(&journal_path)?;
            remove_tree_if_exists(&staging_root(&state_root, &journal.transaction_id))?;
            sync_directory(&journals_root)?;
            RecoveryAction::RolledBack
        };
        reports.push(RecoveryReport {
            transaction_id: journal.transaction_id,
            action,
        });
    }
    cleanup_orphan_staging(&state_root)?;
    Ok(reports)
}

pub fn cleanup_unreferenced_backups(
    state_root: &Path,
    disposable_hashes: &BTreeSet<String>,
) -> Result<usize, DeployError> {
    let state_root = prepare_state_root(state_root, None)?;
    let _lock = acquire_deployment_lock(&state_root)?;
    cleanup_unreferenced_backups_unlocked(&state_root, disposable_hashes)
}

pub fn load_receipt(
    state_root: &Path,
    installation_id: &str,
) -> Result<Option<DeploymentReceipt>, DeployError> {
    validate_identifier("installation", installation_id)?;
    let path = receipt_path(state_root, installation_id);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => read_json(&path).map(Some),
        Ok(_) => Err(DeployError::UnsafeStateRoot(format!(
            "receipt is not a regular file: {}",
            path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(DeployError::Io { path, source }),
    }
}

pub fn reconcile_managed_file_identities(
    state_root: &Path,
    installation_id: &str,
    game_root: &Path,
    transaction_id: &str,
    identities: &BTreeMap<String, DisplacedFile>,
) -> Result<DeploymentReceipt, DeployError> {
    validate_identifier("installation", installation_id)?;
    validate_identifier("transaction", transaction_id)?;
    if identities.is_empty() {
        return Err(DeployError::InvalidReceipt(
            "managed identity reconciliation requires at least one file".to_owned(),
        ));
    }
    let game_root = canonical_directory(game_root)?;
    let state_root = prepare_state_root(state_root, Some(&game_root))?;
    let _lock = acquire_deployment_lock(&state_root)?;
    ensure_no_pending_journals(&state_root)?;
    let mut receipt = load_receipt(&state_root, installation_id)?
        .ok_or_else(|| DeployError::InvalidReceipt("managed receipt does not exist".to_owned()))?;
    receipt = validate_receipt(&receipt, &game_root)?;
    for (relative_path, identity) in identities {
        validate_sha256(&identity.sha256).map_err(DeployError::InvalidReceipt)?;
        let normalized = validate_entry_path(relative_path, false, MAX_DEPLOYMENT_DEPTH)
            .map_err(|error| DeployError::InvalidReceipt(error.to_string()))?;
        if normalized.path != *relative_path {
            return Err(DeployError::InvalidReceipt(format!(
                "non-normalized reconciliation path '{relative_path}'"
            )));
        }
        let owned = receipt
            .files
            .iter_mut()
            .find(|file| file.relative_path == *relative_path)
            .ok_or_else(|| {
                DeployError::InvalidReceipt(format!(
                    "reconciliation path is not owned by the receipt: '{relative_path}'"
                ))
            })?;
        let path = game_root.join(path_from_normalized(relative_path));
        let metadata = fs::symlink_metadata(&path).map_err(|source| DeployError::Io {
            path: path.clone(),
            source,
        })?;
        if !metadata.file_type().is_file()
            || metadata.len() != identity.bytes
            || hash_file(&path)? != identity.sha256
        {
            return Err(DeployError::PlanChanged);
        }
        owned.bytes = identity.bytes;
        owned.sha256 = identity.sha256.clone();
    }
    replace_json(
        &receipt_path(&state_root, installation_id),
        &receipt,
        transaction_id,
    )?;
    Ok(receipt)
}

pub fn reconcile_disabled_marker_aliases(
    state_root: &Path,
    installation_id: &str,
    game_root: &Path,
) -> Result<usize, DeployError> {
    const DISABLED_SUFFIX: &str = ".zdev-disabled";

    validate_identifier("installation", installation_id)?;
    let game_root = canonical_directory(game_root)?;
    let state_root = prepare_state_root(state_root, Some(&game_root))?;
    let _lock = acquire_deployment_lock(&state_root)?;
    ensure_no_pending_journals(&state_root)?;
    let Some(receipt) = load_receipt(&state_root, installation_id)? else {
        return Ok(0);
    };
    let mut receipt = validate_receipt(&receipt, &game_root)?;
    let existing_paths = receipt
        .files
        .iter()
        .map(|file| file.relative_path.clone())
        .collect::<BTreeSet<_>>();
    let mut reconciled = 0;
    for file in &mut receipt.files {
        if !Path::new(&file.relative_path)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("enabled.txt"))
        {
            continue;
        }
        let canonical = game_root.join(path_from_normalized(&file.relative_path));
        match fs::symlink_metadata(&canonical) {
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(DeployError::Io {
                    path: canonical,
                    source,
                });
            }
        }
        let alias_relative = format!("{}{DISABLED_SUFFIX}", file.relative_path);
        if existing_paths.contains(&alias_relative) {
            return Err(DeployError::InvalidReceipt(format!(
                "disabled marker alias is already owned: '{alias_relative}'"
            )));
        }
        let normalized = validate_entry_path(&alias_relative, false, MAX_DEPLOYMENT_DEPTH)
            .map_err(|error| DeployError::InvalidReceipt(error.to_string()))?;
        if normalized.path != alias_relative {
            return Err(DeployError::InvalidReceipt(format!(
                "disabled marker alias is not normalized: '{alias_relative}'"
            )));
        }
        let alias = game_root.join(path_from_normalized(&alias_relative));
        let metadata = match fs::symlink_metadata(&alias) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(DeployError::Io {
                    path: alias,
                    source,
                });
            }
        };
        if !metadata.file_type().is_file()
            || metadata.len() != file.bytes
            || hash_file(&alias)? != file.sha256
        {
            continue;
        }
        file.relative_path = alias_relative;
        reconciled += 1;
    }
    if reconciled > 0 {
        receipt
            .files
            .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        replace_json(
            &receipt_path(&state_root, installation_id),
            &receipt,
            "disabled-marker-aliases",
        )?;
    }
    Ok(reconciled)
}

pub fn inventory_game_files(
    game_root: &Path,
    receipt: Option<&DeploymentReceipt>,
) -> Result<GameFileInventoryReport, DeployError> {
    let game_root = canonical_directory(game_root)?;
    let receipt = receipt
        .map(|receipt| validate_receipt(receipt, &game_root))
        .transpose()?;
    let owned = receipt.as_ref().map(receipt_map).unwrap_or_default();
    let mut owned_keys = BTreeMap::new();
    let mut owned_prefixes = BTreeMap::new();
    for file in owned.values() {
        let normalized = validate_entry_path(&file.relative_path, false, MAX_DEPLOYMENT_DEPTH)
            .map_err(|error| DeployError::InvalidReceipt(error.to_string()))?;
        owned_keys.insert(normalized.collision_key, file.relative_path.clone());
        let components: Vec<_> = file.relative_path.split('/').collect();
        for end in 1..components.len() {
            let prefix = components[..end].join("/");
            let normalized = validate_entry_path(&prefix, true, MAX_DEPLOYMENT_DEPTH)
                .map_err(|error| DeployError::InvalidReceipt(error.to_string()))?;
            owned_prefixes
                .entry(normalized.collision_key)
                .or_insert(prefix);
        }
    }

    let mut entries = Vec::new();
    let mut seen_owned = BTreeSet::new();
    let mut pending = vec![game_root.clone()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|source| DeployError::Io {
            path: directory.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| DeployError::Io {
                path: directory.clone(),
                source,
            })?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|source| DeployError::Io {
                path: path.clone(),
                source,
            })?;
            let relative = path
                .strip_prefix(&game_root)
                .map_err(|_| DeployError::PlanChanged)?;
            let Some(relative) = relative.to_str() else {
                entries.push(GameFileInventoryEntry {
                    relative_path: relative.to_string_lossy().into_owned(),
                    status: InventoryStatus::SpecialEntry,
                    bytes: None,
                    actual_sha256: None,
                    expected_sha256: None,
                    collision_with: None,
                    detail: Some("path is not valid Unicode".to_owned()),
                });
                if file_type.is_dir() && !file_type.is_symlink() {
                    pending.push(path);
                }
                continue;
            };
            let relative = relative.replace(std::path::MAIN_SEPARATOR, "/");
            let normalized =
                match validate_entry_path(&relative, file_type.is_dir(), MAX_DEPLOYMENT_DEPTH) {
                    Ok(normalized) => normalized,
                    Err(error) => {
                        entries.push(GameFileInventoryEntry {
                            relative_path: relative,
                            status: InventoryStatus::SpecialEntry,
                            bytes: None,
                            actual_sha256: None,
                            expected_sha256: None,
                            collision_with: None,
                            detail: Some(error.to_string()),
                        });
                        if file_type.is_dir() && !file_type.is_symlink() {
                            pending.push(path);
                        }
                        continue;
                    }
                };

            let collision_with = owned_keys
                .get(&normalized.collision_key)
                .or_else(|| owned_prefixes.get(&normalized.collision_key));
            if file_type.is_dir() && !file_type.is_symlink() {
                if let Some(expected) = owned.get(&normalized.path) {
                    entries.push(GameFileInventoryEntry {
                        relative_path: normalized.path.clone(),
                        status: InventoryStatus::SpecialEntry,
                        bytes: None,
                        actual_sha256: None,
                        expected_sha256: Some(expected.sha256.clone()),
                        collision_with: None,
                        detail: Some("managed file path is occupied by a directory".to_owned()),
                    });
                } else if let Some(expected) = collision_with
                    && expected != &normalized.path
                {
                    entries.push(collision_entry(&normalized.path, expected));
                }
                pending.push(path);
                continue;
            }
            if file_type.is_symlink() {
                entries.push(GameFileInventoryEntry {
                    relative_path: normalized.path,
                    status: InventoryStatus::UnsafeLink,
                    bytes: None,
                    actual_sha256: None,
                    expected_sha256: owned.get(&relative).map(|file| file.sha256.clone()),
                    collision_with: collision_with.cloned(),
                    detail: Some("filesystem link is not followed".to_owned()),
                });
                continue;
            }
            if !file_type.is_file() {
                entries.push(GameFileInventoryEntry {
                    relative_path: normalized.path,
                    status: InventoryStatus::SpecialEntry,
                    bytes: None,
                    actual_sha256: None,
                    expected_sha256: None,
                    collision_with: collision_with.cloned(),
                    detail: Some("entry is neither a regular file nor a directory".to_owned()),
                });
                continue;
            }
            let metadata = entry.metadata().map_err(|source| DeployError::Io {
                path: path.clone(),
                source,
            })?;
            if let Some(expected) = owned.get(&normalized.path) {
                seen_owned.insert(normalized.path.clone());
                let actual_sha256 = hash_file(&path)?;
                let status = if metadata.len() == expected.bytes && actual_sha256 == expected.sha256
                {
                    InventoryStatus::ManagedMatch
                } else {
                    InventoryStatus::ManagedDrifted
                };
                entries.push(GameFileInventoryEntry {
                    relative_path: normalized.path,
                    status,
                    bytes: Some(metadata.len()),
                    actual_sha256: Some(actual_sha256),
                    expected_sha256: Some(expected.sha256.clone()),
                    collision_with: None,
                    detail: None,
                });
            } else if let Some(expected) = collision_with {
                entries.push(GameFileInventoryEntry {
                    relative_path: normalized.path,
                    status: InventoryStatus::UnmanagedCollision,
                    bytes: Some(metadata.len()),
                    actual_sha256: None,
                    expected_sha256: None,
                    collision_with: Some(expected.clone()),
                    detail: None,
                });
            } else {
                entries.push(GameFileInventoryEntry {
                    relative_path: normalized.path,
                    status: InventoryStatus::Unmanaged,
                    bytes: Some(metadata.len()),
                    actual_sha256: None,
                    expected_sha256: None,
                    collision_with: None,
                    detail: None,
                });
            }
        }
    }
    for file in owned.values() {
        if !seen_owned.contains(&file.relative_path) {
            entries.push(GameFileInventoryEntry {
                relative_path: file.relative_path.clone(),
                status: InventoryStatus::ManagedMissing,
                bytes: None,
                actual_sha256: None,
                expected_sha256: Some(file.sha256.clone()),
                collision_with: None,
                detail: None,
            });
        }
    }
    entries.sort_by(|left, right| {
        left.relative_path
            .cmp(&right.relative_path)
            .then_with(|| left.status.cmp(&right.status))
    });
    Ok(GameFileInventoryReport {
        game_root,
        managed_match_count: count_status(&entries, InventoryStatus::ManagedMatch),
        managed_drift_count: count_status(&entries, InventoryStatus::ManagedDrifted),
        managed_missing_count: count_status(&entries, InventoryStatus::ManagedMissing),
        unmanaged_count: count_status(&entries, InventoryStatus::Unmanaged),
        collision_count: count_status(&entries, InventoryStatus::UnmanagedCollision),
        unsafe_count: entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.status,
                    InventoryStatus::UnsafeLink | InventoryStatus::SpecialEntry
                )
            })
            .count(),
        entries,
    })
}

fn collision_entry(relative_path: &str, expected: &str) -> GameFileInventoryEntry {
    GameFileInventoryEntry {
        relative_path: relative_path.to_owned(),
        status: InventoryStatus::UnmanagedCollision,
        bytes: None,
        actual_sha256: None,
        expected_sha256: None,
        collision_with: Some(expected.to_owned()),
        detail: Some("directory component collides with a managed path".to_owned()),
    }
}

fn count_status(entries: &[GameFileInventoryEntry], status: InventoryStatus) -> usize {
    entries
        .iter()
        .filter(|entry| entry.status == status)
        .count()
}

fn activate_with_failpoint<F, P>(
    plan: &DeploymentPlan,
    game_running: F,
    failpoint: P,
) -> Result<ActivationReport, DeployError>
where
    F: Fn() -> bool,
    P: FnMut(DeploymentBoundary) -> Result<(), DeployError>,
{
    if !plan.ready() {
        return Err(DeployError::PlanBlocked);
    }
    if game_running() {
        return Err(DeployError::GameRunning);
    }
    let refreshed = plan_deployment_with_approvals(
        DeploymentRequest {
            transaction_id: plan.transaction_id.clone(),
            installation_id: plan.installation_id.clone(),
            profile_id: plan.profile_id.clone(),
            game_root: plan.game_root.clone(),
            state_root: plan.state_root.clone(),
            files: plan.files.clone(),
            external_files: plan.external_files.clone(),
            allow_unmanaged: plan.allow_unmanaged,
            game_running: false,
        },
        plan.previous_receipt.as_ref(),
        plan.managed_file_restore_approvals.clone(),
    )?;
    if refreshed != *plan {
        #[cfg(debug_assertions)]
        eprintln!("deployment plan mismatch\nexpected: {plan:#?}\nrefreshed: {refreshed:#?}");
        return Err(DeployError::PlanChanged);
    }

    activate_prepared_with_failpoint(plan, game_running, failpoint)
}

fn activate_prepared_with_failpoint<F, P>(
    plan: &DeploymentPlan,
    game_running: F,
    mut failpoint: P,
) -> Result<ActivationReport, DeployError>
where
    F: Fn() -> bool,
    P: FnMut(DeploymentBoundary) -> Result<(), DeployError>,
{
    if !plan.ready() {
        return Err(DeployError::PlanBlocked);
    }
    if game_running() {
        return Err(DeployError::GameRunning);
    }
    let has_payload_changes = plan.changes.iter().any(|change| {
        !matches!(
            change.kind,
            DeploymentChangeKind::UnchangedManaged | DeploymentChangeKind::AdoptIdenticalUnmanaged
        )
    }) || !plan.external_moves.is_empty();
    if !has_payload_changes && plan.previous_receipt.as_ref() == Some(&plan.target_receipt) {
        if load_receipt(&plan.state_root, &plan.installation_id)? != plan.previous_receipt {
            return Err(DeployError::PlanChanged);
        }
        return Ok(ActivationReport {
            transaction_id: plan.transaction_id.clone(),
            installation_id: plan.installation_id.clone(),
            profile_id: plan.profile_id.clone(),
            receipt_path: receipt_path(&plan.state_root, &plan.installation_id),
            changed_files: 0,
            backup_hashes: Vec::new(),
        });
    }

    let state_root = prepare_state_root(&plan.state_root, Some(&plan.game_root))?;
    let _lock = acquire_deployment_lock(&state_root)?;
    ensure_no_pending_journals(&state_root)?;
    let journal_path = journal_path(&state_root, &plan.transaction_id);
    let marker_path = commit_marker_path(&state_root, &plan.transaction_id);
    if journal_path.exists()
        || marker_path.exists()
        || staging_root(&state_root, &plan.transaction_id).exists()
    {
        return Err(DeployError::TransactionExists(plan.transaction_id.clone()));
    }
    verify_active_receipt(plan, &state_root).inspect_err(|_error| {
        #[cfg(debug_assertions)]
        eprintln!("active receipt verification failed: {_error:?}");
    })?;
    let stage = materialize_staging(plan, &state_root).inspect_err(|_error| {
        #[cfg(debug_assertions)]
        eprintln!("deployment staging failed: {_error:?}");
    })?;
    let backup_hashes = match materialize_backups(plan, &state_root) {
        Ok(hashes) => hashes,
        Err(error) => {
            #[cfg(debug_assertions)]
            eprintln!("deployment backup failed: {error:?}");
            remove_tree_if_exists(&stage)?;
            return Err(error);
        }
    };
    let journal = DeploymentJournal {
        schema_version: 2,
        transaction_id: plan.transaction_id.clone(),
        installation_id: plan.installation_id.clone(),
        game_root: plan.game_root.clone(),
        state_root: state_root.clone(),
        changes: plan.changes.clone(),
        external_moves: plan.external_moves.clone(),
        previous_receipt: plan.previous_receipt.clone(),
        target_receipt: plan.target_receipt.clone(),
    };
    if let Err(error) = write_json_create_new(&journal_path, &journal) {
        remove_file_if_exists(&journal_path)?;
        remove_tree_if_exists(&stage)?;
        return Err(error);
    }
    sync_directory(&state_root.join("journals"))?;

    let result = (|| {
        failpoint(DeploymentBoundary::JournalDurable)?;
        if game_running() {
            return Err(DeployError::GameRunning);
        }
        for (index, change) in plan.changes.iter().enumerate() {
            apply_change(plan, &stage, change).inspect_err(|_error| {
                #[cfg(debug_assertions)]
                eprintln!("deployment change failed for {change:?}: {_error:?}");
            })?;
            failpoint(DeploymentBoundary::OperationApplied(index))?;
            if game_running() {
                return Err(DeployError::GameRunning);
            }
        }
        if !plan.external_moves.is_empty() {
            stage_external_moves(plan)?;
            failpoint(DeploymentBoundary::ExternalSourcesStaged)?;
            if game_running() {
                return Err(DeployError::GameRunning);
            }
            for (index, external_move) in plan.external_moves.iter().enumerate() {
                apply_external_target(plan, index, external_move)?;
                failpoint(DeploymentBoundary::OperationApplied(
                    plan.changes.len() + index,
                ))?;
                if game_running() {
                    return Err(DeployError::GameRunning);
                }
            }
        }
        verify_target_state(plan).inspect_err(|_error| {
            #[cfg(debug_assertions)]
            eprintln!("deployment target verification failed: {_error:?}");
        })?;
        failpoint(DeploymentBoundary::FilesVerified)?;
        if game_running() {
            return Err(DeployError::GameRunning);
        }
        write_active_receipt(&journal, &state_root)?;
        failpoint(DeploymentBoundary::ReceiptWritten)?;
        write_commit_marker(&marker_path)?;
        sync_directory(&state_root.join("journals"))?;
        Ok(())
    })();

    if let Err(error) = result {
        rollback_journal(&journal)?;
        remove_file_if_exists(&journal_path)?;
        remove_tree_if_exists(&stage)?;
        sync_directory(&state_root.join("journals"))?;
        return Err(error);
    }

    cleanup_transaction(&journal, &journal_path, &marker_path)?;
    Ok(ActivationReport {
        transaction_id: plan.transaction_id.clone(),
        installation_id: plan.installation_id.clone(),
        profile_id: plan.profile_id.clone(),
        receipt_path: receipt_path(&state_root, &plan.installation_id),
        changed_files: plan
            .changes
            .iter()
            .filter(|change| {
                !matches!(
                    change.kind,
                    DeploymentChangeKind::UnchangedManaged
                        | DeploymentChangeKind::AdoptIdenticalUnmanaged
                )
            })
            .count()
            + plan.external_moves.len(),
        backup_hashes,
    })
}

fn prepare_state_root(state_root: &Path, game_root: Option<&Path>) -> Result<PathBuf, DeployError> {
    let prospective = prospective_canonical_path(state_root)?;
    if let Some(game_root) = game_root
        && (prospective.starts_with(game_root) || game_root.starts_with(&prospective))
    {
        return Err(DeployError::UnsafeStateRoot(
            "state root and game root must not contain each other".to_owned(),
        ));
    }
    fs::create_dir_all(state_root).map_err(|source| DeployError::Io {
        path: state_root.to_path_buf(),
        source,
    })?;
    let metadata = fs::symlink_metadata(state_root).map_err(|source| DeployError::Io {
        path: state_root.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DeployError::UnsafeStateRoot(format!(
            "state root must be a real directory: {}",
            state_root.display()
        )));
    }
    let canonical = fs::canonicalize(state_root).map_err(|source| DeployError::Io {
        path: state_root.to_path_buf(),
        source,
    })?;
    if let Some(game_root) = game_root
        && (canonical.starts_with(game_root) || game_root.starts_with(&canonical))
    {
        return Err(DeployError::UnsafeStateRoot(
            "state root and game root must not contain each other".to_owned(),
        ));
    }
    for directory in ["backups", "journals", "receipts", "staging"] {
        let path = canonical.join(directory);
        fs::create_dir_all(&path).map_err(|source| DeployError::Io {
            path: path.clone(),
            source,
        })?;
        let metadata = fs::symlink_metadata(&path).map_err(|source| DeployError::Io {
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(DeployError::UnsafeStateRoot(format!(
                "managed state path must be a real directory: {}",
                path.display()
            )));
        }
    }
    Ok(canonical)
}

fn acquire_deployment_lock(state_root: &Path) -> Result<DeploymentLock, DeployError> {
    let path = state_root.join("deployment.lock");
    if let Ok(metadata) = fs::symlink_metadata(&path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(DeployError::UnsafeStateRoot(format!(
            "deployment lock must be a regular file: {}",
            path.display()
        )));
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .map_err(|source| DeployError::Io {
            path: path.clone(),
            source,
        })?;
    let metadata = file.metadata().map_err(|source| DeployError::Io {
        path: path.clone(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(DeployError::UnsafeStateRoot(format!(
            "deployment lock must be a regular file: {}",
            path.display()
        )));
    }
    match file.try_lock() {
        Ok(()) => Ok(DeploymentLock { file }),
        Err(std::fs::TryLockError::WouldBlock) => Err(DeployError::DeploymentBusy),
        Err(std::fs::TryLockError::Error(source)) => Err(DeployError::Io { path, source }),
    }
}

fn ensure_no_pending_journals(state_root: &Path) -> Result<(), DeployError> {
    let journals = state_root.join("journals");
    for entry in fs::read_dir(&journals).map_err(|source| DeployError::Io {
        path: journals.clone(),
        source,
    })? {
        let entry = entry.map_err(|source| DeployError::Io {
            path: journals.clone(),
            source,
        })?;
        if entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            return Err(DeployError::PendingRecovery);
        }
    }
    Ok(())
}

fn cleanup_orphan_staging(state_root: &Path) -> Result<(), DeployError> {
    let staging = state_root.join("staging");
    for entry in fs::read_dir(&staging).map_err(|source| DeployError::Io {
        path: staging.clone(),
        source,
    })? {
        let entry = entry.map_err(|source| DeployError::Io {
            path: staging.clone(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| DeployError::Io {
            path: path.clone(),
            source,
        })?;
        if file_type.is_symlink() || !file_type.is_dir() {
            return Err(DeployError::UnsafeStateRoot(format!(
                "orphan staging path is not a real directory: {}",
                path.display()
            )));
        }
        let transaction_id = entry.file_name().into_string().map_err(|_| {
            DeployError::UnsafeStateRoot(format!(
                "orphan staging path is not valid UTF-8: {}",
                path.display()
            ))
        })?;
        validate_identifier("transaction", &transaction_id)?;
        remove_tree_if_exists(&path)?;
    }
    sync_directory(&staging)
}

fn verify_active_receipt(plan: &DeploymentPlan, state_root: &Path) -> Result<(), DeployError> {
    let current = load_receipt(state_root, &plan.installation_id)?;
    if current != plan.previous_receipt {
        return Err(DeployError::PlanChanged);
    }
    Ok(())
}

fn materialize_staging(plan: &DeploymentPlan, state_root: &Path) -> Result<PathBuf, DeployError> {
    let root = staging_root(state_root, &plan.transaction_id);
    fs::create_dir(&root).map_err(|source| DeployError::Io {
        path: root.clone(),
        source,
    })?;
    let result = sync_directory(&root);
    if let Err(error) = result {
        remove_tree_if_exists(&root)?;
        return Err(error);
    }
    Ok(root)
}

fn materialize_backups(
    plan: &DeploymentPlan,
    state_root: &Path,
) -> Result<Vec<String>, DeployError> {
    let mut hashes = BTreeSet::new();
    for change in &plan.changes {
        if !matches!(
            change.kind,
            DeploymentChangeKind::ReplaceManaged
                | DeploymentChangeKind::ReplaceUnmanaged
                | DeploymentChangeKind::RestoreUnmanaged
        ) {
            continue;
        }
        let hash = change
            .previous_sha256
            .as_ref()
            .ok_or(DeployError::PlanChanged)?;
        let source = plan
            .game_root
            .join(path_from_normalized(&change.relative_path));
        ensure_backup(&source, state_root, hash)?;
        hashes.insert(hash.clone());
        if change.kind == DeploymentChangeKind::RestoreUnmanaged {
            let restore_hash = change
                .next_sha256
                .as_ref()
                .ok_or(DeployError::PlanChanged)?;
            verify_backup(state_root, restore_hash)?;
        }
    }
    for external_file in &plan.external_files {
        let source = plan
            .game_root
            .join(path_from_normalized(&external_file.source_relative_path));
        let metadata = fs::symlink_metadata(&source).map_err(|_| DeployError::PlanChanged)?;
        if !metadata.file_type().is_file()
            || metadata.len() != external_file.bytes
            || hash_file(&source)? != external_file.sha256
        {
            return Err(DeployError::PlanChanged);
        }
        ensure_backup(&source, state_root, &external_file.sha256)?;
        hashes.insert(external_file.sha256.clone());
    }
    Ok(hashes.into_iter().collect())
}

fn ensure_backup(source: &Path, state_root: &Path, expected_hash: &str) -> Result<(), DeployError> {
    let shard = state_root.join("backups").join(&expected_hash[..2]);
    match fs::symlink_metadata(&shard) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(DeployError::UnsafeStateRoot(format!(
                "backup shard must be a real directory: {}",
                shard.display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(&shard).map_err(|source| DeployError::Io {
                path: shard.clone(),
                source,
            })?;
        }
        Err(source) => {
            return Err(DeployError::Io {
                path: shard.clone(),
                source,
            });
        }
    }
    let destination = shard.join(expected_hash);
    match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || hash_file(&destination)? != expected_hash {
                return Err(DeployError::UnsafeStateRoot(format!(
                    "backup is corrupt: {}",
                    destination.display()
                )));
            }
            return Ok(());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(DeployError::Io {
                path: destination.clone(),
                source,
            });
        }
    }
    let metadata = fs::metadata(source).map_err(|source_error| DeployError::Io {
        path: source.to_path_buf(),
        source: source_error,
    })?;
    let temporary = shard.join(format!(".{expected_hash}.incoming"));
    remove_file_if_exists(&temporary)?;
    if fs::hard_link(source, &temporary).is_ok() {
        if hash_file(&temporary)? != expected_hash {
            remove_file_if_exists(&temporary)?;
            return Err(DeployError::PlanChanged);
        }
    } else if let Err(error) =
        clone_or_copy_verified(source, &temporary, metadata.len(), expected_hash)
    {
        remove_file_if_exists(&temporary)?;
        return Err(error);
    }
    match fs::rename(&temporary, &destination) {
        Ok(()) => {}
        Err(_error) if destination.exists() => {
            remove_file_if_exists(&temporary)?;
            if hash_file(&destination)? != expected_hash {
                return Err(DeployError::UnsafeStateRoot(format!(
                    "backup raced with corrupt content: {}",
                    destination.display()
                )));
            }
        }
        Err(source) => {
            return Err(DeployError::Io {
                path: destination,
                source,
            });
        }
    }
    sync_directory(&shard)
}

fn cleanup_unreferenced_backups_unlocked(
    state_root: &Path,
    disposable_hashes: &BTreeSet<String>,
) -> Result<usize, DeployError> {
    let mut referenced = BTreeSet::new();
    let receipts_root = state_root.join("receipts");
    match fs::read_dir(&receipts_root) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|source| DeployError::Io {
                    path: receipts_root.clone(),
                    source,
                })?;
                let file_type = entry.file_type().map_err(|source| DeployError::Io {
                    path: entry.path(),
                    source,
                })?;
                if file_type.is_file()
                    && entry
                        .path()
                        .extension()
                        .is_some_and(|extension| extension == "json")
                {
                    let receipt: DeploymentReceipt = read_json(&entry.path())?;
                    referenced.extend(receipt.files.into_iter().filter_map(|file| {
                        file.displaced_unmanaged.map(|displaced| displaced.sha256)
                    }));
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(DeployError::Io {
                path: receipts_root,
                source,
            });
        }
    }

    let journals_root = state_root.join("journals");
    match fs::read_dir(&journals_root) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|source| DeployError::Io {
                    path: journals_root.clone(),
                    source,
                })?;
                let file_type = entry.file_type().map_err(|source| DeployError::Io {
                    path: entry.path(),
                    source,
                })?;
                if file_type.is_file()
                    && entry
                        .path()
                        .extension()
                        .is_some_and(|extension| extension == "json")
                {
                    let journal: DeploymentJournal = read_json(&entry.path())?;
                    for change in journal.changes {
                        referenced.extend(change.previous_sha256);
                        referenced.extend(change.next_sha256);
                    }
                    referenced.extend(journal.external_moves.into_iter().map(|file| file.sha256));
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(DeployError::Io {
                path: journals_root,
                source,
            });
        }
    }

    let backups_root = state_root.join("backups");
    let shards = match fs::read_dir(&backups_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(source) => {
            return Err(DeployError::Io {
                path: backups_root,
                source,
            });
        }
    };
    let mut removed = 0;
    for shard in shards {
        let shard = shard.map_err(|source| DeployError::Io {
            path: backups_root.clone(),
            source,
        })?;
        let shard_type = shard.file_type().map_err(|source| DeployError::Io {
            path: shard.path(),
            source,
        })?;
        if shard_type.is_symlink() || !shard_type.is_dir() {
            return Err(DeployError::UnsafeStateRoot(format!(
                "backup storage contains an unsafe entry: {}",
                shard.path().display()
            )));
        }
        let backups = fs::read_dir(shard.path()).map_err(|source| DeployError::Io {
            path: shard.path(),
            source,
        })?;
        for backup in backups {
            let backup = backup.map_err(|source| DeployError::Io {
                path: shard.path(),
                source,
            })?;
            let name = backup.file_name().to_string_lossy().into_owned();
            let backup_type = backup.file_type().map_err(|source| DeployError::Io {
                path: backup.path(),
                source,
            })?;
            if !backup_type.is_file()
                || name.len() != 64
                || !name.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(DeployError::UnsafeStateRoot(format!(
                    "backup storage contains an unsafe file: {}",
                    backup.path().display()
                )));
            }
            if !referenced.contains(&name) && disposable_hashes.contains(&name) {
                fs::remove_file(backup.path()).map_err(|source| DeployError::Io {
                    path: backup.path(),
                    source,
                })?;
                removed += 1;
            }
        }
        if fs::read_dir(shard.path())
            .map_err(|source| DeployError::Io {
                path: shard.path(),
                source,
            })?
            .next()
            .is_none()
        {
            fs::remove_dir(shard.path()).map_err(|source| DeployError::Io {
                path: shard.path(),
                source,
            })?;
        }
    }
    Ok(removed)
}

fn verify_backup(state_root: &Path, expected_hash: &str) -> Result<(), DeployError> {
    let path = backup_path(state_root, expected_hash);
    let metadata = fs::symlink_metadata(&path).map_err(|source| DeployError::Io {
        path: path.clone(),
        source,
    })?;
    if !metadata.file_type().is_file() || hash_file(&path)? != expected_hash {
        return Err(DeployError::UnsafeStateRoot(format!(
            "required backup is corrupt: {}",
            path.display()
        )));
    }
    Ok(())
}

fn apply_change(
    plan: &DeploymentPlan,
    stage: &Path,
    change: &DeploymentChange,
) -> Result<(), DeployError> {
    let destination = plan
        .game_root
        .join(path_from_normalized(&change.relative_path));
    if matches!(
        change.kind,
        DeploymentChangeKind::UnchangedManaged | DeploymentChangeKind::AdoptIdenticalUnmanaged
    ) {
        return Ok(());
    }
    if change.kind == DeploymentChangeKind::RemoveManaged {
        let parent = destination.parent().ok_or(DeployError::PlanChanged)?;
        let old = sibling_transaction_path(&destination, &plan.transaction_id, "old")?;
        if old.exists() {
            return Err(DeployError::PlanChanged);
        }
        fs::rename(&destination, &old).map_err(|source| DeployError::Io {
            path: destination.clone(),
            source,
        })?;
        sync_directory(parent)?;
        return Ok(());
    }
    let parent = destination.parent().ok_or(DeployError::PlanChanged)?;
    create_managed_parents(&plan.game_root, &change.relative_path)?;
    let temporary = sibling_transaction_path(&destination, &plan.transaction_id, "new")?;
    let old = sibling_transaction_path(&destination, &plan.transaction_id, "old")?;
    if temporary.exists() || old.exists() {
        return Err(DeployError::PlanChanged);
    }

    if change.kind == DeploymentChangeKind::RestoreUnmanaged {
        let restore_hash = change
            .next_sha256
            .as_ref()
            .ok_or(DeployError::PlanChanged)?;
        let state_root = stage
            .parent()
            .and_then(Path::parent)
            .ok_or(DeployError::PlanChanged)?;
        let backup = backup_path(state_root, restore_hash);
        restore_file(&backup, &destination, restore_hash, &plan.transaction_id)?;
        return Ok(());
    }

    let desired = plan
        .files
        .iter()
        .find(|file| file.relative_path == change.relative_path)
        .ok_or(DeployError::PlanChanged)?;
    clone_or_copy_verified(&desired.source, &temporary, desired.bytes, &desired.sha256)?;
    if change.kind == DeploymentChangeKind::Create {
        fs::hard_link(&temporary, &destination).map_err(|source| DeployError::Io {
            path: destination.clone(),
            source,
        })?;
        remove_file_if_exists(&temporary)?;
        sync_directory(parent)?;
        return Ok(());
    }

    fs::rename(&destination, &old).map_err(|source| DeployError::Io {
        path: destination.clone(),
        source,
    })?;
    if let Err(source) = fs::rename(&temporary, &destination) {
        let _ = fs::rename(&old, &destination);
        let _ = remove_file_if_exists(&temporary);
        return Err(DeployError::Io {
            path: destination,
            source,
        });
    }
    remove_file_if_exists(&old)?;
    sync_directory(parent)
}

fn stage_external_moves(plan: &DeploymentPlan) -> Result<(), DeployError> {
    for external_move in &plan.external_moves {
        create_managed_parents(&plan.game_root, &external_move.target_relative_path)?;
    }
    preflight_external_forward(plan)?;
    let mut parents = BTreeSet::new();
    for (index, external_move) in plan.external_moves.iter().enumerate() {
        let source = plan
            .game_root
            .join(path_from_normalized(&external_move.source_relative_path));
        let temporary =
            external_temporary_path(&plan.game_root, &plan.transaction_id, index, external_move)?;
        fs::rename(&source, &temporary).map_err(|source_error| DeployError::Io {
            path: source.clone(),
            source: source_error,
        })?;
        verify_file_state(
            &temporary,
            external_move.bytes,
            &external_move.sha256,
            &external_move.source_relative_path,
        )?;
        parents.insert(
            source
                .parent()
                .ok_or(DeployError::PlanChanged)?
                .to_path_buf(),
        );
    }
    for parent in parents {
        sync_directory(&parent)?;
    }
    Ok(())
}

fn preflight_external_forward(plan: &DeploymentPlan) -> Result<(), DeployError> {
    let sources: BTreeSet<_> = plan
        .external_moves
        .iter()
        .map(|external_move| external_move.source_relative_path.as_str())
        .collect();
    for (index, external_move) in plan.external_moves.iter().enumerate() {
        let source = plan
            .game_root
            .join(path_from_normalized(&external_move.source_relative_path));
        verify_file_state(
            &source,
            external_move.bytes,
            &external_move.sha256,
            &external_move.source_relative_path,
        )?;
        let temporary =
            external_temporary_path(&plan.game_root, &plan.transaction_id, index, external_move)?;
        verify_path_absent(&temporary, &external_move.source_relative_path)?;
        if !sources.contains(external_move.target_relative_path.as_str()) {
            let target = plan
                .game_root
                .join(path_from_normalized(&external_move.target_relative_path));
            verify_path_absent(&target, &external_move.target_relative_path)?;
        }
    }
    Ok(())
}

fn apply_external_target(
    plan: &DeploymentPlan,
    index: usize,
    external_move: &DeploymentExternalMove,
) -> Result<(), DeployError> {
    let temporary =
        external_temporary_path(&plan.game_root, &plan.transaction_id, index, external_move)?;
    verify_file_state(
        &temporary,
        external_move.bytes,
        &external_move.sha256,
        &external_move.source_relative_path,
    )?;
    let target = plan
        .game_root
        .join(path_from_normalized(&external_move.target_relative_path));
    verify_path_absent(&target, &external_move.target_relative_path)?;
    fs::hard_link(&temporary, &target).map_err(|source| DeployError::Io {
        path: target.clone(),
        source,
    })?;
    sync_directory(target.parent().ok_or(DeployError::PlanChanged)?)?;
    remove_file_if_exists(&temporary)?;
    sync_directory(temporary.parent().ok_or(DeployError::PlanChanged)?)
}

fn external_temporary_path(
    game_root: &Path,
    transaction_id: &str,
    index: usize,
    external_move: &DeploymentExternalMove,
) -> Result<PathBuf, DeployError> {
    let source = game_root.join(path_from_normalized(&external_move.source_relative_path));
    sibling_transaction_path(&source, transaction_id, &format!("external-{index}"))
}

fn verify_file_state(
    path: &Path,
    expected_bytes: u64,
    expected_hash: &str,
    relative_path: &str,
) -> Result<(), DeployError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| DeployError::RecoveryDrift {
        path: relative_path.to_owned(),
    })?;
    if !metadata.file_type().is_file()
        || metadata.len() != expected_bytes
        || hash_file(path)? != expected_hash
    {
        return Err(DeployError::RecoveryDrift {
            path: relative_path.to_owned(),
        });
    }
    Ok(())
}

fn verify_path_absent(path: &Path, relative_path: &str) -> Result<(), DeployError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(DeployError::RecoveryDrift {
            path: relative_path.to_owned(),
        }),
        Err(source) => Err(DeployError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn verify_target_state(plan: &DeploymentPlan) -> Result<(), DeployError> {
    for change in &plan.changes {
        if matches!(
            change.kind,
            DeploymentChangeKind::UnchangedManaged
                | DeploymentChangeKind::AdoptIdenticalUnmanaged
                | DeploymentChangeKind::RemoveManaged
                | DeploymentChangeKind::RestoreUnmanaged
        ) {
            continue;
        }
        let file = plan
            .files
            .iter()
            .find(|file| file.relative_path == change.relative_path)
            .ok_or(DeployError::PlanChanged)?;
        let path = plan
            .game_root
            .join(path_from_normalized(&file.relative_path));
        let metadata = fs::symlink_metadata(&path).map_err(|source| DeployError::Io {
            path: path.clone(),
            source,
        })?;
        if !metadata.file_type().is_file() || metadata.len() != file.bytes {
            return Err(DeployError::PlanChanged);
        }
    }
    let desired: BTreeSet<_> = plan
        .files
        .iter()
        .map(|file| file.relative_path.as_str())
        .collect();
    if let Some(previous) = &plan.previous_receipt {
        for file in &previous.files {
            if !desired.contains(file.relative_path.as_str()) {
                let change = plan
                    .changes
                    .iter()
                    .find(|change| change.relative_path == file.relative_path)
                    .ok_or(DeployError::PlanChanged)?;
                let path = plan
                    .game_root
                    .join(path_from_normalized(&file.relative_path));
                match change.kind {
                    DeploymentChangeKind::RemoveManaged if path.exists() => {
                        return Err(DeployError::PlanChanged);
                    }
                    DeploymentChangeKind::RestoreUnmanaged => {
                        let expected = change
                            .next_sha256
                            .as_ref()
                            .ok_or(DeployError::PlanChanged)?;
                        if !path.is_file() || hash_file(&path)? != *expected {
                            return Err(DeployError::PlanChanged);
                        }
                    }
                    DeploymentChangeKind::RemoveManaged => {}
                    _ => return Err(DeployError::PlanChanged),
                }
            }
        }
    }
    verify_external_target_state(
        &plan.game_root,
        &plan.transaction_id,
        &plan.external_moves,
        &plan.target_receipt.external_files,
    )?;
    Ok(())
}

fn write_active_receipt(journal: &DeploymentJournal, state_root: &Path) -> Result<(), DeployError> {
    let destination = receipt_path(state_root, &journal.installation_id);
    replace_json(
        &destination,
        &journal.target_receipt,
        &journal.transaction_id,
    )
}

fn rollback_journal(journal: &DeploymentJournal) -> Result<(), DeployError> {
    preflight_rollback(journal)?;
    rollback_external_moves(journal)?;
    for change in journal.changes.iter().rev() {
        let destination = journal
            .game_root
            .join(path_from_normalized(&change.relative_path));
        let temporary = sibling_transaction_path(&destination, &journal.transaction_id, "new")?;
        let old = sibling_transaction_path(&destination, &journal.transaction_id, "old")?;
        if change.kind == DeploymentChangeKind::RemoveManaged {
            match fs::symlink_metadata(&old) {
                Ok(metadata) if metadata.file_type().is_file() => {
                    if destination.exists()
                        || change.previous_sha256.as_deref().is_none_or(|expected| {
                            hash_file(&old).ok().as_deref() != Some(expected)
                        })
                    {
                        return Err(DeployError::RecoveryDrift {
                            path: change.relative_path.clone(),
                        });
                    }
                    fs::rename(&old, &destination).map_err(|source| DeployError::Io {
                        path: destination.clone(),
                        source,
                    })?;
                    remove_file_if_exists(&temporary)?;
                    sync_directory(destination.parent().ok_or(DeployError::PlanChanged)?)?;
                    continue;
                }
                Ok(_) => {
                    return Err(DeployError::RecoveryDrift {
                        path: change.relative_path.clone(),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(DeployError::Io {
                        path: old.clone(),
                        source,
                    });
                }
            }
        }
        let actual = match fs::symlink_metadata(&destination) {
            Ok(metadata) if metadata.file_type().is_file() => Some(hash_file(&destination)?),
            Ok(_) => {
                return Err(DeployError::RecoveryDrift {
                    path: change.relative_path.clone(),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(source) => {
                return Err(DeployError::Io {
                    path: destination,
                    source,
                });
            }
        };
        if let Some(previous_hash) = &change.previous_sha256 {
            let allowed = actual.as_ref().is_none_or(|hash| {
                hash == previous_hash || change.next_sha256.as_ref() == Some(hash)
            });
            if !allowed {
                return Err(DeployError::RecoveryDrift {
                    path: change.relative_path.clone(),
                });
            }
            if actual.as_ref() != Some(previous_hash) {
                let backup = backup_path(&journal.state_root, previous_hash);
                restore_file(
                    &backup,
                    &destination,
                    previous_hash,
                    &journal.transaction_id,
                )?;
            }
        } else if let Some(actual_hash) = actual {
            if change.next_sha256.as_ref() != Some(&actual_hash) {
                return Err(DeployError::RecoveryDrift {
                    path: change.relative_path.clone(),
                });
            }
            remove_file_if_exists(&destination)?;
        }
        remove_file_if_exists(&temporary)?;
        remove_file_if_exists(&old)?;
    }

    let active_receipt = receipt_path(&journal.state_root, &journal.installation_id);
    match &journal.previous_receipt {
        Some(receipt) => replace_json(&active_receipt, receipt, &journal.transaction_id)?,
        None => {
            if let Some(current) = load_receipt(&journal.state_root, &journal.installation_id)? {
                if current != journal.target_receipt {
                    return Err(DeployError::RecoveryDrift {
                        path: active_receipt.display().to_string(),
                    });
                }
                remove_file_if_exists(&active_receipt)?;
            }
        }
    }
    Ok(())
}

fn preflight_rollback(journal: &DeploymentJournal) -> Result<(), DeployError> {
    let active_receipt = receipt_path(&journal.state_root, &journal.installation_id);
    let current_receipt = load_receipt(&journal.state_root, &journal.installation_id)?;
    let receipt_is_expected = match &journal.previous_receipt {
        Some(previous) => {
            current_receipt.as_ref() == Some(previous)
                || current_receipt.as_ref() == Some(&journal.target_receipt)
        }
        None => {
            current_receipt.is_none() || current_receipt.as_ref() == Some(&journal.target_receipt)
        }
    };
    if !receipt_is_expected {
        return Err(DeployError::RecoveryDrift {
            path: active_receipt.display().to_string(),
        });
    }

    for change in journal.changes.iter().rev() {
        let destination = journal
            .game_root
            .join(path_from_normalized(&change.relative_path));
        if change.kind == DeploymentChangeKind::RemoveManaged {
            let old = sibling_transaction_path(&destination, &journal.transaction_id, "old")?;
            match fs::symlink_metadata(&old) {
                Ok(metadata) if metadata.file_type().is_file() => {
                    if destination.exists()
                        || change.previous_sha256.as_deref().is_none_or(|expected| {
                            hash_file(&old).ok().as_deref() != Some(expected)
                        })
                    {
                        return Err(DeployError::RecoveryDrift {
                            path: change.relative_path.clone(),
                        });
                    }
                    continue;
                }
                Ok(_) => {
                    return Err(DeployError::RecoveryDrift {
                        path: change.relative_path.clone(),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(source) => return Err(DeployError::Io { path: old, source }),
            }
        }
        let actual = match fs::symlink_metadata(&destination) {
            Ok(metadata) if metadata.file_type().is_file() => Some(hash_file(&destination)?),
            Ok(_) => {
                return Err(DeployError::RecoveryDrift {
                    path: change.relative_path.clone(),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(source) => {
                return Err(DeployError::Io {
                    path: destination,
                    source,
                });
            }
        };
        if let Some(previous_hash) = &change.previous_sha256 {
            let allowed = actual.as_ref().is_none_or(|hash| {
                hash == previous_hash || change.next_sha256.as_ref() == Some(hash)
            });
            if !allowed {
                return Err(DeployError::RecoveryDrift {
                    path: change.relative_path.clone(),
                });
            }
            if actual.as_ref() != Some(previous_hash) {
                verify_backup(&journal.state_root, previous_hash)?;
            }
        } else if let Some(actual_hash) = actual
            && change.next_sha256.as_ref() != Some(&actual_hash)
        {
            return Err(DeployError::RecoveryDrift {
                path: change.relative_path.clone(),
            });
        }
    }
    preflight_external_rollback(journal)?;
    Ok(())
}

fn preflight_external_rollback(journal: &DeploymentJournal) -> Result<(), DeployError> {
    let mut allowed = BTreeMap::<PathBuf, BTreeSet<(u64, String)>>::new();
    let mut expected = BTreeMap::<(u64, String), usize>::new();
    let mut temporary_targets = Vec::new();
    for (index, external_move) in journal.external_moves.iter().enumerate() {
        let signature = (external_move.bytes, external_move.sha256.clone());
        *expected.entry(signature.clone()).or_default() += 1;
        let source = journal
            .game_root
            .join(path_from_normalized(&external_move.source_relative_path));
        let target = journal
            .game_root
            .join(path_from_normalized(&external_move.target_relative_path));
        let temporary = external_temporary_path(
            &journal.game_root,
            &journal.transaction_id,
            index,
            external_move,
        )?;
        allowed.entry(source).or_default().insert(signature.clone());
        allowed
            .entry(target.clone())
            .or_default()
            .insert(signature.clone());
        allowed
            .entry(temporary.clone())
            .or_default()
            .insert(signature.clone());
        temporary_targets.push((temporary, target, signature));
        verify_backup(&journal.state_root, &external_move.sha256)?;
    }

    let mut actual = BTreeMap::<(u64, String), usize>::new();
    let mut occupied = BTreeMap::<PathBuf, (u64, String)>::new();
    for (path, allowed_signatures) in &allowed {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                let signature = (metadata.len(), hash_file(path)?);
                if !allowed_signatures.contains(&signature) {
                    return Err(DeployError::RecoveryDrift {
                        path: path.display().to_string(),
                    });
                }
                *actual.entry(signature.clone()).or_default() += 1;
                occupied.insert(path.clone(), signature);
            }
            Ok(_) => {
                return Err(DeployError::RecoveryDrift {
                    path: path.display().to_string(),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(DeployError::Io {
                    path: path.clone(),
                    source,
                });
            }
        }
    }
    let mut durable_link_duplicates = BTreeMap::<(u64, String), usize>::new();
    for (temporary, target, signature) in temporary_targets {
        if occupied.get(&temporary) == Some(&signature) && occupied.get(&target) == Some(&signature)
        {
            *durable_link_duplicates.entry(signature).or_default() += 1;
        }
    }
    for (signature, expected_count) in expected {
        let actual_count = actual.remove(&signature).unwrap_or_default();
        let maximum = expected_count
            + durable_link_duplicates
                .get(&signature)
                .copied()
                .unwrap_or_default();
        if actual_count < expected_count || actual_count > maximum {
            return Err(DeployError::RecoveryDrift {
                path: journal.game_root.display().to_string(),
            });
        }
    }
    if !actual.is_empty() {
        return Err(DeployError::RecoveryDrift {
            path: journal.game_root.display().to_string(),
        });
    }
    Ok(())
}

fn rollback_external_moves(journal: &DeploymentJournal) -> Result<(), DeployError> {
    let source_paths: BTreeSet<_> = journal
        .external_moves
        .iter()
        .map(|external_move| external_move.source_relative_path.as_str())
        .collect();
    let mut parents = BTreeSet::new();
    for external_move in &journal.external_moves {
        let source = journal
            .game_root
            .join(path_from_normalized(&external_move.source_relative_path));
        let backup = backup_path(&journal.state_root, &external_move.sha256);
        restore_file(
            &backup,
            &source,
            &external_move.sha256,
            &journal.transaction_id,
        )?;
        parents.insert(
            source
                .parent()
                .ok_or(DeployError::PlanChanged)?
                .to_path_buf(),
        );
    }
    for (index, external_move) in journal.external_moves.iter().enumerate() {
        let temporary = external_temporary_path(
            &journal.game_root,
            &journal.transaction_id,
            index,
            external_move,
        )?;
        remove_file_if_exists(&temporary)?;
        parents.insert(
            temporary
                .parent()
                .ok_or(DeployError::PlanChanged)?
                .to_path_buf(),
        );
        if !source_paths.contains(external_move.target_relative_path.as_str()) {
            let target = journal
                .game_root
                .join(path_from_normalized(&external_move.target_relative_path));
            match fs::symlink_metadata(&target) {
                Ok(_) => {
                    verify_file_state(
                        &target,
                        external_move.bytes,
                        &external_move.sha256,
                        &external_move.target_relative_path,
                    )?;
                    remove_file_if_exists(&target)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(DeployError::Io {
                        path: target,
                        source,
                    });
                }
            }
            parents.insert(
                target
                    .parent()
                    .ok_or(DeployError::PlanChanged)?
                    .to_path_buf(),
            );
        }
    }
    for parent in parents {
        sync_directory(&parent)?;
    }
    Ok(())
}

fn restore_file(
    backup: &Path,
    destination: &Path,
    expected_hash: &str,
    transaction_id: &str,
) -> Result<(), DeployError> {
    let metadata = fs::metadata(backup).map_err(|source| DeployError::Io {
        path: backup.to_path_buf(),
        source,
    })?;
    let temporary = sibling_transaction_path(destination, transaction_id, "restore")?;
    remove_file_if_exists(&temporary)?;
    create_parent_directory(destination)?;
    clone_or_copy_verified(backup, &temporary, metadata.len(), expected_hash)?;
    let displaced = sibling_transaction_path(destination, transaction_id, "displaced")?;
    remove_file_if_exists(&displaced)?;
    if destination.exists() {
        fs::rename(destination, &displaced).map_err(|source| DeployError::Io {
            path: destination.to_path_buf(),
            source,
        })?;
    }
    if let Err(source) = fs::rename(&temporary, destination) {
        if displaced.exists() {
            let _ = fs::rename(&displaced, destination);
        }
        return Err(DeployError::Io {
            path: destination.to_path_buf(),
            source,
        });
    }
    remove_file_if_exists(&displaced)?;
    sync_directory(destination.parent().ok_or(DeployError::PlanChanged)?)
}

fn verify_active_receipt_after_recovery(journal: &DeploymentJournal) -> Result<(), DeployError> {
    let current = load_receipt(&journal.state_root, &journal.installation_id)?;
    if current.as_ref() != Some(&journal.target_receipt) {
        return Err(DeployError::RecoveryDrift {
            path: receipt_path(&journal.state_root, &journal.installation_id)
                .display()
                .to_string(),
        });
    }
    Ok(())
}

fn verify_journal_target_state(journal: &DeploymentJournal) -> Result<(), DeployError> {
    for file in &journal.target_receipt.files {
        let path = journal
            .game_root
            .join(path_from_normalized(&file.relative_path));
        let mut blockers = Vec::new();
        inspect_parent_chain(&journal.game_root, &file.relative_path, &mut blockers)?;
        let metadata = fs::symlink_metadata(&path).map_err(|_| DeployError::RecoveryDrift {
            path: file.relative_path.clone(),
        })?;
        if !blockers.is_empty()
            || !metadata.file_type().is_file()
            || metadata.len() != file.bytes
            || hash_file(&path)? != file.sha256
        {
            return Err(DeployError::RecoveryDrift {
                path: file.relative_path.clone(),
            });
        }
    }
    for change in &journal.changes {
        let path = journal
            .game_root
            .join(path_from_normalized(&change.relative_path));
        match change.kind {
            DeploymentChangeKind::RemoveManaged => match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Ok(_) => {
                    return Err(DeployError::RecoveryDrift {
                        path: change.relative_path.clone(),
                    });
                }
                Err(source) => return Err(DeployError::Io { path, source }),
            },
            DeploymentChangeKind::RestoreUnmanaged => {
                let expected =
                    change
                        .next_sha256
                        .as_ref()
                        .ok_or_else(|| DeployError::RecoveryDrift {
                            path: change.relative_path.clone(),
                        })?;
                let mut blockers = Vec::new();
                inspect_parent_chain(&journal.game_root, &change.relative_path, &mut blockers)?;
                let metadata =
                    fs::symlink_metadata(&path).map_err(|_| DeployError::RecoveryDrift {
                        path: change.relative_path.clone(),
                    })?;
                if !blockers.is_empty()
                    || !metadata.file_type().is_file()
                    || hash_file(&path)? != *expected
                {
                    return Err(DeployError::RecoveryDrift {
                        path: change.relative_path.clone(),
                    });
                }
            }
            _ => {}
        }
    }
    verify_external_target_state(
        &journal.game_root,
        &journal.transaction_id,
        &journal.external_moves,
        &journal.target_receipt.external_files,
    )?;
    Ok(())
}

fn verify_external_target_state(
    game_root: &Path,
    transaction_id: &str,
    external_moves: &[DeploymentExternalMove],
    external_files: &[OrderedExternalFile],
) -> Result<(), DeployError> {
    for file in external_files {
        let mut blockers = Vec::new();
        inspect_parent_chain(game_root, &file.current_relative_path, &mut blockers)?;
        if !blockers.is_empty() {
            return Err(DeployError::RecoveryDrift {
                path: file.current_relative_path.clone(),
            });
        }
        let path = game_root.join(path_from_normalized(&file.current_relative_path));
        verify_file_state(&path, file.bytes, &file.sha256, &file.current_relative_path)?;
    }
    let targets: BTreeSet<_> = external_moves
        .iter()
        .map(|external_move| external_move.target_relative_path.as_str())
        .collect();
    for (index, external_move) in external_moves.iter().enumerate() {
        if !targets.contains(external_move.source_relative_path.as_str()) {
            let source = game_root.join(path_from_normalized(&external_move.source_relative_path));
            verify_path_absent(&source, &external_move.source_relative_path)?;
        }
        let temporary = external_temporary_path(game_root, transaction_id, index, external_move)?;
        verify_path_absent(&temporary, &external_move.source_relative_path)?;
    }
    Ok(())
}

fn cleanup_transaction(
    journal: &DeploymentJournal,
    journal_path: &Path,
    marker_path: &Path,
) -> Result<(), DeployError> {
    verify_journal_target_state(journal)?;
    verify_active_receipt_after_recovery(journal)?;
    for (index, external_move) in journal.external_moves.iter().enumerate() {
        remove_file_if_exists(&external_temporary_path(
            &journal.game_root,
            &journal.transaction_id,
            index,
            external_move,
        )?)?;
    }
    for change in &journal.changes {
        let destination = journal
            .game_root
            .join(path_from_normalized(&change.relative_path));
        remove_file_if_exists(&sibling_transaction_path(
            &destination,
            &journal.transaction_id,
            "old",
        )?)?;
    }
    cleanup_empty_managed_directories(&journal.game_root, &journal.changes)?;
    remove_tree_if_exists(&staging_root(&journal.state_root, &journal.transaction_id))?;
    remove_file_if_exists(journal_path)?;
    sync_directory(&journal.state_root.join("journals"))?;
    remove_file_if_exists(marker_path)?;
    sync_directory(&journal.state_root.join("journals"))
}

fn cleanup_empty_managed_directories(
    game_root: &Path,
    changes: &[DeploymentChange],
) -> Result<(), DeployError> {
    let mut candidates = BTreeSet::new();
    for change in changes {
        if change.kind != DeploymentChangeKind::RemoveManaged {
            continue;
        }
        let components = change.relative_path.split('/').collect::<Vec<_>>();
        let protected_len = components
            .windows(2)
            .position(|pair| pair[0].eq_ignore_ascii_case("ue4ss") && pair[1] == "Mods")
            .map(|index| index + 2)
            .or_else(|| {
                components
                    .windows(2)
                    .position(|pair| pair[0] == "Paks" && pair[1] == "~mods")
                    .map(|index| index + 2)
            });
        let Some(protected_len) = protected_len else {
            continue;
        };
        for end in (protected_len + 1)..components.len() {
            candidates.insert(components[..end].join("/"));
        }
    }
    let mut candidates = candidates.into_iter().collect::<Vec<_>>();
    candidates.sort_by_key(|path| std::cmp::Reverse(path.split('/').count()));
    for relative in candidates {
        let path = game_root.join(path_from_normalized(&relative));
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_dir() => match fs::remove_dir(&path) {
                Ok(()) => {
                    if let Some(parent) = path.parent() {
                        sync_directory(parent)?;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
                    ) => {}
                Err(source) => return Err(DeployError::Io { path, source }),
            },
            Ok(_) => {
                return Err(DeployError::RecoveryDrift { path: relative });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(DeployError::Io { path, source }),
        }
    }
    Ok(())
}

fn validate_journal(journal: &DeploymentJournal, state_root: &Path) -> Result<(), DeployError> {
    if !matches!(journal.schema_version, 1 | 2) || journal.state_root != state_root {
        return Err(DeployError::UnsafeStateRoot(
            "journal schema or state root does not match".to_owned(),
        ));
    }
    validate_identifier("transaction", &journal.transaction_id)?;
    validate_identifier("installation", &journal.installation_id)?;
    let game_root = canonical_directory(&journal.game_root)?;
    if game_root != journal.game_root {
        return Err(DeployError::UnsafeStateRoot(
            "journal game root is not canonical".to_owned(),
        ));
    }
    if state_root.starts_with(&game_root) || game_root.starts_with(state_root) {
        return Err(DeployError::UnsafeStateRoot(
            "journal state root and game root overlap".to_owned(),
        ));
    }
    validate_receipt(&journal.target_receipt, &game_root)?;
    if let Some(previous) = &journal.previous_receipt {
        validate_receipt(previous, &game_root)?;
    }
    let mut paths = BTreeSet::new();
    for change in &journal.changes {
        let normalized = validate_entry_path(&change.relative_path, false, MAX_DEPLOYMENT_DEPTH)
            .map_err(|error| {
                DeployError::UnsafeStateRoot(format!("invalid journal path: {error}"))
            })?;
        if normalized.path != change.relative_path || !paths.insert(normalized.collision_key) {
            return Err(DeployError::UnsafeStateRoot(format!(
                "duplicate or non-normalized journal path '{}'",
                change.relative_path
            )));
        }
        if let Some(hash) = &change.previous_sha256 {
            validate_sha256(hash).map_err(DeployError::UnsafeStateRoot)?;
        }
        if let Some(hash) = &change.next_sha256 {
            validate_sha256(hash).map_err(DeployError::UnsafeStateRoot)?;
        }
    }
    validate_external_moves(&journal.external_moves).map_err(DeployError::UnsafeStateRoot)?;
    if journal.schema_version == 1 && !journal.external_moves.is_empty() {
        return Err(DeployError::UnsafeStateRoot(
            "journal schema 1 cannot contain external moves".to_owned(),
        ));
    }
    for external_move in &journal.external_moves {
        let receipt_file = journal
            .target_receipt
            .external_files
            .iter()
            .find(|file| file.current_relative_path == external_move.target_relative_path);
        if !receipt_file.is_some_and(|file| {
            file.bytes == external_move.bytes && file.sha256 == external_move.sha256
        }) {
            return Err(DeployError::UnsafeStateRoot(format!(
                "external move target '{}' is absent from the target receipt",
                external_move.target_relative_path
            )));
        }
        for change in &journal.changes {
            if paths_conflict(&external_move.source_relative_path, &change.relative_path)
                .map_err(|error| DeployError::UnsafeStateRoot(error.to_string()))?
                || paths_conflict(&external_move.target_relative_path, &change.relative_path)
                    .map_err(|error| DeployError::UnsafeStateRoot(error.to_string()))?
            {
                return Err(DeployError::UnsafeStateRoot(format!(
                    "external move collides with managed journal path '{}'",
                    change.relative_path
                )));
            }
        }
    }
    Ok(())
}

fn replace_json<T: Serialize>(
    destination: &Path,
    value: &T,
    transaction_id: &str,
) -> Result<(), DeployError> {
    create_parent_directory(destination)?;
    let temporary = sibling_transaction_path(destination, transaction_id, "next")?;
    remove_file_if_exists(&temporary)?;
    write_json_create_new(&temporary, value)?;
    #[cfg(unix)]
    {
        fs::rename(&temporary, destination).map_err(|source| DeployError::Io {
            path: destination.to_path_buf(),
            source,
        })?;
        sync_directory(destination.parent().ok_or(DeployError::PlanChanged)?)
    }
    #[cfg(not(unix))]
    let previous = sibling_transaction_path(destination, transaction_id, "previous")?;
    #[cfg(not(unix))]
    remove_file_if_exists(&previous)?;
    #[cfg(not(unix))]
    if destination.exists() {
        fs::rename(destination, &previous).map_err(|source| DeployError::Io {
            path: destination.to_path_buf(),
            source,
        })?;
    }
    #[cfg(not(unix))]
    if let Err(source) = fs::rename(&temporary, destination) {
        if previous.exists() {
            let _ = fs::rename(&previous, destination);
        }
        return Err(DeployError::Io {
            path: destination.to_path_buf(),
            source,
        });
    }
    #[cfg(not(unix))]
    remove_file_if_exists(&previous)?;
    #[cfg(not(unix))]
    sync_directory(destination.parent().ok_or(DeployError::PlanChanged)?)
}

fn write_json_create_new<T: Serialize>(path: &Path, value: &T) -> Result<(), DeployError> {
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|source| DeployError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    serde_json::to_writer_pretty(&file, value).map_err(|source| DeployError::Json {
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| DeployError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn read_json<T>(path: &Path) -> Result<T, DeployError>
where
    T: for<'de> Deserialize<'de>,
{
    let input = fs::read(path).map_err(|source| DeployError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&input).map_err(|source| DeployError::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn write_commit_marker(path: &Path) -> Result<(), DeployError> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|source| DeployError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(b"committed\n")
        .map_err(|source| DeployError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    file.sync_all().map_err(|source| DeployError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn copy_verified(
    source: &Path,
    destination: &Path,
    expected_bytes: u64,
    expected_hash: &str,
) -> Result<(), DeployError> {
    let mut input = BufReader::new(File::open(source).map_err(|source_error| DeployError::Io {
        path: source.to_path_buf(),
        source: source_error,
    })?);
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|source_error| DeployError::Io {
            path: destination.to_path_buf(),
            source: source_error,
        })?;
    let mut copied = 0_u64;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|source_error| DeployError::Io {
                path: source.to_path_buf(),
                source: source_error,
            })?;
        if read == 0 {
            break;
        }
        copied = copied.saturating_add(read as u64);
        hasher.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .map_err(|source_error| DeployError::Io {
                path: destination.to_path_buf(),
                source: source_error,
            })?;
    }
    output.sync_all().map_err(|source_error| DeployError::Io {
        path: destination.to_path_buf(),
        source: source_error,
    })?;
    let actual_hash = format!("{:x}", hasher.finalize());
    if copied != expected_bytes || actual_hash != expected_hash {
        remove_file_if_exists(destination)?;
        return Err(DeployError::SourceChanged {
            path: source.to_path_buf(),
            expected_bytes,
            expected_sha256: expected_hash.to_owned(),
            actual_bytes: copied,
            actual_sha256: actual_hash,
        });
    }
    Ok(())
}

fn clone_or_copy_verified(
    source: &Path,
    destination: &Path,
    expected_bytes: u64,
    expected_hash: &str,
) -> Result<(), DeployError> {
    #[cfg(target_os = "linux")]
    if try_reflink(source, destination, expected_bytes)? {
        return Ok(());
    }
    copy_verified(source, destination, expected_bytes, expected_hash)
}

#[cfg(target_os = "linux")]
fn try_reflink(
    source: &Path,
    destination: &Path,
    expected_bytes: u64,
) -> Result<bool, DeployError> {
    use std::os::fd::AsRawFd;

    const FICLONE: libc::c_ulong = 0x4004_9409;
    let input = File::open(source).map_err(|source_error| DeployError::Io {
        path: source.to_path_buf(),
        source: source_error,
    })?;
    let before = file_identity(source)?;
    if before.bytes != expected_bytes {
        return Ok(false);
    }
    let output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|source_error| DeployError::Io {
            path: destination.to_path_buf(),
            source: source_error,
        })?;
    // SAFETY: FICLONE reads the input descriptor and clones it into the open,
    // empty output descriptor. Both descriptors remain alive for the call.
    let result = unsafe { libc::ioctl(output.as_raw_fd(), FICLONE, input.as_raw_fd()) };
    if result != 0 {
        drop(output);
        remove_file_if_exists(destination)?;
        return Ok(false);
    }
    output.sync_all().map_err(|source_error| DeployError::Io {
        path: destination.to_path_buf(),
        source: source_error,
    })?;
    let after = file_identity(source)?;
    let output_metadata =
        fs::symlink_metadata(destination).map_err(|source_error| DeployError::Io {
            path: destination.to_path_buf(),
            source: source_error,
        })?;
    if before != after
        || !output_metadata.file_type().is_file()
        || output_metadata.len() != expected_bytes
    {
        remove_file_if_exists(destination)?;
        return Err(DeployError::PlanChanged);
    }
    Ok(true)
}

fn create_managed_parents(root: &Path, relative_path: &str) -> Result<(), DeployError> {
    let components: Vec<_> = relative_path.split('/').collect();
    let mut current = root.to_path_buf();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(DeployError::RecoveryDrift {
                    path: relative_path.to_owned(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|source| DeployError::Io {
                    path: current.clone(),
                    source,
                })?;
            }
            Err(source) => {
                return Err(DeployError::Io {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn create_parent_directory(path: &Path) -> Result<(), DeployError> {
    let parent = path.parent().ok_or(DeployError::PlanChanged)?;
    fs::create_dir_all(parent).map_err(|source| DeployError::Io {
        path: parent.to_path_buf(),
        source,
    })
}

fn remove_file_if_exists(path: &Path) -> Result<(), DeployError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(DeployError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn remove_tree_if_exists(path: &Path) -> Result<(), DeployError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(DeployError::UnsafeStateRoot(format!(
                "managed staging path is not a real directory: {}",
                path.display()
            )))
        }
        Ok(_) => fs::remove_dir_all(path).map_err(|source| DeployError::Io {
            path: path.to_path_buf(),
            source,
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(DeployError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn sibling_transaction_path(
    destination: &Path,
    transaction_id: &str,
    suffix: &str,
) -> Result<PathBuf, DeployError> {
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(DeployError::PlanChanged)?;
    Ok(destination.with_file_name(format!(".{name}.rrmm-{transaction_id}.{suffix}")))
}

fn backup_path(state_root: &Path, sha256: &str) -> PathBuf {
    state_root.join("backups").join(&sha256[..2]).join(sha256)
}

fn staging_root(state_root: &Path, transaction_id: &str) -> PathBuf {
    state_root.join("staging").join(transaction_id)
}

fn journal_path(state_root: &Path, transaction_id: &str) -> PathBuf {
    state_root
        .join("journals")
        .join(format!("{transaction_id}.json"))
}

fn commit_marker_path(state_root: &Path, transaction_id: &str) -> PathBuf {
    state_root
        .join("journals")
        .join(format!("{transaction_id}.committed"))
}

fn receipt_path(state_root: &Path, installation_id: &str) -> PathBuf {
    state_root
        .join("receipts")
        .join(format!("{installation_id}.json"))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), DeployError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| DeployError::Io {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), DeployError> {
    Ok(())
}

fn normalize_files(files: Vec<DeploymentFile>) -> Result<Vec<DeploymentFile>, DeployError> {
    let mut normalized_files = Vec::with_capacity(files.len());
    let mut collision_keys = BTreeMap::<String, String>::new();
    let mut paths = BTreeSet::new();
    for mut file in files {
        validate_sha256(&file.sha256).map_err(DeployError::InvalidReceipt)?;
        let normalized = validate_entry_path(&file.relative_path, false, MAX_DEPLOYMENT_DEPTH)
            .map_err(|source| DeployError::InvalidPath {
                path: file.relative_path.clone(),
                source,
            })?;
        if let Some(first) =
            collision_keys.insert(normalized.collision_key.clone(), normalized.path.clone())
        {
            return Err(DeployError::PlannedCollision {
                first,
                second: normalized.path,
            });
        }
        paths.insert(normalized.path.clone());
        file.relative_path = normalized.path;
        normalized_files.push(file);
    }
    for path in &paths {
        let components: Vec<_> = path.split('/').collect();
        for end in 1..components.len() {
            let prefix = components[..end].join("/");
            let normalized =
                validate_entry_path(&prefix, true, MAX_DEPLOYMENT_DEPTH).map_err(|source| {
                    DeployError::InvalidPath {
                        path: path.clone(),
                        source,
                    }
                })?;
            if let Some(first) = collision_keys.get(&normalized.collision_key) {
                return Err(DeployError::PrefixCollision {
                    first: first.clone(),
                    second: path.clone(),
                });
            }
        }
    }
    Ok(normalized_files)
}

fn normalize_external_files(
    files: Vec<DeploymentExternalFile>,
) -> Result<Vec<DeploymentExternalFile>, DeployError> {
    let mut normalized_files = Vec::with_capacity(files.len());
    let mut originals = BTreeMap::<String, String>::new();
    let mut sources = BTreeMap::<String, String>::new();
    let mut targets = BTreeMap::<String, String>::new();
    for mut file in files {
        validate_sha256(&file.sha256).map_err(DeployError::InvalidReceipt)?;
        file.original_relative_path = normalize_deployment_path(&file.original_relative_path)?;
        file.source_relative_path = normalize_deployment_path(&file.source_relative_path)?;
        file.target_relative_path = normalize_deployment_path(&file.target_relative_path)?;
        insert_unique_external_path(&mut originals, &file.original_relative_path)?;
        insert_unique_external_path(&mut sources, &file.source_relative_path)?;
        insert_unique_external_path(&mut targets, &file.target_relative_path)?;
        normalized_files.push(file);
    }
    for paths in [&sources, &targets] {
        let values: Vec<_> = paths.values().collect();
        for (index, first) in values.iter().enumerate() {
            for second in values.iter().skip(index + 1) {
                if paths_conflict(first, second)? {
                    return Err(DeployError::PrefixCollision {
                        first: (*first).clone(),
                        second: (*second).clone(),
                    });
                }
            }
        }
    }
    for source in sources.values() {
        for target in targets.values() {
            if collision_key(source)? != collision_key(target)? && paths_conflict(source, target)? {
                return Err(DeployError::PrefixCollision {
                    first: source.clone(),
                    second: target.clone(),
                });
            }
        }
    }
    Ok(normalized_files)
}

fn normalize_deployment_path(path: &str) -> Result<String, DeployError> {
    validate_entry_path(path, false, MAX_DEPLOYMENT_DEPTH)
        .map(|normalized| normalized.path)
        .map_err(|source| DeployError::InvalidPath {
            path: path.to_owned(),
            source,
        })
}

fn insert_unique_external_path(
    paths: &mut BTreeMap<String, String>,
    path: &str,
) -> Result<(), DeployError> {
    let key = collision_key(path)?;
    if let Some(first) = paths.insert(key, path.to_owned()) {
        return Err(DeployError::PlannedCollision {
            first,
            second: path.to_owned(),
        });
    }
    Ok(())
}

fn collision_key(path: &str) -> Result<String, DeployError> {
    validate_entry_path(path, false, MAX_DEPLOYMENT_DEPTH)
        .map(|normalized| normalized.collision_key)
        .map_err(|source| DeployError::InvalidPath {
            path: path.to_owned(),
            source,
        })
}

fn paths_conflict(first: &str, second: &str) -> Result<bool, DeployError> {
    if collision_key(first)? == collision_key(second)? {
        return Ok(true);
    }
    Ok(path_is_prefix(first, second)? || path_is_prefix(second, first)?)
}

fn path_is_prefix(parent: &str, child: &str) -> Result<bool, DeployError> {
    let parent_components: Vec<_> = parent.split('/').collect();
    let child_components: Vec<_> = child.split('/').collect();
    if parent_components.len() >= child_components.len() {
        return Ok(false);
    }
    let child_prefix = child_components[..parent_components.len()].join("/");
    let parent_key = validate_entry_path(parent, true, MAX_DEPLOYMENT_DEPTH)
        .map_err(|source| DeployError::InvalidPath {
            path: parent.to_owned(),
            source,
        })?
        .collision_key;
    let child_key = validate_entry_path(&child_prefix, true, MAX_DEPLOYMENT_DEPTH)
        .map_err(|source| DeployError::InvalidPath {
            path: child.to_owned(),
            source,
        })?
        .collision_key;
    Ok(parent_key == child_key)
}

fn validate_external_plan_paths(
    external_files: &[DeploymentExternalFile],
    files: &[DeploymentFile],
    owned: &BTreeMap<String, OwnedFile>,
    blockers: &mut Vec<DeploymentBlocker>,
) -> Result<(), DeployError> {
    for external_file in external_files {
        for path in [
            &external_file.source_relative_path,
            &external_file.target_relative_path,
        ] {
            for owned_path in owned.keys() {
                if collision_key(path)? == collision_key(owned_path)? {
                    return Err(DeployError::ExternalOwnedPath(path.clone()));
                }
            }
            for managed in files {
                if paths_conflict(path, &managed.relative_path)? {
                    blockers.push(DeploymentBlocker::PathCollision {
                        planned_path: path.clone(),
                        existing_path: managed.relative_path.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn verify_external_sources(
    game_root: &Path,
    files: &[DeploymentExternalFile],
    verified_files: Option<&BTreeMap<PathBuf, VerifiedSource>>,
) -> Result<(), DeployError> {
    for file in files {
        let mut blockers = Vec::new();
        inspect_parent_chain(game_root, &file.source_relative_path, &mut blockers)?;
        let source = game_root.join(path_from_normalized(&file.source_relative_path));
        if !blockers.is_empty() {
            return Err(DeployError::InvalidSource(source));
        }
        let metadata = fs::symlink_metadata(&source).map_err(|source_error| DeployError::Io {
            path: source.clone(),
            source: source_error,
        })?;
        if !metadata.file_type().is_file() {
            return Err(DeployError::InvalidSource(source));
        }
        let identity = file_identity(&source)?;
        let cached_sha256 = verified_files
            .and_then(|files| files.get(&source))
            .filter(|verified| verified.identity == identity)
            .map(|verified| verified.sha256.clone());
        let actual_sha256 = match cached_sha256 {
            Some(sha256) => sha256,
            None => hash_file(&source)?,
        };
        if metadata.len() != file.bytes || actual_sha256 != file.sha256 {
            return Err(DeployError::SourceChanged {
                path: source,
                expected_bytes: file.bytes,
                expected_sha256: file.sha256.clone(),
                actual_bytes: metadata.len(),
                actual_sha256,
            });
        }
    }
    Ok(())
}

fn inspect_external_targets(
    game_root: &Path,
    files: &[DeploymentExternalFile],
    existing: &BTreeMap<String, Vec<String>>,
    blockers: &mut Vec<DeploymentBlocker>,
) -> Result<(), DeployError> {
    let sources: BTreeSet<_> = files
        .iter()
        .map(|file| file.source_relative_path.as_str())
        .collect();
    for file in files {
        inspect_parent_chain(game_root, &file.target_relative_path, blockers)?;
        inspect_external_existing_collisions(
            &file.target_relative_path,
            existing,
            &sources,
            blockers,
        )?;
        if !sources.contains(file.target_relative_path.as_str()) {
            let target = game_root.join(path_from_normalized(&file.target_relative_path));
            match fs::symlink_metadata(&target) {
                Ok(_) => blockers.push(DeploymentBlocker::ExternalTargetOccupied {
                    relative_path: file.target_relative_path.clone(),
                }),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(DeployError::Io {
                        path: target,
                        source,
                    });
                }
            }
        }
    }
    Ok(())
}

fn inspect_external_existing_collisions(
    relative_path: &str,
    existing: &BTreeMap<String, Vec<String>>,
    sources: &BTreeSet<&str>,
    blockers: &mut Vec<DeploymentBlocker>,
) -> Result<(), DeployError> {
    let components: Vec<_> = relative_path.split('/').collect();
    for end in 1..=components.len() {
        let planned_component_path = components[..end].join("/");
        let normalized = validate_entry_path(
            &planned_component_path,
            end != components.len(),
            MAX_DEPLOYMENT_DEPTH,
        )
        .map_err(|source| DeployError::InvalidPath {
            path: relative_path.to_owned(),
            source,
        })?;
        if let Some(paths) = existing.get(&normalized.collision_key) {
            for existing_path in paths {
                let is_movable_source =
                    end == components.len() && sources.contains(existing_path.as_str());
                if existing_path != &planned_component_path && !is_movable_source {
                    blockers.push(DeploymentBlocker::PathCollision {
                        planned_path: relative_path.to_owned(),
                        existing_path: existing_path.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn validate_external_moves(moves: &[DeploymentExternalMove]) -> Result<(), String> {
    let mut sources = BTreeSet::new();
    let mut targets = BTreeSet::new();
    let mut source_paths = Vec::new();
    let mut target_paths = Vec::new();
    for external_move in moves {
        validate_sha256(&external_move.sha256)?;
        let source = validate_entry_path(
            &external_move.source_relative_path,
            false,
            MAX_DEPLOYMENT_DEPTH,
        )
        .map_err(|error| error.to_string())?;
        let target = validate_entry_path(
            &external_move.target_relative_path,
            false,
            MAX_DEPLOYMENT_DEPTH,
        )
        .map_err(|error| error.to_string())?;
        if source.path != external_move.source_relative_path
            || target.path != external_move.target_relative_path
            || source.path == target.path
            || !sources.insert(source.collision_key)
            || !targets.insert(target.collision_key)
        {
            return Err("duplicate, stationary, or non-normalized external move".to_owned());
        }
        source_paths.push(external_move.source_relative_path.as_str());
        target_paths.push(external_move.target_relative_path.as_str());
    }
    for paths in [&source_paths, &target_paths] {
        for (index, first) in paths.iter().enumerate() {
            for second in paths.iter().skip(index + 1) {
                if paths_conflict(first, second).map_err(|error| error.to_string())? {
                    return Err(format!(
                        "external move path prefix collision between '{first}' and '{second}'"
                    ));
                }
            }
        }
    }
    for source in &source_paths {
        for target in &target_paths {
            if collision_key(source).map_err(|error| error.to_string())?
                != collision_key(target).map_err(|error| error.to_string())?
                && paths_conflict(source, target).map_err(|error| error.to_string())?
            {
                return Err(format!(
                    "external source/target prefix collision between '{source}' and '{target}'"
                ));
            }
        }
    }
    Ok(())
}

fn verify_sources(
    files: &[DeploymentFile],
    verified_sources: Option<&BTreeMap<PathBuf, VerifiedSource>>,
) -> Result<(), DeployError> {
    for file in files {
        let identity = file_identity(&file.source)?;
        if let Some(verified) = verified_sources.and_then(|sources| sources.get(&file.source))
            && verified.sha256 == file.sha256
            && verified.identity == identity
        {
            if identity.bytes != file.bytes {
                return Err(DeployError::SourceChanged {
                    path: file.source.clone(),
                    expected_bytes: file.bytes,
                    expected_sha256: file.sha256.clone(),
                    actual_bytes: identity.bytes,
                    actual_sha256: verified.sha256.clone(),
                });
            }
            continue;
        }
        let actual_sha256 = hash_file(&file.source)?;
        if identity.bytes != file.bytes || actual_sha256 != file.sha256 {
            return Err(DeployError::SourceChanged {
                path: file.source.clone(),
                expected_bytes: file.bytes,
                expected_sha256: file.sha256.clone(),
                actual_bytes: identity.bytes,
                actual_sha256,
            });
        }
    }
    Ok(())
}

fn validate_receipt(
    receipt: &DeploymentReceipt,
    game_root: &Path,
) -> Result<DeploymentReceipt, DeployError> {
    if receipt.schema_version != 1 {
        return Err(DeployError::InvalidReceipt(format!(
            "unsupported schema version {}",
            receipt.schema_version
        )));
    }
    if receipt.game_root != game_root {
        return Err(DeployError::InvalidReceipt(
            "game root does not match the deployment target".to_owned(),
        ));
    }
    validate_identifier("receipt profile", &receipt.profile_id)?;
    let mut paths = BTreeSet::new();
    let mut collision_keys = BTreeMap::new();
    for file in &receipt.files {
        validate_sha256(&file.sha256).map_err(DeployError::InvalidReceipt)?;
        if let Some(displaced) = &file.displaced_unmanaged {
            validate_sha256(&displaced.sha256).map_err(DeployError::InvalidReceipt)?;
        }
        let normalized = validate_entry_path(&file.relative_path, false, MAX_DEPLOYMENT_DEPTH)
            .map_err(|error| DeployError::InvalidReceipt(error.to_string()))?;
        if normalized.path != file.relative_path {
            return Err(DeployError::InvalidReceipt(format!(
                "non-normalized path '{}'",
                file.relative_path
            )));
        }
        if let Some(first) =
            collision_keys.insert(normalized.collision_key, file.relative_path.clone())
        {
            return Err(DeployError::InvalidReceipt(format!(
                "cross-platform path collision between '{first}' and '{}'",
                file.relative_path
            )));
        }
        paths.insert(file.relative_path.clone());
    }
    let mut original_keys = BTreeMap::new();
    for file in &receipt.external_files {
        validate_sha256(&file.sha256).map_err(DeployError::InvalidReceipt)?;
        let original =
            validate_entry_path(&file.original_relative_path, false, MAX_DEPLOYMENT_DEPTH)
                .map_err(|error| DeployError::InvalidReceipt(error.to_string()))?;
        let current = validate_entry_path(&file.current_relative_path, false, MAX_DEPLOYMENT_DEPTH)
            .map_err(|error| DeployError::InvalidReceipt(error.to_string()))?;
        if original.path != file.original_relative_path
            || current.path != file.current_relative_path
        {
            return Err(DeployError::InvalidReceipt(
                "non-normalized external file path".to_owned(),
            ));
        }
        if let Some(first) =
            original_keys.insert(original.collision_key, file.original_relative_path.clone())
        {
            return Err(DeployError::InvalidReceipt(format!(
                "external original path collision between '{first}' and '{}'",
                file.original_relative_path
            )));
        }
        if let Some(first) =
            collision_keys.insert(current.collision_key, file.current_relative_path.clone())
        {
            return Err(DeployError::InvalidReceipt(format!(
                "managed/external current path collision between '{first}' and '{}'",
                file.current_relative_path
            )));
        }
        paths.insert(file.current_relative_path.clone());
    }
    for path in &paths {
        let components: Vec<_> = path.split('/').collect();
        for end in 1..components.len() {
            let prefix = components[..end].join("/");
            let normalized = validate_entry_path(&prefix, true, MAX_DEPLOYMENT_DEPTH)
                .map_err(|error| DeployError::InvalidReceipt(error.to_string()))?;
            if let Some(first) = collision_keys.get(&normalized.collision_key) {
                return Err(DeployError::InvalidReceipt(format!(
                    "file/directory prefix collision between '{first}' and '{path}'"
                )));
            }
        }
    }
    Ok(receipt.clone())
}

fn receipt_map(receipt: &DeploymentReceipt) -> BTreeMap<String, OwnedFile> {
    receipt
        .files
        .iter()
        .cloned()
        .map(|file| (file.relative_path.clone(), file))
        .collect()
}

fn validate_restore_approvals(
    approvals: Vec<ManagedFileRestoreApproval>,
) -> Result<BTreeMap<String, ManagedFileRestoreApproval>, DeployError> {
    let mut by_path = BTreeMap::new();
    for mut approval in approvals {
        let normalized = validate_entry_path(&approval.relative_path, false, MAX_DEPLOYMENT_DEPTH)
            .map_err(|source| DeployError::InvalidPath {
                path: approval.relative_path.clone(),
                source,
            })?;
        approval.relative_path = normalized.path;
        validate_sha256(&approval.expected_sha256).map_err(DeployError::InvalidReceipt)?;
        if let Some(current) = &approval.current_sha256 {
            validate_sha256(current).map_err(DeployError::InvalidReceipt)?;
        }
        validate_sha256(&approval.restore_sha256).map_err(DeployError::InvalidReceipt)?;
        let path = approval.relative_path.clone();
        if by_path.insert(path.clone(), approval).is_some() {
            return Err(DeployError::ManagedFileApprovalChanged(path));
        }
    }
    Ok(by_path)
}

struct ManagedInspection<'a> {
    game_root: &'a Path,
    approvals: &'a BTreeMap<String, ManagedFileRestoreApproval>,
    consumed_approvals: &'a mut BTreeSet<String>,
    blockers: &'a mut Vec<DeploymentBlocker>,
    observed: &'a mut BTreeMap<String, Option<(u64, String)>>,
    verified_files: Option<&'a BTreeMap<PathBuf, VerifiedSource>>,
}

fn inspect_managed_file(
    owned: &OwnedFile,
    desired: Option<&DeploymentFile>,
    inspection: &mut ManagedInspection<'_>,
) -> Result<bool, DeployError> {
    inspect_parent_chain(
        inspection.game_root,
        &owned.relative_path,
        inspection.blockers,
    )?;
    let path = inspection
        .game_root
        .join(path_from_normalized(&owned.relative_path));
    if desired.is_none() {
        return match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => Ok(true),
            Ok(_) => {
                inspection
                    .blockers
                    .push(DeploymentBlocker::UnsafeFilesystemEntry {
                        relative_path: owned.relative_path.clone(),
                        detail: "destination exists but is not a regular file".to_owned(),
                    });
                Ok(false)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(DeployError::Io { path, source }),
        };
    }
    let inspected = inspect_file(
        &path,
        &owned.relative_path,
        inspection.blockers,
        inspection.verified_files,
    )?;
    inspection
        .observed
        .insert(owned.relative_path.clone(), inspected.clone());
    let Some((bytes, actual_sha256)) = inspected else {
        if fs::symlink_metadata(&path).is_ok() {
            return Ok(false);
        }
        if let Some(desired) = desired {
            if restore_approval_matches(owned, desired, None, inspection.approvals) {
                inspection
                    .consumed_approvals
                    .insert(owned.relative_path.clone());
            } else {
                inspection
                    .blockers
                    .push(DeploymentBlocker::ManagedFileMissing {
                        relative_path: owned.relative_path.clone(),
                    });
            }
        }
        return Ok(false);
    };
    let matches_receipt = bytes == owned.bytes && actual_sha256 == owned.sha256;
    let matches_desired =
        desired.is_some_and(|desired| bytes == desired.bytes && actual_sha256 == desired.sha256);
    if !matches_receipt && !matches_desired {
        if desired.is_some_and(|desired| {
            restore_approval_matches(owned, desired, Some(&actual_sha256), inspection.approvals)
        }) {
            inspection
                .consumed_approvals
                .insert(owned.relative_path.clone());
        } else {
            inspection
                .blockers
                .push(DeploymentBlocker::ManagedFileDrifted {
                    relative_path: owned.relative_path.clone(),
                    expected_sha256: owned.sha256.clone(),
                    actual_sha256,
                });
        }
    }
    Ok(true)
}

fn restore_approval_matches(
    owned: &OwnedFile,
    desired: &DeploymentFile,
    current_sha256: Option<&String>,
    approvals: &BTreeMap<String, ManagedFileRestoreApproval>,
) -> bool {
    approvals.get(&owned.relative_path).is_some_and(|approval| {
        approval.expected_sha256 == owned.sha256
            && approval.current_sha256.as_ref() == current_sha256
            && approval.restore_sha256 == desired.sha256
    })
}

fn inspect_file(
    path: &Path,
    relative_path: &str,
    blockers: &mut Vec<DeploymentBlocker>,
    verified_files: Option<&BTreeMap<PathBuf, VerifiedSource>>,
) -> Result<Option<(u64, String)>, DeployError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(DeployError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if !metadata.file_type().is_file() {
        blockers.push(DeploymentBlocker::UnsafeFilesystemEntry {
            relative_path: relative_path.to_owned(),
            detail: "destination exists but is not a regular file".to_owned(),
        });
        return Ok(None);
    }
    let identity = file_identity(path)?;
    if let Some(verified) = verified_files.and_then(|files| files.get(path))
        && verified.identity == identity
    {
        return Ok(Some((identity.bytes, verified.sha256.clone())));
    }
    Ok(Some((metadata.len(), hash_file(path)?)))
}

fn inspect_parent_chain(
    game_root: &Path,
    relative_path: &str,
    blockers: &mut Vec<DeploymentBlocker>,
) -> Result<(), DeployError> {
    let mut current = game_root.to_path_buf();
    let components: Vec<_> = relative_path.split('/').collect();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                blockers.push(DeploymentBlocker::UnsafeFilesystemEntry {
                    relative_path: relative_path.to_owned(),
                    detail: format!("parent '{}' is a filesystem link", current.display()),
                });
                return Ok(());
            }
            Ok(metadata) if !metadata.is_dir() => {
                blockers.push(DeploymentBlocker::UnsafeFilesystemEntry {
                    relative_path: relative_path.to_owned(),
                    detail: format!("parent '{}' is not a directory", current.display()),
                });
                return Ok(());
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(DeployError::Io {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn inspect_existing_collisions(
    relative_path: &str,
    existing: &BTreeMap<String, Vec<String>>,
    blockers: &mut Vec<DeploymentBlocker>,
) -> Result<(), DeployError> {
    let components: Vec<_> = relative_path.split('/').collect();
    for end in 1..=components.len() {
        let planned_component_path = components[..end].join("/");
        let normalized = validate_entry_path(
            &planned_component_path,
            end != components.len(),
            MAX_DEPLOYMENT_DEPTH,
        )
        .map_err(|source| DeployError::InvalidPath {
            path: relative_path.to_owned(),
            source,
        })?;
        if let Some(paths) = existing.get(&normalized.collision_key) {
            for existing_path in paths {
                if existing_path != &planned_component_path {
                    blockers.push(DeploymentBlocker::PathCollision {
                        planned_path: relative_path.to_owned(),
                        existing_path: existing_path.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn inventory_existing_scoped(
    root: &Path,
    relevant_paths: &BTreeSet<&str>,
) -> Result<BTreeMap<String, Vec<String>>, DeployError> {
    let mut result = BTreeMap::<String, Vec<String>>::new();
    let mut directories = BTreeSet::from([String::new()]);
    for relative_path in relevant_paths {
        let components = relative_path.split('/').collect::<Vec<_>>();
        for end in 1..components.len() {
            directories.insert(components[..end].join("/"));
        }
    }
    for relative_directory in directories {
        let directory = if relative_directory.is_empty() {
            root.to_path_buf()
        } else {
            root.join(path_from_normalized(&relative_directory))
        };
        match fs::symlink_metadata(&directory) {
            Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            }
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(DeployError::Io {
                    path: directory,
                    source,
                });
            }
        }
        for entry in fs::read_dir(&directory).map_err(|source| DeployError::Io {
            path: directory.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| DeployError::Io {
                path: directory.clone(),
                source,
            })?;
            let path = entry.path();
            let Ok(relative) = path.strip_prefix(root) else {
                continue;
            };
            let Some(relative) = relative.to_str() else {
                continue;
            };
            let relative = relative.replace(std::path::MAIN_SEPARATOR, "/");
            if let Ok(normalized) = validate_entry_path(&relative, false, MAX_DEPLOYMENT_DEPTH) {
                result
                    .entry(normalized.collision_key)
                    .or_default()
                    .push(normalized.path);
            }
        }
    }
    for paths in result.values_mut() {
        paths.sort();
    }
    Ok(result)
}

fn prospective_canonical_path(path: &Path) -> Result<PathBuf, DeployError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| DeployError::Io {
                path: PathBuf::from("."),
                source,
            })?
            .join(path)
    };
    let mut ancestor = absolute.as_path();
    let mut missing = Vec::new();
    loop {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = ancestor.file_name().ok_or_else(|| {
                    DeployError::UnsafeStateRoot(format!(
                        "state root has no existing ancestor: {}",
                        path.display()
                    ))
                })?;
                missing.push(name.to_os_string());
                ancestor = ancestor.parent().ok_or_else(|| {
                    DeployError::UnsafeStateRoot(format!(
                        "state root has no existing ancestor: {}",
                        path.display()
                    ))
                })?;
            }
            Err(source) => {
                return Err(DeployError::Io {
                    path: ancestor.to_path_buf(),
                    source,
                });
            }
        }
    }
    let mut canonical = fs::canonicalize(ancestor).map_err(|source| DeployError::Io {
        path: ancestor.to_path_buf(),
        source,
    })?;
    for component in missing.into_iter().rev() {
        canonical.push(component);
    }
    Ok(canonical)
}

fn canonical_directory(path: &Path) -> Result<PathBuf, DeployError> {
    let canonical = fs::canonicalize(path).map_err(|source| DeployError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = fs::metadata(&canonical).map_err(|source| DeployError::Io {
        path: canonical.clone(),
        source,
    })?;
    if !metadata.is_dir() {
        return Err(DeployError::Io {
            path: canonical,
            source: io::Error::new(io::ErrorKind::NotADirectory, "expected a directory"),
        });
    }
    Ok(canonical)
}

fn hash_file(path: &Path) -> Result<String, DeployError> {
    sha256_path(path).map_err(|error| DeployError::Hash {
        path: path.to_path_buf(),
        detail: error.to_string(),
    })
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), DeployError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(DeployError::InvalidIdentifier {
            field,
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(format!("invalid lowercase SHA-256 '{value}'"))
    }
}

fn path_from_normalized(path: &str) -> PathBuf {
    path.split('/').collect()
}

fn blocker_sort_key(blocker: &DeploymentBlocker) -> String {
    serde_json_sort_key(blocker)
}

fn serde_json_sort_key(blocker: &DeploymentBlocker) -> String {
    // Stable without depending on map iteration or platform path formatting.
    format!("{blocker:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn file_identity_is_stable_until_the_file_changes() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("identity.pak");
        fs::write(&path, b"first").unwrap();

        let first = file_identity(&path).unwrap();
        assert!(first.stable_for_cache());
        assert_eq!(first, file_identity(&path).unwrap());

        let replacement = temporary.path().join("replacement.pak");
        fs::write(&replacement, b"other").unwrap();
        fs::rename(&replacement, &path).unwrap();

        assert_ne!(first, file_identity(&path).unwrap());
    }

    #[test]
    fn removes_only_disposable_unreferenced_backups() {
        let temporary = TempDir::new().unwrap();
        let state_root = temporary.path().join("state");
        let disposable = "a".repeat(64);
        let unmanaged = "b".repeat(64);
        for sha256 in [&disposable, &unmanaged] {
            let path = backup_path(&state_root, sha256);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, sha256.as_bytes()).unwrap();
        }

        let removed =
            cleanup_unreferenced_backups(&state_root, &BTreeSet::from([disposable.clone()]))
                .unwrap();

        assert_eq!(removed, 1);
        assert!(!backup_path(&state_root, &disposable).exists());
        assert!(backup_path(&state_root, &unmanaged).is_file());
    }

    #[cfg(unix)]
    #[test]
    fn backup_reuses_the_source_inode_when_possible() {
        use std::os::unix::fs::MetadataExt;

        let temporary = TempDir::new().unwrap();
        let state_root = prepare_state_root(&temporary.path().join("state"), None).unwrap();
        let source = temporary.path().join("source.pak");
        fs::write(&source, b"managed content").unwrap();
        let sha256 = hash_file(&source).unwrap();

        ensure_backup(&source, &state_root, &sha256).unwrap();

        assert_eq!(
            fs::metadata(&source).unwrap().ino(),
            fs::metadata(backup_path(&state_root, &sha256))
                .unwrap()
                .ino()
        );
    }

    #[test]
    fn plans_create_replace_remove_and_unchanged_files() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        fs::create_dir_all(game.join("mods")).unwrap();
        fs::create_dir_all(&sources).unwrap();
        fs::write(game.join("mods/keep.pak"), b"same").unwrap();
        fs::write(game.join("mods/replace.pak"), b"old").unwrap();
        fs::write(game.join("mods/remove.pak"), b"remove").unwrap();
        let keep = source(&sources, "keep", b"same", "mods/keep.pak");
        let replace = source(&sources, "replace", b"new", "mods/replace.pak");
        let create = source(&sources, "create", b"create", "mods/create.pak");
        let receipt = receipt(
            &game,
            "old",
            &[
                owned("mods/keep.pak", b"same"),
                owned("mods/replace.pak", b"old"),
                owned("mods/remove.pak", b"remove"),
            ],
        );

        let plan = plan_deployment(
            request(&game, temporary.path(), vec![keep, replace, create]),
            Some(&receipt),
        )
        .unwrap();

        assert!(plan.ready());
        assert_eq!(
            plan.changes
                .iter()
                .map(|change| (&change.relative_path, change.kind))
                .collect::<Vec<_>>(),
            vec![
                (&"mods/create.pak".to_owned(), DeploymentChangeKind::Create),
                (
                    &"mods/keep.pak".to_owned(),
                    DeploymentChangeKind::UnchangedManaged
                ),
                (
                    &"mods/remove.pak".to_owned(),
                    DeploymentChangeKind::RemoveManaged
                ),
                (
                    &"mods/replace.pak".to_owned(),
                    DeploymentChangeKind::ReplaceManaged
                ),
            ]
        );
        assert!(plan.changes.iter().all(|change| {
            change.owner_id.as_deref() == Some("test-package")
                && change.owner_name.as_deref() == Some("Test package")
        }));
    }

    #[test]
    fn inventories_managed_drift_missing_unmanaged_and_directory_collisions() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        fs::create_dir_all(game.join("managed")).unwrap();
        fs::create_dir_all(game.join("mods")).unwrap();
        fs::write(game.join("managed/match.pak"), b"match").unwrap();
        fs::write(game.join("managed/drift.pak"), b"changed").unwrap();
        fs::create_dir(game.join("managed/directory.pak")).unwrap();
        fs::write(game.join("loose.txt"), b"unmanaged").unwrap();
        fs::write(game.join("mods/collision.pak"), b"collision").unwrap();
        let receipt = receipt(
            &game,
            "profile",
            &[
                owned("managed/match.pak", b"match"),
                owned("managed/drift.pak", b"expected"),
                owned("managed/missing.pak", b"missing"),
                owned("managed/directory.pak", b"expected file"),
                owned("Mods/expected.pak", b"expected"),
            ],
        );

        let report = inventory_game_files(&game, Some(&receipt)).unwrap();

        assert_eq!(report.managed_match_count, 1);
        assert_eq!(report.managed_drift_count, 1);
        assert_eq!(report.managed_missing_count, 3);
        assert_eq!(report.unmanaged_count, 2);
        assert_eq!(report.collision_count, 1);
        assert_eq!(report.unsafe_count, 1);
        assert!(report.entries.iter().any(|entry| {
            entry.relative_path == "mods"
                && entry.status == InventoryStatus::UnmanagedCollision
                && entry.collision_with.as_deref() == Some("Mods")
        }));
        assert!(report.entries.iter().any(|entry| {
            entry.relative_path == "managed/drift.pak"
                && entry.status == InventoryStatus::ManagedDrifted
                && entry.actual_sha256.is_some()
        }));
        assert!(report.entries.iter().any(|entry| {
            entry.relative_path == "managed/directory.pak"
                && entry.status == InventoryStatus::SpecialEntry
        }));
    }

    #[test]
    fn blocks_unmanaged_files_until_explicitly_allowed() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        fs::create_dir_all(game.join("mods")).unwrap();
        fs::create_dir_all(&sources).unwrap();
        fs::write(game.join("mods/existing.pak"), b"old").unwrap();
        let desired = source(&sources, "new", b"new", "mods/existing.pak");

        let blocked = plan_deployment(
            request(&game, temporary.path(), vec![desired.clone()]),
            None,
        )
        .unwrap();
        assert!(!blocked.ready());
        assert!(matches!(
            blocked.blockers.as_slice(),
            [DeploymentBlocker::UnmanagedPath {
                identical: false,
                ..
            }]
        ));

        let mut allowed_request = request(&game, temporary.path(), vec![desired]);
        allowed_request.allow_unmanaged = true;
        let allowed = plan_deployment(allowed_request, None).unwrap();
        assert!(allowed.ready());
        assert_eq!(
            allowed.changes[0].kind,
            DeploymentChangeKind::ReplaceUnmanaged
        );
    }

    #[test]
    fn adopts_an_identical_unmanaged_file_without_a_global_override() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        fs::create_dir_all(game.join("mods")).unwrap();
        fs::create_dir_all(&sources).unwrap();
        fs::write(game.join("mods/existing.pak"), b"same").unwrap();
        let desired = source(&sources, "new", b"same", "mods/existing.pak");

        let plan = plan_deployment(request(&game, temporary.path(), vec![desired]), None).unwrap();

        assert!(plan.ready());
        assert_eq!(
            plan.changes[0].kind,
            DeploymentChangeKind::AdoptIdenticalUnmanaged
        );
        assert!(plan.target_receipt.files[0].displaced_unmanaged.is_none());
    }

    #[test]
    fn removal_defers_managed_drift_detection_until_apply() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        fs::create_dir_all(game.join("mods")).unwrap();
        fs::write(game.join("mods/drift.pak"), b"changed").unwrap();
        let receipt = receipt(
            &game,
            "old",
            &[
                owned("mods/drift.pak", b"expected"),
                owned("mods/missing.pak", b"missing"),
            ],
        );

        let plan =
            plan_deployment(request(&game, temporary.path(), vec![]), Some(&receipt)).unwrap();

        assert!(plan.ready());
        assert!(plan.blockers.is_empty());
        assert_eq!(plan.changes.len(), 1);
        assert_eq!(plan.changes[0].relative_path, "mods/drift.pak");
        assert!(matches!(
            activate_deployment(&plan, || false),
            Err(DeployError::PlanChanged)
        ));
        assert_eq!(fs::read(game.join("mods/drift.pak")).unwrap(), b"changed");
    }

    #[test]
    fn restores_managed_drift_only_with_an_exact_approval() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        fs::create_dir_all(game.join("mods")).unwrap();
        fs::create_dir_all(&sources).unwrap();
        fs::write(game.join("mods/drift.pak"), b"external edit").unwrap();
        let desired = source(&sources, "managed", b"managed version", "mods/drift.pak");
        let current_sha256 = hash_file(&game.join("mods/drift.pak")).unwrap();
        let mut previous = owned("mods/drift.pak", b"managed version");
        previous.displaced_unmanaged = Some(DisplacedFile {
            bytes: 8,
            sha256: "0".repeat(64),
        });
        let receipt = receipt(&game, "old", std::slice::from_ref(&previous));

        let blocked = plan_deployment(
            request(&game, temporary.path(), vec![desired.clone()]),
            Some(&receipt),
        )
        .unwrap();
        assert!(!blocked.ready());

        let approved = plan_deployment_with_approvals(
            request(&game, temporary.path(), vec![desired.clone()]),
            Some(&receipt),
            vec![ManagedFileRestoreApproval {
                relative_path: "mods/drift.pak".to_owned(),
                expected_sha256: previous.sha256,
                current_sha256: Some(current_sha256.clone()),
                restore_sha256: desired.sha256,
            }],
        )
        .unwrap();

        assert!(approved.ready());
        assert_eq!(
            approved.changes[0].kind,
            DeploymentChangeKind::ReplaceManaged
        );
        assert_eq!(
            approved.changes[0].previous_sha256.as_deref(),
            Some(current_sha256.as_str())
        );
        assert_eq!(
            approved.target_receipt.files[0].displaced_unmanaged,
            receipt.files[0].displaced_unmanaged
        );
    }

    #[test]
    fn rejects_an_approved_restore_if_the_file_changes_again() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        fs::create_dir_all(game.join("mods")).unwrap();
        fs::create_dir_all(&sources).unwrap();
        fs::write(game.join("mods/drift.pak"), b"approved edit").unwrap();
        let desired = source(&sources, "managed", b"managed", "mods/drift.pak");
        let previous = owned("mods/drift.pak", b"managed");
        let receipt = receipt(&game, "old", std::slice::from_ref(&previous));
        let plan = plan_deployment_with_approvals(
            request(&game, temporary.path(), vec![desired.clone()]),
            Some(&receipt),
            vec![ManagedFileRestoreApproval {
                relative_path: "mods/drift.pak".to_owned(),
                expected_sha256: previous.sha256,
                current_sha256: Some(hash_file(&game.join("mods/drift.pak")).unwrap()),
                restore_sha256: desired.sha256,
            }],
        )
        .unwrap();
        fs::write(game.join("mods/drift.pak"), b"changed after approval").unwrap();

        let error = activate_deployment(&plan, || false).unwrap_err();

        assert!(
            matches!(error, DeployError::ManagedFileApprovalChanged(path) if path == "mods/drift.pak")
        );
        assert_eq!(
            fs::read(game.join("mods/drift.pak")).unwrap(),
            b"changed after approval"
        );
    }

    #[test]
    fn backs_up_approved_drift_and_rolls_it_back_on_failure() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        fs::create_dir_all(game.join("mods")).unwrap();
        fs::create_dir_all(&sources).unwrap();
        fs::write(game.join("mods/drift.pak"), b"external edit").unwrap();
        let desired = source(&sources, "managed", b"managed", "mods/drift.pak");
        let previous = owned("mods/drift.pak", b"managed");
        let receipt = receipt(&game, "old", std::slice::from_ref(&previous));
        let drift_sha256 = hash_file(&game.join("mods/drift.pak")).unwrap();
        let plan = plan_deployment_with_approvals(
            request(&game, temporary.path(), vec![desired.clone()]),
            Some(&receipt),
            vec![ManagedFileRestoreApproval {
                relative_path: "mods/drift.pak".to_owned(),
                expected_sha256: previous.sha256,
                current_sha256: Some(drift_sha256.clone()),
                restore_sha256: desired.sha256,
            }],
        )
        .unwrap();
        let state = prepare_state_root(&plan.state_root, Some(&plan.game_root)).unwrap();
        replace_json(
            &receipt_path(&state, &plan.installation_id),
            &receipt,
            "fixture",
        )
        .unwrap();

        let error = activate_with_failpoint(
            &plan,
            || false,
            |boundary| {
                if boundary == DeploymentBoundary::OperationApplied(0) {
                    Err(DeployError::InjectedFailure(boundary))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();

        assert!(matches!(error, DeployError::InjectedFailure(_)));
        assert_eq!(
            fs::read(game.join("mods/drift.pak")).unwrap(),
            b"external edit"
        );
        assert!(backup_path(&plan.state_root, &drift_sha256).is_file());
        assert_eq!(
            load_receipt(&plan.state_root, &plan.installation_id).unwrap(),
            Some(receipt)
        );
    }

    #[test]
    fn recreates_a_missing_managed_file_only_with_explicit_approval() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        fs::create_dir_all(game.join("mods")).unwrap();
        fs::create_dir_all(&sources).unwrap();
        let desired = source(&sources, "managed", b"managed", "mods/missing.pak");
        let previous = owned("mods/missing.pak", b"managed");
        let receipt = receipt(&game, "old", std::slice::from_ref(&previous));

        let blocked = plan_deployment(
            request(&game, temporary.path(), vec![desired.clone()]),
            Some(&receipt),
        )
        .unwrap();
        assert!(blocked.blockers.iter().any(|blocker| matches!(
            blocker,
            DeploymentBlocker::ManagedFileMissing { relative_path }
                if relative_path == "mods/missing.pak"
        )));

        let approved = plan_deployment_with_approvals(
            request(&game, temporary.path(), vec![desired.clone()]),
            Some(&receipt),
            vec![ManagedFileRestoreApproval {
                relative_path: "mods/missing.pak".to_owned(),
                expected_sha256: previous.sha256,
                current_sha256: None,
                restore_sha256: desired.sha256,
            }],
        )
        .unwrap();
        let state = prepare_state_root(&approved.state_root, Some(&approved.game_root)).unwrap();
        replace_json(
            &receipt_path(&state, &approved.installation_id),
            &receipt,
            "fixture",
        )
        .unwrap();
        activate_deployment(&approved, || false).unwrap();

        assert_eq!(fs::read(game.join("mods/missing.pak")).unwrap(), b"managed");
    }

    #[test]
    fn accepts_managed_drift_that_already_matches_the_desired_file() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        fs::create_dir_all(game.join("mods")).unwrap();
        fs::create_dir_all(&sources).unwrap();
        fs::write(game.join("mods/update.pak"), b"new package").unwrap();
        let desired = source(&sources, "update", b"new package", "mods/update.pak");
        let receipt = receipt(&game, "old", &[owned("mods/update.pak", b"old package")]);

        let plan = plan_deployment(
            request(&game, temporary.path(), vec![desired]),
            Some(&receipt),
        )
        .unwrap();

        assert!(plan.ready());
        assert_eq!(plan.changes[0].kind, DeploymentChangeKind::UnchangedManaged);
    }

    #[test]
    fn reconciles_only_a_verified_current_managed_identity() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let state = temporary.path().join("state");
        fs::create_dir_all(game.join("mods")).unwrap();
        fs::create_dir_all(state.join("receipts")).unwrap();
        fs::write(game.join("mods/loader.dll"), b"recognized replacement").unwrap();
        let original = receipt(
            &game,
            "loader",
            &[owned("mods/loader.dll", b"previous managed bytes")],
        );
        replace_json(&receipt_path(&state, "loader"), &original, "fixture").unwrap();
        let replacement = DisplacedFile {
            bytes: b"recognized replacement".len() as u64,
            sha256: hash_file(&game.join("mods/loader.dll")).unwrap(),
        };
        let identities = BTreeMap::from([("mods/loader.dll".to_owned(), replacement.clone())]);

        let updated =
            reconcile_managed_file_identities(&state, "loader", &game, "reconcile", &identities)
                .unwrap();

        assert_eq!(updated.files[0].bytes, replacement.bytes);
        assert_eq!(updated.files[0].sha256, replacement.sha256);
        assert_eq!(load_receipt(&state, "loader").unwrap(), Some(updated));

        let invalid = BTreeMap::from([(
            "mods/loader.dll".to_owned(),
            DisplacedFile {
                bytes: replacement.bytes,
                sha256: "0".repeat(64),
            },
        )]);
        assert!(matches!(
            reconcile_managed_file_identities(
                &state,
                "loader",
                &game,
                "reject-reconcile",
                &invalid,
            ),
            Err(DeployError::PlanChanged)
        ));
    }

    #[test]
    fn reconciles_a_verified_disabled_ue4ss_marker_alias() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let state = temporary.path().join("state");
        let module = game.join("RetroRewind/Binaries/Win64/ue4ss/Mods/Example");
        fs::create_dir_all(&module).unwrap();
        fs::create_dir_all(state.join("receipts")).unwrap();
        fs::write(module.join("Enabled.TXT.zdev-disabled"), b"").unwrap();
        let original = receipt(
            &game,
            "installation",
            &[owned(
                "RetroRewind/Binaries/Win64/ue4ss/Mods/Example/Enabled.TXT",
                b"",
            )],
        );
        replace_json(&receipt_path(&state, "installation"), &original, "fixture").unwrap();

        let reconciled = reconcile_disabled_marker_aliases(&state, "installation", &game).unwrap();
        let updated = load_receipt(&state, "installation").unwrap().unwrap();

        assert_eq!(reconciled, 1);
        assert_eq!(
            updated.files[0].relative_path,
            "RetroRewind/Binaries/Win64/ue4ss/Mods/Example/Enabled.TXT.zdev-disabled"
        );
    }

    #[test]
    fn removes_only_empty_module_directories_after_managed_files_are_removed() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let module = game.join("RetroRewind/Binaries/Win64/ue4ss/Mods/FasterReturns");
        fs::create_dir_all(module.join("Scripts")).unwrap();
        let unrelated = game.join("RetroRewind/Binaries/Win64/ue4ss/Mods/KeepMe");
        fs::create_dir_all(&unrelated).unwrap();

        cleanup_empty_managed_directories(
            &game,
            &[DeploymentChange {
                relative_path:
                    "RetroRewind/Binaries/Win64/ue4ss/Mods/FasterReturns/Scripts/main.lua"
                        .to_owned(),
                kind: DeploymentChangeKind::RemoveManaged,
                previous_sha256: Some("a".repeat(64)),
                next_sha256: None,
                owner_id: Some("nexus:faster-returns".to_owned()),
                owner_name: Some("Faster Returns".to_owned()),
            }],
        )
        .unwrap();

        assert!(!module.exists());
        assert!(unrelated.is_dir());
        assert!(game.join("RetroRewind/Binaries/Win64/ue4ss/Mods").is_dir());
    }

    #[test]
    fn rejects_case_collisions_and_source_changes() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        fs::create_dir_all(&game).unwrap();
        fs::create_dir_all(&sources).unwrap();
        let first = source(&sources, "one", b"one", "Mods/A.pak");
        let second = source(&sources, "two", b"two", "mods/a.PAK");
        let collision =
            plan_deployment(request(&game, temporary.path(), vec![first, second]), None);
        assert!(matches!(
            collision,
            Err(DeployError::PlannedCollision { .. })
        ));

        let file = source(&sources, "prefix-file", b"file", "Mods");
        let child = source(&sources, "prefix-child", b"child", "mods/a.pak");
        let prefix_collision =
            plan_deployment(request(&game, temporary.path(), vec![file, child]), None);
        assert!(matches!(
            prefix_collision,
            Err(DeployError::PrefixCollision { .. })
        ));

        let mut changed = source(&sources, "changed", b"before", "mods/changed.pak");
        fs::write(&changed.source, b"after").unwrap();
        changed.bytes = 6;
        let changed = plan_deployment(request(&game, temporary.path(), vec![changed]), None);
        assert!(matches!(changed, Err(DeployError::SourceChanged { .. })));

        let invalid_receipt = receipt(
            &game,
            "profile",
            &[
                owned("Mods/duplicate.pak", b"one"),
                owned("mods/DUPLICATE.pak", b"two"),
            ],
        );
        assert!(matches!(
            plan_deployment(
                request(&game, temporary.path(), Vec::new()),
                Some(&invalid_receipt)
            ),
            Err(DeployError::InvalidReceipt(_))
        ));
    }

    #[test]
    fn blocks_case_collisions_in_parent_directories() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        fs::create_dir_all(game.join("mods")).unwrap();
        fs::create_dir_all(&sources).unwrap();
        fs::write(game.join("mods/existing.pak"), b"existing").unwrap();
        let desired = source(&sources, "new", b"new", "Mods/new.pak");

        let plan = plan_deployment(request(&game, temporary.path(), vec![desired]), None).unwrap();

        assert!(!plan.ready());
        assert!(plan.blockers.iter().any(|blocker| matches!(
            blocker,
            DeploymentBlocker::PathCollision {
                planned_path,
                existing_path,
            } if planned_path == "Mods/new.pak" && existing_path == "mods"
        )));
    }

    #[cfg(unix)]
    #[test]
    fn blocks_links_in_the_destination_path() {
        use std::os::unix::fs::symlink;

        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let outside = temporary.path().join("outside");
        let sources = temporary.path().join("sources");
        fs::create_dir_all(&game).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(&sources).unwrap();
        symlink(&outside, game.join("mods")).unwrap();
        let desired = source(&sources, "new", b"new", "mods/new.pak");

        let plan = plan_deployment(request(&game, temporary.path(), vec![desired]), None).unwrap();

        assert!(!plan.ready());
        assert!(plan.blockers.iter().any(|blocker| matches!(
            blocker,
            DeploymentBlocker::UnsafeFilesystemEntry { relative_path, .. }
                if relative_path == "mods/new.pak"
        )));
        assert!(!outside.join("new.pak").exists());
    }

    #[test]
    fn serializes_a_stable_preview_without_modifying_the_game() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        fs::create_dir_all(&game).unwrap();
        fs::create_dir_all(&sources).unwrap();
        let desired = source(&sources, "new", b"new", "mods/new.pak");

        let plan = plan_deployment(request(&game, temporary.path(), vec![desired]), None).unwrap();
        let json = serde_json::to_string_pretty(&plan).unwrap();

        assert!(json.contains("\"create\""));
        assert!(!game.join("mods").exists());
    }

    #[test]
    fn activates_switches_and_repeats_a_profile_idempotently() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        let state = temporary.path().join("state");
        fs::create_dir_all(game.join("mods")).unwrap();
        fs::create_dir_all(&sources).unwrap();
        fs::write(game.join("mods/existing.pak"), b"unmanaged").unwrap();
        let existing = source(&sources, "replacement", b"managed", "mods/existing.pak");
        let added = source(&sources, "added", b"added", "mods/added.pak");
        let mut first_request = request(
            &game,
            temporary.path(),
            vec![existing.clone(), added.clone()],
        );
        first_request.state_root = state.clone();
        first_request.allow_unmanaged = true;
        let first = plan_deployment(first_request, None).unwrap();

        let report = activate_deployment(&first, || false).unwrap();

        assert_eq!(report.changed_files, 2);
        assert_eq!(
            fs::read(game.join("mods/existing.pak")).unwrap(),
            b"managed"
        );
        assert_eq!(fs::read(game.join("mods/added.pak")).unwrap(), b"added");
        assert_eq!(report.backup_hashes.len(), 1);
        let first_receipt = load_receipt(&state, "retro_rewind").unwrap().unwrap();
        assert_eq!(first_receipt.profile_id, "profile_1");
        assert!(!state.join("staging/transaction_1").exists());

        let mut repeated_request = request(&game, temporary.path(), vec![existing, added]);
        repeated_request.transaction_id = "transaction_2".to_owned();
        repeated_request.state_root = state.clone();
        let repeated = plan_deployment(repeated_request, Some(&first_receipt)).unwrap();
        for file in &repeated.files {
            fs::remove_file(&file.source).unwrap();
        }
        let repeated_report = activate_prepared_deployment(&repeated, || false).unwrap();
        assert_eq!(repeated_report.changed_files, 0);
        assert!(repeated_report.backup_hashes.is_empty());

        let mut switch_request = request(&game, temporary.path(), vec![]);
        switch_request.transaction_id = "transaction_3".to_owned();
        switch_request.profile_id = "empty_profile".to_owned();
        switch_request.state_root = state.clone();
        let current = load_receipt(&state, "retro_rewind").unwrap().unwrap();
        let switch = plan_deployment(switch_request, Some(&current)).unwrap();
        activate_deployment(&switch, || false).unwrap();
        assert_eq!(
            fs::read(game.join("mods/existing.pak")).unwrap(),
            b"unmanaged"
        );
        assert!(!game.join("mods/added.pak").exists());
        assert_eq!(
            load_receipt(&state, "retro_rewind")
                .unwrap()
                .unwrap()
                .profile_id,
            "empty_profile"
        );
    }

    #[test]
    fn rolls_back_every_injected_durable_boundary() {
        let boundaries = [
            DeploymentBoundary::JournalDurable,
            DeploymentBoundary::OperationApplied(0),
            DeploymentBoundary::OperationApplied(1),
            DeploymentBoundary::FilesVerified,
            DeploymentBoundary::ReceiptWritten,
        ];
        for target in boundaries {
            let temporary = TempDir::new().unwrap();
            let game = temporary.path().join("game");
            let sources = temporary.path().join("sources");
            let state = temporary.path().join("state");
            fs::create_dir_all(game.join("mods")).unwrap();
            fs::create_dir_all(&sources).unwrap();
            fs::write(game.join("mods/a-existing.pak"), b"original").unwrap();
            let replacement = source(
                &sources,
                "replacement",
                b"replacement",
                "mods/a-existing.pak",
            );
            let added = source(&sources, "added", b"added", "mods/z-added.pak");
            let mut deployment = request(&game, temporary.path(), vec![replacement, added]);
            deployment.state_root = state.clone();
            deployment.allow_unmanaged = true;
            let plan = plan_deployment(deployment, None).unwrap();

            let result = activate_with_failpoint(
                &plan,
                || false,
                |boundary| {
                    if boundary == target {
                        Err(DeployError::InjectedFailure(boundary))
                    } else {
                        Ok(())
                    }
                },
            );

            assert!(matches!(result, Err(DeployError::InjectedFailure(_))));
            assert_eq!(
                fs::read(game.join("mods/a-existing.pak")).unwrap(),
                b"original",
                "failed at {target:?}"
            );
            assert!(!game.join("mods/z-added.pak").exists());
            assert!(load_receipt(&state, "retro_rewind").unwrap().is_none());
            assert!(
                fs::read_dir(state.join("journals"))
                    .unwrap()
                    .next()
                    .is_none()
            );
        }
    }

    #[test]
    fn game_start_during_activation_rolls_back_before_commit() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        let state = temporary.path().join("state");
        fs::create_dir_all(&game).unwrap();
        fs::create_dir_all(&sources).unwrap();
        let desired = source(&sources, "new", b"managed", "mods/new.pak");
        let mut deployment = request(&game, temporary.path(), vec![desired]);
        deployment.state_root = state.clone();
        let plan = plan_deployment(deployment, None).unwrap();
        let running = Cell::new(false);

        let result = activate_with_failpoint(
            &plan,
            || running.get(),
            |boundary| {
                if boundary == DeploymentBoundary::OperationApplied(0) {
                    running.set(true);
                }
                Ok(())
            },
        );

        assert!(matches!(result, Err(DeployError::GameRunning)));
        assert!(!game.join("mods/new.pak").exists());
        assert!(load_receipt(&state, "retro_rewind").unwrap().is_none());
        assert!(
            fs::read_dir(state.join("journals"))
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn recovery_drift_preflight_prevents_partial_multifile_rollback() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        let state = temporary.path().join("state");
        fs::create_dir_all(&game).unwrap();
        fs::create_dir_all(&sources).unwrap();
        let a = source(&sources, "a", b"managed-a", "mods/a.pak");
        let z = source(&sources, "z", b"managed-z", "mods/z.pak");
        let mut deployment = request(&game, temporary.path(), vec![a, z]);
        deployment.state_root = state.clone();
        let plan = plan_deployment(deployment, None).unwrap();
        let state = prepare_state_root(&state, Some(&plan.game_root)).unwrap();
        let stage = materialize_staging(&plan, &state).unwrap();
        let journal = DeploymentJournal {
            schema_version: 1,
            transaction_id: plan.transaction_id.clone(),
            installation_id: plan.installation_id.clone(),
            game_root: plan.game_root.clone(),
            state_root: state.clone(),
            changes: plan.changes.clone(),
            external_moves: plan.external_moves.clone(),
            previous_receipt: None,
            target_receipt: plan.target_receipt.clone(),
        };
        let journal_path = journal_path(&state, &plan.transaction_id);
        write_json_create_new(&journal_path, &journal).unwrap();
        for change in &plan.changes {
            apply_change(&plan, &stage, change).unwrap();
        }
        fs::write(game.join("mods/a.pak"), b"external-change").unwrap();

        let result = recover_incomplete(&state, || false);

        assert!(matches!(
            result,
            Err(DeployError::RecoveryDrift { path }) if path == "mods/a.pak"
        ));
        assert_eq!(
            fs::read(game.join("mods/a.pak")).unwrap(),
            b"external-change"
        );
        assert_eq!(fs::read(game.join("mods/z.pak")).unwrap(), b"managed-z");
        assert!(journal_path.exists());
        assert!(stage.exists());
    }

    #[test]
    fn recovery_receipt_drift_is_detected_before_file_rollback() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        let state = temporary.path().join("state");
        fs::create_dir_all(&game).unwrap();
        fs::create_dir_all(&sources).unwrap();
        let desired = source(&sources, "new", b"managed", "mods/new.pak");
        let mut deployment = request(&game, temporary.path(), vec![desired]);
        deployment.state_root = state.clone();
        let plan = plan_deployment(deployment, None).unwrap();
        let state = prepare_state_root(&state, Some(&plan.game_root)).unwrap();
        let stage = materialize_staging(&plan, &state).unwrap();
        let journal = DeploymentJournal {
            schema_version: 1,
            transaction_id: plan.transaction_id.clone(),
            installation_id: plan.installation_id.clone(),
            game_root: plan.game_root.clone(),
            state_root: state.clone(),
            changes: plan.changes.clone(),
            external_moves: plan.external_moves.clone(),
            previous_receipt: None,
            target_receipt: plan.target_receipt.clone(),
        };
        let journal_path = journal_path(&state, &plan.transaction_id);
        write_json_create_new(&journal_path, &journal).unwrap();
        apply_change(&plan, &stage, &plan.changes[0]).unwrap();
        write_active_receipt(&journal, &state).unwrap();
        let mut external_receipt = plan.target_receipt.clone();
        external_receipt.profile_id = "external_profile".to_owned();
        let receipt_path = receipt_path(&state, &plan.installation_id);
        replace_json(&receipt_path, &external_receipt, "external_receipt").unwrap();

        let result = recover_incomplete(&state, || false);

        assert!(matches!(
            result,
            Err(DeployError::RecoveryDrift { path }) if path == receipt_path.display().to_string()
        ));
        assert_eq!(fs::read(game.join("mods/new.pak")).unwrap(), b"managed");
        assert_eq!(
            load_receipt(&state, "retro_rewind").unwrap(),
            Some(external_receipt)
        );
        assert!(journal_path.exists());
        assert!(stage.exists());
    }

    #[test]
    fn recovery_cleans_prejournal_staging_and_allows_retry() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        let state = temporary.path().join("state");
        fs::create_dir_all(&game).unwrap();
        fs::create_dir_all(&sources).unwrap();
        let desired = source(&sources, "new", b"managed", "mods/new.pak");
        let mut deployment = request(&game, temporary.path(), vec![desired]);
        deployment.state_root = state.clone();
        let plan = plan_deployment(deployment, None).unwrap();
        let prepared_state = prepare_state_root(&state, Some(&plan.game_root)).unwrap();
        let stage = materialize_staging(&plan, &prepared_state).unwrap();

        let recovery = recover_incomplete(&state, || false).unwrap();

        assert!(recovery.is_empty());
        assert!(!stage.exists());
        activate_deployment(&plan, || false).unwrap();
        assert_eq!(fs::read(game.join("mods/new.pak")).unwrap(), b"managed");
    }

    #[test]
    fn startup_recovery_rolls_back_an_incomplete_journal() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        let state = temporary.path().join("state");
        fs::create_dir_all(game.join("mods")).unwrap();
        fs::create_dir_all(&sources).unwrap();
        fs::write(game.join("mods/existing.pak"), b"original").unwrap();
        let replacement = source(&sources, "replacement", b"replacement", "mods/existing.pak");
        let mut deployment = request(&game, temporary.path(), vec![replacement]);
        deployment.state_root = state.clone();
        deployment.allow_unmanaged = true;
        let plan = plan_deployment(deployment, None).unwrap();
        let state = prepare_state_root(&state, Some(&plan.game_root)).unwrap();
        let stage = materialize_staging(&plan, &state).unwrap();
        materialize_backups(&plan, &state).unwrap();
        let journal = DeploymentJournal {
            schema_version: 1,
            transaction_id: plan.transaction_id.clone(),
            installation_id: plan.installation_id.clone(),
            game_root: plan.game_root.clone(),
            state_root: state.clone(),
            changes: plan.changes.clone(),
            external_moves: plan.external_moves.clone(),
            previous_receipt: None,
            target_receipt: plan.target_receipt.clone(),
        };
        let journal_path = journal_path(&state, &plan.transaction_id);
        write_json_create_new(&journal_path, &journal).unwrap();
        apply_change(&plan, &stage, &plan.changes[0]).unwrap();
        assert_eq!(
            fs::read(game.join("mods/existing.pak")).unwrap(),
            b"replacement"
        );

        let recovery = recover_incomplete(&state, || false).unwrap();

        assert_eq!(
            recovery,
            vec![RecoveryReport {
                transaction_id: "transaction_1".to_owned(),
                action: RecoveryAction::RolledBack,
            }]
        );
        assert_eq!(
            fs::read(game.join("mods/existing.pak")).unwrap(),
            b"original"
        );
        assert!(!journal_path.exists());
        assert!(!stage.exists());
    }

    #[test]
    fn startup_recovery_restores_a_quarantined_managed_removal() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let state = temporary.path().join("state");
        fs::create_dir_all(game.join("mods")).unwrap();
        fs::write(game.join("mods/large.pak"), b"managed").unwrap();
        let previous = receipt(&game, "old", &[owned("mods/large.pak", b"managed")]);
        let mut deployment = request(&game, temporary.path(), Vec::new());
        deployment.state_root = state.clone();
        let plan = plan_deployment(deployment, Some(&previous)).unwrap();
        let state = prepare_state_root(&state, Some(&plan.game_root)).unwrap();
        let stage = materialize_staging(&plan, &state).unwrap();
        assert!(materialize_backups(&plan, &state).unwrap().is_empty());
        replace_json(
            &receipt_path(&state, &plan.installation_id),
            &previous,
            "fixture",
        )
        .unwrap();
        let journal = DeploymentJournal {
            schema_version: 2,
            transaction_id: plan.transaction_id.clone(),
            installation_id: plan.installation_id.clone(),
            game_root: plan.game_root.clone(),
            state_root: state.clone(),
            changes: plan.changes.clone(),
            external_moves: plan.external_moves.clone(),
            previous_receipt: Some(previous),
            target_receipt: plan.target_receipt.clone(),
        };
        let journal_path = journal_path(&state, &plan.transaction_id);
        write_json_create_new(&journal_path, &journal).unwrap();
        apply_change(&plan, &stage, &plan.changes[0]).unwrap();
        let destination = game.join("mods/large.pak");
        let quarantine =
            sibling_transaction_path(&destination, &plan.transaction_id, "old").unwrap();
        assert!(!destination.exists());
        assert_eq!(fs::read(&quarantine).unwrap(), b"managed");

        let recovery = recover_incomplete(&state, || false).unwrap();

        assert_eq!(recovery[0].action, RecoveryAction::RolledBack);
        assert_eq!(fs::read(destination).unwrap(), b"managed");
        assert!(!quarantine.exists());
        assert!(!journal_path.exists());
    }

    #[test]
    fn startup_recovery_cleans_a_committed_journal_without_rollback() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        let state = temporary.path().join("state");
        fs::create_dir_all(&game).unwrap();
        fs::create_dir_all(&sources).unwrap();
        let desired = source(&sources, "new", b"managed", "mods/new.pak");
        let mut deployment = request(&game, temporary.path(), vec![desired]);
        deployment.state_root = state.clone();
        let plan = plan_deployment(deployment, None).unwrap();
        let state = prepare_state_root(&state, Some(&plan.game_root)).unwrap();
        let stage = materialize_staging(&plan, &state).unwrap();
        let journal = DeploymentJournal {
            schema_version: 1,
            transaction_id: plan.transaction_id.clone(),
            installation_id: plan.installation_id.clone(),
            game_root: plan.game_root.clone(),
            state_root: state.clone(),
            changes: plan.changes.clone(),
            external_moves: plan.external_moves.clone(),
            previous_receipt: None,
            target_receipt: plan.target_receipt.clone(),
        };
        let journal_path = journal_path(&state, &plan.transaction_id);
        let marker = commit_marker_path(&state, &plan.transaction_id);
        write_json_create_new(&journal_path, &journal).unwrap();
        apply_change(&plan, &stage, &plan.changes[0]).unwrap();
        verify_target_state(&plan).unwrap();
        write_active_receipt(&journal, &state).unwrap();
        write_commit_marker(&marker).unwrap();

        let recovery = recover_incomplete(&state, || false).unwrap();

        assert_eq!(
            recovery,
            vec![RecoveryReport {
                transaction_id: "transaction_1".to_owned(),
                action: RecoveryAction::CleanedCommitted,
            }]
        );
        assert_eq!(fs::read(game.join("mods/new.pak")).unwrap(), b"managed");
        assert_eq!(
            load_receipt(&state, "retro_rewind")
                .unwrap()
                .unwrap()
                .profile_id,
            "profile_1"
        );
        assert!(!journal_path.exists());
        assert!(!marker.exists());
        assert!(!stage.exists());
    }

    #[test]
    fn committed_recovery_keeps_evidence_when_deployed_content_drifted() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        let state = temporary.path().join("state");
        fs::create_dir_all(&game).unwrap();
        fs::create_dir_all(&sources).unwrap();
        let desired = source(&sources, "new", b"managed", "mods/new.pak");
        let mut deployment = request(&game, temporary.path(), vec![desired]);
        deployment.state_root = state.clone();
        let plan = plan_deployment(deployment, None).unwrap();
        let state = prepare_state_root(&state, Some(&plan.game_root)).unwrap();
        let stage = materialize_staging(&plan, &state).unwrap();
        let journal = DeploymentJournal {
            schema_version: 1,
            transaction_id: plan.transaction_id.clone(),
            installation_id: plan.installation_id.clone(),
            game_root: plan.game_root.clone(),
            state_root: state.clone(),
            changes: plan.changes.clone(),
            external_moves: plan.external_moves.clone(),
            previous_receipt: None,
            target_receipt: plan.target_receipt.clone(),
        };
        let journal_path = journal_path(&state, &plan.transaction_id);
        let marker = commit_marker_path(&state, &plan.transaction_id);
        write_json_create_new(&journal_path, &journal).unwrap();
        apply_change(&plan, &stage, &plan.changes[0]).unwrap();
        write_active_receipt(&journal, &state).unwrap();
        write_commit_marker(&marker).unwrap();
        fs::write(game.join("mods/new.pak"), b"drifted").unwrap();

        assert!(matches!(
            recover_incomplete(&state, || false),
            Err(DeployError::RecoveryDrift { .. })
        ));
        assert_eq!(fs::read(game.join("mods/new.pak")).unwrap(), b"drifted");
        assert!(journal_path.exists());
        assert!(marker.exists());
    }

    #[test]
    fn recovery_refuses_to_overwrite_external_post_crash_drift() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        let state = temporary.path().join("state");
        fs::create_dir_all(&game).unwrap();
        fs::create_dir_all(&sources).unwrap();
        let desired = source(&sources, "new", b"managed", "mods/new.pak");
        let mut deployment = request(&game, temporary.path(), vec![desired]);
        deployment.state_root = state.clone();
        let plan = plan_deployment(deployment, None).unwrap();
        let state = prepare_state_root(&state, Some(&plan.game_root)).unwrap();
        let stage = materialize_staging(&plan, &state).unwrap();
        let journal = DeploymentJournal {
            schema_version: 1,
            transaction_id: plan.transaction_id.clone(),
            installation_id: plan.installation_id.clone(),
            game_root: plan.game_root.clone(),
            state_root: state.clone(),
            changes: plan.changes.clone(),
            external_moves: plan.external_moves.clone(),
            previous_receipt: None,
            target_receipt: plan.target_receipt.clone(),
        };
        let journal_path = journal_path(&state, &plan.transaction_id);
        write_json_create_new(&journal_path, &journal).unwrap();
        apply_change(&plan, &stage, &plan.changes[0]).unwrap();
        fs::write(game.join("mods/new.pak"), b"external after crash").unwrap();

        assert!(matches!(
            recover_incomplete(&state, || false),
            Err(DeployError::RecoveryDrift { .. })
        ));
        assert_eq!(
            fs::read(game.join("mods/new.pak")).unwrap(),
            b"external after crash"
        );
        assert!(journal_path.exists());
    }

    #[test]
    fn blocks_activation_and_recovery_while_the_game_is_running() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        let state = temporary.path().join("state");
        fs::create_dir_all(&game).unwrap();
        fs::create_dir_all(&sources).unwrap();
        let desired = source(&sources, "new", b"new", "mods/new.pak");
        let mut deployment = request(&game, temporary.path(), vec![desired]);
        deployment.state_root = state.clone();
        let plan = plan_deployment(deployment, None).unwrap();

        assert!(matches!(
            activate_deployment(&plan, || true),
            Err(DeployError::GameRunning)
        ));
        assert!(!state.exists());
        fs::create_dir(&state).unwrap();
        assert!(matches!(
            recover_incomplete(&state, || true),
            Err(DeployError::GameRunning)
        ));
        assert!(!game.join("mods/new.pak").exists());
    }

    #[test]
    fn serializes_deployment_and_requires_recovery_before_a_new_apply() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        let state = temporary.path().join("state");
        fs::create_dir_all(&game).unwrap();
        fs::create_dir_all(&sources).unwrap();
        let desired = source(&sources, "new", b"new", "mods/new.pak");
        let mut deployment = request(&game, temporary.path(), vec![desired]);
        deployment.state_root = state.clone();
        let plan = plan_deployment(deployment, None).unwrap();
        let state = prepare_state_root(&state, Some(&plan.game_root)).unwrap();
        let lock = acquire_deployment_lock(&state).unwrap();

        assert!(matches!(
            activate_deployment(&plan, || false),
            Err(DeployError::DeploymentBusy)
        ));
        drop(lock);
        fs::write(state.join("journals/interrupted.json"), b"{}").unwrap();
        assert!(matches!(
            activate_deployment(&plan, || false),
            Err(DeployError::PendingRecovery)
        ));
        assert!(!game.join("mods/new.pak").exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlinked_content_addressed_backup_shard() {
        use std::os::unix::fs::symlink;

        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        let state = temporary.path().join("state");
        let outside = temporary.path().join("outside");
        fs::create_dir_all(game.join("mods")).unwrap();
        fs::create_dir_all(&sources).unwrap();
        fs::create_dir_all(state.join("backups")).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(game.join("mods/existing.pak"), b"unmanaged").unwrap();
        let original_hash = sha256_path(&game.join("mods/existing.pak")).unwrap();
        symlink(&outside, state.join("backups").join(&original_hash[..2])).unwrap();
        let desired = source(&sources, "new", b"managed", "mods/existing.pak");
        let mut deployment = request(&game, temporary.path(), vec![desired]);
        deployment.state_root = state.clone();
        deployment.allow_unmanaged = true;
        let plan = plan_deployment(deployment, None).unwrap();

        assert!(matches!(
            activate_deployment(&plan, || false),
            Err(DeployError::UnsafeStateRoot(_))
        ));
        assert_eq!(
            fs::read(game.join("mods/existing.pak")).unwrap(),
            b"unmanaged"
        );
        assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
        assert!(!state.join("staging/transaction_1").exists());
    }

    #[test]
    fn rejects_state_inside_the_game_before_creating_it() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        fs::create_dir_all(&game).unwrap();
        fs::create_dir_all(&sources).unwrap();
        let desired = source(&sources, "new", b"new", "mods/new.pak");
        let mut deployment = request(&game, temporary.path(), vec![desired]);
        deployment.state_root = game.join(".rrmm-state");
        let plan = plan_deployment(deployment, None).unwrap();

        assert!(matches!(
            activate_deployment(&plan, || false),
            Err(DeployError::UnsafeStateRoot(_))
        ));
        assert!(!game.join(".rrmm-state").exists());
        assert!(!game.join("mods/new.pak").exists());
    }

    #[test]
    fn rejects_destination_changes_between_preview_and_apply() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        let state = temporary.path().join("state");
        fs::create_dir_all(game.join("mods")).unwrap();
        fs::create_dir_all(&sources).unwrap();
        fs::write(game.join("mods/existing.pak"), b"first").unwrap();
        let desired = source(&sources, "new", b"managed", "mods/existing.pak");
        let mut deployment = request(&game, temporary.path(), vec![desired]);
        deployment.state_root = state.clone();
        deployment.allow_unmanaged = true;
        let plan = plan_deployment(deployment, None).unwrap();
        fs::write(game.join("mods/existing.pak"), b"external change").unwrap();

        assert!(matches!(
            activate_deployment(&plan, || false),
            Err(DeployError::PlanChanged)
        ));
        assert_eq!(
            fs::read(game.join("mods/existing.pak")).unwrap(),
            b"external change"
        );
        assert!(!state.exists());
    }

    #[test]
    fn renames_external_file_and_records_it_separately() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let state = temporary.path().join("state");
        fs::create_dir_all(game.join("mods")).unwrap();
        fs::write(game.join("mods/mod.pak"), b"external").unwrap();
        let mut deployment = request(&game, temporary.path(), Vec::new());
        deployment.state_root = state.clone();
        deployment.external_files = vec![external_file(
            &game,
            "mods/mod.pak",
            "mods/mod.pak",
            "mods/000_mod.pak",
        )];

        let plan = plan_deployment(deployment, None).unwrap();
        assert!(plan.ready());
        assert_eq!(plan.external_moves.len(), 1);
        assert_eq!(
            plan.external_moves[0].owner_id.as_deref(),
            Some("test-external")
        );
        assert_eq!(
            plan.external_moves[0].owner_name.as_deref(),
            Some("Test external mod")
        );
        activate_deployment(&plan, || false).unwrap();

        assert!(!game.join("mods/mod.pak").exists());
        assert_eq!(
            fs::read(game.join("mods/000_mod.pak")).unwrap(),
            b"external"
        );
        let receipt = load_receipt(&state, "retro_rewind").unwrap().unwrap();
        assert!(receipt.files.is_empty());
        assert_eq!(receipt.external_files.len(), 1);
        assert_eq!(
            receipt.external_files[0].original_relative_path,
            "mods/mod.pak"
        );
        assert_eq!(
            receipt.external_files[0].current_relative_path,
            "mods/000_mod.pak"
        );
    }

    #[test]
    fn renames_external_pak_and_sig_in_one_transaction() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        fs::create_dir_all(game.join("mods")).unwrap();
        fs::write(game.join("mods/mod.pak"), b"pak").unwrap();
        fs::write(game.join("mods/mod.sig"), b"sig").unwrap();
        let mut deployment = request(&game, temporary.path(), Vec::new());
        deployment.external_files = vec![
            external_file(&game, "mods/mod.pak", "mods/mod.pak", "mods/010_mod.pak"),
            external_file(&game, "mods/mod.sig", "mods/mod.sig", "mods/010_mod.sig"),
        ];

        let plan = plan_deployment(deployment, None).unwrap();
        activate_deployment(&plan, || false).unwrap();

        assert_eq!(fs::read(game.join("mods/010_mod.pak")).unwrap(), b"pak");
        assert_eq!(fs::read(game.join("mods/010_mod.sig")).unwrap(), b"sig");
        assert_eq!(plan.external_moves.len(), 2);
    }

    #[test]
    fn supports_external_swaps_and_chains() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        fs::create_dir_all(&game).unwrap();
        fs::write(game.join("a.pak"), b"a").unwrap();
        fs::write(game.join("b.pak"), b"b").unwrap();
        let mut swap = request(&game, temporary.path(), Vec::new());
        swap.external_files = vec![
            external_file(&game, "a.pak", "a.pak", "b.pak"),
            external_file(&game, "b.pak", "b.pak", "a.pak"),
        ];
        let swap = plan_deployment(swap, None).unwrap();
        activate_deployment(&swap, || false).unwrap();
        assert_eq!(fs::read(game.join("a.pak")).unwrap(), b"b");
        assert_eq!(fs::read(game.join("b.pak")).unwrap(), b"a");

        let receipt = load_receipt(&temporary.path().join("state"), "retro_rewind")
            .unwrap()
            .unwrap();
        let mut chain = request(&game, temporary.path(), Vec::new());
        chain.transaction_id = "transaction_2".to_owned();
        chain.external_files = vec![
            external_file(&game, "a.pak", "a.pak", "b.pak"),
            external_file(&game, "b.pak", "b.pak", "c.pak"),
        ];
        let chain = plan_deployment(chain, Some(&receipt)).unwrap();
        activate_deployment(&chain, || false).unwrap();
        assert!(!game.join("a.pak").exists());
        assert_eq!(fs::read(game.join("b.pak")).unwrap(), b"b");
        assert_eq!(fs::read(game.join("c.pak")).unwrap(), b"a");
    }

    #[test]
    fn rolls_back_and_recovers_external_files_between_move_phases() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let state = temporary.path().join("state");
        fs::create_dir_all(&game).unwrap();
        fs::write(game.join("a.pak"), b"a").unwrap();
        fs::write(game.join("b.pak"), b"b").unwrap();
        let mut deployment = request(&game, temporary.path(), Vec::new());
        deployment.state_root = state.clone();
        deployment.external_files = vec![
            external_file(&game, "a.pak", "a.pak", "b.pak"),
            external_file(&game, "b.pak", "b.pak", "a.pak"),
        ];
        let plan = plan_deployment(deployment, None).unwrap();
        let failed = activate_with_failpoint(
            &plan,
            || false,
            |boundary| {
                if boundary == DeploymentBoundary::ExternalSourcesStaged {
                    Err(DeployError::InjectedFailure(boundary))
                } else {
                    Ok(())
                }
            },
        );
        assert!(matches!(failed, Err(DeployError::InjectedFailure(_))));
        assert_eq!(fs::read(game.join("a.pak")).unwrap(), b"a");
        assert_eq!(fs::read(game.join("b.pak")).unwrap(), b"b");

        let state = prepare_state_root(&state, Some(&plan.game_root)).unwrap();
        materialize_backups(&plan, &state).unwrap();
        let journal = DeploymentJournal {
            schema_version: 2,
            transaction_id: plan.transaction_id.clone(),
            installation_id: plan.installation_id.clone(),
            game_root: plan.game_root.clone(),
            state_root: state.clone(),
            changes: plan.changes.clone(),
            external_moves: plan.external_moves.clone(),
            previous_receipt: None,
            target_receipt: plan.target_receipt.clone(),
        };
        let journal_path = journal_path(&state, &plan.transaction_id);
        write_json_create_new(&journal_path, &journal).unwrap();
        stage_external_moves(&plan).unwrap();
        apply_external_target(&plan, 0, &plan.external_moves[0]).unwrap();

        let recovered = recover_incomplete(&state, || false).unwrap();
        assert_eq!(recovered[0].action, RecoveryAction::RolledBack);
        assert_eq!(fs::read(game.join("a.pak")).unwrap(), b"a");
        assert_eq!(fs::read(game.join("b.pak")).unwrap(), b"b");
        assert!(!journal_path.exists());
    }

    #[test]
    fn blocks_an_external_target_with_unknown_content() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        fs::create_dir_all(&game).unwrap();
        fs::write(game.join("source.pak"), b"source").unwrap();
        fs::write(game.join("target.pak"), b"unknown").unwrap();
        let mut deployment = request(&game, temporary.path(), Vec::new());
        deployment.external_files = vec![external_file(
            &game,
            "source.pak",
            "source.pak",
            "target.pak",
        )];

        let plan = plan_deployment(deployment, None).unwrap();
        assert!(!plan.ready());
        assert!(plan.blockers.iter().any(|blocker| matches!(
            blocker,
            DeploymentBlocker::ExternalTargetOccupied { relative_path }
                if relative_path == "target.pak"
        )));
    }

    #[test]
    fn blocks_external_source_drift_before_activation() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        fs::create_dir_all(&game).unwrap();
        fs::write(game.join("source.pak"), b"source").unwrap();
        let mut deployment = request(&game, temporary.path(), Vec::new());
        deployment.external_files = vec![external_file(
            &game,
            "source.pak",
            "source.pak",
            "target.pak",
        )];
        let plan = plan_deployment(deployment, None).unwrap();
        fs::write(game.join("source.pak"), b"drifted").unwrap();

        assert!(matches!(
            activate_deployment(&plan, || false),
            Err(DeployError::SourceChanged { .. })
        ));
        assert!(!game.join("target.pak").exists());
    }

    #[test]
    fn deserializes_v1_receipts_and_journals_without_external_files() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let state = temporary.path().join("state");
        fs::create_dir_all(&game).unwrap();
        fs::create_dir_all(&state).unwrap();
        let receipt_json = serde_json::json!({
            "schema_version": 1,
            "profile_id": "profile_1",
            "game_root": fs::canonicalize(&game).unwrap(),
            "files": []
        });
        let receipt: DeploymentReceipt = serde_json::from_value(receipt_json).unwrap();
        assert!(receipt.external_files.is_empty());
        let journal_json = serde_json::json!({
            "schema_version": 1,
            "transaction_id": "transaction_1",
            "installation_id": "retro_rewind",
            "game_root": fs::canonicalize(&game).unwrap(),
            "state_root": fs::canonicalize(&state).unwrap(),
            "changes": [],
            "previous_receipt": null,
            "target_receipt": receipt
        });
        let journal: DeploymentJournal = serde_json::from_value(journal_json).unwrap();
        assert!(journal.external_moves.is_empty());
    }

    #[test]
    fn keeps_stationary_external_file_without_creating_a_move() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        fs::create_dir_all(&game).unwrap();
        fs::write(game.join("mod.pak"), b"external").unwrap();
        let mut deployment = request(&game, temporary.path(), Vec::new());
        deployment.external_files = vec![external_file(&game, "mod.pak", "mod.pak", "mod.pak")];

        let plan = plan_deployment(deployment, None).unwrap();
        assert!(plan.ready());
        assert!(plan.external_moves.is_empty());
        assert_eq!(plan.target_receipt.external_files.len(), 1);
        activate_deployment(&plan, || false).unwrap();
        assert_eq!(fs::read(game.join("mod.pak")).unwrap(), b"external");
    }

    #[test]
    fn blocks_external_paths_that_collide_with_managed_destinations() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let sources = temporary.path().join("sources");
        fs::create_dir_all(&game).unwrap();
        fs::create_dir_all(&sources).unwrap();
        fs::write(game.join("external.pak"), b"external").unwrap();
        let managed = source(&sources, "managed", b"managed", "ordered.pak");
        let mut deployment = request(&game, temporary.path(), vec![managed]);
        deployment.external_files = vec![external_file(
            &game,
            "external.pak",
            "external.pak",
            "ordered.pak",
        )];

        let plan = plan_deployment(deployment, None).unwrap();
        assert!(!plan.ready());
        assert!(plan.blockers.iter().any(|blocker| matches!(
            blocker,
            DeploymentBlocker::PathCollision { planned_path, existing_path }
                if planned_path == "ordered.pak" && existing_path == "ordered.pak"
        )));
    }

    fn request(game: &Path, state: &Path, files: Vec<DeploymentFile>) -> DeploymentRequest {
        DeploymentRequest {
            transaction_id: "transaction_1".to_owned(),
            installation_id: "retro_rewind".to_owned(),
            profile_id: "profile_1".to_owned(),
            game_root: game.to_path_buf(),
            state_root: state.join("state"),
            files,
            external_files: Vec::new(),
            allow_unmanaged: false,
            game_running: false,
        }
    }

    fn source(root: &Path, name: &str, contents: &[u8], relative_path: &str) -> DeploymentFile {
        let path = root.join(name);
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(contents).unwrap();
        file.sync_all().unwrap();
        DeploymentFile {
            source: path,
            relative_path: relative_path.to_owned(),
            bytes: contents.len() as u64,
            sha256: sha256_path(root.join(name).as_path()).unwrap(),
            package_id: Some("test-package".to_owned()),
            package_name: Some("Test package".to_owned()),
        }
    }

    fn external_file(
        game: &Path,
        original_relative_path: &str,
        source_relative_path: &str,
        target_relative_path: &str,
    ) -> DeploymentExternalFile {
        let source = game.join(path_from_normalized(source_relative_path));
        DeploymentExternalFile {
            original_relative_path: original_relative_path.to_owned(),
            source_relative_path: source_relative_path.to_owned(),
            target_relative_path: target_relative_path.to_owned(),
            bytes: fs::metadata(&source).unwrap().len(),
            sha256: sha256_path(&source).unwrap(),
            owner_id: Some("test-external".to_owned()),
            owner_name: Some("Test external mod".to_owned()),
        }
    }

    fn owned(relative_path: &str, contents: &[u8]) -> OwnedFile {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("file");
        fs::write(&path, contents).unwrap();
        OwnedFile {
            relative_path: relative_path.to_owned(),
            bytes: contents.len() as u64,
            sha256: sha256_path(&path).unwrap(),
            displaced_unmanaged: None,
            package_id: Some("test-package".to_owned()),
            package_name: Some("Test package".to_owned()),
        }
    }

    fn receipt(game: &Path, profile: &str, files: &[OwnedFile]) -> DeploymentReceipt {
        DeploymentReceipt {
            schema_version: 1,
            profile_id: profile.to_owned(),
            game_root: fs::canonicalize(game).unwrap(),
            files: files.to_vec(),
            external_files: Vec::new(),
        }
    }
}
