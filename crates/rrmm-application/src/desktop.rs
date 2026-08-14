use crate::bug_report::{
    BugReportActiveMod, BugReportContext, PendingBugReport, prepare_bug_report,
    redact_sensitive_text, write_bug_report_zip,
};
use crate::{
    BugReportPreviewView, BugReportRequestView, DeploymentMetadata, IncidentMarkerView,
    RecipeCatalogValidation, RecipeDeploymentResolution, materialize_desktop_deployment_request,
    validate_recipe_deployment_target_with_profile,
};
use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use rrmm_archive::{
    ArchiveExtractionReport, ArchiveLimits, ArchivePreflightReport, ArchiveWorkerRequest,
    ArchiveWorkerResponse, PackageKind,
};
use rrmm_artifacts::{
    ArtifactManifest, accept_artifact, load_verified_artifact, preview_artifact_manifest,
};
use rrmm_deploy::{
    DeploymentBlocker, DeploymentChangeKind, DeploymentExternalFile, DeploymentFile,
    DeploymentPlan, DeploymentReceipt, DeploymentRequest, DisplacedFile, FileIdentity,
    ManagedFileRestoreApproval, VerifiedSource, activate_deployment, activate_prepared_deployment,
    cleanup_unreferenced_backups, file_identity, load_receipt, plan_deployment,
    plan_deployment_with_verified_sources, reconcile_disabled_marker_aliases,
    reconcile_managed_file_identities, recover_incomplete,
};
use rrmm_domain::{
    BuildRecipe, BuildStatus, InstallationSource, LayoutStatus, PakLoadOrderPreference,
    Profile as DomainProfile, ProfilePackageSelection, SUPPORTED_BUILD_ID,
};
use rrmm_manifest::{
    CatalogPackage, ComponentType, ManifestProvenance, ResolutionBlocker, ResolveRequest,
    ResolveSelection, SourceProvider, infer_manifest, resolve_packages,
    validate_catalog_package_artifact,
};
use rrmm_pak::{
    MemberHashEvidence, PakConflictOutcome, PakInventory, PakLimits, PakLoadOrderConstraint,
    PakLoadOrderNode, PakWorkerRequest, PakWorkerResponse, analyze_conflicts, discover_paks,
    overlapping_member_hash_requests, parse_priority_hint, resolve_pak_load_order,
    rrmm_ordered_pak_name, validate_inventory_contract,
};
use rrmm_recipes::{
    CatalogTrustFloor, CompatibilityRecipe, RecipeApplicationBlocker, RecipeApplicationReport,
    RecipeError, RecipeOperation, SignedRecipeCatalog, SignedRootMetadata, TrustedRootKey,
    VerifiedRecipeCatalog, resolve_and_apply_verified_recipes, validate_declared_package_in_store,
    verify_signed_catalog,
};
use rrmm_steam::{
    DiscoveryOptions, LaunchReport, candidate_steam_roots, discover_installations,
    inspect_manifest, is_game_running, launch_game_via_steam,
};
use rrmm_store::{CatalogTrustState, FileVerificationFingerprint, Store, StoredArtifact};
use rrmm_ue4ss::{
    EntryStatus, LuaAdvisoryArgument, LuaAdvisoryLimits, LuaAdvisoryReport, ModsTxtAnalysisStatus,
    Ue4ssActivationLimits, Ue4ssDeclaredActivation, Ue4ssFileKind, Ue4ssInstallationStatus,
    Ue4ssInventoryLimits, Ue4ssLoaderIdentityLimits, Ue4ssLoaderIdentityStatus, Ue4ssLuaApi,
    Ue4ssModuleKind, analyze_ue4ss_activation, analyze_ue4ss_lua, inspect_ue4ss_loader_identity,
    inventory_ue4ss, read_game_relative_file, replace_game_relative_file,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};
#[cfg(not(unix))]
use sysinfo::Disks;

const INSTALLATION_ID: &str = "steam-3552140";
const UE4SS_LOADER_INSTALLATION_ID: &str = "steam-3552140-ue4ss-loader";
const TARGET_UE4SS_BUILD_ID: &str = "ue4ss-662df91503379fc383bc745f7ade795d7b2ca215";
const LOCAL_UE4SS_POLICY_ID: &str = "ue4ss:local-lua-supported";
const EXISTING_MODS_DIRECTORY: &str = "existing-mods";
const OPERATION_FAILURES_KEY: &str = "desktop.operation_failures";
const MAX_OPERATION_FAILURES: usize = 20;
const MAX_OPERATION_ERROR_CHARS: usize = 4_000;
const EXISTING_GROUP_OPERATIONS_DIRECTORY: &str = "existing-group-operations";
const BULK_DELETE_QUARANTINE_PREFIX: &str = "bulk-delete-quarantine-";
const BUILD_RECIPE_JSON: &str = include_str!("../../../recipes/builds/23896268.json");
const PACKAGE_CATALOG_JSON: &str = include_str!("../../../catalogs/packages/23896268.json");
const PRODUCTION_ROOTS_JSON: &str = include_str!("../../../trust/production-roots.json");
const SIGNED_ROOT_METADATA_JSON: &str = include_str!("../../../catalogs/signed/root-metadata.json");
const SIGNED_RECIPE_CATALOG_JSON: &str =
    include_str!("../../../catalogs/signed/recipe-catalog.json");
const RECIPE_CATALOG_CHANNEL: &str = "stable";
const EXTERNAL_MOD_GROUPS_JSON: &str =
    include_str!("../../../catalogs/external-groups/23896268.json");
const EXTERNAL_MOD_LINKS_JSON: &str =
    include_str!("../../../catalogs/external-links/23896268.json");
const UE4SS_LOADER_ARTIFACT_JSON: &str =
    include_str!("../../../catalogs/ue4ss-loader/23896268.json");
const DESKTOP_PREFERENCES_KEY: &str = "desktop.preferences.v1";
const SELECTED_GAME_ROOT_KEY: &str = "desktop.selected_game_root.v1";
const ADOPTED_EXTERNAL_MODS_KEY: &str = "desktop.adopted_external_mods.v1";
const ADOPTED_PACKAGE_CATALOG_KEY: &str = "desktop.adopted_package_catalog.v1";
const MAX_PENDING_IMPORT_REVIEWS: usize = 8;
const MAX_PENDING_ARCHIVE_PREFLIGHTS: usize = 64;
const MAX_PENDING_BULK_DELETES: usize = 16;
const ARCHIVE_INPUT_PREFIX: &str = "archive-input-";
const GIB: u64 = 1024 * 1024 * 1024;

fn desktop_archive_limits() -> ArchiveLimits {
    ArchiveLimits {
        max_archive_bytes: 8 * GIB,
        max_expanded_bytes: 32 * GIB,
        max_file_bytes: 16 * GIB,
        max_entries: 100_000,
        max_depth: 32,
        max_compression_ratio: 10_000,
    }
}

fn desktop_pak_limits() -> PakLimits {
    PakLimits {
        max_archive_bytes: 128 * GIB,
        max_index_bytes: 512 * 1024 * 1024,
        max_entries: 250_000,
        max_member_bytes: 32 * GIB,
    }
}

#[derive(Debug)]
struct ComputedDeployment {
    plan: Option<DeploymentPlan>,
    profile_id: String,
    profile_name: String,
    profile_revision: u64,
    build_id: u64,
    blockers: Vec<String>,
    unmanaged_count: usize,
    pak_conflicts: Vec<PakConflictView>,
    recipes: RecipePreviewView,
    disableable_package_ids: BTreeSet<String>,
    watched_files: Vec<FileSnapshot>,
}

#[derive(Debug, Clone)]
pub struct DesktopPaths {
    pub data_root: PathBuf,
    pub database: PathBuf,
    pub artifact_store: PathBuf,
    pub deployment_state: PathBuf,
    pub staging: PathBuf,
}

impl DesktopPaths {
    pub fn for_local_user() -> Result<Self> {
        let data_root = dirs::data_local_dir()
            .context("the local application data directory is unavailable")?
            .join("rr-mod-manager");
        Ok(Self::under(data_root))
    }

    pub fn under(data_root: PathBuf) -> Self {
        Self {
            database: data_root.join("rrmm.sqlite3"),
            artifact_store: data_root.join("store"),
            deployment_state: data_root.join("deployment"),
            staging: data_root.join("staging"),
            data_root,
        }
    }

    fn ensure(&self) -> Result<()> {
        for path in [
            &self.data_root,
            &self.artifact_store,
            &self.deployment_state,
            &self.staging,
        ] {
            fs::create_dir_all(path)
                .with_context(|| format!("failed to create {}", path.display()))?;
        }
        Ok(())
    }
}

pub struct DesktopApplication {
    paths: DesktopPaths,
    archive_worker: PathBuf,
    pak_worker: PathBuf,
    #[cfg(test)]
    deployment_build_recipe_override: Option<BuildRecipe>,
    pending_archives: Mutex<BTreeMap<String, PendingArchive>>,
    pending_import_reviews: Mutex<BTreeMap<String, PendingImportReview>>,
    previews: Mutex<BTreeMap<String, PendingPreview>>,
    pending_bulk_deletes: Mutex<BTreeMap<String, PendingBulkDelete>>,
    bug_report_previews: Mutex<BTreeMap<String, PendingBugReport>>,
    incident_markers: Mutex<Vec<IncidentMarkerView>>,
    operation_timings: Mutex<BTreeMap<String, u64>>,
    operation_contexts: Mutex<BTreeMap<String, OperationContext>>,
    mod_operations: Mutex<()>,
    nonce: AtomicU64,
}

#[derive(Debug, Clone)]
struct PendingArchive {
    snapshot: ArchiveSnapshot,
    report: ArchivePreflightReport,
}

#[derive(Debug, Clone)]
struct ArchiveSnapshot {
    source_path: PathBuf,
    root: PathBuf,
    archive_path: PathBuf,
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Clone)]
struct PendingImportReview {
    snapshot: ArchiveSnapshot,
    preflight: ArchivePreflightReport,
    extraction: ArchiveExtractionReport,
    manifest: ArtifactManifest,
    package_name: String,
    activation_supported: bool,
    conflict_review: ImportConflictReview,
    review_sha256: String,
    executable_acknowledgement_required: bool,
    in_progress: bool,
}

#[derive(Debug, Clone)]
struct PendingPreview {
    plan: DeploymentPlan,
    profile_id: String,
    profile_revision: u64,
    build_id: u64,
    allow_unmanaged: bool,
    package_blockers: Vec<String>,
    pak_conflicts: Vec<PakConflictView>,
    disableable_package_ids: BTreeSet<String>,
    watched_files: Vec<FileSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct FileSnapshot {
    path: PathBuf,
    state: FileSnapshotState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum FileSnapshotState {
    Absent,
    File(FileIdentity),
    Other,
}

#[derive(Debug, Clone)]
struct PendingBulkDelete {
    transaction_id: String,
    artifact_sha256: Vec<String>,
    external_mod_ids: Vec<String>,
    external_units: Vec<BulkDeleteExternalUnit>,
    profiles_before: Vec<DomainProfile>,
    profiles_after: Vec<DomainProfile>,
    artifacts: Vec<StoredArtifact>,
    installation: Option<rrmm_domain::InstallationInspection>,
    receipt: Option<DeploymentReceipt>,
    plan: Option<DeploymentPlan>,
    external_mods: Vec<ExistingModView>,
    requires_deployment: bool,
    blockers: Vec<BulkDeleteBlockerView>,
    evidence_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct BulkDeleteExternalUnit {
    group_id: Option<String>,
    member_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactQuarantineJournal {
    artifacts: Vec<ArtifactQuarantineEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactQuarantineEntry {
    sha256: String,
    original: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ActivationPakInput {
    read_path: PathBuf,
    effective_path: PathBuf,
    display_path: String,
    pak_sha256: String,
    destination: Option<String>,
    owner: ActivationPakOwner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ActivationPakOwner {
    display_name: String,
    package_id: Option<String>,
    source_kind: String,
    artifact_sha256: Option<String>,
    existing_mod_id: Option<String>,
    manageable: bool,
    original_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActivationPakAnalysis {
    blockers: Vec<String>,
    evidence_sha256: String,
    conflicts: Vec<PakConflictView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ImportConflictReview {
    conflict_check_complete: bool,
    pak_conflicts: Vec<PakConflictView>,
    destination_conflicts: Vec<ArchiveDestinationConflictView>,
    warnings: Vec<UiNoticeView>,
    blocked_reasons: Vec<UiNoticeView>,
    evidence_sha256: String,
}

struct ImportDestinationInspection<'a> {
    game_root: &'a Path,
    manifest: &'a ArtifactManifest,
    package: Option<&'a CatalogPackage>,
    package_name: &'a str,
    receipt: Option<&'a DeploymentReceipt>,
    catalog: &'a [CatalogPackage],
    artifact_store: &'a Path,
}

struct OperationTimer<'a> {
    timings: &'a Mutex<BTreeMap<String, u64>>,
    operation: &'static str,
    started: Instant,
}

#[derive(Debug, Clone)]
struct OperationContext {
    operation: String,
    stage: String,
    started: Instant,
    details: BTreeMap<String, serde_json::Value>,
    rollback: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationFailureView {
    pub occurred_at: String,
    pub operation: String,
    pub stage: String,
    pub duration_ms: u64,
    pub category: String,
    pub error: String,
    pub rollback: String,
    pub details: BTreeMap<String, serde_json::Value>,
}

impl<'a> OperationTimer<'a> {
    fn new(timings: &'a Mutex<BTreeMap<String, u64>>, operation: &'static str) -> Self {
        Self {
            timings,
            operation,
            started: Instant::now(),
        }
    }
}

impl Drop for OperationTimer<'_> {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        if let Ok(mut timings) = self.timings.lock() {
            timings.insert(self.operation.to_owned(), elapsed);
        }
    }
}

impl DesktopApplication {
    pub fn new(paths: DesktopPaths, archive_worker: PathBuf, pak_worker: PathBuf) -> Result<Self> {
        paths.ensure()?;
        cleanup_stale_import_review_staging(&paths.staging)?;
        let store = Store::open(&paths.database)?;
        recover_artifact_quarantines(&paths, &store)?;
        let artifacts = store.artifacts()?;
        cleanup_stored_source_archives(&paths, &artifacts)?;
        if !is_game_running() {
            recover_incomplete(&paths.deployment_state, is_game_running)
                .context("failed to recover an interrupted mod change")?;
            if let Some((_, game_root)) = store.installation_binding(INSTALLATION_ID)? {
                reconcile_disabled_marker_aliases(
                    &paths.deployment_state,
                    INSTALLATION_ID,
                    &game_root,
                )
                .context("failed to reconcile disabled UE4SS markers")?;
            }
        }
        cleanup_unreferenced_backups(
            &paths.deployment_state,
            &selected_artifact_file_hashes(&artifacts)?,
        )?;
        Ok(Self {
            paths,
            archive_worker,
            pak_worker,
            #[cfg(test)]
            deployment_build_recipe_override: None,
            pending_archives: Mutex::new(BTreeMap::new()),
            pending_import_reviews: Mutex::new(BTreeMap::new()),
            previews: Mutex::new(BTreeMap::new()),
            pending_bulk_deletes: Mutex::new(BTreeMap::new()),
            bug_report_previews: Mutex::new(BTreeMap::new()),
            incident_markers: Mutex::new(Vec::new()),
            operation_timings: Mutex::new(BTreeMap::new()),
            operation_contexts: Mutex::new(BTreeMap::new()),
            mod_operations: Mutex::new(()),
            nonce: AtomicU64::new(1),
        })
    }

    pub fn paths(&self) -> &DesktopPaths {
        &self.paths
    }

    pub fn begin_operation(&self, operation_id: &str, operation: &str) {
        if let Ok(mut contexts) = self.operation_contexts.lock() {
            contexts.insert(
                operation_id.to_owned(),
                OperationContext {
                    operation: operation.to_owned(),
                    stage: "started".to_owned(),
                    started: Instant::now(),
                    details: BTreeMap::new(),
                    rollback: "not_required".to_owned(),
                },
            );
        }
    }

    pub fn complete_operation(&self, operation_id: &str) {
        if let Ok(mut contexts) = self.operation_contexts.lock() {
            contexts.remove(operation_id);
        }
    }

    pub fn fail_operation(&self, operation_id: &str, error: &anyhow::Error) {
        let context = self
            .operation_contexts
            .lock()
            .ok()
            .and_then(|mut contexts| contexts.remove(operation_id));
        let context = context.unwrap_or_else(|| OperationContext {
            operation: "unknown".to_owned(),
            stage: "unknown".to_owned(),
            started: Instant::now(),
            details: BTreeMap::new(),
            rollback: "not_required".to_owned(),
        });
        let message = truncate_chars(
            &redact_sensitive_text(&format!("{error:#}")),
            MAX_OPERATION_ERROR_CHARS,
        );
        let failure = OperationFailureView {
            occurred_at: now(),
            operation: context.operation,
            stage: context.stage,
            duration_ms: context.started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            category: operation_error_category(&message),
            error: message,
            rollback: context.rollback,
            details: context
                .details
                .into_iter()
                .map(|(key, value)| (key, redact_json_value(value)))
                .collect(),
        };
        let _ = self.persist_operation_failure(failure);
    }

    pub fn operation_failure_count(&self) -> Result<usize> {
        Ok(self.operation_failures()?.len())
    }

    pub fn clear_diagnostic_history(&self) -> Result<usize> {
        let store = self.store()?;
        let count = operation_failures(&store)?.len();
        store.set_setting(OPERATION_FAILURES_KEY, &serde_json::json!([]))?;
        self.operation_timings
            .lock()
            .expect("operation timings mutex")
            .clear();
        Ok(count)
    }

    fn operation_stage(&self, operation: &str, stage: &str) {
        if let Ok(mut contexts) = self.operation_contexts.lock()
            && let Some(context) = contexts
                .values_mut()
                .find(|item| item.operation == operation)
        {
            context.stage = stage.to_owned();
        }
    }

    fn operation_detail(&self, operation: &str, key: &str, value: serde_json::Value) {
        if let Ok(mut contexts) = self.operation_contexts.lock()
            && let Some(context) = contexts
                .values_mut()
                .find(|item| item.operation == operation)
        {
            context.details.insert(key.to_owned(), value);
        }
    }

    fn operation_rollback(&self, operation: &str, rollback: &str) {
        if let Ok(mut contexts) = self.operation_contexts.lock()
            && let Some(context) = contexts
                .values_mut()
                .find(|item| item.operation == operation)
        {
            context.rollback = rollback.to_owned();
        }
    }

    fn operation_failures(&self) -> Result<Vec<OperationFailureView>> {
        operation_failures(&self.store()?)
    }

    fn persist_operation_failure(&self, failure: OperationFailureView) -> Result<()> {
        let store = self.store()?;
        let mut failures = operation_failures(&store)?;
        failures.push(failure);
        if failures.len() > MAX_OPERATION_FAILURES {
            failures.drain(..failures.len() - MAX_OPERATION_FAILURES);
        }
        store.set_setting(OPERATION_FAILURES_KEY, &serde_json::to_value(failures)?)?;
        Ok(())
    }

    pub fn bootstrap(&self) -> Result<AppSnapshot> {
        let _timing = OperationTimer::new(&self.operation_timings, "bootstrap");
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        self.recover_automatically()?;
        if self.installation_discovery_required()? {
            self.refresh_installations()?;
        }
        self.ensure_default_profile()?;
        self.consolidate_inactive_artifact_revisions()?;
        self.snapshot()
    }

    pub fn refresh_snapshot(&self) -> Result<AppSnapshot> {
        let _timing = OperationTimer::new(&self.operation_timings, "refreshSnapshot");
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        self.recover_automatically()?;
        if self.installation_discovery_required()? {
            self.refresh_installations()?;
        }
        self.snapshot()
    }

    pub fn rediscover_game_installation(&self) -> Result<AppSnapshot> {
        let _timing = OperationTimer::new(&self.operation_timings, "rediscoverGameInstallation");
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        self.recover_automatically()?;
        self.refresh_installations()?;
        self.snapshot()
    }

    fn installation_discovery_required(&self) -> Result<bool> {
        let installations = self.store()?.installations()?;
        Ok(installations.is_empty()
            || installations.iter().all(|installation| {
                !installation.installation.manifest_path.is_file()
                    || !installation.installation.game_root.is_dir()
            }))
    }

    fn recover_automatically(&self) -> Result<()> {
        if !is_game_running() {
            recover_incomplete(&self.paths.deployment_state, is_game_running)
                .context("failed to recover an interrupted mod change")?;
        }
        Ok(())
    }

    fn consolidate_inactive_artifact_revisions(&self) -> Result<()> {
        let store = self.store()?;
        let artifacts = store.artifacts()?;
        let authored = authored_package_catalog()?;
        let active_enabled = store
            .active_profile(INSTALLATION_ID)?
            .map(|profile| {
                profile
                    .packages
                    .into_iter()
                    .filter(|package| package.enabled)
                    .map(|package| package.artifact_sha256)
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        let deployed_files = load_receipt(&self.paths.deployment_state, INSTALLATION_ID)?
            .into_iter()
            .flat_map(|receipt| {
                receipt
                    .files
                    .into_iter()
                    .map(|file| (file.relative_path, file.sha256))
            })
            .collect::<BTreeSet<_>>();
        drop(store);

        for group in artifact_revision_groups(&artifacts, &authored)? {
            let newest_accepted_at = group
                .iter()
                .map(|artifact| artifact.accepted_at)
                .max()
                .context("artifact revision group is empty")?;
            let mut newest_candidates = group
                .iter()
                .filter(|artifact| artifact.accepted_at == newest_accepted_at);
            let Some(newest) = newest_candidates.next() else {
                continue;
            };
            if newest_candidates.next().is_some() {
                continue;
            }
            if group.iter().any(|artifact| {
                artifact.sha256 != newest.sha256 && active_enabled.contains(&artifact.sha256)
            }) {
                continue;
            }
            let manifest: ArtifactManifest = serde_json::from_value(newest.manifest.clone())?;
            let newest_deployed_files =
                planned_import_destinations(&manifest, inferred_local_package(&manifest).is_some())
                    .into_iter()
                    .filter_map(|(source, destination)| {
                        manifest
                            .files
                            .iter()
                            .find(|file| file.path == source)
                            .map(|file| (destination, file.sha256.clone()))
                    })
                    .collect::<BTreeSet<_>>();
            let group_deployed_files = group
                .iter()
                .map(|artifact| {
                    serde_json::from_value::<ArtifactManifest>(artifact.manifest.clone())
                })
                .collect::<std::result::Result<Vec<_>, _>>()?
                .iter()
                .flat_map(|artifact| {
                    planned_import_destinations(
                        artifact,
                        inferred_local_package(artifact).is_some(),
                    )
                    .into_iter()
                    .filter_map(|(source, destination)| {
                        artifact
                            .files
                            .iter()
                            .find(|file| file.path == source)
                            .map(|file| (destination, file.sha256.clone()))
                    })
                    .collect::<Vec<_>>()
                })
                .collect::<BTreeSet<_>>();
            if group_deployed_files
                .iter()
                .any(|file| deployed_files.contains(file))
                && !newest_deployed_files
                    .iter()
                    .all(|file| deployed_files.contains(file))
            {
                continue;
            }
            let package_name = authored
                .iter()
                .find(|package| package.artifact_sha256 == newest.sha256)
                .map(|package| package.manifest.name.clone())
                .unwrap_or_else(|| local_package_name(&manifest));
            self.commit_imported_artifact_revision(
                &rrmm_artifacts::AcceptedArtifact {
                    root: newest.root.clone(),
                    duplicate: true,
                    manifest,
                },
                &package_name,
            )?;
        }
        Ok(())
    }

    pub fn preflight_archive(&self, path: &Path) -> Result<ArchivePreflightView> {
        let source_path = fs::canonicalize(path)
            .with_context(|| format!("failed to resolve archive {}", path.display()))?;
        if !fs::metadata(&source_path)?.is_file() {
            bail!("selected archive is not a regular file");
        }
        let token = self.token("archive");
        let mut snapshot =
            create_archive_snapshot(&self.paths, &source_path, &token, &desktop_archive_limits())?;
        snapshot.source_path = path.to_path_buf();
        let result = (|| {
            let response = self.run_archive_worker(ArchiveWorkerRequest::Preflight {
                archive: snapshot.archive_path.clone(),
                limits: desktop_archive_limits(),
            })?;
            let report = response
                .preflight
                .context("archive worker returned no preflight report")?;
            verify_archive_snapshot_report(&snapshot, &report)?;
            let view = archive_preflight_view(
                token.clone(),
                &report,
                &snapshot.source_path,
                None,
                Vec::new(),
                false,
            );
            if report.accepted {
                let mut pending_archives =
                    self.pending_archives.lock().expect("pending archive mutex");
                while pending_archives.len() >= MAX_PENDING_ARCHIVE_PREFLIGHTS {
                    if let Some((_, evicted)) = pending_archives.pop_first() {
                        remove_archive_snapshot(&evicted.snapshot)?;
                    }
                }
                pending_archives.insert(
                    token.clone(),
                    PendingArchive {
                        snapshot: snapshot.clone(),
                        report,
                    },
                );
            }
            Ok(view)
        })();
        let retained = self
            .pending_archives
            .lock()
            .expect("pending archive mutex")
            .contains_key(&token);
        if !retained {
            let _ = remove_archive_snapshot(&snapshot);
        }
        result
    }

    pub fn review_archive(&self, preflight_token: &str) -> Result<ArchiveImportReviewView> {
        let pending = self
            .pending_archives
            .lock()
            .expect("pending archive mutex")
            .remove(preflight_token)
            .context("archive preflight expired; select the archive again")?;
        let review_token = self.token("archive-review");
        let staging = self.paths.staging.join(&review_token);
        let result = (|| {
            if !pending.report.accepted {
                bail!("a rejected archive cannot be reviewed");
            }
            verify_archive_snapshot(&pending.snapshot)?;
            ensure_import_disk_space(&self.paths, &pending.report, &pending.snapshot.sha256)?;
            if staging.exists() {
                bail!("private review staging already exists");
            }
            let extraction = self
                .run_archive_worker(ArchiveWorkerRequest::Extract {
                    archive: pending.snapshot.archive_path.clone(),
                    staging: staging.clone(),
                    limits: desktop_archive_limits(),
                })?
                .extraction
                .context("archive worker returned no extraction report")?;
            if extraction.staging_root != staging {
                bail!("archive worker returned an unexpected staging path");
            }
            if extraction.archive_sha256 != pending.snapshot.sha256 {
                bail!("archive bytes changed between preflight and extraction");
            }
            let manifest = preview_artifact_manifest(
                &pending.snapshot.archive_path,
                &extraction,
                &desktop_archive_limits(),
            )?;
            let package = inferred_local_package(&manifest);
            let package_name = package
                .as_ref()
                .map(|package| package.manifest.name.clone())
                .unwrap_or_else(|| local_package_name(&manifest));
            let activation_supported = package.is_some();
            let executable_acknowledgement_required = manifest
                .files
                .iter()
                .any(|file| file.executable_payload || file.native_binary);
            let conflict_review = self.inspect_import_conflicts(
                &extraction,
                &manifest,
                package.as_ref(),
                &package_name,
                activation_supported,
            );
            let mut review = PendingImportReview {
                snapshot: pending.snapshot.clone(),
                preflight: pending.report.clone(),
                extraction,
                manifest,
                package_name,
                activation_supported,
                conflict_review,
                review_sha256: String::new(),
                executable_acknowledgement_required,
                in_progress: false,
            };
            review.review_sha256 = archive_import_review_sha256(&review_token, &review)?;
            let view = archive_import_review_view(&review_token, &review);
            self.insert_pending_import_review(review_token, review)?;
            Ok(view)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(staging);
            let _ = remove_archive_snapshot(&pending.snapshot);
        }
        result
    }

    pub fn import_reviewed_archive(
        &self,
        review_token: &str,
        confirmation: ImportArchiveConfirmationView,
    ) -> Result<ImportResult> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        let pending = {
            let mut reviews = self
                .pending_import_reviews
                .lock()
                .expect("pending import review mutex");
            let pending = reviews
                .get_mut(review_token)
                .context("archive import review expired; review the archive again")?;
            if confirmation.review_sha256 != pending.review_sha256 {
                bail!("archive import confirmation does not match the reviewed content");
            }
            if pending.executable_acknowledgement_required
                && !confirmation.executable_payloads_acknowledged
            {
                bail!("executable or native payload acknowledgement is required");
            }
            if pending.in_progress {
                bail!("archive import is already in progress");
            }
            pending.in_progress = true;
            pending.clone()
        };

        let result = (|| {
            let current_hash = rrmm_archive::sha256_path(&pending.snapshot.archive_path)?;
            if pending.preflight.archive_sha256.as_deref() != Some(current_hash.as_str())
                || pending.extraction.archive_sha256 != current_hash
                || pending.snapshot.sha256 != current_hash
            {
                bail!("archive bytes changed after review");
            }
            let current_manifest = preview_artifact_manifest(
                &pending.snapshot.archive_path,
                &pending.extraction,
                &desktop_archive_limits(),
            )?;
            if current_manifest != pending.manifest {
                bail!("archive extraction changed after review");
            }
            if !pending.conflict_review.conflict_check_complete {
                bail!("archive conflict analysis was incomplete; review the archive again");
            }
            let current_package = inferred_local_package(&current_manifest);
            let current_conflict_review = self.inspect_import_conflicts(
                &pending.extraction,
                &current_manifest,
                current_package.as_ref(),
                &pending.package_name,
                pending.activation_supported,
            );
            if current_conflict_review != pending.conflict_review {
                bail!("installation or PAK conflict evidence changed after review");
            }
            let current_review_sha256 = archive_import_review_sha256(review_token, &pending)?;
            if current_review_sha256 != pending.review_sha256 {
                bail!("archive review content changed after confirmation");
            }
            let accepted = accept_artifact(
                &pending.snapshot.archive_path,
                &pending.extraction,
                &self.paths.artifact_store,
                &desktop_archive_limits(),
            )?;
            self.commit_imported_artifact_revision(&accepted, &pending.package_name)
        })();

        let mut reviews = self
            .pending_import_reviews
            .lock()
            .expect("pending import review mutex");
        if result.is_ok() {
            reviews.remove(review_token);
            let _ = fs::remove_dir_all(&pending.extraction.staging_root);
            let _ = remove_archive_snapshot(&pending.snapshot);
        } else if !pending.extraction.staging_root.exists() {
            reviews.remove(review_token);
            let _ = remove_archive_snapshot(&pending.snapshot);
        } else if let Some(current) = reviews.get_mut(review_token)
            && current.review_sha256 == pending.review_sha256
        {
            current.in_progress = false;
        }
        result
    }

    pub fn adopt_existing_mod(&self, mod_id: &str) -> Result<ImportResult> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        if is_game_running() {
            bail!("Retro Rewind is running; close the game before adopting an installed mod");
        }
        let store = self.store()?;
        let installation = selected_installation(&store)?
            .context("no inventoried Retro Rewind Steam installation is available")?;
        let receipt = load_receipt(&self.paths.deployment_state, INSTALLATION_ID)?;
        let existing = existing_mod_views(
            &installation.installation.game_root,
            &self.paths.deployment_state,
            receipt.as_ref(),
        )?;
        let selected = existing
            .iter()
            .find(|item| item.id == mod_id)
            .with_context(|| format!("installed mod '{mod_id}' is no longer available"))?;
        let members = if let Some(group_id) = &selected.group_id {
            existing
                .iter()
                .filter(|item| item.group_id.as_ref() == Some(group_id))
                .collect::<Vec<_>>()
        } else {
            vec![selected]
        };
        if members.iter().any(|item| {
            !item.enabled
                || !item.manageable
                || item.related_paths.is_empty()
                || item.mod_type == "ue4ss_link"
        }) {
            bail!("only active regular PAK and UE4SS mods can be adopted into the library");
        }

        let token = self.token("adopt");
        let archive = self.paths.staging.join(format!("{token}.zip"));
        let extraction_root = self.paths.staging.join(format!("{token}-files"));
        let result = (|| {
            write_existing_mod_adoption_archive(
                &installation.installation.game_root,
                &archive,
                &members,
            )?;
            let report = self
                .run_archive_worker(ArchiveWorkerRequest::Preflight {
                    archive: archive.clone(),
                    limits: desktop_archive_limits(),
                })?
                .preflight
                .context("archive worker returned no adoption preflight report")?;
            if !report.accepted {
                bail!("the installed mod could not be represented as a safe RRMM package");
            }
            let extraction = self
                .run_archive_worker(ArchiveWorkerRequest::Extract {
                    archive: archive.clone(),
                    staging: extraction_root.clone(),
                    limits: desktop_archive_limits(),
                })?
                .extraction
                .context("archive worker returned no adoption extraction report")?;
            let manifest =
                preview_artifact_manifest(&archive, &extraction, &desktop_archive_limits())?;
            let package = inferred_local_package(&manifest)
                .context("the installed mod layout cannot be activated through profiles")?;
            let accepted = accept_artifact(
                &archive,
                &extraction,
                &self.paths.artifact_store,
                &desktop_archive_limits(),
            )?;
            let imported =
                self.commit_imported_artifact_revision(&accepted, &package.manifest.name)?;
            if let Some(group_id) = selected.group_id.as_deref()
                && let Some(group) = external_mod_groups()?.into_iter().find(|group| {
                    format!("reviewed:{}:{}", group.package_id, group.version) == group_id
                })
                && let Some(mut reviewed) = authored_package_catalog()?.into_iter().find(|item| {
                    item.manifest.id == group.package_id && item.manifest.version == group.version
                })
            {
                reviewed.artifact_sha256 = imported.artifact_sha256.clone();
                let mut local_catalog = adopted_package_catalog(&store)?;
                local_catalog.retain(|item| item.artifact_sha256 != imported.artifact_sha256);
                local_catalog.push(reviewed);
                store.set_setting(
                    ADOPTED_PACKAGE_CATALOG_KEY,
                    &serde_json::to_value(local_catalog)?,
                )?;
            }
            let mut selected_profile = store
                .active_profile(INSTALLATION_ID)?
                .context("no profile is selected")?;
            let catalog = effective_package_catalog(&store, &self.paths.artifact_store)?;
            update_profile_selection(
                &mut selected_profile,
                &imported.artifact_sha256,
                true,
                &catalog,
            );
            let mut adopted = adopted_external_mods(&store)?;
            for member in &members {
                adopted.insert(member.id.clone(), imported.artifact_sha256.clone());
            }
            store.set_setting(ADOPTED_EXTERNAL_MODS_KEY, &serde_json::to_value(adopted)?)?;
            let revision = selected_profile.revision;
            store.update_profile(&selected_profile, revision)?;
            Ok(imported)
        })();
        let _ = fs::remove_file(&archive);
        let _ = fs::remove_dir_all(&extraction_root);
        result
    }

    fn commit_imported_artifact_revision(
        &self,
        accepted: &rrmm_artifacts::AcceptedArtifact,
        package_name: &str,
    ) -> Result<ImportResult> {
        let mut store = self.store()?;
        cache_accepted_artifact_files(&store, accepted)?;
        let stored_before = store.artifacts()?;
        let authored = authored_package_catalog()?;
        let mut replaced = Vec::new();
        for artifact in stored_before
            .iter()
            .filter(|artifact| artifact.sha256 != accepted.manifest.sha256)
        {
            let manifest: ArtifactManifest = serde_json::from_value(artifact.manifest.clone())?;
            if artifact_revisions_match(&accepted.manifest, &manifest, &authored) {
                replaced.push(artifact.clone());
            }
        }
        if replaced.is_empty() {
            store.upsert_artifact(
                &accepted.manifest.sha256,
                &accepted.root,
                &serde_json::to_value(&accepted.manifest)?,
            )?;
            return Ok(ImportResult {
                artifact_sha256: accepted.manifest.sha256.clone(),
                package_name: package_name.to_owned(),
            });
        }

        for artifact in &replaced {
            validate_stored_artifact_root(&self.paths, artifact)?;
        }
        let replaced_sha256 = replaced
            .iter()
            .map(|artifact| artifact.sha256.clone())
            .collect::<BTreeSet<_>>();
        let profiles_before = store.profiles()?;
        let replacement_package = authored
            .iter()
            .find(|package| package.artifact_sha256 == accepted.manifest.sha256);
        let mut profiles_after = profiles_before.clone();
        for profile in &mut profiles_after {
            replace_profile_artifact_revisions(
                profile,
                &replaced_sha256,
                &accepted.manifest.sha256,
                replacement_package,
            );
        }
        let removed_pak_hashes = artifact_pak_hashes(&replaced)?
            .difference(&artifact_pak_hashes(
                &stored_before
                    .iter()
                    .filter(|artifact| !replaced_sha256.contains(&artifact.sha256))
                    .cloned()
                    .chain(std::iter::once(StoredArtifact {
                        sha256: accepted.manifest.sha256.clone(),
                        root: accepted.root.clone(),
                        manifest: serde_json::to_value(&accepted.manifest)?,
                        accepted_at: 0,
                    }))
                    .collect::<Vec<_>>(),
            )?)
            .cloned()
            .collect::<BTreeSet<_>>();
        for profile in &mut profiles_after {
            profile.pak_load_order.retain(|preference| {
                !removed_pak_hashes.contains(&preference.first_pak_sha256)
                    && !removed_pak_hashes.contains(&preference.second_pak_sha256)
                    && !removed_pak_hashes.contains(&preference.winner_pak_sha256)
            });
        }
        let profile_updates = profiles_after
            .iter()
            .zip(&profiles_before)
            .filter(|(after, before)| {
                after.packages != before.packages || after.pak_load_order != before.pak_load_order
            })
            .map(|(after, before)| (after.clone(), before.revision))
            .collect::<Vec<_>>();

        let new_record = StoredArtifact {
            sha256: accepted.manifest.sha256.clone(),
            root: accepted.root.clone(),
            manifest: serde_json::to_value(&accepted.manifest)?,
            accepted_at: 0,
        };
        let _updated_profiles =
            match store.replace_artifacts_and_update_profiles(&[new_record], &[], &profile_updates)
            {
                Ok(profiles) => profiles,
                Err(error) => {
                    if !accepted.duplicate {
                        let _ = fs::remove_dir_all(&accepted.root);
                    }
                    return Err(error.into());
                }
            };

        let _ = self.cleanup_superseded_artifacts(&mut store, &replaced);
        self.previews.lock().expect("preview mutex").clear();
        Ok(ImportResult {
            artifact_sha256: accepted.manifest.sha256.clone(),
            package_name: package_name.to_owned(),
        })
    }

    fn cleanup_superseded_artifacts(
        &self,
        store: &mut Store,
        artifacts: &[StoredArtifact],
    ) -> Result<()> {
        let quarantine = self
            .paths
            .staging
            .join(self.token(BULK_DELETE_QUARANTINE_PREFIX.trim_end_matches('-')));
        fs::create_dir(&quarantine)?;
        if let Err(error) = write_artifact_quarantine_journal(&quarantine, artifacts) {
            let _ = fs::remove_dir_all(&quarantine);
            return Err(error);
        }
        let mut quarantined = Vec::new();
        for artifact in artifacts {
            let destination = quarantine.join(&artifact.sha256);
            if let Err(error) = fs::rename(&artifact.root, &destination) {
                rollback_artifact_quarantine(&quarantined)?;
                let _ = fs::remove_dir_all(&quarantine);
                return Err(error).with_context(|| {
                    format!(
                        "failed to quarantine superseded artifact {}",
                        artifact.sha256
                    )
                });
            }
            quarantined.push((destination, artifact.root.clone()));
        }
        let deleted = artifacts
            .iter()
            .map(|artifact| artifact.sha256.clone())
            .collect::<Vec<_>>();
        if let Err(error) = store.delete_artifacts_without_profile_references(&deleted) {
            rollback_artifact_quarantine(&quarantined)?;
            let _ = fs::remove_dir_all(&quarantine);
            return Err(error.into());
        }
        fs::remove_dir_all(quarantine)?;
        Ok(())
    }

    pub fn discard_archive_review(&self, review_token: &str) -> Result<()> {
        let mut reviews = self
            .pending_import_reviews
            .lock()
            .expect("pending import review mutex");
        let pending = reviews
            .get(review_token)
            .context("archive import review expired or is invalid")?;
        if pending.in_progress {
            bail!("archive import is already in progress");
        }
        remove_review_staging(&pending.extraction.staging_root)?;
        remove_archive_snapshot(&pending.snapshot)?;
        reviews.remove(review_token);
        Ok(())
    }

    fn insert_pending_import_review(
        &self,
        token: String,
        pending: PendingImportReview,
    ) -> Result<()> {
        let mut reviews = self
            .pending_import_reviews
            .lock()
            .expect("pending import review mutex");
        while reviews.len() >= MAX_PENDING_IMPORT_REVIEWS {
            let evicted_token = reviews
                .iter()
                .filter(|(_, review)| !review.in_progress)
                .min_by_key(|(token, _)| {
                    token
                        .rsplit('-')
                        .next()
                        .and_then(|nonce| nonce.parse::<u64>().ok())
                        .unwrap_or(u64::MAX)
                })
                .map(|(token, _)| token.clone())
                .context("too many archive imports are currently in progress")?;
            let evicted = reviews
                .get(&evicted_token)
                .expect("eviction candidate came from the review map");
            remove_review_staging(&evicted.extraction.staging_root)?;
            remove_archive_snapshot(&evicted.snapshot)?;
            reviews.remove(&evicted_token);
        }
        reviews.insert(token, pending);
        Ok(())
    }

    pub fn create_profile(&self, name: &str) -> Result<ProfileView> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        let name = validate_desktop_profile_name(name)?;
        let profile = DomainProfile {
            schema_version: 1,
            id: self.token("profile"),
            name: name.to_owned(),
            revision: 0,
            packages: Vec::new(),
            pak_load_order: Vec::new(),
        };
        let store = self.store()?;
        store.create_profile(&profile)?;
        self.previews.lock().expect("preview mutex").clear();
        Ok(profile_view(&profile))
    }

    pub fn clone_profile(&self, source_id: &str, name: &str) -> Result<ProfileView> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        let name = validate_desktop_profile_name(name)?;
        let store = self.store()?;
        let cloned = store.clone_profile(source_id, &self.token("profile"), name)?;
        self.previews.lock().expect("preview mutex").clear();
        Ok(profile_view(&cloned))
    }

    pub fn rename_profile(&self, profile_id: &str, name: &str) -> Result<ProfileView> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        let name = validate_desktop_profile_name(name)?;
        let store = self.store()?;
        let mut profile = store
            .profile(profile_id)?
            .with_context(|| format!("profile '{profile_id}' does not exist"))?;
        let revision = profile.revision;
        profile.name = name.to_owned();
        let updated = store.update_profile(&profile, revision)?;
        self.previews.lock().expect("preview mutex").clear();
        Ok(profile_view(&updated))
    }

    #[cfg(test)]
    pub fn update_profile_package(
        &self,
        profile_id: &str,
        artifact_sha256: &str,
        enabled: bool,
    ) -> Result<ProfileView> {
        self.set_profile_mods_enabled(profile_id, &[artifact_sha256.to_owned()], enabled)
    }

    pub fn set_profile_mods_enabled(
        &self,
        profile_id: &str,
        artifact_sha256: &[String],
        enabled: bool,
    ) -> Result<ProfileView> {
        let _timing = OperationTimer::new(&self.operation_timings, "setProfileModsEnabled");
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        if artifact_sha256.is_empty() {
            bail!("select at least one managed mod");
        }
        let store = self.store()?;
        let active = store
            .active_profile(INSTALLATION_ID)?
            .context("no active profile is selected")?;
        if active.id != profile_id {
            bail!("the selected profile is no longer active");
        }
        let catalog = effective_package_catalog(&store, &self.paths.artifact_store)?;
        let mut updated = active.clone();
        let normalized = artifact_sha256
            .iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        if normalized.iter().any(|sha256| !is_sha256(sha256)) {
            bail!("a selected managed mod has an invalid identity");
        }
        for sha256 in &normalized {
            if store.artifact(sha256)?.is_none() {
                bail!("a selected managed mod is no longer installed");
            }
            if enabled
                && !catalog
                    .iter()
                    .any(|package| package.artifact_sha256 == *sha256)
            {
                bail!("a selected mod cannot be activated safely");
            }
            update_profile_selection(&mut updated, sha256, enabled, &catalog);
        }
        let updated = if updated.packages != active.packages {
            store.update_profile(&updated, active.revision)?
        } else {
            active
        };
        self.previews.lock().expect("preview mutex").clear();
        Ok(profile_view(&updated))
    }

    pub fn set_pak_conflict_winner(
        &self,
        preview_id: &str,
        conflict_id: &str,
        winner_pak_sha256: &str,
    ) -> Result<ProfileView> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        let pending = self
            .previews
            .lock()
            .expect("preview mutex")
            .get(preview_id)
            .cloned()
            .context("activation preview expired; generate a fresh preview")?;
        let conflict = pending
            .pak_conflicts
            .iter()
            .find(|conflict| conflict.conflict_id == conflict_id)
            .context("PAK conflict is not part of the reviewed preview")?;
        if conflict.outcome == "benign_duplicate" {
            bail!("a benign duplicate does not require a load winner");
        }
        let (first, second) =
            canonical_pak_pair(&conflict.first.pak_sha256, &conflict.second.pak_sha256)?;
        let winner_pak_sha256 = validate_pak_winner(&first, &second, winner_pak_sha256)?;

        let store = self.store()?;
        let installation = selected_installation(&store)?
            .context("no inventoried Retro Rewind Steam installation is available")?;
        if installation.installation.build_id != pending.build_id {
            bail!("game build changed after the reviewed preview");
        }
        let mut profile = store
            .active_profile(INSTALLATION_ID)?
            .context("no active profile is selected")?;
        if profile.id != pending.profile_id || profile.revision != pending.profile_revision {
            bail!("active profile changed after the reviewed preview");
        }
        profile.pak_load_order.retain(|preference| {
            preference.build_id != pending.build_id
                || canonical_pak_pair(&preference.first_pak_sha256, &preference.second_pak_sha256)
                    .ok()
                    .as_ref()
                    != Some(&(first.clone(), second.clone()))
        });
        profile.pak_load_order.push(PakLoadOrderPreference {
            build_id: pending.build_id,
            first_pak_sha256: first,
            second_pak_sha256: second,
            winner_pak_sha256,
        });
        profile.pak_load_order.sort_by(|left, right| {
            left.build_id
                .cmp(&right.build_id)
                .then_with(|| left.first_pak_sha256.cmp(&right.first_pak_sha256))
                .then_with(|| left.second_pak_sha256.cmp(&right.second_pak_sha256))
        });
        validate_preview_pak_preferences(
            pending.build_id,
            &profile.pak_load_order,
            &pending.pak_conflicts,
        )?;
        let updated = store.update_profile(&profile, pending.profile_revision)?;
        self.previews.lock().expect("preview mutex").clear();
        Ok(profile_view(&updated))
    }

    pub fn set_pak_load_order(
        &self,
        preview_id: &str,
        ordered_pak_sha256: &[String],
    ) -> Result<ProfileView> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        let pending = self
            .previews
            .lock()
            .expect("preview mutex")
            .get(preview_id)
            .cloned()
            .context("activation preview expired; generate a fresh preview")?;
        let store = self.store()?;
        let installation = selected_installation(&store)?
            .context("no inventoried Retro Rewind Steam installation is available")?;
        if installation.installation.build_id != pending.build_id {
            bail!("game build changed after the reviewed preview");
        }
        let mut profile = store
            .active_profile(INSTALLATION_ID)?
            .context("no active profile is selected")?;
        if profile.id != pending.profile_id || profile.revision != pending.profile_revision {
            bail!("active profile changed after the reviewed preview");
        }
        apply_profile_pak_load_order(
            &mut profile,
            pending.build_id,
            &pending.pak_conflicts,
            ordered_pak_sha256,
        )?;
        validate_preview_pak_preferences(
            pending.build_id,
            &profile.pak_load_order,
            &pending.pak_conflicts,
        )?;
        let updated = store.update_profile(&profile, pending.profile_revision)?;
        self.previews.lock().expect("preview mutex").clear();
        Ok(profile_view(&updated))
    }

    pub fn remove_blocking_ue4ss_link(&self, preview_id: &str, relative_path: &str) -> Result<()> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        if is_game_running() {
            bail!("Retro Rewind is running; close the game before changing installed mods");
        }
        if pending_recovery(&self.paths.deployment_state)? {
            bail!("restore the interrupted deployment before changing installed mods");
        }
        let pending = self
            .previews
            .lock()
            .expect("preview mutex")
            .get(preview_id)
            .cloned()
            .context("activation preview expired; generate a fresh preview")?;
        let links = blocking_link_views(&pending.plan)?;
        if !links.iter().any(|link| link.relative_path == relative_path) {
            bail!("filesystem link is not part of the reviewed activation preview");
        }
        remove_reviewed_filesystem_link(&pending.plan.game_root, relative_path)?;
        self.previews.lock().expect("preview mutex").clear();
        Ok(())
    }

    pub fn delete_artifact(&self, artifact_sha256: &str) -> Result<()> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        if artifact_sha256.len() != 64
            || !artifact_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            bail!("invalid artifact SHA-256");
        }
        if pending_recovery(&self.paths.deployment_state)? {
            bail!("restore the interrupted deployment before deleting a managed mod");
        }
        let mut store = self.store()?;
        let artifact = store
            .artifacts()?
            .into_iter()
            .find(|artifact| artifact.sha256 == artifact_sha256)
            .with_context(|| format!("artifact '{artifact_sha256}' is not in the local store"))?;
        let manifest: ArtifactManifest = serde_json::from_value(artifact.manifest.clone())?;
        let profiles = store.profiles()?;
        let receipt = load_receipt(&self.paths.deployment_state, INSTALLATION_ID)?;
        if let Some(blocker) =
            artifact_deletion_blocker(artifact_sha256, &manifest, &profiles, receipt.as_ref())
        {
            match blocker {
                "enabled_in_profile" => {
                    bail!("disable this mod in every profile before deleting it")
                }
                "deployed" => bail!(
                    "apply the profile after disabling this mod so its deployed files are removed before deletion"
                ),
                _ => bail!("the managed mod cannot be deleted safely"),
            }
        }
        let expected_root = self
            .paths
            .artifact_store
            .join("artifacts")
            .join(&artifact_sha256[..2])
            .join(artifact_sha256);
        if artifact.root != expected_root {
            bail!("artifact store path does not match its content address");
        }
        let metadata = fs::symlink_metadata(&artifact.root).with_context(|| {
            format!("artifact directory {} is missing", artifact.root.display())
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("artifact store entry is not a regular directory");
        }
        let quarantine = self
            .paths
            .staging
            .join(self.token("delete-managed-artifact"));
        fs::rename(&artifact.root, &quarantine).with_context(|| {
            format!(
                "failed to quarantine managed artifact {}",
                artifact.root.display()
            )
        })?;
        if let Err(error) = store.delete_artifact_and_profile_references(artifact_sha256) {
            fs::rename(&quarantine, &artifact.root).with_context(|| {
                format!(
                    "artifact deletion was rejected and {} could not be restored",
                    artifact.root.display()
                )
            })?;
            return Err(error.into());
        }
        let _ = fs::remove_dir_all(quarantine);
        self.previews.lock().expect("preview mutex").clear();
        Ok(())
    }

    pub fn preview_bulk_delete(
        &self,
        external_mod_ids: &[String],
        artifact_sha256: &[String],
    ) -> Result<BulkDeletePreviewView> {
        let _operation = self.mod_operations.try_lock().map_err(|_| {
            anyhow!("another mod operation is still running; wait or restart RR Mod Manager")
        })?;
        let transaction_id = self.token("bulk-delete");
        let pending =
            self.compute_bulk_delete(&transaction_id, external_mod_ids, artifact_sha256, false)?;
        let token = format!("{}-{}", transaction_id, pending.evidence_sha256);
        let view = bulk_delete_preview_view(&token, &pending)?;
        let mut previews = self
            .pending_bulk_deletes
            .lock()
            .expect("bulk delete preview mutex");
        while previews.len() >= MAX_PENDING_BULK_DELETES {
            previews.pop_first();
        }
        previews.insert(token, pending);
        Ok(view)
    }

    pub fn apply_bulk_delete(&self, token: &str) -> Result<BulkDeleteResultView> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        let pending = self
            .pending_bulk_deletes
            .lock()
            .expect("bulk delete preview mutex")
            .get(token)
            .cloned()
            .context("bulk deletion preview expired; generate a fresh preview")?;
        if !token.ends_with(&pending.evidence_sha256) {
            bail!("bulk deletion token does not match its reviewed evidence");
        }
        if !pending.blockers.is_empty() {
            bail!("blocked bulk deletion preview cannot be applied");
        }

        let current = self.compute_bulk_delete(
            &pending.transaction_id,
            &pending.external_mod_ids,
            &pending.artifact_sha256,
            false,
        )?;
        if current.evidence_sha256 != pending.evidence_sha256
            || current.profiles_before != pending.profiles_before
            || current.profiles_after != pending.profiles_after
            || current.artifacts != pending.artifacts
            || current.installation != pending.installation
            || current.receipt != pending.receipt
            || current.plan != pending.plan
            || current.external_mods != pending.external_mods
            || current.external_units != pending.external_units
            || current.requires_deployment != pending.requires_deployment
            || !current.blockers.is_empty()
        {
            bail!(
                "profiles, receipt, game build, selected mods, artifacts, or deletion plan changed after preview; generate a fresh preview"
            );
        }

        self.pending_bulk_deletes
            .lock()
            .expect("bulk delete preview mutex")
            .remove(token)
            .context("bulk deletion preview expired before it could be applied")?;

        let profile_updates = pending
            .profiles_after
            .iter()
            .zip(&pending.profiles_before)
            .filter(|(after, before)| {
                after.packages != before.packages || after.pak_load_order != before.pak_load_order
            })
            .map(|(after, before)| (after.clone(), before.revision))
            .collect::<Vec<_>>();
        let updated_profiles = if profile_updates.is_empty() {
            Vec::new()
        } else {
            self.store()?.update_profiles_batch(&profile_updates)?
        };

        let deployment_applied = if let Some(plan) = &pending.plan {
            if let Err(error) = activate_deployment(plan, is_game_running) {
                let rollback_updates = pending
                    .profiles_before
                    .iter()
                    .filter_map(|before| {
                        updated_profiles
                            .iter()
                            .find(|updated| updated.id == before.id)
                            .map(|updated| (before.clone(), updated.revision))
                    })
                    .collect::<Vec<_>>();
                if !rollback_updates.is_empty() {
                    self.store()?
                        .update_profiles_batch(&rollback_updates)
                        .context(
                            "deployment failed and profile selections could not be restored",
                        )?;
                }
                return Err(error).context(
                    "deployment failed; profile selections were restored and managed artifacts were preserved",
                );
            }
            self.store()?
                .set_setting("desktop.last_applied_at", &serde_json::Value::String(now()))?;
            true
        } else {
            false
        };

        let selected_hashes = selected_artifact_file_hashes(&pending.artifacts)?;
        let receipt_after = load_receipt(&self.paths.deployment_state, INSTALLATION_ID)?;
        if receipt_after.as_ref().is_some_and(|receipt| {
            receipt
                .files
                .iter()
                .any(|file| selected_hashes.contains(&file.sha256))
        }) {
            bail!(
                "deployment completed without removing every selected artifact hash from the receipt; artifacts were preserved"
            );
        }

        let quarantine = self
            .paths
            .staging
            .join(self.token(BULK_DELETE_QUARANTINE_PREFIX.trim_end_matches('-')));
        fs::create_dir(&quarantine).with_context(|| {
            format!(
                "failed to create artifact quarantine {}",
                quarantine.display()
            )
        })?;
        if let Err(error) = write_artifact_quarantine_journal(&quarantine, &pending.artifacts) {
            fs::remove_dir_all(&quarantine).with_context(|| {
                format!(
                    "failed to initialize artifact quarantine and could not clean '{}'",
                    quarantine.display()
                )
            })?;
            return Err(error).context("failed to initialize recoverable artifact quarantine");
        }
        let mut quarantined = Vec::new();
        for artifact in &pending.artifacts {
            if let Err(error) = validate_stored_artifact_root(&self.paths, artifact) {
                rollback_artifact_quarantine(&quarantined).context(
                    "artifact validation failed and earlier quarantined artifacts could not be restored",
                )?;
                fs::remove_dir_all(&quarantine).with_context(|| {
                    format!(
                        "artifact validation failed and quarantine cleanup at '{}' also failed",
                        quarantine.display()
                    )
                })?;
                return Err(error).context("managed artifacts were preserved");
            }
            let destination = quarantine.join(&artifact.sha256);
            if let Err(error) = fs::rename(&artifact.root, &destination) {
                rollback_artifact_quarantine(&quarantined).context(
                    "artifact quarantine failed and earlier artifacts could not be restored",
                )?;
                let _ = fs::remove_dir(&quarantine);
                return Err(error).with_context(|| {
                    format!("failed to quarantine managed artifact {}", artifact.sha256)
                });
            }
            quarantined.push((destination, artifact.root.clone()));
        }
        if let Err(error) = self
            .store()?
            .delete_artifacts_without_profile_references(&pending.artifact_sha256)
        {
            rollback_artifact_quarantine(&quarantined).context(
                "artifact database deletion failed and quarantined artifacts could not be restored",
            )?;
            let _ = fs::remove_dir(&quarantine);
            return Err(error.into());
        }

        let mut warnings = Vec::new();
        if let Err(error) = fs::remove_dir_all(&quarantine) {
            warnings.push(format!(
                "artifact records were removed, but quarantine cleanup at '{}' failed: {error}",
                quarantine.display()
            ));
        }

        let mut external_deleted = Vec::new();
        let mut external_failures = Vec::new();
        if !pending.external_units.is_empty() {
            let installation = pending
                .installation
                .as_ref()
                .context("selected installation disappeared after managed deletion")?;
            for unit in &pending.external_units {
                match delete_existing_mod_unit_unlocked(
                    &installation.installation.game_root,
                    &self.paths.deployment_state,
                    unit,
                    &pending.external_mods,
                ) {
                    Ok(deleted) => external_deleted.extend(deleted),
                    Err(error) => external_failures.push(BulkDeleteExternalFailureView {
                        item_id: unit
                            .group_id
                            .clone()
                            .unwrap_or_else(|| unit.member_ids[0].clone()),
                        message: format!("{error:#}"),
                    }),
                }
            }
        }
        external_deleted.sort();
        external_deleted.dedup();
        self.previews.lock().expect("preview mutex").clear();
        self.pending_bulk_deletes
            .lock()
            .expect("bulk delete preview mutex")
            .clear();
        Ok(BulkDeleteResultView {
            status: if external_failures.is_empty() {
                "completed".to_owned()
            } else {
                "partial".to_owned()
            },
            managed_artifact_sha256: pending.artifact_sha256,
            external_mod_ids: external_deleted,
            external_failures,
            deployment_applied,
            warnings,
        })
    }

    pub fn select_profile(&self, profile_id: &str) -> Result<ProfileView> {
        let _timing = OperationTimer::new(&self.operation_timings, "selectProfile");
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        let store = self.store()?;
        let profile = store
            .profile(profile_id)?
            .with_context(|| format!("profile '{profile_id}' does not exist"))?;
        store.set_active_profile(INSTALLATION_ID, profile_id)?;
        self.previews.lock().expect("preview mutex").clear();
        Ok(profile_view(&profile))
    }

    pub fn delete_profile(&self, profile_id: &str) -> Result<()> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        let store = self.store()?;
        let profile = store
            .profile(profile_id)?
            .with_context(|| format!("profile '{profile_id}' does not exist"))?;
        if store
            .active_profile(INSTALLATION_ID)?
            .is_some_and(|active| active.id == profile.id)
        {
            bail!("select another profile before deleting the active profile");
        }
        if load_receipt(&self.paths.deployment_state, INSTALLATION_ID)?
            .is_some_and(|receipt| receipt.profile_id == profile.id)
        {
            bail!("apply another profile before deleting the profile installed in the game");
        }
        store.delete_profile(profile_id)?;
        self.previews.lock().expect("preview mutex").clear();
        Ok(())
    }

    pub fn set_offline_mode(&self, enabled: bool) -> Result<PreferencesView> {
        let store = self.store()?;
        let preferences = DesktopPreferences {
            schema_version: 1,
            offline_mode: enabled,
        };
        store.set_setting(
            DESKTOP_PREFERENCES_KEY,
            &serde_json::to_value(&preferences)?,
        )?;
        Ok(preferences_view(&preferences))
    }

    pub fn select_game_folder(&self, game_root: &Path) -> Result<AppSnapshot> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        let game_root = fs::canonicalize(game_root)
            .with_context(|| format!("failed to resolve game folder {}", game_root.display()))?;
        let common = game_root
            .parent()
            .context("the selected game folder has no parent")?;
        if !common
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("common"))
        {
            bail!("select the Retro Rewind folder directly inside steamapps/common");
        }
        let steamapps = common
            .parent()
            .context("the selected game folder is not inside steamapps/common")?;
        if !steamapps
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("steamapps"))
        {
            bail!("select the Retro Rewind folder directly inside steamapps/common");
        }
        let library_root = steamapps
            .parent()
            .context("the selected Steam library has no root")?;
        let manifest_path = steamapps.join("appmanifest_3552140.acf");
        let inspection = inspect_manifest(
            &manifest_path,
            library_root,
            library_root,
            InstallationSource::UserOverride,
            Some(&build_recipe()?),
            true,
        )?;
        if fs::canonicalize(&inspection.installation.game_root)? != game_root {
            bail!("the selected folder does not match the Retro Rewind Steam manifest");
        }
        let store = self.store()?;
        if let Some((bound_manifest, bound_root)) = store.installation_binding(INSTALLATION_ID)?
            && (!paths_refer_to_same_entry(&bound_manifest, &inspection.installation.manifest_path)
                || !paths_refer_to_same_entry(&bound_root, &inspection.installation.game_root))
        {
            bail!(
                "this manager state is already bound to another Retro Rewind installation; restore or remove managed files there before switching"
            );
        }
        if let Some(receipt) = load_receipt(&self.paths.deployment_state, INSTALLATION_ID)?
            && !paths_refer_to_same_entry(&receipt.game_root, &inspection.installation.game_root)
        {
            bail!(
                "this manager state owns files in another Retro Rewind installation; restore or remove them there before switching"
            );
        }
        if store
            .setting(SELECTED_GAME_ROOT_KEY)?
            .and_then(|value| value.as_str().map(PathBuf::from))
            .is_some_and(|selected| {
                !paths_refer_to_same_entry(&selected, &inspection.installation.game_root)
            })
            && fs::read_dir(self.paths.deployment_state.join(EXISTING_MODS_DIRECTORY))
                .is_ok_and(|mut entries| entries.next().is_some())
        {
            bail!(
                "installed mods are stored for another Retro Rewind installation; restore or remove them there before switching"
            );
        }
        store.upsert_installation(&inspection)?;
        ensure_desktop_installation_binding(
            &store,
            INSTALLATION_ID,
            &inspection.installation.manifest_path,
            &inspection.installation.game_root,
        )?;
        store.set_setting(
            SELECTED_GAME_ROOT_KEY,
            &serde_json::Value::String(inspection.installation.game_root.display().to_string()),
        )?;
        self.previews.lock().expect("preview mutex").clear();
        self.snapshot()
    }

    pub fn mark_game_incident(&self) -> Result<IncidentMarkerView> {
        let marker = IncidentMarkerView {
            id: self.token("incident"),
            recorded_at: now(),
            game_running: is_game_running(),
        };
        let mut markers = self.incident_markers.lock().expect("incident marker mutex");
        markers.push(marker.clone());
        if markers.len() > 32 {
            markers.remove(0);
        }
        Ok(marker)
    }

    pub fn preview_bug_report(
        &self,
        request: BugReportRequestView,
    ) -> Result<BugReportPreviewView> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        let snapshot = self.snapshot()?;
        let store = self.store()?;
        let installation = selected_installation(&store)?;
        let active_mods = request
            .include_active_mods
            .then(|| self.bug_report_active_mods(&store, installation.as_ref()))
            .transpose()?;
        let game_running = is_game_running();
        let incident_marker = self
            .incident_markers
            .lock()
            .expect("incident marker mutex")
            .last()
            .filter(|marker| request.occurred_at.as_deref() == Some(marker.recorded_at.as_str()))
            .cloned();
        let context = BugReportContext {
            generated_at: now(),
            game_running,
            game_detected: installation.is_some(),
            game_build_id: installation
                .as_ref()
                .map(|item| item.installation.build_id.to_string()),
            game_root: installation
                .as_ref()
                .map(|item| item.installation.game_root.clone()),
            active_mods,
            incident_marker,
            technical_summary: bug_report_technical_summary(
                &snapshot,
                &self
                    .operation_timings
                    .lock()
                    .expect("operation timings mutex"),
            ),
            operation_history: serde_json::json!({
                "schemaVersion": 1,
                "maximumEntries": MAX_OPERATION_FAILURES,
                "failures": self.operation_failures()?
            }),
        };
        let (files, warnings) = prepare_bug_report(request, context)?;
        let token = self.token("bug-report");
        let mut previews = self
            .bug_report_previews
            .lock()
            .expect("bug report preview mutex");
        while previews.len() >= 8 {
            previews.pop_first();
        }
        previews.insert(
            token.clone(),
            PendingBugReport {
                files: files.clone(),
            },
        );
        Ok(BugReportPreviewView {
            token,
            files,
            warnings,
        })
    }

    pub fn export_bug_report(&self, token: &str, destination: &Path) -> Result<String> {
        let temporary_id = self.token("export");
        let mut previews = self
            .bug_report_previews
            .lock()
            .expect("bug report preview mutex");
        let pending = previews
            .get(token)
            .context("bug report preview expired; generate a new preview")?;
        let exported = write_bug_report_zip(pending, destination, &temporary_id)?;
        previews.remove(token);
        Ok(exported)
    }

    pub fn set_existing_mod_enabled(&self, mod_id: &str, enabled: bool) -> Result<()> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        if is_game_running() {
            bail!("Retro Rewind is running; close the game before changing installed mods");
        }
        if pending_recovery(&self.paths.deployment_state)? {
            bail!("restore the interrupted deployment before changing installed mods");
        }
        let store = self.store()?;
        let installation = selected_installation(&store)?
            .context("no inventoried Retro Rewind Steam installation is available")?;
        let receipt = load_receipt(&self.paths.deployment_state, INSTALLATION_ID)?;
        let mods = existing_mod_views(
            &installation.installation.game_root,
            &self.paths.deployment_state,
            receipt.as_ref(),
        )?;
        let existing = mods
            .iter()
            .find(|item| item.id == mod_id)
            .with_context(|| format!("installed mod '{mod_id}' is no longer available"))?;
        if enabled && existing.related_paths.is_empty() {
            bail!("an empty UE4SS module directory cannot be enabled");
        }
        if !existing.manageable {
            bail!(
                "{}",
                existing
                    .blocked_reason
                    .as_deref()
                    .unwrap_or("this installed mod cannot be managed safely")
            );
        }
        if existing.group_id.is_some() {
            bail!("grouped hybrid mods must be changed as one atomic unit");
        }
        if existing.mods_txt_controlled {
            let module_name = existing
                .ue4ss_module_name
                .as_deref()
                .context("UE4SS module identity is unavailable")?;
            set_ue4ss_mods_txt_state(
                &installation.installation.game_root,
                module_name,
                Some(enabled),
            )?;
            self.previews.lock().expect("preview mutex").clear();
            return Ok(());
        }
        if existing.enabled == enabled {
            return Ok(());
        }
        if enabled {
            if existing.stored {
                enable_existing_mod(
                    &installation.installation.game_root,
                    &self.paths.deployment_state,
                    mod_id,
                )?;
            } else if existing.mod_type.starts_with("ue4ss_") {
                enable_live_ue4ss_module(&installation.installation.game_root, existing)?;
            } else {
                bail!("this installed mod has no stored files to enable");
            }
        } else {
            disable_existing_mod(
                &installation.installation.game_root,
                &self.paths.deployment_state,
                existing,
            )?;
        }
        self.previews.lock().expect("preview mutex").clear();
        Ok(())
    }

    pub fn delete_existing_mod(&self, mod_id: &str) -> Result<()> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        if is_game_running() {
            bail!("Retro Rewind is running; close the game before deleting installed mods");
        }
        if pending_recovery(&self.paths.deployment_state)? {
            bail!("restore the interrupted deployment before deleting installed mods");
        }
        let store = self.store()?;
        let installation = selected_installation(&store)?
            .context("no inventoried Retro Rewind Steam installation is available")?;
        let receipt = load_receipt(&self.paths.deployment_state, INSTALLATION_ID)?;
        let mods = existing_mod_views(
            &installation.installation.game_root,
            &self.paths.deployment_state,
            receipt.as_ref(),
        )?;
        let existing = mods
            .iter()
            .find(|item| item.id == mod_id)
            .with_context(|| format!("installed mod '{mod_id}' is no longer available"))?;
        if !existing.manageable {
            bail!(
                "{}",
                existing
                    .blocked_reason
                    .as_deref()
                    .unwrap_or("this installed mod cannot be deleted safely")
            );
        }
        if existing.group_id.is_some() {
            bail!("grouped hybrid mods must be deleted as one atomic unit");
        }
        if existing.mods_txt_controlled {
            let module_name = existing
                .ue4ss_module_name
                .as_deref()
                .context("UE4SS module identity is unavailable")?;
            delete_mods_txt_controlled_existing_mod(
                &installation.installation.game_root,
                &self.paths.deployment_state,
                existing,
                module_name,
            )?;
            self.previews.lock().expect("preview mutex").clear();
            return Ok(());
        }
        if existing.enabled {
            delete_active_existing_mod(
                &installation.installation.game_root,
                &self.paths.deployment_state,
                existing,
            )?;
        } else {
            if existing.stored {
                delete_disabled_existing_mod(
                    &installation.installation.game_root,
                    &self.paths.deployment_state,
                    mod_id,
                )?;
            } else {
                delete_active_existing_mod(
                    &installation.installation.game_root,
                    &self.paths.deployment_state,
                    existing,
                )?;
            }
        }
        self.previews.lock().expect("preview mutex").clear();
        Ok(())
    }

    pub fn operate_existing_mod_group(
        &self,
        group_id: &str,
        operation: ExistingModGroupOperation,
    ) -> Result<()> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        if is_game_running() {
            bail!("Retro Rewind is running; close the game before changing installed mods");
        }
        if pending_recovery(&self.paths.deployment_state)? {
            bail!("restore the interrupted deployment before changing installed mods");
        }
        let store = self.store()?;
        let installation = selected_installation(&store)?
            .context("no inventoried Retro Rewind Steam installation is available")?;
        let receipt = load_receipt(&self.paths.deployment_state, INSTALLATION_ID)?;
        let mods = existing_mod_views(
            &installation.installation.game_root,
            &self.paths.deployment_state,
            receipt.as_ref(),
        )?;
        let group: Vec<_> = mods
            .iter()
            .filter(|item| item.group_id.as_deref() == Some(group_id))
            .cloned()
            .collect();
        if group.len() < 2 {
            bail!("reviewed hybrid group '{group_id}' is incomplete or no longer available");
        }
        if group
            .iter()
            .any(|item| !item.manageable || item.mods_txt_controlled)
        {
            bail!("reviewed hybrid group cannot be changed safely as one unit");
        }
        let snapshot = capture_existing_group_snapshot(
            &installation.installation.game_root,
            &self.paths.deployment_state,
            &group,
        )?;
        let result: Result<()> = (|| {
            for item in &group {
                match operation {
                    ExistingModGroupOperation::Enable if !item.enabled => {
                        set_existing_mod_enabled_unlocked(
                            &installation.installation.game_root,
                            &self.paths.deployment_state,
                            item,
                            true,
                        )?;
                    }
                    ExistingModGroupOperation::Disable if item.enabled => {
                        set_existing_mod_enabled_unlocked(
                            &installation.installation.game_root,
                            &self.paths.deployment_state,
                            item,
                            false,
                        )?;
                    }
                    ExistingModGroupOperation::Delete => delete_existing_mod_unlocked(
                        &installation.installation.game_root,
                        &self.paths.deployment_state,
                        item,
                    )?,
                    _ => {}
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            rollback_existing_group_snapshot(
                &installation.installation.game_root,
                &self.paths.deployment_state,
                &snapshot,
            )
            .context("hybrid operation failed and its rollback could not be completed")?;
            fs::remove_dir_all(&snapshot.root)?;
            return Err(error.context("hybrid operation was rolled back"));
        }
        fs::remove_dir_all(&snapshot.root)?;
        self.previews.lock().expect("preview mutex").clear();
        Ok(())
    }

    pub fn preview_activation(&self, allow_unmanaged: bool) -> Result<ActivationPreviewView> {
        let _timing = OperationTimer::new(&self.operation_timings, "previewActivation");
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        let transaction_id = self.token("desktop");
        let computed = self.compute_plan(allow_unmanaged, &transaction_id, &[])?;
        self.store_activation_preview(transaction_id, allow_unmanaged, computed)
    }

    pub fn approve_managed_file_restore(
        &self,
        preview_id: &str,
        relative_path: &str,
    ) -> Result<ActivationPreviewView> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        let pending = self
            .previews
            .lock()
            .expect("preview mutex")
            .get(preview_id)
            .cloned()
            .context("activation preview expired; generate a fresh preview")?;
        let approval = managed_file_restore_approval(&pending.plan, relative_path)
            .context("this managed file cannot be restored from the reviewed plan")?;
        let mut approvals = pending.plan.managed_file_restore_approvals.clone();
        approvals.retain(|item| item.relative_path != approval.relative_path);
        approvals.push(approval);
        let transaction_id = self.token("desktop");
        let computed = self.compute_plan(pending.allow_unmanaged, &transaction_id, &approvals)?;
        if computed.profile_id != pending.profile_id
            || computed.profile_revision != pending.profile_revision
            || computed.build_id != pending.build_id
        {
            bail!("active profile or game build changed after preview");
        }
        self.store_activation_preview(transaction_id, pending.allow_unmanaged, computed)
    }

    pub fn disable_managed_file_package(
        &self,
        preview_id: &str,
        relative_path: &str,
    ) -> Result<ActivationPreviewView> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        let pending = self
            .previews
            .lock()
            .expect("preview mutex")
            .get(preview_id)
            .cloned()
            .context("activation preview expired; generate a fresh preview")?;
        let issue = managed_file_issue_views(&pending.plan, &pending.disableable_package_ids)
            .into_iter()
            .find(|item| item.path == relative_path)
            .context("managed file is not part of the reviewed preview")?;
        let package_id = issue
            .package_id
            .filter(|_| {
                issue
                    .allowed_actions
                    .iter()
                    .any(|action| action == "disable_package")
            })
            .context("ownership cannot be attributed exactly enough to disable a package")?;

        let store = self.store()?;
        let mut profile = store
            .active_profile(INSTALLATION_ID)?
            .context("no active profile is selected")?;
        if profile.id != pending.profile_id || profile.revision != pending.profile_revision {
            bail!("active profile changed after preview");
        }
        let catalog = effective_package_catalog(&store, &self.paths.artifact_store)?;
        let matches = profile
            .packages
            .iter()
            .filter(|selection| selection.enabled)
            .filter(|selection| {
                catalog.iter().any(|package| {
                    package.artifact_sha256 == selection.artifact_sha256
                        && package.manifest.id == package_id
                })
            })
            .map(|selection| selection.artifact_sha256.clone())
            .collect::<Vec<_>>();
        let [artifact_sha256] = matches.as_slice() else {
            bail!("package ownership changed after preview");
        };
        let selection = profile
            .packages
            .iter_mut()
            .find(|selection| selection.artifact_sha256 == *artifact_sha256)
            .context("owned package selection disappeared after preview")?;
        selection.enabled = false;
        let expected_revision = profile.revision;
        store.update_profile(&profile, expected_revision)?;
        self.previews.lock().expect("preview mutex").clear();

        let transaction_id = self.token("desktop");
        let computed = self.compute_plan(pending.allow_unmanaged, &transaction_id, &[])?;
        self.store_activation_preview(transaction_id, pending.allow_unmanaged, computed)
    }

    fn store_activation_preview(
        &self,
        transaction_id: String,
        allow_unmanaged: bool,
        computed: ComputedDeployment,
    ) -> Result<ActivationPreviewView> {
        let ComputedDeployment {
            plan,
            profile_id,
            profile_name,
            profile_revision,
            build_id,
            blockers,
            unmanaged_count,
            pak_conflicts,
            recipes,
            disableable_package_ids,
            watched_files,
        } = computed;
        let Some(plan) = plan else {
            return Ok(ActivationPreviewView {
                preview_id: transaction_id,
                profile_id,
                profile_name,
                blocked: true,
                requires_apply: false,
                blockers,
                changes: Vec::new(),
                unmanaged_files_preserved: unmanaged_count,
                allow_unmanaged,
                pak_conflicts,
                blocking_links: Vec::new(),
                managed_file_issues: Vec::new(),
                recipes,
            });
        };
        let view = activation_preview_view(
            &profile_name,
            &plan,
            &blockers,
            unmanaged_count,
            &pak_conflicts,
            &recipes,
            &disableable_package_ids,
        );
        let allow_unmanaged = plan.allow_unmanaged;
        self.previews.lock().expect("preview mutex").insert(
            transaction_id.clone(),
            PendingPreview {
                profile_id,
                profile_revision,
                build_id,
                plan,
                allow_unmanaged,
                package_blockers: blockers,
                pak_conflicts,
                disableable_package_ids,
                watched_files,
            },
        );
        Ok(view)
    }

    pub fn apply_activation(&self, preview_id: &str) -> Result<ActivationResult> {
        let _timing = OperationTimer::new(&self.operation_timings, "applyActivation");
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        let pending = self
            .previews
            .lock()
            .expect("preview mutex")
            .remove(preview_id)
            .context("activation preview expired; generate a fresh preview")?;
        let store = self.store()?;
        let profile = store
            .active_profile(INSTALLATION_ID)?
            .context("no active profile is selected")?;
        let installation = selected_installation(&store)?
            .context("no inventoried Retro Rewind Steam installation is available")?;
        if profile.id != pending.profile_id
            || profile.revision != pending.profile_revision
            || installation.installation.build_id != pending.build_id
        {
            bail!("active profile or game build changed after preview");
        }
        if !pending.plan.ready() || !pending.package_blockers.is_empty() {
            bail!("blocked activation preview cannot be applied");
        }
        validate_file_snapshots(&pending.watched_files)
            .context("installation or mod files changed after preview; generate a fresh preview")?;
        let report = activate_prepared_deployment(&pending.plan, is_game_running)?;
        let _ = self
            .store()?
            .set_setting("desktop.last_applied_at", &serde_json::Value::String(now()));
        Ok(ActivationResult {
            status: "applied".to_owned(),
            applied_profile_id: Some(report.profile_id),
            applied_at: now(),
        })
    }

    pub fn recover_deployment(&self) -> Result<ActivationResult> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        if is_game_running() {
            bail!("Retro Rewind is running; close the game before recovery");
        }
        if let Some(installation) = selected_installation(&self.store()?)? {
            recover_existing_group_operations(
                &installation.installation.game_root,
                &self.paths.deployment_state,
            )?;
            recover_existing_mod_records(
                &installation.installation.game_root,
                &self.paths.deployment_state,
            )?;
        }
        let reports = recover_incomplete(&self.paths.deployment_state, is_game_running)?;
        let applied_profile_id = load_receipt(&self.paths.deployment_state, INSTALLATION_ID)?
            .map(|receipt| receipt.profile_id);
        Ok(ActivationResult {
            status: if reports.is_empty() {
                "recovered".to_owned()
            } else {
                format!("recovered_{}", reports.len())
            },
            applied_profile_id,
            applied_at: now(),
        })
    }

    pub fn refresh_ue4ss(&self) -> Result<Ue4ssStateView> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        let Some(installation) = selected_installation(&self.store()?)? else {
            return Ok(Ue4ssStateView::absent("Retro Rewind is not detected."));
        };
        ue4ss_view(&installation.installation.game_root, &build_recipe()?)
    }

    pub fn analyze_keybinds(&self) -> Result<KeybindAnalysisView> {
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        let installation = selected_installation(&self.store()?)?
            .context("no inventoried Retro Rewind Steam installation is available")?;
        let report = analyze_ue4ss_lua(
            &installation.installation.game_root,
            &Ue4ssInventoryLimits::default(),
            &LuaAdvisoryLimits::default(),
        )?;
        Ok(keybind_analysis_view(&report))
    }

    pub fn install_or_repair_ue4ss(&self) -> Result<Ue4ssStateView> {
        let operation = "installOrRepairUe4ss";
        self.operation_stage(operation, "validate_game");
        let _operation = self.mod_operations.lock().expect("mod operation mutex");
        if is_game_running() {
            bail!("Retro Rewind is running; close the game before installing UE4SS");
        }
        if pending_recovery(&self.paths.deployment_state)? {
            bail!("restore the interrupted deployment before installing UE4SS");
        }
        let store = self.store()?;
        let installation = selected_installation(&store)?
            .context("no inventoried Retro Rewind Steam installation is available")?;
        if installation.installation.build_id != SUPPORTED_BUILD_ID
            || installation.build_status != BuildStatus::SupportedExact
            || installation.layout_status != LayoutStatus::Complete
        {
            bail!("UE4SS installation requires the exact supported Retro Rewind build");
        }
        let game_root = &installation.installation.game_root;
        self.operation_stage(operation, "inspect_installed_loader");
        reject_ambiguous_ue4ss_layout(game_root)?;
        let artifact = ue4ss_loader_artifact()?;
        let current = ue4ss_view(game_root, &build_recipe()?)?;
        self.operation_detail(
            operation,
            "installedBuild",
            serde_json::json!(current.version),
        );
        self.operation_detail(
            operation,
            "expectedBuild",
            serde_json::json!(artifact.loader_build_id),
        );
        self.operation_detail(
            operation,
            "expectedArchiveSha256",
            serde_json::json!(artifact.archive_sha256),
        );
        self.operation_detail(
            operation,
            "expectedProxySha256",
            serde_json::json!(artifact.proxy_sha256),
        );
        self.operation_detail(
            operation,
            "expectedCoreSha256",
            serde_json::json!(artifact.core_sha256),
        );
        if let Ok(identity) =
            inspect_ue4ss_loader_identity(game_root, &Ue4ssLoaderIdentityLimits::default())
            && let Some(identity) = identity.identity
        {
            self.operation_detail(
                operation,
                "detectedProxySha256",
                serde_json::json!(identity.proxy.sha256),
            );
            self.operation_detail(
                operation,
                "detectedCoreSha256",
                serde_json::json!(identity.core.sha256),
            );
        }
        if current.version.as_deref() == Some(&artifact.loader_build_id)
            && current.health == HealthLevel::Ready
            && !current.mixed_installation
        {
            return Ok(current);
        }
        self.operation_stage(operation, "download_and_verify_archive");
        let archive = self.download_ue4ss_archive(&artifact)?;
        self.operation_detail(
            operation,
            "archiveSourceHost",
            serde_json::json!("github.com"),
        );
        let token = self.token("ue4ss-loader");
        let extraction_root = self.paths.staging.join(&token);
        if extraction_root.exists() {
            bail!("UE4SS extraction staging already exists");
        }
        self.operation_stage(operation, "extract_archive");
        let response = self.run_archive_worker(ArchiveWorkerRequest::Extract {
            archive,
            staging: extraction_root.clone(),
            limits: desktop_archive_limits(),
        });
        let result = (|| {
            let extraction = response?
                .extraction
                .context("archive worker returned no UE4SS extraction report")?;
            if extraction.archive_sha256 != artifact.archive_sha256 {
                bail!("UE4SS archive changed during extraction");
            }
            let files = ue4ss_deployment_files(game_root, &extraction, &artifact)?;
            self.operation_stage(operation, "plan_and_backup");
            let receipt = load_receipt(&self.paths.deployment_state, UE4SS_LOADER_INSTALLATION_ID)?;
            let receipt = reconcile_recognized_ue4ss_receipt(
                game_root,
                &self.paths.deployment_state,
                &token,
                receipt,
                &build_recipe()?,
            )?;
            let plan = plan_deployment(
                DeploymentRequest {
                    transaction_id: token.clone(),
                    installation_id: UE4SS_LOADER_INSTALLATION_ID.to_owned(),
                    profile_id: "ue4ss-loader".to_owned(),
                    game_root: game_root.clone(),
                    state_root: self.paths.deployment_state.clone(),
                    files,
                    external_files: Vec::new(),
                    allow_unmanaged: true,
                    game_running: false,
                },
                receipt.as_ref(),
            )?;
            if !plan.ready() {
                bail!(
                    "UE4SS installation is blocked: {}",
                    plan.blockers
                        .iter()
                        .map(deployment_blocker)
                        .collect::<Vec<_>>()
                        .join("; ")
                );
            }
            self.operation_stage(operation, "replace_files");
            self.operation_rollback(operation, "pending");
            match activate_deployment(&plan, is_game_running) {
                Ok(_) => self.operation_rollback(operation, "not_required"),
                Err(error) => {
                    let recovery_pending =
                        pending_recovery(&self.paths.deployment_state).unwrap_or(true);
                    self.operation_rollback(
                        operation,
                        if recovery_pending {
                            "incomplete"
                        } else {
                            "completed"
                        },
                    );
                    return Err(error.into());
                }
            }
            self.operation_stage(operation, "verify_installed_loader");
            let refreshed = ue4ss_view(game_root, &build_recipe()?)?;
            if refreshed.version.as_deref() != Some(&artifact.loader_build_id)
                || refreshed.health != HealthLevel::Ready
                || refreshed.mixed_installation
            {
                self.operation_rollback(operation, "unavailable_after_commit");
                bail!("UE4SS files were installed but exact identity verification failed");
            }
            self.operation_detail(
                operation,
                "verifiedBuild",
                serde_json::json!(refreshed.version),
            );
            if let Some(identity) =
                inspect_ue4ss_loader_identity(game_root, &Ue4ssLoaderIdentityLimits::default())?
                    .identity
            {
                self.operation_detail(
                    operation,
                    "verifiedProxySha256",
                    serde_json::json!(identity.proxy.sha256),
                );
                self.operation_detail(
                    operation,
                    "verifiedCoreSha256",
                    serde_json::json!(identity.core.sha256),
                );
            }
            Ok(refreshed)
        })();
        let _ = fs::remove_dir_all(extraction_root);
        result
    }

    pub fn launch_game(&self) -> Result<LaunchReport> {
        let store = self.store()?;
        let installation = selected_installation(&store)?
            .context("no inventoried Retro Rewind Steam installation is available")?;
        let steam_root = &installation.installation.steam_root;
        let mut candidates = vec![
            steam_root.join("steam.exe"),
            steam_root.join("steam"),
            steam_root.join("steam.sh"),
            PathBuf::from("/usr/bin/steam"),
            PathBuf::from("/app/bin/steam"),
        ];
        for (root, _) in candidate_steam_roots(None) {
            candidates.push(root.join("steam.exe"));
            candidates.push(root.join("steam"));
            candidates.push(root.join("steam.sh"));
        }
        let steam = candidates
            .iter()
            .find(|path| path.is_file())
            .context("Steam executable was not found beside the selected installation")?;
        Ok(launch_game_via_steam(steam)?)
    }

    fn refresh_installations(&self) -> Result<()> {
        let recipe = build_recipe()?;
        let report = discover_installations(DiscoveryOptions {
            steam_root_override: None,
            recipe: Some(&recipe),
            deep: true,
        });
        let store = self.store()?;
        for installation in &report.installations {
            store.upsert_installation(installation)?;
        }
        if let Some(game_root) = store
            .setting(SELECTED_GAME_ROOT_KEY)?
            .and_then(|value| value.as_str().map(PathBuf::from))
            && let Ok(game_root) = fs::canonicalize(game_root)
            && let Some(common) = game_root.parent()
            && let Some(steamapps) = common.parent()
            && let Some(library_root) = steamapps.parent()
        {
            let manifest_path = steamapps.join("appmanifest_3552140.acf");
            if let Ok(inspection) = inspect_manifest(
                &manifest_path,
                library_root,
                library_root,
                InstallationSource::UserOverride,
                Some(&recipe),
                true,
            ) {
                store.upsert_installation(&inspection)?;
            }
        }
        Ok(())
    }

    fn ensure_default_profile(&self) -> Result<()> {
        let store = self.store()?;
        if store.profiles()?.is_empty() {
            store.create_profile(&DomainProfile {
                schema_version: 1,
                id: "default".to_owned(),
                name: "Default".to_owned(),
                revision: 0,
                packages: Vec::new(),
                pak_load_order: Vec::new(),
            })?;
        }
        if store.active_profile(INSTALLATION_ID)?.is_none() {
            let first = store
                .profiles()?
                .into_iter()
                .next()
                .context("default profile creation failed")?;
            store.set_active_profile(INSTALLATION_ID, &first.id)?;
        }
        Ok(())
    }

    fn snapshot(&self) -> Result<AppSnapshot> {
        let store = self.store()?;
        let recipe = build_recipe()?;
        let catalog = effective_package_catalog(&store, &self.paths.artifact_store)?;
        let installation = selected_installation(&store)?;
        let game = installation
            .as_ref()
            .map(game_installation_view)
            .unwrap_or_else(|| GameInstallationView::absent(recipe.build_id));
        let domain_profiles = store.profiles()?;
        let profiles: Vec<_> = domain_profiles.iter().map(profile_view).collect();
        let active = store.active_profile(INSTALLATION_ID)?;
        let receipt = load_receipt(&self.paths.deployment_state, INSTALLATION_ID)?;
        if let (Some(installation), Some(receipt)) = (&installation, &receipt)
            && !paths_refer_to_same_entry(&receipt.game_root, &installation.installation.game_root)
        {
            bail!(
                "deployment state belongs to another Retro Rewind installation; select that installation and recover it first"
            );
        }
        let artifacts = artifact_views(&store, &domain_profiles, receipt.as_ref(), &catalog)?;
        let ue4ss = installation
            .as_ref()
            .map(|installation| ue4ss_view(&installation.installation.game_root, &recipe))
            .transpose()?
            .unwrap_or_else(|| Ue4ssStateView::absent("Retro Rewind is not detected."));
        if let Some(installation) = &installation
            && !is_game_running()
        {
            recover_existing_group_operations(
                &installation.installation.game_root,
                &self.paths.deployment_state,
            )?;
            recover_existing_mod_records(
                &installation.installation.game_root,
                &self.paths.deployment_state,
            )?;
        }
        let mut existing_mods = installation
            .as_ref()
            .map(|installation| {
                existing_mod_views(
                    &installation.installation.game_root,
                    &self.paths.deployment_state,
                    receipt.as_ref(),
                )
            })
            .transpose()?
            .unwrap_or_default();
        let stored_artifacts = artifacts
            .iter()
            .map(|artifact| artifact.sha256.as_str())
            .collect::<BTreeSet<_>>();
        let adopted = adopted_external_mods(&store)?;
        existing_mods.retain(|item| {
            adopted
                .get(&item.id)
                .is_none_or(|sha256| !stored_artifacts.contains(sha256.as_str()))
        });
        let unmanaged_files: Vec<_> = existing_mods
            .iter()
            .filter(|item| item.enabled && item.mod_type == "pak")
            .map(|item| UnmanagedFileView {
                path: item
                    .active_paths
                    .get(&item.path)
                    .cloned()
                    .unwrap_or_else(|| item.path.clone()),
                size_bytes: item.size_bytes,
                pak_sha256: item.pak_sha256.clone().unwrap_or_default(),
                original_path: item
                    .original_path
                    .clone()
                    .unwrap_or_else(|| item.path.clone()),
                existing_mod_id: Some(item.id.clone()),
                display_name: Some(item.display_name.clone()),
                manageable: item.manageable,
                active_paths: item.active_paths.clone(),
            })
            .collect();
        let conflicts = conflict_views(active.as_ref(), &catalog, &unmanaged_files)?;
        let enabled_external_mod_count = existing_mods.iter().filter(|item| item.enabled).count();
        let recovery_available = pending_recovery(&self.paths.deployment_state)?;
        let last_applied_at = store
            .setting("desktop.last_applied_at")?
            .and_then(|value| value.as_str().map(str::to_owned));
        let deployment_health = if recovery_available
            || conflicts
                .iter()
                .any(|conflict| conflict.severity == "blocker")
        {
            HealthLevel::Blocked
        } else if game.health == HealthLevel::Ready && enabled_external_mod_count == 0 {
            HealthLevel::Ready
        } else {
            HealthLevel::Attention
        };
        let diagnostics = diagnostics(
            &game,
            &ue4ss,
            recovery_available,
            &self.paths,
            unmanaged_files.len(),
        );
        let preferences = desktop_preferences(&store)?;
        let operation_failure_count = operation_failures(&store)?.len();
        Ok(AppSnapshot {
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            generated_at: now(),
            game,
            deployment: DeploymentStateView {
                health: deployment_health,
                selected_profile_id: active.as_ref().map(|profile| profile.id.clone()),
                selected_profile_name: active.as_ref().map(|profile| profile.name.clone()),
                applied_profile_id: receipt.as_ref().map(|receipt| receipt.profile_id.clone()),
                applied_profile_name: receipt.as_ref().and_then(|receipt| {
                    domain_profiles
                        .iter()
                        .find(|profile| profile.id == receipt.profile_id)
                        .map(|profile| profile.name.clone())
                }),
                managed_file_count: receipt.as_ref().map_or(0, |receipt| receipt.files.len()),
                unmanaged_files,
                existing_mods,
                recovery_available,
                last_applied_at,
            },
            artifacts,
            profiles,
            conflicts,
            ue4ss,
            diagnostics,
            preferences: preferences_view(&preferences),
            operation_failure_count,
        })
    }

    fn compute_bulk_delete(
        &self,
        transaction_id: &str,
        external_mod_ids: &[String],
        artifact_sha256: &[String],
        persist_validation_state: bool,
    ) -> Result<PendingBulkDelete> {
        let mut blockers = Vec::new();
        let mut normalized_artifacts = BTreeSet::new();
        for value in artifact_sha256 {
            let normalized = value.trim().to_ascii_lowercase();
            if !is_sha256(&normalized) {
                blockers.push(bulk_delete_blocker(
                    "invalid_artifact_sha256",
                    "A selected managed artifact has an invalid SHA-256.",
                    Some(value.trim()),
                ));
            } else {
                normalized_artifacts.insert(normalized);
            }
        }
        let normalized_artifacts = normalized_artifacts.into_iter().collect::<Vec<_>>();
        let normalized_external = external_mod_ids
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        if normalized_artifacts.is_empty() && normalized_external.is_empty() {
            blockers.push(bulk_delete_blocker(
                "empty_selection",
                "Select at least one manageable mod to delete.",
                None,
            ));
        }
        let game_running = is_game_running();
        if pending_recovery(&self.paths.deployment_state)? {
            blockers.push(bulk_delete_blocker(
                "recovery_pending",
                "Restore the interrupted deployment or external-mod operation before deleting mods.",
                None,
            ));
        }

        let store = self.store()?;
        let profiles_before = store.profiles()?;
        let mut profiles_after = profiles_before.clone();
        let selected_set = normalized_artifacts
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        for profile in &mut profiles_after {
            profile
                .packages
                .retain(|package| !selected_set.contains(&package.artifact_sha256));
        }

        let stored_artifacts = store.artifacts()?;
        let mut artifacts = Vec::new();
        for sha256 in &normalized_artifacts {
            match stored_artifacts
                .iter()
                .find(|artifact| artifact.sha256 == *sha256)
            {
                Some(artifact) => {
                    if let Err(error) = validate_stored_artifact_root(&self.paths, artifact) {
                        blockers.push(bulk_delete_blocker(
                            "artifact_not_manageable",
                            &format!(
                                "Managed artifact '{sha256}' cannot be quarantined safely: {error}"
                            ),
                            Some(sha256),
                        ));
                    }
                    artifacts.push(artifact.clone());
                }
                None => blockers.push(bulk_delete_blocker(
                    "artifact_missing",
                    &format!("Managed artifact '{sha256}' is no longer in the local store."),
                    Some(sha256),
                )),
            }
        }
        let selected_pak_hashes = artifact_pak_hashes(&artifacts)?;
        let retained_artifacts = stored_artifacts
            .iter()
            .filter(|artifact| !selected_set.contains(&artifact.sha256))
            .cloned()
            .collect::<Vec<_>>();
        let retained_pak_hashes = artifact_pak_hashes(&retained_artifacts)?;
        let removed_pak_hashes = selected_pak_hashes
            .difference(&retained_pak_hashes)
            .cloned()
            .collect::<BTreeSet<_>>();
        for profile in &mut profiles_after {
            profile.pak_load_order.retain(|preference| {
                !removed_pak_hashes.contains(&preference.first_pak_sha256)
                    && !removed_pak_hashes.contains(&preference.second_pak_sha256)
                    && !removed_pak_hashes.contains(&preference.winner_pak_sha256)
            });
        }

        let installation = selected_installation(&store)?;
        let receipt = load_receipt(&self.paths.deployment_state, INSTALLATION_ID)?;
        if let (Some(installation), Some(receipt)) = (&installation, &receipt)
            && !paths_refer_to_same_entry(&installation.installation.game_root, &receipt.game_root)
        {
            blockers.push(bulk_delete_blocker(
                "receipt_installation_mismatch",
                "The active deployment receipt belongs to a different game installation; select and recover that installation first.",
                None,
            ));
        }

        let selected_file_hashes = selected_artifact_file_hashes(&artifacts)?;
        let catalog = if receipt.is_some() {
            effective_package_catalog(&store, &self.paths.artifact_store)?
        } else {
            Vec::new()
        };
        let selected_package_ids = catalog
            .iter()
            .filter(|package| selected_set.contains(&package.artifact_sha256))
            .map(|package| package.manifest.id.clone())
            .collect::<BTreeSet<_>>();
        let deployed_artifact_hashes = artifacts
            .iter()
            .filter_map(|artifact| {
                let manifest =
                    serde_json::from_value::<ArtifactManifest>(artifact.manifest.clone()).ok()?;
                let package_ids = catalog
                    .iter()
                    .filter(|package| package.artifact_sha256 == artifact.sha256)
                    .map(|package| package.manifest.id.as_str())
                    .collect::<BTreeSet<_>>();
                receipt
                    .as_ref()
                    .is_some_and(|receipt| {
                        receipt.files.iter().any(|owned| {
                            owned.package_id.as_deref().map_or_else(
                                || {
                                    manifest
                                        .files
                                        .iter()
                                        .any(|file| file.sha256 == owned.sha256)
                                },
                                |package_id| package_ids.contains(package_id),
                            )
                        })
                    })
                    .then_some(artifact.sha256.clone())
            })
            .collect::<BTreeSet<_>>();
        let requires_deployment = !deployed_artifact_hashes.is_empty();
        if game_running && (requires_deployment || !normalized_external.is_empty()) {
            blockers.push(bulk_delete_blocker(
                "game_running",
                "Retro Rewind is running; close the game before deleting installed mod files.",
                None,
            ));
        }
        if blockers
            .iter()
            .any(|blocker| matches!(blocker.code.as_str(), "game_running" | "recovery_pending"))
        {
            return finish_bulk_delete_evidence(PendingBulkDelete {
                transaction_id: transaction_id.to_owned(),
                artifact_sha256: normalized_artifacts,
                external_mod_ids: normalized_external.into_iter().collect(),
                external_units: Vec::new(),
                profiles_before,
                profiles_after,
                artifacts,
                installation,
                receipt,
                plan: None,
                external_mods: Vec::new(),
                requires_deployment,
                blockers,
                evidence_sha256: String::new(),
            });
        }

        let mut external_mods = Vec::new();
        let mut external_units = Vec::new();
        let mut expanded_external_ids = BTreeSet::new();
        if !normalized_external.is_empty() {
            let Some(installation) = &installation else {
                blockers.push(bulk_delete_blocker(
                    "game_not_found",
                    "No inventoried Retro Rewind Steam installation is available for the selected external mods.",
                    None,
                ));
                return finish_bulk_delete_evidence(PendingBulkDelete {
                    transaction_id: transaction_id.to_owned(),
                    artifact_sha256: normalized_artifacts,
                    external_mod_ids: normalized_external.into_iter().collect(),
                    external_units,
                    profiles_before,
                    profiles_after,
                    artifacts,
                    installation: None,
                    receipt,
                    plan: None,
                    external_mods,
                    requires_deployment,
                    blockers,
                    evidence_sha256: String::new(),
                });
            };
            let all_external = existing_mod_views(
                &installation.installation.game_root,
                &self.paths.deployment_state,
                receipt.as_ref(),
            )?;
            let mut units = BTreeMap::<String, BulkDeleteExternalUnit>::new();
            for selected_id in &normalized_external {
                let Some(selected) = all_external.iter().find(|item| item.id == *selected_id)
                else {
                    blockers.push(bulk_delete_blocker(
                        "external_mod_missing",
                        &format!("Installed mod '{selected_id}' is no longer available."),
                        Some(selected_id),
                    ));
                    continue;
                };
                if let Some(group_id) = &selected.group_id {
                    let members = all_external
                        .iter()
                        .filter(|item| item.group_id.as_ref() == Some(group_id))
                        .map(|item| item.id.clone())
                        .collect::<Vec<_>>();
                    units.insert(
                        format!("group:{group_id}"),
                        BulkDeleteExternalUnit {
                            group_id: Some(group_id.clone()),
                            member_ids: members,
                        },
                    );
                } else {
                    units.insert(
                        format!("mod:{}", selected.id),
                        BulkDeleteExternalUnit {
                            group_id: None,
                            member_ids: vec![selected.id.clone()],
                        },
                    );
                }
            }
            for mut unit in units.into_values() {
                unit.member_ids.sort();
                unit.member_ids.dedup();
                let members = unit
                    .member_ids
                    .iter()
                    .filter_map(|id| all_external.iter().find(|item| item.id == *id).cloned())
                    .collect::<Vec<_>>();
                if unit.group_id.is_some() && members.len() < 2 {
                    blockers.push(bulk_delete_blocker(
                        "external_group_incomplete",
                        "A selected reviewed hybrid group is incomplete and cannot be deleted atomically.",
                        unit.group_id.as_deref(),
                    ));
                }
                for member in &members {
                    expanded_external_ids.insert(member.id.clone());
                    if !member.manageable {
                        blockers.push(bulk_delete_blocker(
                            "external_mod_not_manageable",
                            member
                                .blocked_reason
                                .as_deref()
                                .unwrap_or("This installed mod cannot be deleted safely."),
                            Some(&member.id),
                        ));
                    }
                    if unit.group_id.is_some() && member.mods_txt_controlled {
                        blockers.push(bulk_delete_blocker(
                            "external_group_not_manageable",
                            "A selected hybrid group uses shared mods.txt control and cannot be deleted atomically.",
                            unit.group_id.as_deref(),
                        ));
                    }
                }
                external_mods.extend(members);
                external_units.push(unit);
            }
        }
        external_mods.sort_by(|left, right| left.id.cmp(&right.id));
        external_units.sort_by(|left, right| {
            left.group_id
                .cmp(&right.group_id)
                .then_with(|| left.member_ids.cmp(&right.member_ids))
        });

        let mut plan = None;
        if requires_deployment
            && !blockers.iter().any(|blocker| {
                matches!(
                    blocker.code.as_str(),
                    "game_running"
                        | "recovery_pending"
                        | "artifact_missing"
                        | "artifact_not_manageable"
                        | "receipt_installation_mismatch"
                )
            })
        {
            let active = store
                .active_profile(INSTALLATION_ID)?
                .context("no active profile is selected")?;
            let projected = profiles_after
                .iter()
                .find(|profile| profile.id == active.id)
                .context("active profile projection is unavailable")?;
            match self.compute_plan_for_profile(
                true,
                transaction_id,
                &[],
                Some(projected),
                persist_validation_state,
            ) {
                Ok(computed) => {
                    for message in computed.blockers {
                        blockers.push(bulk_delete_blocker("deployment_conflict", &message, None));
                    }
                    if let Some(computed_plan) = computed.plan {
                        for blocker in &computed_plan.blockers {
                            blockers.push(bulk_delete_blocker(
                                deployment_blocker_code(blocker),
                                &deployment_blocker(blocker),
                                None,
                            ));
                        }
                        for change in computed_plan.changes.iter().filter(|change| {
                            matches!(
                                change.kind,
                                DeploymentChangeKind::ReplaceUnmanaged
                                    | DeploymentChangeKind::AdoptIdenticalUnmanaged
                            )
                        }) {
                            blockers.push(bulk_delete_blocker(
                                "unmanaged_path",
                                &format!(
                                    "Safe deletion would change the unmanaged path '{}'; apply or resolve the profile separately before deleting.",
                                    change.relative_path
                                ),
                                Some(&change.relative_path),
                            ));
                        }
                        if computed_plan.target_receipt.files.iter().any(|file| {
                            file.package_id.as_ref().map_or_else(
                                || selected_file_hashes.contains(&file.sha256),
                                |package_id| selected_package_ids.contains(package_id),
                            )
                        }) {
                            blockers.push(bulk_delete_blocker(
                                "deployment_retains_artifact",
                                "The projected active profile would still deploy a selected artifact hash.",
                                None,
                            ));
                        }
                        plan = Some(computed_plan);
                    } else {
                        blockers.push(bulk_delete_blocker(
                            "deployment_unavailable",
                            "A safe deployment plan could not be constructed for the projected active profile.",
                            None,
                        ));
                    }
                }
                Err(error) => blockers.push(bulk_delete_blocker(
                    "deployment_validation_failed",
                    &format!("The projected deployment could not be validated safely: {error:#}"),
                    None,
                )),
            }
        }

        blockers.sort_by(|left, right| {
            left.code
                .cmp(&right.code)
                .then_with(|| left.item_id.cmp(&right.item_id))
                .then_with(|| left.message.cmp(&right.message))
        });
        blockers.dedup();
        finish_bulk_delete_evidence(PendingBulkDelete {
            transaction_id: transaction_id.to_owned(),
            artifact_sha256: normalized_artifacts,
            external_mod_ids: expanded_external_ids.into_iter().collect(),
            external_units,
            profiles_before,
            profiles_after,
            artifacts,
            installation,
            receipt,
            plan,
            external_mods,
            requires_deployment,
            blockers,
            evidence_sha256: String::new(),
        })
    }

    fn compute_plan(
        &self,
        allow_unmanaged: bool,
        transaction_id: &str,
        managed_file_restore_approvals: &[ManagedFileRestoreApproval],
    ) -> Result<ComputedDeployment> {
        self.compute_plan_for_profile(
            allow_unmanaged,
            transaction_id,
            managed_file_restore_approvals,
            None,
            true,
        )
    }

    fn compute_plan_for_profile(
        &self,
        allow_unmanaged: bool,
        transaction_id: &str,
        managed_file_restore_approvals: &[ManagedFileRestoreApproval],
        profile_override: Option<&DomainProfile>,
        persist_validation_state: bool,
    ) -> Result<ComputedDeployment> {
        let store = self.store()?;
        let recipe = self.deployment_build_recipe()?;
        let catalog = effective_package_catalog(&store, &self.paths.artifact_store)?;
        let installation = selected_installation(&store)?
            .context("no inventoried Retro Rewind Steam installation is available")?;
        if persist_validation_state {
            ensure_desktop_installation_binding(
                &store,
                INSTALLATION_ID,
                &installation.installation.manifest_path,
                &installation.installation.game_root,
            )?;
        } else if let Some((manifest_path, game_root)) =
            store.installation_binding(INSTALLATION_ID)?
            && (!paths_refer_to_same_entry(
                &manifest_path,
                &installation.installation.manifest_path,
            ) || !paths_refer_to_same_entry(&game_root, &installation.installation.game_root))
        {
            bail!("this manager state is already bound to another Retro Rewind installation");
        }
        let stored_profile = store
            .active_profile(INSTALLATION_ID)?
            .context("no active profile is selected")?;
        let profile = profile_override.unwrap_or(&stored_profile);
        if profile.id != stored_profile.id || profile.revision < stored_profile.revision {
            bail!("profile override does not match the active stored profile");
        }
        let request = ResolveRequest {
            build_id: installation.installation.build_id,
            selections: profile
                .packages
                .iter()
                .filter(|package| package.enabled)
                .map(|package| ResolveSelection {
                    artifact_sha256: package.artifact_sha256.clone(),
                    variant: package.variant.clone(),
                })
                .collect(),
        };
        let base_resolution = resolve_packages(&request, &catalog)?;
        let (report, recipes, accepted_floor, catalog_valid_until) =
            match embedded_recipe_catalog_with_persistence(&store, persist_validation_state) {
                EmbeddedRecipeCatalog::Verified {
                    catalog: verified_catalog,
                    floor,
                } => {
                    let report = resolve_and_apply_verified_recipes(
                        &self.paths.artifact_store,
                        &request,
                        &catalog,
                        &verified_catalog,
                        &floor,
                    )?;
                    let preview = recipe_preview(&verified_catalog, &report);
                    let valid_until = verified_catalog.valid_until();
                    (report, preview, floor, valid_until)
                }
                EmbeddedRecipeCatalog::Unavailable(notice) => (
                    RecipeApplicationReport {
                        ready: base_resolution.ready,
                        resolution: base_resolution,
                        applied_recipe_ids: Vec::new(),
                        winner_decisions: Vec::new(),
                        install_name_overrides: Vec::new(),
                        disabled_components: Vec::new(),
                        blockers: Vec::new(),
                    },
                    RecipePreviewView {
                        available: false,
                        applied_recipe_ids: Vec::new(),
                        effects: Vec::new(),
                        notice: Some(notice),
                    },
                    CatalogTrustFloor {
                        root_generation: 0,
                        root_payload_sha256: None,
                        catalog_sequence: 0,
                        catalog_payload_sha256: None,
                    },
                    u64::MAX,
                ),
                EmbeddedRecipeCatalog::Rejected(notice) => {
                    let mut blockers = vec![notice.clone()];
                    blockers.extend(resolution_blockers(&base_resolution.blockers));
                    blockers.sort();
                    blockers.dedup();
                    return Ok(ComputedDeployment {
                        plan: None,
                        profile_id: profile.id.clone(),
                        profile_name: profile.name.clone(),
                        profile_revision: profile.revision,
                        build_id: installation.installation.build_id,
                        blockers,
                        unmanaged_count: 0,
                        pak_conflicts: Vec::new(),
                        recipes: RecipePreviewView {
                            available: false,
                            applied_recipe_ids: Vec::new(),
                            effects: Vec::new(),
                            notice: Some(notice),
                        },
                        disableable_package_ids: BTreeSet::new(),
                        watched_files: Vec::new(),
                    });
                }
            };
        if !report.ready {
            let mut blockers = recipe_application_blockers(&report.blockers);
            blockers.extend(resolution_blockers(&report.resolution.blockers));
            blockers.sort();
            blockers.dedup();
            return Ok(ComputedDeployment {
                plan: None,
                profile_id: profile.id.clone(),
                profile_name: profile.name.clone(),
                profile_revision: profile.revision,
                build_id: installation.installation.build_id,
                blockers,
                unmanaged_count: 0,
                pak_conflicts: Vec::new(),
                recipes,
                disableable_package_ids: BTreeSet::new(),
                watched_files: Vec::new(),
            });
        }
        let validation = validate_recipe_deployment_target_with_profile(
            &store,
            INSTALLATION_ID,
            &profile.id,
            &installation.installation.game_root,
            RecipeDeploymentResolution {
                request: &request,
                package_catalog: &catalog,
                report: &report,
            },
            &recipe,
            RecipeCatalogValidation {
                trust_floor: accepted_floor,
                valid_until: catalog_valid_until,
            },
            profile_override,
        )?;
        let authorized_ue4ss_policies: BTreeSet<_> = validation
            .ue4ss
            .iter()
            .flat_map(|validation| validation.required_policies.iter().cloned())
            .collect();
        let mut deployment = materialize_desktop_deployment_request(
            &self.paths.artifact_store,
            &catalog,
            &report,
            &authorized_ue4ss_policies,
            DeploymentMetadata {
                transaction_id: transaction_id.to_owned(),
                installation_id: INSTALLATION_ID.to_owned(),
                profile_id: profile.id.clone(),
                game_root: installation.installation.game_root.clone(),
                state_root: self.paths.deployment_state.clone(),
                allow_unmanaged,
                game_running: is_game_running(),
            },
        )?;
        let receipt = load_receipt(&self.paths.deployment_state, INSTALLATION_ID)?;
        let unmanaged_files = unmanaged_pak_views_cached(
            &installation.installation.game_root,
            receipt.as_ref(),
            &store,
        )?;
        let conflicts = unmanaged_package_conflicts(profile, &catalog, &unmanaged_files);
        let mut package_blockers = Vec::new();
        let provisional_request = deployment.clone();
        let mut verified_sources = verified_deployment_sources(&store, &deployment.files)?;
        cache_deployment_targets(&store, &deployment, receipt.as_ref(), &mut verified_sources)?;
        let provisional_plan = plan_deployment_with_verified_sources(
            provisional_request.clone(),
            receipt.as_ref(),
            Vec::new(),
            &verified_sources,
        )?;
        let provisional_inputs = activation_pak_inputs(
            &provisional_plan,
            &unmanaged_files,
            &self.paths.artifact_store,
            &catalog,
        )?;
        let provisional_analysis = match self.inspect_activation_paks(
            &provisional_inputs,
            installation.installation.build_id,
            &profile.pak_load_order,
        ) {
            Ok(analysis) => analysis,
            Err(error) => ActivationPakAnalysis {
                blockers: vec![format!(
                    "PAK structural and hash analysis could not be completed safely: {error}"
                )],
                evidence_sha256: sha256_serialized(&format!("pak-analysis-error:{error:#}"))?,
                conflicts: Vec::new(),
            },
        };
        let non_benign_hashes: BTreeSet<_> = provisional_analysis
            .conflicts
            .iter()
            .filter(|conflict| conflict.outcome != "benign_duplicate")
            .flat_map(|conflict| {
                [
                    conflict.first.pak_sha256.clone(),
                    conflict.second.pak_sha256.clone(),
                ]
            })
            .collect();
        package_blockers.extend(
            conflicts
                .iter()
                .filter(|conflict| {
                    unmanaged_files
                        .iter()
                        .find(|file| file.path == conflict.path)
                        .is_none_or(|file| {
                            !provisional_analysis.conflicts.iter().any(|pak_conflict| {
                                if pak_conflict.outcome == "benign_duplicate" {
                                    return false;
                                }
                                let pair = [&pak_conflict.first, &pak_conflict.second];
                                pair.iter().enumerate().any(|(index, party)| {
                                    party.source_kind == "external"
                                        && party.pak_sha256 == file.pak_sha256
                                        && pair[1 - index]
                                            .display_name
                                            .eq_ignore_ascii_case(&conflict.selected_name)
                                })
                            })
                        })
                })
                .map(|conflict| conflict.reason.clone()),
        );

        let mut ordering_blockers = Vec::new();
        if !non_benign_hashes.is_empty() {
            let nodes: Vec<_> = non_benign_hashes
                .iter()
                .map(|pak_sha256| PakLoadOrderNode {
                    pak_sha256: pak_sha256.clone(),
                })
                .collect();
            let constraints = active_pak_constraints(
                installation.installation.build_id,
                &profile.pak_load_order,
                &non_benign_hashes,
            )?;
            match resolve_pak_load_order(&nodes, &constraints) {
                Ok(ordering) => apply_pak_ordering(
                    &mut deployment,
                    &unmanaged_files,
                    receipt.as_ref(),
                    &ordering.slots,
                )?,
                Err(error) => ordering_blockers.push(format!(
                    "PAK load-winner choices cannot be applied because their order graph is invalid: {error}"
                )),
            }
        } else {
            restore_unneeded_external_ordering(
                &mut deployment,
                receipt.as_ref(),
                &BTreeSet::new(),
            )?;
        }

        let plan = if deployment == provisional_request && managed_file_restore_approvals.is_empty()
        {
            provisional_plan
        } else {
            cache_deployment_targets(&store, &deployment, receipt.as_ref(), &mut verified_sources)?;
            plan_deployment_with_verified_sources(
                deployment,
                receipt.as_ref(),
                managed_file_restore_approvals.to_vec(),
                &verified_sources,
            )?
        };
        let pak_inputs = activation_pak_inputs(
            &plan,
            &unmanaged_files,
            &self.paths.artifact_store,
            &catalog,
        )?;
        let pak_analysis = if pak_inputs == provisional_inputs {
            provisional_analysis.clone()
        } else {
            match self.inspect_activation_paks(
                &pak_inputs,
                installation.installation.build_id,
                &profile.pak_load_order,
            ) {
                Ok(analysis) => analysis,
                Err(error) => ActivationPakAnalysis {
                    blockers: vec![format!(
                        "Final PAK structural and hash analysis could not be completed safely: {error}"
                    )],
                    evidence_sha256: sha256_serialized(&format!(
                        "final-pak-analysis-error:{error:#}"
                    ))?,
                    conflicts: Vec::new(),
                },
            }
        };
        if provisional_analysis.conflicts.is_empty() {
            package_blockers.extend(provisional_analysis.blockers);
        }
        package_blockers.extend(ordering_blockers);
        package_blockers.extend(pak_analysis.blockers);
        let disableable_package_ids = exact_disableable_package_ids(profile, &catalog, &plan);
        let watched_files = deployment_file_snapshots(&plan, &pak_inputs)?;
        Ok(ComputedDeployment {
            plan: Some(plan),
            profile_id: profile.id.clone(),
            profile_name: profile.name.clone(),
            profile_revision: profile.revision,
            build_id: installation.installation.build_id,
            blockers: package_blockers,
            unmanaged_count: unmanaged_files.len(),
            pak_conflicts: pak_analysis.conflicts,
            recipes,
            disableable_package_ids,
            watched_files,
        })
    }

    fn deployment_build_recipe(&self) -> Result<BuildRecipe> {
        #[cfg(test)]
        if let Some(recipe) = &self.deployment_build_recipe_override {
            return Ok(recipe.clone());
        }
        build_recipe()
    }

    fn store(&self) -> Result<Store> {
        Store::open(&self.paths.database).map_err(Into::into)
    }

    fn bug_report_active_mods(
        &self,
        store: &Store,
        installation: Option<&rrmm_domain::InstallationInspection>,
    ) -> Result<Vec<BugReportActiveMod>> {
        let catalog = effective_package_catalog(store, &self.paths.artifact_store)?;
        let mut active_mods = Vec::new();
        if let Some(profile) = store.active_profile(INSTALLATION_ID)? {
            for (index, selection) in profile
                .packages
                .iter()
                .filter(|selection| selection.enabled)
                .enumerate()
            {
                let Some(package) = catalog
                    .iter()
                    .find(|package| package.artifact_sha256 == selection.artifact_sha256)
                else {
                    continue;
                };
                let mut types: BTreeSet<_> = package
                    .manifest
                    .components
                    .iter()
                    .map(|component| component_type_name(component.component_type))
                    .collect();
                let priority = package
                    .manifest
                    .components
                    .iter()
                    .filter(|component| component.component_type == ComponentType::Pak)
                    .filter_map(|component| {
                        component
                            .install_name
                            .as_deref()
                            .or_else(|| Path::new(&component.root).file_name()?.to_str())
                    })
                    .map(|name| parse_priority_hint(name).patch_generation)
                    .max();
                active_mods.push(BugReportActiveMod {
                    name: package.manifest.name.clone(),
                    version: package.manifest.version.clone(),
                    mod_type: types.pop_first().map_or_else(
                        || "unknown".to_owned(),
                        |first| {
                            std::iter::once(first)
                                .chain(types)
                                .collect::<Vec<_>>()
                                .join("+")
                        },
                    ),
                    order: Some(index + 1),
                    priority,
                });
            }
        }
        if let Some(installation) = installation {
            let receipt = load_receipt(&self.paths.deployment_state, INSTALLATION_ID)?;
            let existing = existing_mod_views(
                &installation.installation.game_root,
                &self.paths.deployment_state,
                receipt.as_ref(),
            )?;
            let reviewed_groups = external_mod_groups()?;
            for item in existing.into_iter().filter(|item| item.enabled) {
                let version = item
                    .group_id
                    .as_deref()
                    .and_then(|group_id| {
                        reviewed_groups
                            .iter()
                            .find(|group| group.package_id == group_id)
                    })
                    .map(|group| group.version.clone())
                    .unwrap_or_else(|| "unknown".to_owned());
                let priority = (item.mod_type == "pak").then(|| {
                    Path::new(&item.path)
                        .file_name()
                        .map(|name| parse_priority_hint(&name.to_string_lossy()).patch_generation)
                        .unwrap_or_default()
                });
                active_mods.push(BugReportActiveMod {
                    name: item.group_name.unwrap_or(item.display_name),
                    version,
                    mod_type: item.mod_type,
                    order: None,
                    priority,
                });
            }
        }
        Ok(active_mods)
    }

    fn token(&self, prefix: &str) -> String {
        let value = self.nonce.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}-{}-{value}", Utc::now().timestamp_millis())
    }

    fn run_archive_worker(&self, request: ArchiveWorkerRequest) -> Result<ArchiveWorkerResponse> {
        #[cfg(test)]
        if self.archive_worker == Path::new(":in-process-archive-worker:") {
            let mut response = rrmm_archive::execute_worker_request(request);
            response.sandboxed = response.ok;
            if !response.ok {
                bail!(
                    "archive worker rejected the operation: {}",
                    response.error.as_deref().unwrap_or("unknown worker error")
                );
            }
            return Ok(response);
        }
        let timeout = archive_request_path(&request)
            .map(worker_processing_timeout)
            .unwrap_or_else(|| Duration::from_secs(300));
        let response: ArchiveWorkerResponse =
            run_json_worker(&self.archive_worker, "archive worker", &request, timeout)?;
        if response.ok && !response.sandboxed {
            bail!("archive worker completed without the required OS sandbox");
        }
        if !response.ok {
            bail!(
                "archive worker rejected the operation: {}",
                response.error.as_deref().unwrap_or("unknown worker error")
            );
        }
        Ok(response)
    }

    fn run_pak_worker(&self, request: PakWorkerRequest) -> Result<PakWorkerResponse> {
        #[cfg(test)]
        if self.pak_worker == Path::new(":in-process-pak-worker:") {
            let mut response = rrmm_pak::execute_worker_request(request);
            response.sandboxed = response.ok;
            if !response.ok {
                bail!(
                    "PAK worker rejected the operation: {}",
                    response.error.as_deref().unwrap_or("unknown worker error")
                );
            }
            return Ok(response);
        }
        let timeout = pak_request_path(&request)
            .map(worker_processing_timeout)
            .unwrap_or_else(|| Duration::from_secs(300));
        let response: PakWorkerResponse =
            run_json_worker(&self.pak_worker, "PAK worker", &request, timeout)?;
        if response.ok && !response.sandboxed {
            bail!("PAK worker completed without the required OS sandbox");
        }
        if !response.ok {
            bail!(
                "PAK worker rejected the operation: {}",
                response.error.as_deref().unwrap_or("unknown worker error")
            );
        }
        Ok(response)
    }

    fn download_ue4ss_archive(&self, artifact: &Ue4ssLoaderArtifact) -> Result<PathBuf> {
        let operation = "installOrRepairUe4ss";
        let cache = self.paths.data_root.join("downloads");
        fs::create_dir_all(&cache)?;
        if !fs::symlink_metadata(&cache)?.file_type().is_dir() {
            bail!("UE4SS download cache is not a regular directory");
        }
        let destination = cache.join(&artifact.filename);
        if destination.exists() {
            let metadata = fs::symlink_metadata(&destination)?;
            if !metadata.file_type().is_file() {
                bail!("UE4SS cached archive is not a regular file");
            }
            let cached_sha256 = rrmm_archive::sha256_path(&destination)?;
            self.operation_detail(
                operation,
                "cachedArchiveBytes",
                serde_json::json!(metadata.len()),
            );
            self.operation_detail(
                operation,
                "cachedArchiveSha256",
                serde_json::json!(cached_sha256),
            );
            if metadata.len() == artifact.archive_size && cached_sha256 == artifact.archive_sha256 {
                self.operation_detail(
                    operation,
                    "archiveSource",
                    serde_json::json!("verified_cache"),
                );
                return Ok(destination);
            }
            fs::remove_file(&destination)?;
        }
        if desktop_preferences(&self.store()?)?.offline_mode {
            bail!("offline mode is enabled and no verified cached UE4SS archive is available");
        }
        let partial = cache.join(format!(
            ".{}-{}.partial",
            artifact.filename,
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let download = (|| {
            let client = reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::custom(|attempt| {
                    let url = attempt.url();
                    let trusted = url.scheme() == "https"
                        && url.host_str().is_some_and(|host| {
                            host == "github.com"
                                || host == "release-assets.githubusercontent.com"
                                || host.ends_with(".githubusercontent.com")
                        });
                    if trusted && attempt.previous().len() < 5 {
                        attempt.follow()
                    } else {
                        attempt.stop()
                    }
                }))
                .timeout(Duration::from_secs(120))
                .build()?;
            let response = client.get(&artifact.url).send()?;
            self.operation_detail(
                operation,
                "httpStatus",
                serde_json::json!(response.status().as_u16()),
            );
            let mut response = response.error_for_status()?;
            let final_url = response.url();
            let trusted_host = final_url.host_str().is_some_and(|host| {
                host == "github.com"
                    || host == "release-assets.githubusercontent.com"
                    || host.ends_with(".githubusercontent.com")
            });
            if final_url.scheme() != "https" || !trusted_host {
                bail!("UE4SS download redirected outside trusted GitHub HTTPS hosts");
            }
            if response
                .content_length()
                .is_some_and(|size| size != artifact.archive_size)
            {
                bail!("UE4SS download size does not match the pinned artifact");
            }
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&partial)?;
            let total = copy_verified_ue4ss_download(
                &mut response,
                &mut output,
                artifact.archive_size,
                &artifact.archive_sha256,
            )?;
            output.sync_all()?;
            fs::rename(&partial, &destination)?;
            sync_directory_if_supported(&cache)?;
            let installed_metadata = fs::symlink_metadata(&destination)?;
            if !installed_metadata.file_type().is_file()
                || installed_metadata.len() != artifact.archive_size
                || rrmm_archive::sha256_path(&destination)? != artifact.archive_sha256
            {
                bail!("UE4SS cached download changed while it was being finalized");
            }
            self.operation_detail(operation, "archiveSource", serde_json::json!("network"));
            self.operation_detail(
                operation,
                "downloadedArchiveBytes",
                serde_json::json!(total),
            );
            self.operation_detail(
                operation,
                "downloadedArchiveSha256",
                serde_json::json!(artifact.archive_sha256),
            );
            Ok(destination.clone())
        })();
        if download.is_err() {
            let _ = fs::remove_file(partial);
        }
        download
    }

    fn inspect_activation_paks(
        &self,
        inputs: &[ActivationPakInput],
        build_id: u64,
        preferences: &[PakLoadOrderPreference],
    ) -> Result<ActivationPakAnalysis> {
        const MAX_HASH_REQUEST_BYTES: usize = 900 * 1024;

        let cache_key = activation_pak_analysis_cache_key(inputs, build_id, preferences)?;
        if let Some(cache_key) = &cache_key
            && let Some(analysis) = self
                .store()?
                .activation_pak_analysis::<ActivationPakAnalysis>(cache_key)?
        {
            return Ok(analysis);
        }

        let limits = desktop_pak_limits();
        let mut original_by_effective = BTreeMap::<PathBuf, (PathBuf, PakInventory)>::new();
        let mut inventories = Vec::with_capacity(inputs.len());
        for input in inputs {
            let observed_bytes = fs::metadata(&input.read_path)
                .with_context(|| format!("failed to inspect {}", input.display_path))?
                .len();
            let response = self.run_pak_worker(PakWorkerRequest::Inspect {
                pak: input.read_path.clone(),
                limits: limits.clone(),
                hash_members: Vec::new(),
            })?;
            if !response.member_digests.is_empty()
                || response.index_metadata_sha256.is_some()
                || response.error.is_some()
            {
                bail!("PAK worker returned an invalid inventory-only response");
            }
            let original = response
                .inventory
                .context("PAK worker omitted its inventory")?;
            validate_inventory_contract(&original, &input.read_path, observed_bytes, &limits)?;
            let mut projected = original.clone();
            projected.archive_path = input.effective_path.clone();
            projected.archive_name = input
                .effective_path
                .file_name()
                .context("effective PAK path has no filename")?
                .to_string_lossy()
                .into_owned();
            projected.priority = parse_priority_hint(&projected.archive_name);
            if original_by_effective
                .insert(
                    input.effective_path.clone(),
                    (input.read_path.clone(), original),
                )
                .is_some()
            {
                bail!("multiple active PAKs resolve to the same effective path");
            }
            inventories.push(projected);
        }

        let requests = overlapping_member_hash_requests(&inventories);
        let mut by_archive = BTreeMap::<PathBuf, Vec<_>>::new();
        for request in requests {
            by_archive
                .entry(request.archive_path.clone())
                .or_default()
                .push(request);
        }
        let mut evidence = Vec::new();
        for (effective_path, requests) in by_archive {
            let (read_path, original) = original_by_effective
                .get(&effective_path)
                .context("PAK hash request did not match an inventory")?;
            let mut batches: Vec<Vec<_>> = Vec::new();
            let mut batch = Vec::new();
            let mut batch_bytes = 0_usize;
            for request in requests {
                let request_bytes = request.stored_path.len().saturating_add(16);
                if request_bytes > MAX_HASH_REQUEST_BYTES {
                    bail!("PAK member path is too large for the worker protocol");
                }
                if !batch.is_empty()
                    && batch_bytes.saturating_add(request_bytes) > MAX_HASH_REQUEST_BYTES
                {
                    batches.push(std::mem::take(&mut batch));
                    batch_bytes = 0;
                }
                batch_bytes = batch_bytes.saturating_add(request_bytes);
                batch.push(request);
            }
            if !batch.is_empty() {
                batches.push(batch);
            }
            for batch in batches {
                let response = self.run_pak_worker(PakWorkerRequest::Inspect {
                    pak: read_path.clone(),
                    limits: limits.clone(),
                    hash_members: batch
                        .iter()
                        .map(|request| request.stored_path.clone())
                        .collect(),
                })?;
                let current = response
                    .inventory
                    .context("PAK worker omitted its inventory while hashing")?;
                if current != *original {
                    bail!("PAK changed while structural and hash evidence was being analyzed");
                }
                if response.index_metadata_sha256.is_some() || response.error.is_some() {
                    bail!("PAK worker returned an invalid hash response");
                }
                let mut digests = BTreeMap::new();
                for digest in response.member_digests {
                    if digest.sha256.len() != 64
                        || !digest.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                        || digests.insert(digest.stored_path, digest.sha256).is_some()
                    {
                        bail!("PAK worker returned invalid or duplicate member evidence");
                    }
                }
                if digests.len() != batch.len() {
                    bail!("PAK worker returned incomplete member evidence");
                }
                for request in batch {
                    let sha256 = digests.remove(&request.stored_path).with_context(|| {
                        format!("PAK worker omitted hash for {}", request.stored_path)
                    })?;
                    evidence.push(MemberHashEvidence {
                        archive_path: effective_path.clone(),
                        collision_key: request.collision_key,
                        sha256,
                    });
                }
                if !digests.is_empty() {
                    bail!("PAK worker returned unexpected member evidence");
                }
            }
        }
        evidence.sort_by(|left, right| {
            left.archive_path
                .cmp(&right.archive_path)
                .then_with(|| left.collision_key.cmp(&right.collision_key))
        });
        let graph = analyze_conflicts(&inventories, &evidence);
        let mut blockers = Vec::new();
        let mut conflicts = Vec::new();
        for edge in &graph.edges {
            let first_input = activation_pak_input(inputs, &edge.first_archive)?;
            let second_input = activation_pak_input(inputs, &edge.second_archive)?;
            let first = pak_conflict_party(first_input);
            let second = pak_conflict_party(second_input);
            let selected_winner_pak_sha256 =
                selected_pak_winner(build_id, preferences, &first.pak_sha256, &second.pak_sha256);
            let winner_pak_sha256 = edge
                .winner
                .as_ref()
                .and_then(|winner| activation_pak_input(inputs, winner).ok())
                .map(|input| input.pak_sha256.clone());
            let conflict_identity = pak_conflict_identity(&first, &second)?;
            let conflict_id = sha256_serialized(&(
                conflict_identity,
                &edge.domains,
                &edge.members,
                &edge.packages,
            ))?;
            if let Some(blocker) = pak_conflict_selection_blocker(
                edge.outcome,
                &first,
                &second,
                selected_winner_pak_sha256.as_deref(),
                winner_pak_sha256.as_deref(),
            ) {
                blockers.push(blocker);
            }
            conflicts.push(PakConflictView {
                conflict_id,
                first_archive: first.archive.clone(),
                second_archive: second.archive.clone(),
                first,
                second,
                outcome: match edge.outcome {
                    PakConflictOutcome::BenignDuplicate => "benign_duplicate",
                    PakConflictOutcome::OrderedWithLoss => "ordered_with_loss",
                    PakConflictOutcome::UnknownOrder => "unknown_order",
                }
                .to_owned(),
                winner: edge
                    .winner
                    .as_ref()
                    .map(|winner| display_activation_pak(inputs, winner)),
                winner_pak_sha256,
                selected_winner_pak_sha256,
                order_confidence: match edge.order_confidence {
                    rrmm_pak::PakOrderConfidence::ObservedPatchGeneration => {
                        "observed_patch_generation"
                    }
                    rrmm_pak::PakOrderConfidence::UnverifiedLexicalTie => "unverified_lexical_tie",
                }
                .to_owned(),
                winner_reason: edge.winner_reason.clone(),
                domains: edge
                    .domains
                    .iter()
                    .map(|domain| match domain {
                        rrmm_pak::PakConflictDomain::CookedPackage => "cooked_package",
                        rrmm_pak::PakConflictDomain::Localization => "localization",
                        rrmm_pak::PakConflictDomain::LooseFile => "loose_file",
                    })
                    .map(str::to_owned)
                    .collect(),
                affected_member_count: edge.members.len(),
                affected_package_count: edge.packages.len(),
                split_package: edge.packages.iter().any(|package| package.split_package),
            });
        }
        let evidence_sha256 = sha256_serialized(&(
            inputs,
            inventories,
            evidence,
            &graph,
            build_id,
            preferences,
            &conflicts,
        ))?;
        let analysis = ActivationPakAnalysis {
            blockers,
            evidence_sha256,
            conflicts,
        };
        if let Some(cache_key) = &cache_key {
            self.store()?
                .upsert_activation_pak_analysis(cache_key, &analysis)?;
        }
        Ok(analysis)
    }

    fn inspect_import_conflicts(
        &self,
        extraction: &ArchiveExtractionReport,
        manifest: &ArtifactManifest,
        package: Option<&CatalogPackage>,
        package_name: &str,
        activation_supported: bool,
    ) -> ImportConflictReview {
        let inspected = (|| -> Result<ImportConflictReview> {
            let store = self.store()?;
            let installation = selected_installation(&store)?
                .context("no inventoried Retro Rewind installation is available")?;
            let game_root = fs::canonicalize(&installation.installation.game_root)
                .context("the selected Retro Rewind installation cannot be inspected")?;
            if !fs::metadata(&game_root)?.is_dir() {
                bail!("the selected Retro Rewind installation is not a directory");
            }
            let profile = store
                .active_profile(INSTALLATION_ID)?
                .context("no active profile is selected for conflict analysis")?;
            let catalog = effective_package_catalog(&store, &self.paths.artifact_store)?;
            let receipt = load_receipt(&self.paths.deployment_state, INSTALLATION_ID)?;
            if receipt
                .as_ref()
                .is_some_and(|receipt| !paths_refer_to_same_entry(&receipt.game_root, &game_root))
            {
                bail!("deployment state belongs to a different game installation");
            }

            let destinations = planned_import_destinations(manifest, activation_supported);
            let destination_conflicts = inspect_import_destinations(
                &ImportDestinationInspection {
                    game_root: &game_root,
                    manifest,
                    package,
                    package_name,
                    receipt: receipt.as_ref(),
                    catalog: &catalog,
                    artifact_store: &self.paths.artifact_store,
                },
                &destinations,
            )?;

            let candidate_paks: Vec<_> = manifest
                .layout
                .pak_files
                .iter()
                .filter_map(|path| {
                    manifest
                        .files
                        .iter()
                        .find(|file| file.path == *path)
                        .map(|file| (path, file))
                })
                .collect();
            if candidate_paks.len() != manifest.layout.pak_files.len() {
                bail!("one or more candidate PAKs are absent from the extracted file report");
            }

            let mut pak_conflicts = Vec::new();
            let mut pak_evidence_sha256 = sha256_serialized(&"no-candidate-paks")?;
            if !candidate_paks.is_empty() {
                let canonical_staging_root = fs::canonicalize(&extraction.staging_root)
                    .context("private archive staging is unavailable")?;
                if !fs::metadata(&canonical_staging_root)?.is_dir() {
                    bail!("private archive staging is not a directory");
                }
                let mut inputs = Vec::new();
                for (index, (path, file)) in candidate_paks.iter().enumerate() {
                    let read_path = fs::canonicalize(extraction.staging_root.join(Path::new(path)))
                        .with_context(|| format!("failed to resolve candidate PAK '{path}'"))?;
                    if !read_path.starts_with(&canonical_staging_root)
                        || !fs::metadata(&read_path)?.is_file()
                    {
                        bail!("candidate PAK escaped or changed in private staging");
                    }
                    let file_name = Path::new(path)
                        .file_name()
                        .context("candidate PAK has no filename")?;
                    inputs.push(ActivationPakInput {
                        read_path,
                        effective_path: game_root
                            .join(".rrmm-import-review")
                            .join("candidate")
                            .join(index.to_string())
                            .join(file_name),
                        display_path: path.to_string(),
                        pak_sha256: file.sha256.clone(),
                        destination: destinations.get(path.as_str()).cloned(),
                        owner: ActivationPakOwner {
                            display_name: package_name.to_owned(),
                            package_id: package.map(|package| package.manifest.id.clone()),
                            source_kind: "candidate".to_owned(),
                            artifact_sha256: Some(manifest.sha256.clone()),
                            existing_mod_id: None,
                            manageable: false,
                            original_path: None,
                        },
                    });
                }

                if let Some(receipt) = &receipt {
                    for (index, file) in receipt
                        .files
                        .iter()
                        .filter(|file| {
                            Path::new(&file.relative_path)
                                .extension()
                                .is_some_and(|extension| extension.eq_ignore_ascii_case("pak"))
                        })
                        .enumerate()
                    {
                        let read_path = checked_game_mod_path(&game_root, &file.relative_path)?;
                        let owner =
                            receipt_managed_owner(file, &catalog, &self.paths.artifact_store)?;
                        let file_name = Path::new(&file.relative_path)
                            .file_name()
                            .context("managed PAK has no filename")?;
                        inputs.push(ActivationPakInput {
                            read_path,
                            effective_path: game_root
                                .join(".rrmm-import-review")
                                .join("managed")
                                .join(index.to_string())
                                .join(file_name),
                            display_path: file.relative_path.clone(),
                            pak_sha256: file.sha256.clone(),
                            destination: Some(file.relative_path.clone()),
                            owner,
                        });
                    }
                }

                for (index, file) in
                    unmanaged_pak_views_cached(&game_root, receipt.as_ref(), &store)?
                        .into_iter()
                        .enumerate()
                {
                    let read_path = checked_game_mod_path(&game_root, &file.path)?;
                    let file_name = Path::new(&file.path)
                        .file_name()
                        .context("external PAK has no filename")?;
                    inputs.push(ActivationPakInput {
                        read_path,
                        effective_path: game_root
                            .join(".rrmm-import-review")
                            .join("external")
                            .join(index.to_string())
                            .join(file_name),
                        display_path: file.path.clone(),
                        pak_sha256: file.pak_sha256,
                        destination: Some(file.path.clone()),
                        owner: ActivationPakOwner {
                            display_name: file
                                .display_name
                                .unwrap_or_else(|| "External PAK".to_owned()),
                            package_id: None,
                            source_kind: "external".to_owned(),
                            artifact_sha256: None,
                            existing_mod_id: file.existing_mod_id,
                            manageable: file.manageable,
                            original_path: Some(file.original_path),
                        },
                    });
                }
                inputs.sort_by(|left, right| left.effective_path.cmp(&right.effective_path));
                let analysis = self.inspect_activation_paks(
                    &inputs,
                    installation.installation.build_id,
                    &profile.pak_load_order,
                )?;
                pak_evidence_sha256 = analysis.evidence_sha256;
                pak_conflicts = analysis
                    .conflicts
                    .into_iter()
                    .filter(|conflict| {
                        conflict.first.source_kind == "candidate"
                            || conflict.second.source_kind == "candidate"
                    })
                    .collect();
            }

            let mut warnings = Vec::new();
            if !pak_conflicts.is_empty() {
                warnings.push(UiNoticeView {
                    code: "pak_conflicts_detected".to_owned(),
                    path: None,
                    count: Some(pak_conflicts.len()),
                });
            }
            if !destination_conflicts.is_empty() {
                warnings.push(UiNoticeView {
                    code: "destination_conflicts_detected".to_owned(),
                    path: None,
                    count: Some(destination_conflicts.len()),
                });
            }
            let blocked_reasons = destination_conflicts
                .iter()
                .filter(|conflict| conflict.blocking)
                .map(|conflict| UiNoticeView {
                    code: "unsafe_planned_destination".to_owned(),
                    path: Some(conflict.destination.clone()),
                    count: None,
                })
                .collect::<Vec<_>>();
            let evidence_sha256 = sha256_serialized(&(
                &game_root,
                installation.installation.build_id,
                &profile.id,
                profile.revision,
                receipt.as_ref(),
                &pak_evidence_sha256,
                &pak_conflicts,
                &destination_conflicts,
            ))?;
            Ok(ImportConflictReview {
                conflict_check_complete: true,
                pak_conflicts,
                destination_conflicts,
                warnings,
                blocked_reasons,
                evidence_sha256,
            })
        })();

        inspected.unwrap_or_else(|error| ImportConflictReview {
            conflict_check_complete: false,
            pak_conflicts: Vec::new(),
            destination_conflicts: Vec::new(),
            warnings: Vec::new(),
            blocked_reasons: vec![UiNoticeView {
                code: "conflict_check_incomplete".to_owned(),
                path: None,
                count: None,
            }],
            evidence_sha256: sha256_serialized(&format!(
                "import-conflict-analysis-error:{error:#}"
            ))
            .unwrap_or_else(|_| "conflict-analysis-error".to_owned()),
        })
    }
}

impl Drop for DesktopApplication {
    fn drop(&mut self) {
        if let Ok(reviews) = self.pending_import_reviews.get_mut() {
            for review in std::mem::take(reviews).into_values() {
                let _ = fs::remove_dir_all(review.extraction.staging_root);
            }
        }
    }
}

fn inspect_import_destinations(
    inspection: &ImportDestinationInspection<'_>,
    destinations: &BTreeMap<String, String>,
) -> Result<Vec<ArchiveDestinationConflictView>> {
    let package_id = inspection
        .package
        .map(|package| package.manifest.id.clone())
        .unwrap_or_else(|| format!("local:{}", &inspection.manifest.sha256[..12]));
    let mut by_destination = BTreeMap::<String, Vec<String>>::new();
    for (source, destination) in destinations {
        by_destination
            .entry(destination.clone())
            .or_default()
            .push(source.clone());
    }
    let mut conflicts = Vec::new();
    for (destination, mut sources) in by_destination {
        sources.sort();
        let candidate_parties = sources
            .iter()
            .map(|source| ArchiveConflictPartyView {
                id: package_id.clone(),
                name: inspection.package_name.to_owned(),
                source_kind: "candidate".to_owned(),
                path: source.clone(),
            })
            .collect::<Vec<_>>();
        if sources.len() > 1 {
            let conflict_id =
                sha256_serialized(&("duplicate_candidate_destination", &destination, &sources))?;
            conflicts.push(ArchiveDestinationConflictView {
                conflict_id,
                destination: destination.clone(),
                parties: candidate_parties.clone(),
                outcome: "duplicate_candidate_destination".to_owned(),
                winner: None,
                confidence: "exact_planned_destination".to_owned(),
                reason: "multiple files from the candidate package plan the same destination"
                    .to_owned(),
                blocking: false,
            });
        }

        let destination_path = inspection.game_root.join(Path::new(&destination));
        let mut current = inspection.game_root.to_path_buf();
        let mut unsafe_parent = None;
        if let Some(parent) = Path::new(&destination).parent() {
            for component in parent.components() {
                let std::path::Component::Normal(component) = component else {
                    bail!("planned import destination is not normalized");
                };
                current.push(component);
                match fs::symlink_metadata(&current) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        unsafe_parent = Some(current.clone());
                        break;
                    }
                    Ok(metadata) if !metadata.is_dir() => {
                        unsafe_parent = Some(current.clone());
                        break;
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                    Err(error) => return Err(error.into()),
                }
            }
        }
        if let Some(unsafe_path) = unsafe_parent {
            let relative = unsafe_path
                .strip_prefix(inspection.game_root)
                .unwrap_or(&unsafe_path)
                .to_string_lossy()
                .replace('\\', "/");
            let mut parties = candidate_parties.clone();
            parties.push(ArchiveConflictPartyView {
                id: format!("filesystem:{relative}"),
                name: "Unsafe filesystem entry".to_owned(),
                source_kind: "filesystem".to_owned(),
                path: relative,
            });
            conflicts.push(ArchiveDestinationConflictView {
                conflict_id: sha256_serialized(&(
                    "unsafe_destination_parent",
                    &destination,
                    &parties,
                ))?,
                destination,
                parties,
                outcome: "unsafe_filesystem_entry".to_owned(),
                winner: None,
                confidence: "exact_filesystem_snapshot".to_owned(),
                reason: "a planned destination traverses a link or non-directory entry".to_owned(),
                blocking: true,
            });
            continue;
        }

        let metadata = match fs::symlink_metadata(&destination_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let managed = inspection.receipt.and_then(|receipt| {
            receipt
                .files
                .iter()
                .find(|file| file.relative_path == destination)
        });
        let (occupant, outcome, reason, blocking) = if metadata.file_type().is_file() {
            if let Some(file) = managed {
                let owner =
                    receipt_managed_owner(file, inspection.catalog, inspection.artifact_store)?;
                (
                    ArchiveConflictPartyView {
                        id: owner
                            .package_id
                            .unwrap_or_else(|| format!("managed:{}", &file.sha256[..12])),
                        name: owner.display_name,
                        source_kind: "managed".to_owned(),
                        path: destination.clone(),
                    },
                    "occupied_managed_destination",
                    "the planned destination is currently owned by the active profile",
                    false,
                )
            } else {
                let sha256 = rrmm_archive::sha256_path(&destination_path)?;
                (
                    ArchiveConflictPartyView {
                        id: format!("external:{}", &sha256[..12]),
                        name: "External/unmanaged file".to_owned(),
                        source_kind: "external".to_owned(),
                        path: destination.clone(),
                    },
                    "occupied_unmanaged_destination",
                    "an external or unmanaged file currently occupies the planned destination",
                    false,
                )
            }
        } else {
            (
                ArchiveConflictPartyView {
                    id: format!("filesystem:{}", sha256_serialized(&destination)?),
                    name: "Unsafe filesystem entry".to_owned(),
                    source_kind: "filesystem".to_owned(),
                    path: destination.clone(),
                },
                "unsafe_filesystem_entry",
                "a link, directory, or special entry occupies the planned file destination",
                true,
            )
        };
        let mut parties = candidate_parties;
        parties.push(occupant);
        conflicts.push(ArchiveDestinationConflictView {
            conflict_id: sha256_serialized(&(outcome, &destination, &parties))?,
            destination,
            parties,
            outcome: outcome.to_owned(),
            winner: None,
            confidence: "exact_filesystem_snapshot".to_owned(),
            reason: reason.to_owned(),
            blocking,
        });
    }
    conflicts.sort_by(|left, right| {
        left.destination
            .cmp(&right.destination)
            .then_with(|| left.outcome.cmp(&right.outcome))
    });
    Ok(conflicts)
}

fn receipt_managed_owner(
    file: &rrmm_deploy::OwnedFile,
    catalog: &[CatalogPackage],
    artifact_store: &Path,
) -> Result<ActivationPakOwner> {
    let exact = if file.package_id.is_some() && file.package_name.is_some() {
        file.package_id.clone().zip(file.package_name.clone())
    } else {
        exact_package_owner(&file.sha256, catalog, artifact_store)?
    };
    Ok(ActivationPakOwner {
        display_name: exact
            .as_ref()
            .map(|(_, name)| name.clone())
            .unwrap_or_else(|| "Previously managed package".to_owned()),
        package_id: exact.map(|(id, _)| id),
        source_kind: "managed".to_owned(),
        artifact_sha256: None,
        existing_mod_id: None,
        manageable: true,
        original_path: None,
    })
}

fn exact_package_owner(
    file_sha256: &str,
    catalog: &[CatalogPackage],
    artifact_store: &Path,
) -> Result<Option<(String, String)>> {
    let mut owners = BTreeSet::new();
    for package in catalog {
        let root = artifact_store
            .join("artifacts")
            .join(&package.artifact_sha256[..2])
            .join(&package.artifact_sha256);
        let Ok(artifact) = load_verified_artifact(&root) else {
            continue;
        };
        if artifact.files.iter().any(|file| file.sha256 == file_sha256) {
            owners.insert((package.manifest.id.clone(), package.manifest.name.clone()));
        }
    }
    Ok((owners.len() == 1)
        .then(|| owners.into_iter().next())
        .flatten())
}

fn archive_request_path(request: &ArchiveWorkerRequest) -> Option<&Path> {
    match request {
        ArchiveWorkerRequest::Preflight { archive, .. }
        | ArchiveWorkerRequest::Extract { archive, .. } => Some(archive),
    }
}

fn pak_request_path(request: &PakWorkerRequest) -> Option<&Path> {
    match request {
        PakWorkerRequest::Fingerprint { pak, .. } | PakWorkerRequest::Inspect { pak, .. } => {
            Some(pak)
        }
    }
}

fn worker_processing_timeout(path: &Path) -> Duration {
    const GIB: u64 = 1024 * 1024 * 1024;
    let gibibytes = fs::metadata(path)
        .map(|metadata| metadata.len().div_ceil(GIB))
        .unwrap_or(0);
    Duration::from_secs(300_u64.saturating_add(gibibytes.saturating_mul(300)))
}

fn activation_pak_inputs(
    plan: &DeploymentPlan,
    unmanaged: &[UnmanagedFileView],
    artifact_store: &Path,
    catalog: &[CatalogPackage],
) -> Result<Vec<ActivationPakInput>> {
    let mut inputs = Vec::new();
    let mut planned_paths = BTreeSet::new();
    for file in &plan.files {
        if !Path::new(&file.relative_path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("pak"))
        {
            continue;
        }
        let read_path = fs::canonicalize(&file.source)
            .with_context(|| format!("failed to resolve {}", file.source.display()))?;
        if !fs::metadata(&read_path)?.is_file() {
            bail!("selected PAK source is not a regular file");
        }
        planned_paths.insert(file.relative_path.to_ascii_lowercase());
        inputs.push(ActivationPakInput {
            read_path,
            effective_path: plan.game_root.join(Path::new(&file.relative_path)),
            display_path: file.relative_path.clone(),
            pak_sha256: file.sha256.clone(),
            destination: Some(file.relative_path.clone()),
            owner: if let (Some(package_id), Some(package_name)) =
                (&file.package_id, &file.package_name)
            {
                ActivationPakOwner {
                    display_name: package_name.clone(),
                    package_id: Some(package_id.clone()),
                    source_kind: "managed".to_owned(),
                    artifact_sha256: catalog
                        .iter()
                        .find(|package| package.manifest.id == *package_id)
                        .map(|package| package.artifact_sha256.clone()),
                    existing_mod_id: None,
                    manageable: true,
                    original_path: None,
                }
            } else {
                managed_pak_owner(&file.source, artifact_store, catalog)
            },
        });
    }
    for file in unmanaged {
        let path = checked_game_mod_path(&plan.game_root, &file.path)?;
        let read_path = fs::canonicalize(&path)
            .with_context(|| format!("failed to resolve unmanaged PAK {}", file.path))?;
        if !fs::metadata(&read_path)?.is_file() {
            bail!("unmanaged PAK is not a regular file: {}", file.path);
        }
        let effective_relative = plan
            .external_files
            .iter()
            .find(|external| external.source_relative_path == file.path)
            .map(|external| external.target_relative_path.clone())
            .unwrap_or_else(|| file.path.clone());
        if planned_paths.contains(&effective_relative.to_ascii_lowercase()) {
            continue;
        }
        inputs.push(ActivationPakInput {
            effective_path: plan.game_root.join(&effective_relative),
            read_path,
            display_path: effective_relative.clone(),
            pak_sha256: file.pak_sha256.clone(),
            destination: Some(effective_relative),
            owner: ActivationPakOwner {
                display_name: file.display_name.clone().unwrap_or_else(|| {
                    Path::new(&file.original_path)
                        .file_stem()
                        .map(|stem| stem.to_string_lossy().into_owned())
                        .unwrap_or_else(|| file.original_path.clone())
                }),
                package_id: None,
                source_kind: "external".to_owned(),
                artifact_sha256: None,
                existing_mod_id: file.existing_mod_id.clone(),
                manageable: file.manageable,
                original_path: Some(file.original_path.clone()),
            },
        });
    }
    inputs.sort_by(|left, right| left.effective_path.cmp(&right.effective_path));
    Ok(inputs)
}

fn managed_pak_owner(
    source: &Path,
    artifact_store: &Path,
    catalog: &[CatalogPackage],
) -> ActivationPakOwner {
    let package = catalog.iter().find(|package| {
        source.starts_with(
            artifact_store
                .join("artifacts")
                .join(&package.artifact_sha256[..2])
                .join(&package.artifact_sha256),
        )
    });
    ActivationPakOwner {
        display_name: package
            .map(|package| package.manifest.name.clone())
            .unwrap_or_else(|| "Managed PAK".to_owned()),
        package_id: package.map(|package| package.manifest.id.clone()),
        source_kind: "managed".to_owned(),
        artifact_sha256: package.map(|package| package.artifact_sha256.clone()),
        existing_mod_id: None,
        manageable: true,
        original_path: None,
    }
}

fn activation_pak_input<'a>(
    inputs: &'a [ActivationPakInput],
    effective_path: &Path,
) -> Result<&'a ActivationPakInput> {
    inputs
        .iter()
        .find(|input| input.effective_path == effective_path)
        .context("PAK conflict references an unknown activation input")
}

fn pak_conflict_party(input: &ActivationPakInput) -> PakConflictPartyView {
    let load_order = input
        .effective_path
        .file_name()
        .map(|name| parse_priority_hint(&name.to_string_lossy()).patch_generation)
        .unwrap_or_default();
    PakConflictPartyView {
        archive: input.display_path.clone(),
        display_name: input.owner.display_name.clone(),
        package_id: input.owner.package_id.clone(),
        pak_sha256: input.pak_sha256.clone(),
        source_kind: input.owner.source_kind.clone(),
        artifact_sha256: input.owner.artifact_sha256.clone(),
        existing_mod_id: input.owner.existing_mod_id.clone(),
        manageable: input.owner.manageable,
        load_order,
        destination: input.destination.clone(),
    }
}

fn pak_conflict_selection_blocker(
    outcome: PakConflictOutcome,
    first: &PakConflictPartyView,
    second: &PakConflictPartyView,
    selected_winner: Option<&str>,
    effective_winner: Option<&str>,
) -> Option<String> {
    if outcome == PakConflictOutcome::BenignDuplicate {
        return None;
    }
    if !first.manageable || !second.manageable {
        return Some(format!(
            "PAK content conflict between '{}' and '{}' cannot be ordered because one external archive is not safely manageable.",
            first.display_name, second.display_name
        ));
    }
    let Some(selected_winner) = selected_winner else {
        return Some(format!(
            "Choose which PAK loads later for the content conflict between '{}' and '{}'.",
            first.display_name, second.display_name
        ));
    };
    (effective_winner != Some(selected_winner)).then(|| {
        format!(
            "The selected load winner for '{}' and '{}' was not produced by the final PAK order.",
            first.display_name, second.display_name
        )
    })
}

fn pak_conflict_identity(
    first: &PakConflictPartyView,
    second: &PakConflictPartyView,
) -> Result<serde_json::Value> {
    if first.pak_sha256 == second.pak_sha256 {
        return Ok(serde_json::json!({
            "identicalPakSha256": &first.pak_sha256,
            "firstArchive": &first.archive,
            "secondArchive": &second.archive,
        }));
    }
    Ok(serde_json::to_value(canonical_pak_pair(
        &first.pak_sha256,
        &second.pak_sha256,
    )?)?)
}

fn canonical_pak_pair(first: &str, second: &str) -> Result<(String, String)> {
    for sha256 in [first, second] {
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("invalid lowercase PAK SHA-256");
        }
    }
    if first == second {
        bail!("PAK load-order pair must contain distinct hashes");
    }
    Ok(if first < second {
        (first.to_owned(), second.to_owned())
    } else {
        (second.to_owned(), first.to_owned())
    })
}

fn validate_pak_winner(first: &str, second: &str, winner: &str) -> Result<String> {
    if winner != first && winner != second {
        bail!("selected PAK winner does not belong to the conflict pair");
    }
    canonical_pak_pair(first, second)?;
    Ok(winner.to_owned())
}

fn selected_pak_winner(
    build_id: u64,
    preferences: &[PakLoadOrderPreference],
    first: &str,
    second: &str,
) -> Option<String> {
    let pair = canonical_pak_pair(first, second).ok()?;
    preferences
        .iter()
        .find(|preference| {
            preference.build_id == build_id
                && canonical_pak_pair(&preference.first_pak_sha256, &preference.second_pak_sha256)
                    .ok()
                    .as_ref()
                    == Some(&pair)
        })
        .and_then(|preference| {
            validate_pak_winner(&pair.0, &pair.1, &preference.winner_pak_sha256).ok()
        })
}

fn active_pak_constraints(
    build_id: u64,
    preferences: &[PakLoadOrderPreference],
    active_hashes: &BTreeSet<String>,
) -> Result<Vec<PakLoadOrderConstraint>> {
    let mut constraints = Vec::new();
    for preference in preferences
        .iter()
        .filter(|preference| preference.build_id == build_id)
    {
        let (first, second) =
            canonical_pak_pair(&preference.first_pak_sha256, &preference.second_pak_sha256)?;
        if !active_hashes.contains(&first) || !active_hashes.contains(&second) {
            continue;
        }
        let winner = validate_pak_winner(&first, &second, &preference.winner_pak_sha256)?;
        let loser = if winner == first { second } else { first };
        constraints.push(PakLoadOrderConstraint {
            loser_pak_sha256: loser,
            winner_pak_sha256: winner,
        });
    }
    constraints.sort_by(|left, right| {
        left.loser_pak_sha256
            .cmp(&right.loser_pak_sha256)
            .then_with(|| left.winner_pak_sha256.cmp(&right.winner_pak_sha256))
    });
    constraints.dedup();
    Ok(constraints)
}

fn validate_preview_pak_preferences(
    build_id: u64,
    preferences: &[PakLoadOrderPreference],
    conflicts: &[PakConflictView],
) -> Result<()> {
    let hashes: BTreeSet<_> = conflicts
        .iter()
        .filter(|conflict| conflict.outcome != "benign_duplicate")
        .flat_map(|conflict| {
            [
                conflict.first.pak_sha256.clone(),
                conflict.second.pak_sha256.clone(),
            ]
        })
        .collect();
    let nodes: Vec<_> = hashes
        .iter()
        .map(|pak_sha256| PakLoadOrderNode {
            pak_sha256: pak_sha256.clone(),
        })
        .collect();
    let constraints = active_pak_constraints(build_id, preferences, &hashes)?;
    resolve_pak_load_order(&nodes, &constraints).map_err(|error| {
        anyhow::anyhow!("PAK load-winner choices form an invalid graph: {error}")
    })?;
    Ok(())
}

fn apply_profile_pak_load_order(
    profile: &mut DomainProfile,
    build_id: u64,
    conflicts: &[PakConflictView],
    ordered_pak_sha256: &[String],
) -> Result<()> {
    let expected: BTreeSet<_> = conflicts
        .iter()
        .filter(|conflict| conflict.outcome != "benign_duplicate")
        .flat_map(|conflict| {
            [
                conflict.first.pak_sha256.clone(),
                conflict.second.pak_sha256.clone(),
            ]
        })
        .collect();
    let supplied: BTreeSet<_> = ordered_pak_sha256.iter().cloned().collect();
    if expected.is_empty() || supplied != expected || supplied.len() != ordered_pak_sha256.len() {
        bail!("load order must contain every conflicting PAK exactly once");
    }
    let positions: BTreeMap<_, _> = ordered_pak_sha256
        .iter()
        .enumerate()
        .map(|(index, sha256)| (sha256.as_str(), index))
        .collect();
    let reviewed_pairs: BTreeSet<_> = conflicts
        .iter()
        .filter(|conflict| conflict.outcome != "benign_duplicate")
        .map(|conflict| canonical_pak_pair(&conflict.first.pak_sha256, &conflict.second.pak_sha256))
        .collect::<Result<_>>()?;
    profile.pak_load_order.retain(|preference| {
        preference.build_id != build_id
            || canonical_pak_pair(&preference.first_pak_sha256, &preference.second_pak_sha256)
                .ok()
                .is_none_or(|pair| !reviewed_pairs.contains(&pair))
    });
    for (first, second) in reviewed_pairs {
        let winner_pak_sha256 = if positions[first.as_str()] > positions[second.as_str()] {
            first.clone()
        } else {
            second.clone()
        };
        profile.pak_load_order.push(PakLoadOrderPreference {
            build_id,
            first_pak_sha256: first,
            second_pak_sha256: second,
            winner_pak_sha256,
        });
    }
    profile.pak_load_order.sort_by(|left, right| {
        left.build_id
            .cmp(&right.build_id)
            .then_with(|| left.first_pak_sha256.cmp(&right.first_pak_sha256))
            .then_with(|| left.second_pak_sha256.cmp(&right.second_pak_sha256))
    });
    Ok(())
}

fn apply_pak_ordering(
    deployment: &mut DeploymentRequest,
    unmanaged: &[UnmanagedFileView],
    receipt: Option<&DeploymentReceipt>,
    slots: &BTreeMap<String, u64>,
) -> Result<()> {
    let mut managed_renames = Vec::new();
    for file in deployment.files.iter_mut().filter(|file| {
        Path::new(&file.relative_path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("pak"))
            && slots.contains_key(&file.sha256)
    }) {
        let old = file.relative_path.clone();
        let name = rrmm_ordered_pak_name(&file.sha256, slots[&file.sha256])?;
        file.relative_path = relative_with_file_name(&old, &name)?;
        managed_renames.push((old, file.relative_path.clone()));
    }
    for (old_pak, new_pak) in managed_renames {
        let old_sig = replace_relative_extension(&old_pak, "sig")?;
        if let Some(signature) = deployment
            .files
            .iter_mut()
            .find(|file| file.relative_path.eq_ignore_ascii_case(&old_sig))
        {
            signature.relative_path = replace_relative_extension(&new_pak, "sig")?;
        }
    }

    let involved_originals: BTreeSet<_> = unmanaged
        .iter()
        .filter(|file| slots.contains_key(&file.pak_sha256))
        .map(|file| external_stem_key(&file.original_path))
        .collect::<Result<_>>()?;
    for file in unmanaged
        .iter()
        .filter(|file| slots.contains_key(&file.pak_sha256) && file.manageable)
    {
        let target_name = rrmm_ordered_pak_name(&file.pak_sha256, slots[&file.pak_sha256])?;
        let target = relative_with_file_name(&file.original_path, &target_name)?;
        deployment.external_files.push(DeploymentExternalFile {
            original_relative_path: file.original_path.clone(),
            source_relative_path: file.path.clone(),
            target_relative_path: target.clone(),
            bytes: file.size_bytes,
            sha256: file.pak_sha256.clone(),
            owner_id: file.existing_mod_id.clone(),
            owner_name: file.display_name.clone(),
        });
        if let Some(signature) = external_signature_file(
            &deployment.game_root,
            file,
            receipt,
            &replace_relative_extension(&target, "sig")?,
        )? {
            deployment.external_files.push(signature);
        }
    }
    restore_unneeded_external_ordering(deployment, receipt, &involved_originals)?;
    Ok(())
}

fn restore_unneeded_external_ordering(
    deployment: &mut DeploymentRequest,
    receipt: Option<&DeploymentReceipt>,
    involved_originals: &BTreeSet<String>,
) -> Result<()> {
    let Some(receipt) = receipt else {
        return Ok(());
    };
    let existing_sources: BTreeSet<_> = deployment
        .external_files
        .iter()
        .map(|file| file.source_relative_path.clone())
        .collect();
    for file in &receipt.external_files {
        if file.current_relative_path == file.original_relative_path
            || existing_sources.contains(&file.current_relative_path)
            || involved_originals.contains(&external_stem_key(&file.original_relative_path)?)
            || !deployment
                .game_root
                .join(&file.current_relative_path)
                .is_file()
        {
            continue;
        }
        deployment.external_files.push(DeploymentExternalFile {
            original_relative_path: file.original_relative_path.clone(),
            source_relative_path: file.current_relative_path.clone(),
            target_relative_path: file.original_relative_path.clone(),
            bytes: file.bytes,
            sha256: file.sha256.clone(),
            owner_id: file.owner_id.clone(),
            owner_name: file.owner_name.clone(),
        });
    }
    Ok(())
}

fn external_signature_file(
    game_root: &Path,
    pak: &UnmanagedFileView,
    receipt: Option<&DeploymentReceipt>,
    target_path: &str,
) -> Result<Option<DeploymentExternalFile>> {
    let current_pak = checked_game_mod_path(game_root, &pak.path)?;
    let Some(parent) = current_pak.parent() else {
        return Ok(None);
    };
    let Some(stem) = current_pak.file_stem().and_then(|stem| stem.to_str()) else {
        return Ok(None);
    };
    for entry in fs::read_dir(parent)? {
        let path = entry?.path();
        if !path
            .file_stem()
            .and_then(|candidate| candidate.to_str())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(stem))
            || !path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("sig"))
        {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() {
            bail!("external PAK signature is not a regular file");
        }
        let source = path
            .strip_prefix(game_root)?
            .to_str()
            .context("external PAK signature path is not valid UTF-8")?
            .replace('\\', "/");
        let sha256 = rrmm_archive::sha256_path(&path)?;
        let original = match receipt_original_external_path(receipt, &source, &sha256) {
            Some(original) => original,
            None => replace_relative_extension(&pak.original_path, "sig")?,
        };
        return Ok(Some(DeploymentExternalFile {
            original_relative_path: original,
            source_relative_path: source,
            target_relative_path: target_path.to_owned(),
            bytes: metadata.len(),
            sha256,
            owner_id: pak.existing_mod_id.clone(),
            owner_name: pak.display_name.clone(),
        }));
    }
    Ok(None)
}

fn relative_with_file_name(path: &str, file_name: &str) -> Result<String> {
    let parent = Path::new(path)
        .parent()
        .context("PAK deployment path has no parent")?;
    Ok(parent.join(file_name).to_string_lossy().replace('\\', "/"))
}

fn replace_relative_extension(path: &str, extension: &str) -> Result<String> {
    let mut path = PathBuf::from(path);
    if !path.set_extension(extension) {
        bail!("PAK deployment path has no filename");
    }
    Ok(path.to_string_lossy().replace('\\', "/"))
}

fn external_stem_key(path: &str) -> Result<String> {
    let parent = Path::new(path)
        .parent()
        .context("external PAK path has no parent")?;
    let stem = Path::new(path)
        .file_stem()
        .context("external PAK path has no filename")?;
    Ok(parent
        .join(stem)
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase())
}

fn display_activation_pak(inputs: &[ActivationPakInput], effective_path: &Path) -> String {
    inputs
        .iter()
        .find(|input| input.effective_path == effective_path)
        .map(|input| input.display_path.clone())
        .unwrap_or_else(|| effective_path.display().to_string())
}

fn sha256_serialized(value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn activation_pak_analysis_cache_key(
    inputs: &[ActivationPakInput],
    build_id: u64,
    preferences: &[PakLoadOrderPreference],
) -> Result<Option<String>> {
    let mut identities = Vec::with_capacity(inputs.len());
    for input in inputs {
        let identity = file_identity(&input.read_path)?;
        if !identity.stable_for_cache() {
            return Ok(None);
        }
        identities.push((
            &input.read_path,
            &input.effective_path,
            &input.pak_sha256,
            identity,
        ));
    }
    Ok(Some(sha256_serialized(&(
        "activation-pak-analysis-v1",
        build_id,
        preferences,
        inputs,
        identities,
    ))?))
}

fn verified_deployment_sources(
    store: &Store,
    files: &[DeploymentFile],
) -> Result<BTreeMap<PathBuf, VerifiedSource>> {
    let mut verified = BTreeMap::new();
    for file in files {
        if verified.contains_key(&file.source) {
            continue;
        }
        let identity = file_identity(&file.source)?;
        if identity.bytes != file.bytes {
            bail!("deployment source changed size: {}", file.source.display());
        }
        let fingerprint = stable_file_fingerprint(&file.source, &identity, &file.sha256)?;
        let cache_hit = match &fingerprint {
            Some(fingerprint) => store.file_is_verified(fingerprint)?,
            None => false,
        };
        if !cache_hit {
            let actual = rrmm_archive::sha256_path(&file.source)?;
            if actual != file.sha256 {
                bail!("deployment source changed: {}", file.source.display());
            }
            if let Some(fingerprint) = &fingerprint {
                store.upsert_file_verification(fingerprint)?;
            }
        }
        verified.insert(
            file.source.clone(),
            VerifiedSource {
                identity,
                sha256: file.sha256.clone(),
            },
        );
    }
    Ok(verified)
}

fn cache_deployment_targets(
    store: &Store,
    request: &DeploymentRequest,
    receipt: Option<&DeploymentReceipt>,
    verified: &mut BTreeMap<PathBuf, VerifiedSource>,
) -> Result<()> {
    let mut relative_paths = BTreeSet::new();
    relative_paths.extend(request.files.iter().map(|file| file.relative_path.as_str()));
    relative_paths.extend(request.external_files.iter().flat_map(|file| {
        [
            file.source_relative_path.as_str(),
            file.target_relative_path.as_str(),
        ]
    }));
    if let Some(receipt) = receipt {
        relative_paths.extend(receipt.files.iter().map(|file| file.relative_path.as_str()));
        relative_paths.extend(
            receipt
                .external_files
                .iter()
                .map(|file| file.current_relative_path.as_str()),
        );
    }
    for relative_path in relative_paths {
        let path = relative_path
            .split('/')
            .fold(request.game_root.clone(), |path, component| {
                path.join(component)
            });
        if verified.contains_key(&path) {
            continue;
        }
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.file_type().is_file() {
            continue;
        }
        let sha256 = cached_file_sha256(store, &path)?;
        verified.insert(
            path.clone(),
            VerifiedSource {
                identity: file_identity(&path)?,
                sha256,
            },
        );
    }
    Ok(())
}

fn cached_file_sha256(store: &Store, path: &Path) -> Result<String> {
    let identity = file_identity(path)?;
    let lookup = stable_file_fingerprint(path, &identity, "")?;
    if let Some(lookup) = &lookup
        && let Some(sha256) = store.verified_file_sha256(lookup)?
    {
        return Ok(sha256);
    }
    let sha256 = rrmm_archive::sha256_path(path)?;
    if let Some(fingerprint) = stable_file_fingerprint(path, &identity, &sha256)? {
        store.upsert_file_verification(&fingerprint)?;
    }
    Ok(sha256)
}

fn cache_accepted_artifact_files(
    store: &Store,
    accepted: &rrmm_artifacts::AcceptedArtifact,
) -> Result<()> {
    for file in &accepted.manifest.files {
        let path = file
            .path
            .split('/')
            .fold(accepted.root.join("files"), |path, component| {
                path.join(component)
            });
        if !path.exists() {
            continue;
        }
        let identity = file_identity(&path)?;
        if identity.bytes != file.bytes {
            bail!("accepted artifact changed before it could be cached");
        }
        if let Some(fingerprint) = stable_file_fingerprint(&path, &identity, &file.sha256)? {
            store.upsert_file_verification(&fingerprint)?;
        }
    }
    Ok(())
}

fn stable_file_fingerprint(
    path: &Path,
    identity: &FileIdentity,
    sha256: &str,
) -> Result<Option<FileVerificationFingerprint>> {
    if !identity.stable_for_cache() {
        return Ok(None);
    }
    Ok(Some(FileVerificationFingerprint {
        canonical_path: fs::canonicalize(path)
            .with_context(|| format!("failed to resolve {}", path.display()))?,
        device_id: identity
            .device_id
            .context("file device identity is unavailable")?
            .to_string(),
        file_id: identity
            .file_id
            .context("file identity is unavailable")?
            .to_string(),
        bytes: identity.bytes,
        modified_ns: identity.modified_ns,
        changed_ns: identity
            .changed_ns
            .context("file change time is unavailable")?,
        sha256: sha256.to_owned(),
    }))
}

fn deployment_file_snapshots(
    plan: &DeploymentPlan,
    pak_inputs: &[ActivationPakInput],
) -> Result<Vec<FileSnapshot>> {
    let mut paths = BTreeSet::new();
    for file in &plan.files {
        paths.insert(file.source.clone());
        paths.insert(
            plan.game_root
                .join(file.relative_path.split('/').collect::<PathBuf>()),
        );
    }
    for file in &plan.external_files {
        paths.insert(
            plan.game_root
                .join(file.source_relative_path.split('/').collect::<PathBuf>()),
        );
        paths.insert(
            plan.game_root
                .join(file.target_relative_path.split('/').collect::<PathBuf>()),
        );
    }
    paths.extend(pak_inputs.iter().map(|input| input.read_path.clone()));
    paths
        .into_iter()
        .map(|path| capture_file_snapshot(&path))
        .collect()
}

fn capture_file_snapshot(path: &Path) -> Result<FileSnapshot> {
    let state = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            FileSnapshotState::File(file_identity(path)?)
        }
        Ok(_) => FileSnapshotState::Other,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => FileSnapshotState::Absent,
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    Ok(FileSnapshot {
        path: path.to_path_buf(),
        state,
    })
}

fn validate_file_snapshots(snapshots: &[FileSnapshot]) -> Result<()> {
    for expected in snapshots {
        if capture_file_snapshot(&expected.path)? != *expected {
            bail!("file changed after preview: {}", expected.path.display());
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthLevel {
    Ready,
    Attention,
    Blocked,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSnapshot {
    pub app_version: String,
    pub generated_at: String,
    pub game: GameInstallationView,
    pub deployment: DeploymentStateView,
    pub artifacts: Vec<ArtifactView>,
    pub profiles: Vec<ProfileView>,
    pub conflicts: Vec<ConflictView>,
    pub ue4ss: Ue4ssStateView,
    pub diagnostics: Vec<DiagnosticView>,
    pub preferences: PreferencesView,
    pub operation_failure_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreferencesView {
    pub offline_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesktopPreferences {
    schema_version: u32,
    offline_mode: bool,
}

impl Default for DesktopPreferences {
    fn default() -> Self {
        Self {
            schema_version: 1,
            offline_mode: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GameInstallationView {
    pub detected: bool,
    pub root_path: Option<String>,
    pub build_id: Option<String>,
    pub expected_build_id: String,
    pub health: HealthLevel,
    pub status: String,
    pub writable: bool,
    pub game_running: bool,
    pub source: String,
    pub warnings: Vec<String>,
}

impl GameInstallationView {
    fn absent(build_id: u64) -> Self {
        Self {
            detected: false,
            root_path: None,
            build_id: None,
            expected_build_id: build_id.to_string(),
            health: HealthLevel::Blocked,
            status: "not_found".to_owned(),
            writable: false,
            game_running: false,
            source: "none".to_owned(),
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactView {
    pub sha256: String,
    pub package_id: String,
    pub name: String,
    pub version: String,
    pub author: String,
    pub source_archive: String,
    pub kind: String,
    pub verified: bool,
    pub imported_at: String,
    pub description: String,
    pub file_count: usize,
    pub nexus_page_url: Option<String>,
    pub activation_supported: bool,
    pub deletable: bool,
    pub delete_blocked_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfilePackageView {
    pub artifact_sha256: String,
    pub enabled: bool,
    pub priority: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileView {
    pub id: String,
    pub name: String,
    pub packages: Vec<ProfilePackageView>,
    pub pak_load_order: Vec<PakLoadOrderPreference>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictView {
    pub id: String,
    pub severity: String,
    pub path: String,
    pub package_names: Vec<String>,
    pub reason: String,
    pub resolution: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnmanagedFileView {
    pub path: String,
    pub size_bytes: u64,
    pub pak_sha256: String,
    pub original_path: String,
    #[serde(skip_serializing)]
    pub existing_mod_id: Option<String>,
    #[serde(skip_serializing)]
    pub display_name: Option<String>,
    #[serde(skip_serializing)]
    pub manageable: bool,
    #[serde(skip_serializing)]
    pub active_paths: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExistingModView {
    pub id: String,
    pub display_name: String,
    pub path: String,
    pub related_paths: Vec<String>,
    pub size_bytes: u64,
    pub mod_type: String,
    pub origin: String,
    pub components: Vec<String>,
    pub enabled: bool,
    pub manageable: bool,
    pub blocked_reason: Option<String>,
    pub nexus_page_url: Option<String>,
    pub group_id: Option<String>,
    pub group_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pak_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_path: Option<String>,
    #[serde(skip_serializing)]
    pub stored: bool,
    #[serde(skip_serializing)]
    pub directories: Vec<String>,
    #[serde(skip_serializing)]
    pub ue4ss_module_name: Option<String>,
    #[serde(skip_serializing)]
    pub mods_txt_controlled: bool,
    #[serde(skip_serializing)]
    pub file_identities: BTreeMap<String, (u64, String)>,
    #[serde(skip_serializing)]
    pub active_paths: BTreeMap<String, String>,
    #[serde(skip_serializing)]
    pub symlink_target: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentStateView {
    pub health: HealthLevel,
    pub selected_profile_id: Option<String>,
    pub selected_profile_name: Option<String>,
    pub applied_profile_id: Option<String>,
    pub applied_profile_name: Option<String>,
    pub managed_file_count: usize,
    pub unmanaged_files: Vec<UnmanagedFileView>,
    pub existing_mods: Vec<ExistingModView>,
    pub recovery_available: bool,
    pub last_applied_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ue4ssModuleView {
    pub id: String,
    pub name: String,
    pub version: String,
    pub enabled: bool,
    pub source_package: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ue4ssStateView {
    pub installed: bool,
    pub version: Option<String>,
    pub health: HealthLevel,
    pub root_path: Option<String>,
    pub modules: Vec<Ue4ssModuleView>,
    pub message: String,
    pub proxy_build_id: Option<String>,
    pub core_build_id: Option<String>,
    pub mixed_installation: bool,
    pub expected_version: String,
    pub installation_action: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeybindAnalysisView {
    pub complete: bool,
    pub bindings: Vec<KeybindFindingView>,
    pub collisions: Vec<KeybindCollisionView>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeybindFindingView {
    pub module: String,
    pub script: String,
    pub line: usize,
    pub binding: Option<String>,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeybindCollisionView {
    pub binding: String,
    pub modules: Vec<String>,
}

impl Ue4ssStateView {
    fn absent(message: &str) -> Self {
        Self {
            installed: false,
            version: None,
            health: HealthLevel::Unknown,
            root_path: None,
            modules: Vec::new(),
            message: message.to_owned(),
            proxy_build_id: None,
            core_build_id: None,
            mixed_installation: false,
            expected_version: TARGET_UE4SS_BUILD_ID.to_owned(),
            installation_action: "install".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticView {
    pub id: String,
    pub label: String,
    pub level: HealthLevel,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchivePreflightView {
    pub token: String,
    pub archive_path: String,
    pub display_name: String,
    pub format: String,
    pub accepted: bool,
    pub package_kind: String,
    pub file_count: usize,
    pub unpacked_size_bytes: u64,
    pub warnings: Vec<UiNoticeView>,
    pub blocked_reasons: Vec<UiNoticeView>,
    pub manifest_found: bool,
    pub recognized_package_name: Option<String>,
    pub conflicts: Vec<ConflictView>,
    pub conflict_check_complete: bool,
    pub entries: Vec<ArchiveEntryView>,
    pub entries_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UiNoticeView {
    pub code: String,
    pub path: Option<String>,
    pub count: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveEntryView {
    pub path: String,
    pub expanded_bytes: u64,
    pub directory: bool,
    pub executable_payload: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveImportReviewView {
    pub token: String,
    pub review_sha256: String,
    pub archive_sha256: String,
    pub display_name: String,
    pub package_name: String,
    pub package_kind: String,
    pub activation_supported: bool,
    pub layout: ArchiveImportLayoutView,
    pub files: Vec<ArchiveImportFileView>,
    pub warnings: Vec<UiNoticeView>,
    pub blocked_reasons: Vec<UiNoticeView>,
    pub conflict_check_complete: bool,
    pub pak_conflicts: Vec<PakConflictView>,
    pub destination_conflicts: Vec<ArchiveDestinationConflictView>,
    pub executable_acknowledgement_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveDestinationConflictView {
    pub conflict_id: String,
    pub destination: String,
    pub parties: Vec<ArchiveConflictPartyView>,
    pub outcome: String,
    pub winner: Option<String>,
    pub confidence: String,
    pub reason: String,
    pub blocking: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveConflictPartyView {
    pub id: String,
    pub name: String,
    pub source_kind: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveImportLayoutView {
    pub pak_files: Vec<String>,
    pub ue4ss_mod_roots: Vec<String>,
    pub documentation_files: Vec<String>,
    pub executable_files: Vec<String>,
    pub issues: Vec<String>,
    pub requires_review: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveImportFileView {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub executable_payload: bool,
    pub native_binary: bool,
    pub planned_destination: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportArchiveConfirmationView {
    pub review_sha256: String,
    pub executable_payloads_acknowledged: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub artifact_sha256: String,
    pub package_name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationChangeView {
    pub operation: String,
    pub path: String,
    pub package_id: Option<String>,
    pub package_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PakConflictView {
    pub conflict_id: String,
    pub first: PakConflictPartyView,
    pub second: PakConflictPartyView,
    pub winner_pak_sha256: Option<String>,
    pub selected_winner_pak_sha256: Option<String>,
    pub first_archive: String,
    pub second_archive: String,
    pub outcome: String,
    pub winner: Option<String>,
    pub order_confidence: String,
    pub winner_reason: String,
    pub domains: Vec<String>,
    pub affected_member_count: usize,
    pub affected_package_count: usize,
    pub split_package: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PakConflictPartyView {
    pub archive: String,
    pub display_name: String,
    pub package_id: Option<String>,
    pub pak_sha256: String,
    pub source_kind: String,
    pub artifact_sha256: Option<String>,
    pub existing_mod_id: Option<String>,
    pub manageable: bool,
    pub load_order: u64,
    pub destination: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockingLinkView {
    pub relative_path: String,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedFileIssueView {
    pub path: String,
    pub expected_sha256: String,
    pub current_sha256: Option<String>,
    pub package_id: Option<String>,
    pub package_name: Option<String>,
    pub allowed_actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipeEffectView {
    pub recipe_id: String,
    pub kind: String,
    pub target: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipePreviewView {
    pub available: bool,
    pub applied_recipe_ids: Vec<String>,
    pub effects: Vec<RecipeEffectView>,
    pub notice: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationPreviewView {
    pub preview_id: String,
    pub profile_id: String,
    pub profile_name: String,
    pub blocked: bool,
    pub requires_apply: bool,
    pub blockers: Vec<String>,
    pub changes: Vec<ActivationChangeView>,
    pub unmanaged_files_preserved: usize,
    pub allow_unmanaged: bool,
    pub pak_conflicts: Vec<PakConflictView>,
    pub blocking_links: Vec<BlockingLinkView>,
    pub managed_file_issues: Vec<ManagedFileIssueView>,
    pub recipes: RecipePreviewView,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationResult {
    pub status: String,
    pub applied_profile_id: Option<String>,
    pub applied_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkDeleteBlockerView {
    pub code: String,
    pub message: String,
    pub item_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkDeleteProfileView {
    pub id: String,
    pub name: String,
    pub artifact_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkDeletePreviewView {
    pub token: String,
    pub blocked: bool,
    pub managed_artifact_count: usize,
    pub external_mod_count: usize,
    pub external_group_count: usize,
    pub affected_profiles: Vec<BulkDeleteProfileView>,
    pub deployed_artifact_count: usize,
    pub requires_deployment: bool,
    pub deployment_change_count: usize,
    pub blockers: Vec<BulkDeleteBlockerView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkDeleteExternalFailureView {
    pub item_id: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkDeleteResultView {
    pub status: String,
    pub managed_artifact_sha256: Vec<String>,
    pub external_mod_ids: Vec<String>,
    pub external_failures: Vec<BulkDeleteExternalFailureView>,
    pub deployment_applied: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExistingModGroupOperation {
    Enable,
    Disable,
    Delete,
}

fn ue4ss_loader_artifact() -> Result<Ue4ssLoaderArtifact> {
    let artifact: Ue4ssLoaderArtifact = serde_json::from_str(UE4SS_LOADER_ARTIFACT_JSON)?;
    let filename = Path::new(&artifact.filename);
    let url = reqwest::Url::parse(&artifact.url)?;
    if artifact.build_id != SUPPORTED_BUILD_ID
        || artifact.loader_build_id != TARGET_UE4SS_BUILD_ID
        || artifact.archive_size == 0
        || filename.is_absolute()
        || filename.components().count() != 1
        || !artifact.filename.ends_with(".zip")
        || url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || !is_sha256(&artifact.archive_sha256)
        || !is_sha256(&artifact.proxy_sha256)
        || !is_sha256(&artifact.core_sha256)
        || artifact.proxy_path != "dwmapi.dll"
        || artifact.core_path != "ue4ss/UE4SS.dll"
    {
        bail!("embedded UE4SS loader descriptor is invalid");
    }
    Ok(artifact)
}

fn reject_ambiguous_ue4ss_layout(game_root: &Path) -> Result<()> {
    let win64 = game_root.join("RetroRewind/Binaries/Win64");
    for relative in [
        "override.txt",
        "xinput1_3.dll",
        "UE4SS.dll",
        "UE4SS-settings.ini",
        "Mods",
    ] {
        let path = win64.join(relative);
        if path.exists() {
            bail!(
                "UE4SS uses a legacy or customized '{}' layout. Remove or migrate it explicitly before automatic repair.",
                relative
            );
        }
    }
    Ok(())
}

fn ue4ss_deployment_files(
    game_root: &Path,
    extraction: &ArchiveExtractionReport,
    artifact: &Ue4ssLoaderArtifact,
) -> Result<Vec<DeploymentFile>> {
    let mut proxy_verified = false;
    let mut core_verified = false;
    let mut files = Vec::with_capacity(2);
    for file in &extraction.files {
        let runtime = if file.path == artifact.proxy_path {
            if file.sha256 != artifact.proxy_sha256 {
                bail!("UE4SS proxy inside the pinned archive has an unexpected hash");
            }
            proxy_verified = true;
            true
        } else if file.path == artifact.core_path {
            if file.sha256 != artifact.core_sha256 {
                bail!("UE4SS core inside the pinned archive has an unexpected hash");
            }
            core_verified = true;
            true
        } else {
            false
        };
        let relative_path = format!("RetroRewind/Binaries/Win64/{}", file.path);
        if !runtime {
            let destination = game_root.join(Path::new(&relative_path));
            match fs::symlink_metadata(&destination) {
                Ok(metadata) if metadata.file_type().is_file() => continue,
                Ok(_) => {
                    bail!(
                        "UE4SS stock destination is not a regular file: {}",
                        destination.display()
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        files.push(DeploymentFile {
            source: extraction.staging_root.join(Path::new(&file.path)),
            relative_path,
            bytes: file.bytes,
            sha256: file.sha256.clone(),
            package_id: Some("ue4ss-loader".to_owned()),
            package_name: Some("UE4SS loader".to_owned()),
        });
    }
    if !proxy_verified || !core_verified {
        bail!("pinned UE4SS archive is missing its required proxy or core binary");
    }
    Ok(files)
}

fn build_recipe() -> Result<BuildRecipe> {
    let recipe: BuildRecipe = serde_json::from_str(BUILD_RECIPE_JSON)?;
    rrmm_steam::validate_build_recipe(&recipe)?;
    Ok(recipe)
}

enum EmbeddedRecipeCatalog {
    Verified {
        catalog: VerifiedRecipeCatalog,
        floor: CatalogTrustFloor,
    },
    Unavailable(String),
    Rejected(String),
}

fn embedded_recipe_catalog_with_persistence(
    store: &Store,
    persist_trust_floor: bool,
) -> EmbeddedRecipeCatalog {
    verify_embedded_recipe_catalog(
        store,
        PRODUCTION_ROOTS_JSON,
        SIGNED_ROOT_METADATA_JSON,
        SIGNED_RECIPE_CATALOG_JSON,
        persist_trust_floor,
    )
}

fn verify_embedded_recipe_catalog(
    store: &Store,
    roots_json: &str,
    root_json: &str,
    catalog_json: &str,
    persist_trust_floor: bool,
) -> EmbeddedRecipeCatalog {
    let roots: Vec<TrustedRootKey> = match serde_json::from_str(roots_json) {
        Ok(roots) => roots,
        Err(error) => {
            return EmbeddedRecipeCatalog::Rejected(format!(
                "The embedded production recipe roots are invalid ({error}). Reinstall or update RR Mod Manager."
            ));
        }
    };
    if roots.is_empty() {
        return EmbeddedRecipeCatalog::Unavailable(
            "Signed compatibility recipes are not included in this version. Profiles can be applied without recipe transformations."
                .to_owned(),
        );
    }
    let root: SignedRootMetadata = match serde_json::from_str(root_json) {
        Ok(root) => root,
        Err(error) => {
            return EmbeddedRecipeCatalog::Rejected(format!(
                "The embedded signed root metadata is invalid ({error}). Reinstall or update RR Mod Manager."
            ));
        }
    };
    let signed_catalog: SignedRecipeCatalog = match serde_json::from_str(catalog_json) {
        Ok(catalog) => catalog,
        Err(error) => {
            return EmbeddedRecipeCatalog::Rejected(format!(
                "The embedded signed recipe catalog is invalid ({error}). Reinstall or update RR Mod Manager."
            ));
        }
    };
    let floor = match catalog_trust_floor(store) {
        Ok(floor) => floor,
        Err(error) => {
            return EmbeddedRecipeCatalog::Rejected(format!(
                "The local recipe anti-rollback state could not be read ({error}). Repair the RR Mod Manager data store."
            ));
        }
    };
    let verified = match verify_signed_catalog(&roots, &root, &signed_catalog, &floor) {
        Ok(verified) => verified,
        Err(error) => {
            return EmbeddedRecipeCatalog::Rejected(recipe_catalog_error(&error));
        }
    };
    let accepted = verified.trust_floor();
    if persist_trust_floor && let Err(error) = persist_catalog_trust_floor(store, &accepted) {
        return EmbeddedRecipeCatalog::Rejected(format!(
            "The signed recipe catalog passed verification but its anti-rollback state could not be saved ({error}). Repair the RR Mod Manager data store."
        ));
    }
    EmbeddedRecipeCatalog::Verified {
        catalog: verified,
        floor: accepted,
    }
}

fn catalog_trust_floor(store: &Store) -> Result<CatalogTrustFloor> {
    Ok(match store.catalog_trust_state(RECIPE_CATALOG_CHANNEL)? {
        Some(state) => CatalogTrustFloor {
            root_generation: state.root_generation,
            root_payload_sha256: Some(state.root_payload_sha256),
            catalog_sequence: state.catalog_sequence,
            catalog_payload_sha256: Some(state.catalog_payload_sha256),
        },
        None => CatalogTrustFloor {
            root_generation: 0,
            root_payload_sha256: None,
            catalog_sequence: 0,
            catalog_payload_sha256: None,
        },
    })
}

fn persist_catalog_trust_floor(store: &Store, floor: &CatalogTrustFloor) -> Result<()> {
    store.advance_catalog_trust_state(
        RECIPE_CATALOG_CHANNEL,
        &CatalogTrustState {
            root_generation: floor.root_generation,
            root_payload_sha256: floor
                .root_payload_sha256
                .clone()
                .context("verified root metadata omitted its payload hash")?,
            catalog_sequence: floor.catalog_sequence,
            catalog_payload_sha256: floor
                .catalog_payload_sha256
                .clone()
                .context("verified recipe catalog omitted its payload hash")?,
        },
    )?;
    Ok(())
}

fn recipe_catalog_error(error: &RecipeError) -> String {
    match error {
        RecipeError::Expired(_) => "The embedded signed compatibility catalog has expired. Update RR Mod Manager before applying this profile.".to_owned(),
        RecipeError::RootRollback { .. }
        | RecipeError::CatalogRollback { .. }
        | RecipeError::SameVersionMismatch => "The embedded compatibility catalog is older than or differs from metadata already accepted on this computer. Update RR Mod Manager; rollback was blocked.".to_owned(),
        RecipeError::UntrustedSignature => "The embedded compatibility catalog signature is not trusted. Reinstall RR Mod Manager from an official release.".to_owned(),
        _ => format!(
            "The embedded signed compatibility catalog is invalid ({error}). Reinstall or update RR Mod Manager."
        ),
    }
}

fn recipe_preview(
    catalog: &VerifiedRecipeCatalog,
    report: &RecipeApplicationReport,
) -> RecipePreviewView {
    let applied: BTreeSet<_> = report
        .applied_recipe_ids
        .iter()
        .map(String::as_str)
        .collect();
    let effects = catalog
        .recipes()
        .iter()
        .filter(|recipe| applied.contains(recipe.id.as_str()))
        .flat_map(recipe_effects)
        .collect();
    RecipePreviewView {
        available: true,
        applied_recipe_ids: report.applied_recipe_ids.clone(),
        effects,
        notice: None,
    }
}

fn recipe_effects(recipe: &CompatibilityRecipe) -> Vec<RecipeEffectView> {
    recipe
        .operations
        .iter()
        .map(|operation| match operation {
            RecipeOperation::SelectWinner {
                winner_package_id,
                resource,
            } => RecipeEffectView {
                recipe_id: recipe.id.clone(),
                kind: "select_winner".to_owned(),
                target: winner_package_id.clone(),
                detail: resource.clone(),
            },
            RecipeOperation::ReplaceWithCombined {
                combined_package_id,
                combined_sha256,
                ..
            } => RecipeEffectView {
                recipe_id: recipe.id.clone(),
                kind: "replace_with_combined".to_owned(),
                target: combined_package_id.clone(),
                detail: combined_sha256.clone(),
            },
            RecipeOperation::RequireInstallName {
                package_id,
                install_name,
            } => RecipeEffectView {
                recipe_id: recipe.id.clone(),
                kind: "require_install_name".to_owned(),
                target: package_id.clone(),
                detail: install_name.clone(),
            },
            RecipeOperation::DisableComponent {
                package_id,
                component_id,
                ..
            } => RecipeEffectView {
                recipe_id: recipe.id.clone(),
                kind: "disable_component".to_owned(),
                target: package_id.clone(),
                detail: component_id.clone(),
            },
        })
        .collect()
}

fn authored_package_catalog() -> Result<Vec<CatalogPackage>> {
    let mut catalog: Vec<CatalogPackage> = serde_json::from_str(PACKAGE_CATALOG_JSON)?;
    catalog.retain(|package| package.manifest.id != "local:smart-shelf-organizer");
    for package in &catalog {
        rrmm_manifest::validate_manifest(&package.manifest)?;
    }
    Ok(catalog)
}

#[cfg(test)]
fn package_catalog() -> Result<Vec<CatalogPackage>> {
    authored_package_catalog()
}

fn effective_package_catalog(store: &Store, artifact_store: &Path) -> Result<Vec<CatalogPackage>> {
    let reviewed: BTreeMap<_, _> = authored_package_catalog()?
        .into_iter()
        .chain(adopted_package_catalog(store)?)
        .map(|package| (package.artifact_sha256.clone(), package))
        .collect();
    let mut catalog = Vec::new();
    for stored in store.artifacts()? {
        let artifact: ArtifactManifest = serde_json::from_value(stored.manifest)?;
        if artifact.sha256 != stored.sha256 {
            bail!("stored artifact metadata does not match its content address");
        }
        if let Some(package) = reviewed.get(&artifact.sha256) {
            let validation = (|| -> Result<()> {
                match &package.provenance {
                    ManifestProvenance::Declared => {
                        validate_declared_package_in_store(artifact_store, package)?
                    }
                    ManifestProvenance::Inferred { reviewed: true, .. } => {
                        let verified = load_verified_artifact(&stored.root)?;
                        validate_catalog_package_artifact(package, &verified)?;
                    }
                    ManifestProvenance::Inferred {
                        reviewed: false, ..
                    } => bail!("catalog package has not been reviewed"),
                }
                Ok(())
            })();
            validation.with_context(|| {
                format!(
                    "reviewed package '{}' failed immutable-store revalidation",
                    package.manifest.id
                )
            })?;
            catalog.push(package.clone());
        } else if let Some(package) = inferred_local_package(&artifact) {
            catalog.push(package);
        }
    }
    Ok(catalog)
}

fn inferred_local_package(artifact: &ArtifactManifest) -> Option<CatalogPackage> {
    if artifact.layout.kind == PackageKind::Unknown || !artifact.layout.executable_files.is_empty()
    {
        return None;
    }

    let mut recognized = BTreeSet::new();
    recognized.extend(artifact.layout.pak_files.iter().map(String::as_str));
    recognized.extend(
        artifact
            .layout
            .documentation_files
            .iter()
            .map(String::as_str),
    );
    for pak in &artifact.layout.pak_files {
        let signature = replace_extension(pak, "sig");
        if let Some(file) = artifact
            .files
            .iter()
            .find(|file| file.path.eq_ignore_ascii_case(&signature))
        {
            recognized.insert(file.path.as_str());
        }
    }
    for root in &artifact.layout.ue4ss_mod_roots {
        let prefix = format!("{root}/");
        let descendants: Vec<_> = artifact
            .files
            .iter()
            .filter(|file| file.path.starts_with(&prefix))
            .collect();
        if !descendants.iter().any(|file| {
            file.path
                .eq_ignore_ascii_case(&format!("{root}/enabled.txt"))
        }) {
            return None;
        }
        recognized.extend(descendants.into_iter().map(|file| file.path.as_str()));
    }
    if let Some(manifest) = artifact
        .files
        .iter()
        .find(|file| file.path == "rrmm-manifest.json")
    {
        recognized.insert(manifest.path.as_str());
    }
    if artifact
        .files
        .iter()
        .any(|file| !recognized.contains(file.path.as_str()))
    {
        return None;
    }

    let mut inferred = infer_manifest(
        artifact,
        &format!("local:{}", &artifact.sha256[..12]),
        &local_package_name(artifact),
        "local",
        SUPPORTED_BUILD_ID,
    )
    .ok()?;
    if inferred
        .manifest
        .components
        .iter()
        .any(|component| component.component_type == ComponentType::Ue4ss)
    {
        inferred.manifest.runtime_requirements.ue4ss_loader_policy =
            Some(LOCAL_UE4SS_POLICY_ID.to_owned());
    }
    Some(CatalogPackage {
        artifact_sha256: artifact.sha256.clone(),
        manifest: inferred.manifest,
        provenance: ManifestProvenance::Inferred {
            confidence: inferred.confidence,
            reviewed: true,
            issues: inferred.issues,
        },
    })
}

fn local_package_name(artifact: &ArtifactManifest) -> String {
    let candidate = match (
        artifact.layout.pak_files.as_slice(),
        artifact.layout.ue4ss_mod_roots.as_slice(),
    ) {
        (_, [root]) => root.rsplit('/').next(),
        ([pak], _) => pak.rsplit('/').next(),
        _ => None,
    };
    let Some(candidate) = candidate else {
        return format!("Local mod {}", &artifact.sha256[..12]);
    };
    let without_extension = candidate
        .rsplit_once('.')
        .filter(|(_, extension)| extension.eq_ignore_ascii_case("pak"))
        .map_or(candidate, |(name, _)| name);
    let without_suffix = without_extension
        .strip_suffix("_P")
        .or_else(|| without_extension.strip_suffix("_p"))
        .unwrap_or(without_extension);
    let separated = without_suffix.replace(['_', '-'], " ");
    let characters: Vec<_> = separated.chars().collect();
    let mut readable = String::with_capacity(separated.len());
    for (index, character) in characters.iter().copied().enumerate() {
        if index > 0
            && character.is_uppercase()
            && (characters[index - 1].is_lowercase()
                || characters[index - 1].is_ascii_digit()
                || (characters[index - 1].is_uppercase()
                    && characters
                        .get(index + 1)
                        .is_some_and(|next| next.is_lowercase())))
        {
            readable.push(' ');
        }
        readable.push(character);
    }
    if readable.trim().is_empty() {
        format!("Local mod {}", &artifact.sha256[..12])
    } else {
        readable
    }
}

fn archive_import_review_sha256(token: &str, pending: &PendingImportReview) -> Result<String> {
    let mut displayed = archive_import_review_view(token, pending);
    displayed.review_sha256.clear();
    sha256_serialized(&(
        1_u32,
        token,
        &pending.snapshot.source_path,
        &pending.snapshot.sha256,
        &pending.preflight,
        &pending.extraction,
        &pending.manifest,
        displayed,
    ))
}

fn archive_import_review_view(
    token: &str,
    pending: &PendingImportReview,
) -> ArchiveImportReviewView {
    let manifest = &pending.manifest;
    let missing_markers: Vec<_> = manifest
        .layout
        .ue4ss_mod_roots
        .iter()
        .filter(|root| {
            !manifest.files.iter().any(|file| {
                file.path
                    .eq_ignore_ascii_case(&format!("{root}/enabled.txt"))
            })
        })
        .cloned()
        .collect();
    let recognized = recognized_local_file_paths(manifest);
    let unrecognized_count = manifest
        .files
        .iter()
        .filter(|file| !recognized.contains(file.path.as_str()))
        .count();
    let executable_count = manifest
        .files
        .iter()
        .filter(|file| file.executable_payload)
        .count();
    let native_count = manifest
        .files
        .iter()
        .filter(|file| file.native_binary)
        .count();
    let mut issues = manifest.layout.issues.clone();
    if unrecognized_count > 0 {
        issues.push(format!(
            "archive contains {unrecognized_count} unrecognized file(s)"
        ));
    }
    for root in &missing_markers {
        issues.push(format!("UE4SS root '{root}' has no enabled.txt marker"));
    }
    let requires_review = manifest.layout.requires_review
        || manifest.layout.kind == PackageKind::Unknown
        || unrecognized_count > 0
        || !missing_markers.is_empty()
        || pending.executable_acknowledgement_required;

    let mut warnings = pending.conflict_review.warnings.clone();
    if !issues.is_empty() {
        warnings.push(UiNoticeView {
            code: "layout_requires_review".to_owned(),
            path: None,
            count: Some(issues.len()),
        });
    }
    if executable_count > 0 {
        warnings.push(UiNoticeView {
            code: "executable_payloads".to_owned(),
            path: None,
            count: Some(executable_count),
        });
    }
    if native_count > 0 {
        warnings.push(UiNoticeView {
            code: "native_binaries".to_owned(),
            path: None,
            count: Some(native_count),
        });
    }

    if manifest.layout.kind == PackageKind::Unknown {
        warnings.push(UiNoticeView {
            code: "unknown_layout".to_owned(),
            path: None,
            count: None,
        });
    }
    if unrecognized_count > 0 {
        warnings.push(UiNoticeView {
            code: "unrecognized_files".to_owned(),
            path: None,
            count: Some(unrecognized_count),
        });
    }
    warnings.extend(missing_markers.iter().map(|root| UiNoticeView {
        code: "missing_enabled_marker".to_owned(),
        path: Some(root.clone()),
        count: None,
    }));
    if pending.executable_acknowledgement_required {
        warnings.push(UiNoticeView {
            code: "executable_payload_activation_unsupported".to_owned(),
            path: None,
            count: Some(
                manifest
                    .files
                    .iter()
                    .filter(|file| file.executable_payload || file.native_binary)
                    .count(),
            ),
        });
    }
    if !pending.activation_supported {
        warnings.push(UiNoticeView {
            code: "activation_unsupported".to_owned(),
            path: None,
            count: None,
        });
    }

    let destinations = planned_import_destinations(manifest, pending.activation_supported);
    ArchiveImportReviewView {
        token: token.to_owned(),
        review_sha256: pending.review_sha256.clone(),
        archive_sha256: manifest.sha256.clone(),
        display_name: pending
            .snapshot
            .source_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("Selected archive")
            .to_owned(),
        package_name: pending.package_name.clone(),
        package_kind: package_kind(manifest.layout.kind).to_owned(),
        activation_supported: pending.activation_supported,
        layout: ArchiveImportLayoutView {
            pak_files: manifest.layout.pak_files.clone(),
            ue4ss_mod_roots: manifest.layout.ue4ss_mod_roots.clone(),
            documentation_files: manifest.layout.documentation_files.clone(),
            executable_files: manifest.layout.executable_files.clone(),
            issues,
            requires_review,
        },
        files: manifest
            .files
            .iter()
            .map(|file| ArchiveImportFileView {
                path: file.path.clone(),
                bytes: file.bytes,
                sha256: file.sha256.clone(),
                executable_payload: file.executable_payload,
                native_binary: file.native_binary,
                planned_destination: destinations.get(&file.path).cloned(),
            })
            .collect(),
        warnings,
        blocked_reasons: pending.conflict_review.blocked_reasons.clone(),
        conflict_check_complete: pending.conflict_review.conflict_check_complete,
        pak_conflicts: pending.conflict_review.pak_conflicts.clone(),
        destination_conflicts: pending.conflict_review.destination_conflicts.clone(),
        executable_acknowledgement_required: pending.executable_acknowledgement_required,
    }
}

fn recognized_local_file_paths(artifact: &ArtifactManifest) -> BTreeSet<&str> {
    let mut recognized = BTreeSet::new();
    recognized.extend(artifact.layout.pak_files.iter().map(String::as_str));
    recognized.extend(
        artifact
            .layout
            .documentation_files
            .iter()
            .map(String::as_str),
    );
    for pak in &artifact.layout.pak_files {
        let signature = replace_extension(pak, "sig");
        if let Some(file) = artifact
            .files
            .iter()
            .find(|file| file.path.eq_ignore_ascii_case(&signature))
        {
            recognized.insert(file.path.as_str());
        }
    }
    for root in &artifact.layout.ue4ss_mod_roots {
        let prefix = format!("{root}/");
        recognized.extend(
            artifact
                .files
                .iter()
                .filter(|file| file.path.starts_with(&prefix))
                .map(|file| file.path.as_str()),
        );
    }
    if let Some(manifest) = artifact
        .files
        .iter()
        .find(|file| file.path == "rrmm-manifest.json")
    {
        recognized.insert(manifest.path.as_str());
    }
    recognized
}

fn planned_import_destinations(
    artifact: &ArtifactManifest,
    activation_supported: bool,
) -> BTreeMap<String, String> {
    if !activation_supported {
        return BTreeMap::new();
    }
    let Some(package) = inferred_local_package(artifact) else {
        return BTreeMap::new();
    };
    let mut destinations = BTreeMap::new();
    for component in &package.manifest.components {
        match component.component_type {
            ComponentType::Pak => {
                let Some(install_name) = component.install_name.as_deref() else {
                    continue;
                };
                destinations.insert(
                    component.root.clone(),
                    format!("RetroRewind/Content/Paks/{install_name}"),
                );
                let signature_path = replace_extension(&component.root, "sig");
                if let Some(signature) = artifact
                    .files
                    .iter()
                    .find(|file| file.path.eq_ignore_ascii_case(&signature_path))
                {
                    destinations.insert(
                        signature.path.clone(),
                        format!(
                            "RetroRewind/Content/Paks/{}",
                            replace_extension(install_name, "sig")
                        ),
                    );
                }
            }
            ComponentType::Ue4ss => {
                let Some(install_name) = component.install_name.as_deref() else {
                    continue;
                };
                let prefix = format!("{}/", component.root);
                for file in &artifact.files {
                    if let Some(suffix) = file.path.strip_prefix(&prefix) {
                        destinations.insert(
                            file.path.clone(),
                            format!(
                                "RetroRewind/Binaries/Win64/ue4ss/Mods/{install_name}/{suffix}"
                            ),
                        );
                    }
                }
            }
            _ => {}
        }
    }
    destinations
}

fn artifact_revisions_match(
    candidate: &ArtifactManifest,
    stored: &ArtifactManifest,
    authored: &[CatalogPackage],
) -> bool {
    let trusted_package_id = |sha256: &str| {
        authored
            .iter()
            .find(|package| package.artifact_sha256 == sha256)
            .map(|package| package.manifest.id.as_str())
    };
    if let (Some(candidate_id), Some(stored_id)) = (
        trusted_package_id(&candidate.sha256),
        trusted_package_id(&stored.sha256),
    ) && candidate_id == stored_id
    {
        return true;
    }

    let destinations = |artifact: &ArtifactManifest| {
        planned_import_destinations(artifact, inferred_local_package(artifact).is_some())
            .into_values()
            .collect::<BTreeSet<_>>()
    };
    let candidate_destinations = destinations(candidate);
    !candidate_destinations.is_empty() && candidate_destinations == destinations(stored)
}

fn artifact_revision_groups(
    artifacts: &[StoredArtifact],
    authored: &[CatalogPackage],
) -> Result<Vec<Vec<StoredArtifact>>> {
    let manifests = artifacts
        .iter()
        .map(|artifact| {
            Ok((
                artifact.clone(),
                serde_json::from_value::<ArtifactManifest>(artifact.manifest.clone())?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut remaining = (0..manifests.len()).collect::<BTreeSet<_>>();
    let mut groups = Vec::new();
    while let Some(seed) = remaining.pop_first() {
        let mut group = vec![seed];
        loop {
            let matched = remaining
                .iter()
                .copied()
                .filter(|candidate| {
                    group.iter().any(|member| {
                        artifact_revisions_match(
                            &manifests[*candidate].1,
                            &manifests[*member].1,
                            authored,
                        )
                    })
                })
                .collect::<Vec<_>>();
            if matched.is_empty() {
                break;
            }
            for candidate in matched {
                remaining.remove(&candidate);
                group.push(candidate);
            }
        }
        if group.len() > 1 {
            groups.push(
                group
                    .into_iter()
                    .map(|index| manifests[index].0.clone())
                    .collect(),
            );
        }
    }
    Ok(groups)
}

fn replace_profile_artifact_revisions(
    profile: &mut DomainProfile,
    replaced_sha256: &BTreeSet<String>,
    replacement_sha256: &str,
    replacement_package: Option<&CatalogPackage>,
) {
    let mut packages = Vec::<ProfilePackageSelection>::new();
    for mut package in std::mem::take(&mut profile.packages) {
        if replaced_sha256.contains(&package.artifact_sha256) {
            package.artifact_sha256 = replacement_sha256.to_owned();
            if package.variant.as_ref().is_some_and(|variant| {
                !replacement_package.is_some_and(|replacement| {
                    replacement
                        .manifest
                        .variants
                        .iter()
                        .any(|candidate| candidate.id == *variant)
                })
            }) {
                package.variant = None;
            }
        }
        if let Some(existing) = packages.iter_mut().find(|existing| {
            existing.artifact_sha256 == package.artifact_sha256
                && existing.variant == package.variant
        }) {
            existing.enabled |= package.enabled;
        } else {
            packages.push(package);
        }
    }
    profile.packages = packages;
}

fn replace_extension(path: &str, extension: &str) -> String {
    path.rsplit_once('.').map_or_else(
        || format!("{path}.{extension}"),
        |(base, _)| format!("{base}.{extension}"),
    )
}

fn nexus_page_url(package: &CatalogPackage) -> Option<String> {
    let source = package.manifest.source.as_ref()?;
    let domain = source.game_domain.as_deref()?;
    if source.provider != SourceProvider::Nexus
        || !domain
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return None;
    }
    Some(format!(
        "https://www.nexusmods.com/{domain}/mods/{}",
        source.mod_id?
    ))
}

fn create_archive_snapshot(
    paths: &DesktopPaths,
    source_path: &Path,
    token: &str,
    limits: &ArchiveLimits,
) -> Result<ArchiveSnapshot> {
    let metadata = fs::metadata(source_path).with_context(|| {
        format!(
            "failed to inspect selected archive {}",
            source_path.display()
        )
    })?;
    if !metadata.is_file() {
        bail!("selected archive is not a regular file");
    }
    if metadata.len() > limits.max_archive_bytes {
        bail!(
            "selected archive exceeds the configured limit: {} > {} bytes",
            metadata.len(),
            limits.max_archive_bytes
        );
    }
    let storage_root = fs::canonicalize(&paths.data_root).with_context(|| {
        format!(
            "failed to inspect private archive storage at {}",
            paths.data_root.display()
        )
    })?;
    if let Some(available) = available_space_at(&storage_root)?
        && available < metadata.len()
    {
        bail!(
            "insufficient disk space: archive snapshot requires {} bytes but only {available} bytes are available",
            metadata.len()
        );
    }

    let root = paths.staging.join(format!("{ARCHIVE_INPUT_PREFIX}{token}"));
    if root.exists() {
        bail!("private archive snapshot already exists");
    }
    fs::create_dir(&root).with_context(|| {
        format!(
            "failed to create private archive snapshot {}",
            root.display()
        )
    })?;
    set_private_snapshot_directory(&root)?;
    let partial = root.join("archive.partial");
    let archive_path = root.join("archive.bin");
    let result = (|| {
        let mut source = fs::File::open(source_path).with_context(|| {
            format!("failed to read selected archive {}", source_path.display())
        })?;
        let mut destination = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&partial)
            .with_context(|| {
                format!(
                    "failed to create private archive snapshot {}",
                    partial.display()
                )
            })?;
        let mut hasher = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = source.read(&mut buffer).with_context(|| {
                format!("failed to read selected archive {}", source_path.display())
            })?;
            if read == 0 {
                break;
            }
            copied = copied
                .checked_add(read as u64)
                .context("selected archive size exceeds the supported range")?;
            if copied > limits.max_archive_bytes {
                bail!(
                    "selected archive exceeds the configured limit while being copied: {copied} > {} bytes",
                    limits.max_archive_bytes
                );
            }
            hasher.update(&buffer[..read]);
            destination.write_all(&buffer[..read]).with_context(|| {
                format!(
                    "failed to write private archive snapshot {}",
                    partial.display()
                )
            })?;
        }
        destination.sync_all().with_context(|| {
            format!(
                "failed to finalize private archive snapshot {}",
                partial.display()
            )
        })?;
        drop(destination);
        fs::rename(&partial, &archive_path).with_context(|| {
            format!(
                "failed to publish private archive snapshot {}",
                archive_path.display()
            )
        })?;
        let root = fs::canonicalize(&root)?;
        let archive_path = fs::canonicalize(&archive_path)?;
        if archive_path.parent() != Some(root.as_path()) {
            bail!("private archive snapshot escaped its storage directory");
        }
        Ok(ArchiveSnapshot {
            source_path: source_path.to_path_buf(),
            root,
            archive_path,
            sha256: format!("{:x}", hasher.finalize()),
            bytes: copied,
        })
    })();
    if result.is_err() {
        let _ = remove_review_staging(&root);
    }
    result
}

#[cfg(unix)]
fn set_private_snapshot_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).with_context(|| {
        format!(
            "failed to secure private archive snapshot {}",
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn set_private_snapshot_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn verify_archive_snapshot(snapshot: &ArchiveSnapshot) -> Result<()> {
    let root = fs::canonicalize(&snapshot.root)
        .context("private archive snapshot directory is unavailable")?;
    let metadata = fs::symlink_metadata(&snapshot.archive_path)
        .context("private archive snapshot is unavailable")?;
    if !metadata.file_type().is_file() || metadata.len() != snapshot.bytes {
        bail!("private archive snapshot type or size changed after selection");
    }
    let archive_path = fs::canonicalize(&snapshot.archive_path)
        .context("private archive snapshot is unavailable")?;
    if archive_path.parent() != Some(root.as_path()) {
        bail!("private archive snapshot escaped its storage directory");
    }
    let current_hash = rrmm_archive::sha256_path(&archive_path)?;
    if current_hash != snapshot.sha256 {
        bail!("private archive snapshot bytes changed after selection");
    }
    Ok(())
}

fn verify_archive_snapshot_report(
    snapshot: &ArchiveSnapshot,
    report: &ArchivePreflightReport,
) -> Result<()> {
    verify_archive_snapshot(snapshot)?;
    if report.archive_path != snapshot.archive_path
        || report.archive_bytes != snapshot.bytes
        || report.archive_sha256.as_deref() != Some(snapshot.sha256.as_str())
    {
        bail!("archive worker report does not match the private archive snapshot");
    }
    Ok(())
}

fn remove_archive_snapshot(snapshot: &ArchiveSnapshot) -> Result<()> {
    remove_review_staging(&snapshot.root)
}

fn ensure_import_disk_space(
    paths: &DesktopPaths,
    report: &ArchivePreflightReport,
    archive_sha256: &str,
) -> Result<()> {
    let artifact_exists = paths
        .artifact_store
        .join("artifacts")
        .join(&archive_sha256[..2])
        .join(archive_sha256)
        .is_dir();
    let staging_bytes = report.expanded_bytes;
    let publication_bytes = if artifact_exists {
        0
    } else {
        report
            .expanded_bytes
            .checked_add(report.archive_bytes)
            .context("import size exceeds the supported filesystem range")?
    };
    let required = staging_bytes
        .checked_add(publication_bytes)
        .context("import size exceeds the supported filesystem range")?;
    let root = fs::canonicalize(&paths.data_root)
        .with_context(|| format!("failed to inspect storage at {}", paths.data_root.display()))?;
    let available = available_space_at(&root)?;
    if let Some(available) = available
        && available < required
    {
        bail!(
            "insufficient disk space: import requires {required} bytes but only {available} bytes are available"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn available_space_at(path: &Path) -> Result<Option<u64>> {
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes()).context("storage path contains a NUL")?;
    let mut statistics = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: both pointers remain valid for the call and statvfs initializes the output on success.
    if unsafe { libc::statvfs(path.as_ptr(), statistics.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to inspect available storage");
    }
    // SAFETY: statvfs returned success, so the output structure is initialized.
    let statistics = unsafe { statistics.assume_init() };
    Ok(Some(
        statistics.f_bavail.saturating_mul(statistics.f_frsize),
    ))
}

#[cfg(not(unix))]
fn available_space_at(path: &Path) -> Result<Option<u64>> {
    let disks = Disks::new_with_refreshed_list();
    Ok(disks
        .list()
        .iter()
        .filter(|disk| path.starts_with(disk.mount_point()))
        .max_by_key(|disk| {
            (
                disk.mount_point().components().count(),
                disk.available_space(),
            )
        })
        .map(|disk| disk.available_space()))
}

fn remove_review_staging(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("failed to remove private staging {}", path.display())),
    }
}

fn cleanup_stale_import_review_staging(staging_root: &Path) -> Result<()> {
    for entry in fs::read_dir(staging_root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("archive-review-") && !name.starts_with(ARCHIVE_INPUT_PREFIX) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || metadata.is_file() {
            fs::remove_file(&path)?;
        } else if metadata.is_dir() {
            remove_review_staging(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}

fn cleanup_stored_source_archives(
    paths: &DesktopPaths,
    artifacts: &[StoredArtifact],
) -> Result<usize> {
    let mut removed = 0;
    for artifact in artifacts {
        validate_stored_artifact_root(paths, artifact)?;
        for name in ["source.zip", "source.7z"] {
            let source = artifact.root.join(name);
            match fs::symlink_metadata(&source) {
                Ok(metadata) if metadata.file_type().is_file() => {
                    fs::remove_file(&source)?;
                    removed += 1;
                }
                Ok(_) => bail!("artifact source archive is not a regular file"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(removed)
}

fn selected_installation(store: &Store) -> Result<Option<rrmm_domain::InstallationInspection>> {
    let installations = store.installations()?;
    let selected_root = store
        .setting(SELECTED_GAME_ROOT_KEY)?
        .and_then(|value| value.as_str().map(PathBuf::from));
    Ok(installations
        .iter()
        .find(|installation| {
            selected_root.as_ref().is_some_and(|root| {
                paths_refer_to_same_entry(root, &installation.installation.game_root)
            })
        })
        .or_else(|| {
            installations.iter().find(|installation| {
                installation.build_status == BuildStatus::SupportedExact
                    && installation.layout_status == LayoutStatus::Complete
            })
        })
        .or_else(|| installations.first())
        .cloned())
}

fn paths_refer_to_same_entry(first: &Path, second: &Path) -> bool {
    if first == second {
        return true;
    }
    match (fs::canonicalize(first), fs::canonicalize(second)) {
        (Ok(first), Ok(second)) => first == second,
        _ => false,
    }
}

fn ensure_desktop_installation_binding(
    store: &Store,
    installation_id: &str,
    manifest_path: &Path,
    game_root: &Path,
) -> Result<()> {
    match store.installation_binding(installation_id)? {
        Some((bound_manifest, bound_root))
            if paths_refer_to_same_entry(&bound_manifest, manifest_path)
                && paths_refer_to_same_entry(&bound_root, game_root) =>
        {
            Ok(())
        }
        Some(_) => {
            bail!("this manager state is already bound to another Retro Rewind installation")
        }
        None => {
            store.bind_installation_id(installation_id, manifest_path, game_root)?;
            Ok(())
        }
    }
}

fn game_installation_view(
    installation: &rrmm_domain::InstallationInspection,
) -> GameInstallationView {
    let game_running = is_game_running();
    let status = if installation.layout_status != LayoutStatus::Complete {
        "partial_install"
    } else if !installation.writable_hint {
        "unwritable"
    } else {
        match installation.build_status {
            BuildStatus::SupportedExact => "supported_exact",
            BuildStatus::SupportedModified => "supported_modified",
            BuildStatus::SupportedUnfingerprinted => "supported_unfingerprinted",
            BuildStatus::KnownUnsupported => "known_unsupported",
            BuildStatus::Unknown => "unknown_build",
            BuildStatus::PartialInstall => "partial_install",
        }
    };
    let health = match status {
        "supported_exact" if !game_running => HealthLevel::Ready,
        "supported_exact" | "supported_modified" | "supported_unfingerprinted" => {
            HealthLevel::Attention
        }
        _ => HealthLevel::Blocked,
    };
    GameInstallationView {
        detected: true,
        root_path: Some(installation.installation.game_root.display().to_string()),
        build_id: Some(installation.installation.build_id.to_string()),
        expected_build_id: SUPPORTED_BUILD_ID.to_string(),
        health,
        status: status.to_owned(),
        writable: installation.writable_hint,
        game_running,
        source: match installation.installation.source {
            InstallationSource::SteamLibrary => "steam_library",
            InstallationSource::UserOverride => "user_override",
        }
        .to_owned(),
        warnings: installation.warnings.clone(),
    }
}

fn desktop_preferences(store: &Store) -> Result<DesktopPreferences> {
    let Some(value) = store.setting(DESKTOP_PREFERENCES_KEY)? else {
        return Ok(DesktopPreferences::default());
    };
    let preferences: DesktopPreferences = serde_json::from_value(value)
        .context("desktop preferences are invalid; reset the local setting")?;
    if preferences.schema_version != 1 {
        bail!(
            "unsupported desktop preferences schema {}",
            preferences.schema_version
        );
    }
    Ok(preferences)
}

fn copy_verified_ue4ss_download(
    mut input: impl Read,
    mut output: impl Write,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<u64> {
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .context("UE4SS download size overflow")?;
        if total > expected_size {
            bail!("UE4SS download exceeded the pinned artifact size");
        }
        output.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
    }
    if total != expected_size || format!("{:x}", hasher.finalize()) != expected_sha256 {
        bail!("UE4SS download failed SHA-256 verification");
    }
    Ok(total)
}

#[cfg(unix)]
fn sync_directory_if_supported(path: &Path) -> Result<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory_if_supported(_path: &Path) -> Result<()> {
    Ok(())
}

fn preferences_view(preferences: &DesktopPreferences) -> PreferencesView {
    PreferencesView {
        offline_mode: preferences.offline_mode,
    }
}

fn operation_failures(store: &Store) -> Result<Vec<OperationFailureView>> {
    let Some(value) = store.setting(OPERATION_FAILURES_KEY)? else {
        return Ok(Vec::new());
    };
    let failures: Vec<OperationFailureView> = serde_json::from_value(value).unwrap_or_default();
    Ok(failures
        .into_iter()
        .rev()
        .take(MAX_OPERATION_FAILURES)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect())
}

fn redact_json_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(value) => serde_json::Value::String(truncate_chars(
            &redact_sensitive_text(&value),
            MAX_OPERATION_ERROR_CHARS,
        )),
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(redact_json_value).collect())
        }
        serde_json::Value::Object(values) => serde_json::Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, redact_json_value(value)))
                .collect(),
        ),
        value => value,
    }
}

fn truncate_chars(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_owned();
    }
    let mut output = value
        .chars()
        .take(limit.saturating_sub(1))
        .collect::<String>();
    output.push('…');
    output
}

fn operation_error_category(error: &str) -> String {
    let error = error.to_ascii_lowercase();
    if error.contains("http") || error.contains("download") || error.contains("offline") {
        "network".to_owned()
    } else if error.contains("sha-256") || error.contains("hash") || error.contains("identity") {
        "verification".to_owned()
    } else if error.contains("sandbox")
        || error.contains("appcontainer")
        || error.contains("process security attribute")
        || error.contains("child-process policy")
        || error.contains("job object")
    {
        "sandbox".to_owned()
    } else if error.contains("worker") || error.contains("extract") || error.contains("archive") {
        "worker".to_owned()
    } else if error.contains("permission")
        || error.contains("access")
        || error.contains("acesso negado")
        || error.contains("os error 5")
        || error.contains("i/o")
    {
        "filesystem".to_owned()
    } else if error.contains("rollback") || error.contains("recover") || error.contains("journal") {
        "recovery".to_owned()
    } else if error.contains("profile") || error.contains("deployment") {
        "deployment".to_owned()
    } else {
        "operation".to_owned()
    }
}

fn bug_report_technical_summary(
    snapshot: &AppSnapshot,
    operation_timings: &BTreeMap<String, u64>,
) -> serde_json::Value {
    serde_json::json!({
        "offlineMode": snapshot.preferences.offline_mode,
        "game": {
            "health": snapshot.game.health,
            "expectedBuildId": snapshot.game.expected_build_id
        },
        "deployment": {
            "health": snapshot.deployment.health,
            "managedFileCount": snapshot.deployment.managed_file_count,
            "externalModCount": snapshot.deployment.existing_mods.len(),
            "recoveryAvailable": snapshot.deployment.recovery_available
        },
        "ue4ss": {
            "installed": snapshot.ue4ss.installed,
            "health": snapshot.ue4ss.health,
            "recognizedBuild": snapshot.ue4ss.version,
            "mixedInstallation": snapshot.ue4ss.mixed_installation,
            "expectedBuild": snapshot.ue4ss.expected_version
        },
        "counts": {
            "importedMods": snapshot.artifacts.len(),
            "profiles": snapshot.profiles.len(),
            "conflicts": snapshot.conflicts.len()
        },
        "lastOperationDurationMs": operation_timings,
        "diagnostics": snapshot.diagnostics.iter().map(|item| serde_json::json!({
            "id": item.id,
            "level": item.level
        })).collect::<Vec<_>>()
    })
}

fn artifact_views(
    store: &Store,
    profiles: &[DomainProfile],
    receipt: Option<&DeploymentReceipt>,
    catalog: &[CatalogPackage],
) -> Result<Vec<ArtifactView>> {
    let mut views = Vec::new();
    for artifact in store.artifacts()? {
        let manifest: ArtifactManifest = serde_json::from_value(artifact.manifest)?;
        let delete_blocked_reason =
            artifact_deletion_blocker(&artifact.sha256, &manifest, profiles, receipt)
                .map(str::to_owned);
        let package = catalog
            .iter()
            .find(|package| package.artifact_sha256 == artifact.sha256);
        let activation_supported = package.is_some();
        let (package_id, name, version, description, verified, nexus_page_url) = package.map_or_else(
            || {
                (
                    format!("local:{}", &artifact.sha256[..12]),
                    local_package_name(&manifest),
                    "local".to_owned(),
                    "The archive was stored safely, but its file layout is ambiguous or contains unsupported content.".to_owned(),
                    false,
                    None,
                )
            },
            |package| {
                let declared = package.provenance == ManifestProvenance::Declared;
                (
                    package.manifest.id.clone(),
                    package.manifest.name.clone(),
                    package.manifest.version.clone(),
                    if declared {
                        package
                            .manifest
                            .install_notes
                            .first()
                            .cloned()
                            .unwrap_or_else(|| "Reviewed package record.".to_owned())
                    } else {
                        "PAK and UE4SS destinations were inferred from the archive structure. Compatibility is not declared by the author.".to_owned()
                    },
                    declared,
                    declared.then(|| nexus_page_url(package)).flatten(),
                )
            },
        );
        views.push(ArtifactView {
            sha256: artifact.sha256,
            package_id,
            name,
            version,
            author: "Local catalog".to_owned(),
            source_archive: "Immutable artifact store".to_owned(),
            kind: package_kind(manifest.layout.kind).to_owned(),
            verified,
            imported_at: timestamp_from_unix(artifact.accepted_at),
            description,
            file_count: manifest.files.len(),
            nexus_page_url,
            activation_supported,
            deletable: delete_blocked_reason.is_none(),
            delete_blocked_reason,
        });
    }
    views.reverse();
    Ok(views)
}

fn artifact_deletion_blocker(
    artifact_sha256: &str,
    manifest: &ArtifactManifest,
    profiles: &[DomainProfile],
    receipt: Option<&DeploymentReceipt>,
) -> Option<&'static str> {
    if profiles.iter().any(|profile| {
        profile
            .packages
            .iter()
            .any(|package| package.artifact_sha256 == artifact_sha256 && package.enabled)
    }) {
        return Some("enabled_in_profile");
    }
    let artifact_file_hashes: BTreeSet<_> = manifest
        .files
        .iter()
        .map(|file| file.sha256.as_str())
        .collect();
    if receipt.is_some_and(|receipt| {
        receipt
            .files
            .iter()
            .any(|file| artifact_file_hashes.contains(file.sha256.as_str()))
    }) {
        return Some("deployed");
    }
    None
}

fn bulk_delete_blocker(code: &str, message: &str, item_id: Option<&str>) -> BulkDeleteBlockerView {
    BulkDeleteBlockerView {
        code: code.to_owned(),
        message: message.to_owned(),
        item_id: item_id.map(str::to_owned),
    }
}

fn finish_bulk_delete_evidence(mut pending: PendingBulkDelete) -> Result<PendingBulkDelete> {
    pending.evidence_sha256 = sha256_serialized(&serde_json::json!({
        "transactionId": pending.transaction_id,
        "artifactSha256": pending.artifact_sha256,
        "externalModIds": pending.external_mod_ids,
        "externalUnits": pending.external_units,
        "profilesBefore": pending.profiles_before,
        "profilesAfter": pending.profiles_after,
        "artifacts": pending.artifacts,
        "installation": pending.installation,
        "receipt": pending.receipt,
        "plan": pending.plan,
        "externalEvidence": format!("{:?}", pending.external_mods),
        "requiresDeployment": pending.requires_deployment,
        "blockers": pending.blockers,
    }))?;
    Ok(pending)
}

fn bulk_delete_preview_view(
    token: &str,
    pending: &PendingBulkDelete,
) -> Result<BulkDeletePreviewView> {
    let selected = pending
        .artifact_sha256
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let affected_profiles = pending
        .profiles_before
        .iter()
        .zip(&pending.profiles_after)
        .filter_map(|(before, after)| {
            let artifact_count = before
                .packages
                .iter()
                .filter(|package| selected.contains(&package.artifact_sha256))
                .count();
            (before.packages != after.packages || before.pak_load_order != after.pak_load_order)
                .then(|| BulkDeleteProfileView {
                    id: before.id.clone(),
                    name: before.name.clone(),
                    artifact_count,
                })
        })
        .collect();
    let deployed_artifact_count = pending
        .artifacts
        .iter()
        .filter(|artifact| {
            serde_json::from_value::<ArtifactManifest>(artifact.manifest.clone()).is_ok_and(
                |manifest| {
                    pending.receipt.as_ref().is_some_and(|receipt| {
                        receipt.files.iter().any(|owned| {
                            manifest
                                .files
                                .iter()
                                .any(|file| file.sha256 == owned.sha256)
                        })
                    })
                },
            )
        })
        .count();
    Ok(BulkDeletePreviewView {
        token: token.to_owned(),
        blocked: !pending.blockers.is_empty(),
        managed_artifact_count: pending.artifact_sha256.len(),
        external_mod_count: pending.external_mod_ids.len(),
        external_group_count: pending
            .external_units
            .iter()
            .filter(|unit| unit.group_id.is_some())
            .count(),
        affected_profiles,
        deployed_artifact_count,
        requires_deployment: pending.requires_deployment,
        deployment_change_count: pending.plan.as_ref().map_or(0, |plan| {
            plan.changes
                .iter()
                .filter(|change| change.kind != DeploymentChangeKind::UnchangedManaged)
                .count()
        }),
        blockers: pending.blockers.clone(),
    })
}

fn selected_artifact_file_hashes(artifacts: &[StoredArtifact]) -> Result<BTreeSet<String>> {
    let mut hashes = BTreeSet::new();
    for artifact in artifacts {
        let manifest: ArtifactManifest = serde_json::from_value(artifact.manifest.clone())?;
        hashes.extend(manifest.files.into_iter().map(|file| file.sha256));
    }
    Ok(hashes)
}

fn artifact_pak_hashes(artifacts: &[StoredArtifact]) -> Result<BTreeSet<String>> {
    let mut hashes = BTreeSet::new();
    for artifact in artifacts {
        let manifest: ArtifactManifest = serde_json::from_value(artifact.manifest.clone())?;
        hashes.extend(
            manifest
                .files
                .into_iter()
                .filter(|file| file.path.to_ascii_lowercase().ends_with(".pak"))
                .map(|file| file.sha256),
        );
    }
    Ok(hashes)
}

fn validate_stored_artifact_root(paths: &DesktopPaths, artifact: &StoredArtifact) -> Result<()> {
    let expected = paths
        .artifact_store
        .join("artifacts")
        .join(&artifact.sha256[..2])
        .join(&artifact.sha256);
    if artifact.root != expected {
        bail!("artifact store path does not match its content address");
    }
    let metadata = fs::symlink_metadata(&artifact.root)
        .with_context(|| format!("artifact directory {} is missing", artifact.root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("artifact store entry is not a regular directory");
    }
    Ok(())
}

fn rollback_artifact_quarantine(quarantined: &[(PathBuf, PathBuf)]) -> Result<()> {
    for (quarantine, original) in quarantined.iter().rev() {
        if original.exists() {
            bail!(
                "artifact quarantine rollback destination already exists: {}",
                original.display()
            );
        }
        fs::rename(quarantine, original).with_context(|| {
            format!(
                "failed to restore quarantined artifact to {}",
                original.display()
            )
        })?;
    }
    Ok(())
}

fn write_artifact_quarantine_journal(
    quarantine: &Path,
    artifacts: &[StoredArtifact],
) -> Result<()> {
    let journal = ArtifactQuarantineJournal {
        artifacts: artifacts
            .iter()
            .map(|artifact| ArtifactQuarantineEntry {
                sha256: artifact.sha256.clone(),
                original: artifact.root.clone(),
            })
            .collect(),
    };
    let journal_path = quarantine.join("journal.json");
    let temporary_path = quarantine.join("journal.next");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)?;
    file.write_all(&serde_json::to_vec_pretty(&journal)?)?;
    file.sync_all()?;
    fs::rename(&temporary_path, &journal_path)?;
    fs::File::open(quarantine)?.sync_all()?;
    if let Some(parent) = quarantine.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn recover_artifact_quarantines(paths: &DesktopPaths, store: &Store) -> Result<usize> {
    let stored = store
        .artifacts()?
        .into_iter()
        .map(|artifact| (artifact.sha256, artifact.root))
        .collect::<BTreeMap<_, _>>();
    let mut recovered = 0;
    for entry in fs::read_dir(&paths.staging)? {
        let entry = entry?;
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(BULK_DELETE_QUARANTINE_PREFIX)
        {
            continue;
        }
        let root = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() || !file_type.is_dir() {
            bail!("bulk-delete quarantine contains an unsafe filesystem entry");
        }
        let journal_path = root.join("journal.json");
        if !journal_path.exists() {
            if fs::read_dir(&root)?.next().is_none() {
                fs::remove_dir(&root)?;
                continue;
            }
            bail!(
                "bulk-delete quarantine '{}' has no recovery journal",
                root.display()
            );
        }
        let journal: ArtifactQuarantineJournal = serde_json::from_slice(&fs::read(&journal_path)?)?;
        for artifact in &journal.artifacts {
            if !is_sha256(&artifact.sha256) {
                bail!("bulk-delete quarantine journal contains an invalid artifact hash");
            }
            let expected = paths
                .artifact_store
                .join("artifacts")
                .join(&artifact.sha256[..2])
                .join(&artifact.sha256);
            if artifact.original != expected {
                bail!("bulk-delete quarantine journal contains an unsafe artifact path");
            }
            let quarantined = root.join(&artifact.sha256);
            if stored.get(&artifact.sha256) == Some(&artifact.original) {
                match (artifact.original.exists(), quarantined.exists()) {
                    (false, true) => fs::rename(&quarantined, &artifact.original)?,
                    (true, false) => {}
                    (true, true) => bail!(
                        "artifact '{}' exists in both its store and quarantine paths",
                        artifact.sha256
                    ),
                    (false, false) => bail!(
                        "artifact '{}' is missing from both its store and quarantine paths",
                        artifact.sha256
                    ),
                }
            }
        }
        fs::remove_dir_all(&root)?;
        recovered += 1;
    }
    Ok(recovered)
}

fn deployment_blocker_code(blocker: &DeploymentBlocker) -> &'static str {
    match blocker {
        DeploymentBlocker::GameRunning => "game_running",
        DeploymentBlocker::ManagedFileMissing { .. }
        | DeploymentBlocker::ManagedFileDrifted { .. } => "deployment_drift",
        DeploymentBlocker::PathCollision { .. }
        | DeploymentBlocker::ExternalTargetOccupied { .. } => "deployment_conflict",
        DeploymentBlocker::UnmanagedPath { .. } => "unmanaged_path",
        DeploymentBlocker::UnsafeFilesystemEntry { .. } => "unsafe_filesystem_entry",
    }
}

fn profile_view(profile: &DomainProfile) -> ProfileView {
    ProfileView {
        id: profile.id.clone(),
        name: profile.name.clone(),
        packages: profile
            .packages
            .iter()
            .enumerate()
            .map(|(index, package)| ProfilePackageView {
                artifact_sha256: package.artifact_sha256.clone(),
                enabled: package.enabled,
                priority: (index + 1) * 10,
            })
            .collect(),
        pak_load_order: profile.pak_load_order.clone(),
        updated_at: now(),
    }
}

fn validate_desktop_profile_name(name: &str) -> Result<&str> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 48 || name.contains(['\0', '\r', '\n']) {
        bail!("profile name must contain 1 to 48 single-line characters");
    }
    Ok(name)
}

fn update_profile_selection(
    profile: &mut DomainProfile,
    artifact_sha256: &str,
    enabled: bool,
    catalog: &[CatalogPackage],
) {
    if enabled
        && let Some(target) = catalog
            .iter()
            .find(|package| package.artifact_sha256 == artifact_sha256)
    {
        let alternatives: BTreeSet<_> = catalog
            .iter()
            .filter(|package| package.manifest.id == target.manifest.id)
            .map(|package| package.artifact_sha256.as_str())
            .collect();
        for package in &mut profile.packages {
            if package.artifact_sha256 != artifact_sha256
                && alternatives.contains(package.artifact_sha256.as_str())
            {
                package.enabled = false;
            }
        }
    }
    match profile
        .packages
        .iter_mut()
        .find(|package| package.artifact_sha256 == artifact_sha256)
    {
        Some(package) => package.enabled = enabled,
        None => profile.packages.push(ProfilePackageSelection {
            artifact_sha256: artifact_sha256.to_owned(),
            variant: None,
            enabled,
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UnmanagedPackageConflict {
    path: String,
    selected_name: String,
    installed_name: String,
    reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExistingModRecordState {
    Disabling,
    Disabled,
    Enabling,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredExistingModFile {
    original_path: String,
    #[serde(default)]
    active_path: Option<String>,
    stored_name: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredExistingModLink {
    original_path: String,
    target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExistingModRecord {
    schema_version: u32,
    id: String,
    display_name: String,
    #[serde(default = "default_existing_mod_type")]
    mod_type: String,
    #[serde(default)]
    components: Vec<String>,
    #[serde(default = "default_existing_mod_origin")]
    origin: String,
    #[serde(default)]
    directories: Vec<String>,
    state: ExistingModRecordState,
    files: Vec<StoredExistingModFile>,
    #[serde(default)]
    links: Vec<StoredExistingModLink>,
    #[serde(default)]
    mods_txt_edit: Option<ModsTxtEditSnapshot>,
    #[serde(default)]
    nexus_page_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ModsTxtEditSnapshot {
    relative_path: String,
    before: Vec<u8>,
    after: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExistingGroupSnapshot {
    #[serde(skip)]
    root: PathBuf,
    files: Vec<ExistingGroupSnapshotFile>,
    records: Vec<ExistingGroupSnapshotRecord>,
    directories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExistingGroupSnapshotFile {
    relative_path: String,
    expected_sha256: String,
    backup_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExistingGroupSnapshotRecord {
    id: String,
    backup_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ue4ssLoaderArtifact {
    build_id: u64,
    loader_build_id: String,
    filename: String,
    url: String,
    archive_size: u64,
    archive_sha256: String,
    proxy_path: String,
    proxy_sha256: String,
    core_path: String,
    core_sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalModGroup {
    package_id: String,
    name: String,
    version: String,
    #[serde(default)]
    nexus_page_url: Option<String>,
    pak_install_name: String,
    pak_sha256: String,
    ue4ss_install_name: String,
    ue4ss_files: Vec<ExternalModGroupFile>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalModGroupFile {
    path: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalModLink {
    display_names: Vec<String>,
    #[serde(default)]
    mod_types: Vec<String>,
    nexus_page_url: String,
}

fn default_existing_mod_type() -> String {
    "pak".to_owned()
}

fn default_existing_mod_origin() -> String {
    "external".to_owned()
}

fn adopted_external_mods(store: &Store) -> Result<BTreeMap<String, String>> {
    store
        .setting(ADOPTED_EXTERNAL_MODS_KEY)?
        .map(serde_json::from_value)
        .transpose()
        .map_err(Into::into)
        .map(|value| value.unwrap_or_default())
}

fn adopted_package_catalog(store: &Store) -> Result<Vec<CatalogPackage>> {
    let catalog: Vec<CatalogPackage> = store
        .setting(ADOPTED_PACKAGE_CATALOG_KEY)?
        .map(serde_json::from_value)
        .transpose()?
        .unwrap_or_default();
    for package in &catalog {
        rrmm_manifest::validate_manifest(&package.manifest)?;
        if package.artifact_sha256.is_empty() {
            bail!("adopted package catalog contains an empty artifact identity");
        }
    }
    Ok(catalog)
}

fn write_existing_mod_adoption_archive(
    game_root: &Path,
    archive: &Path,
    members: &[&ExistingModView],
) -> Result<()> {
    let file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(archive)?;
    let mut writer = zip::ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let mut archive_paths = BTreeSet::new();
    for member in members {
        let module_name = Path::new(&member.path)
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned);
        for relative in &member.related_paths {
            let archive_path = if member.mod_type == "pak" {
                Path::new(relative)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .context("installed PAK path is not valid UTF-8")?
                    .to_owned()
            } else {
                let module_name = module_name
                    .as_deref()
                    .context("installed UE4SS module has no directory name")?;
                let suffix = relative
                    .strip_prefix(&member.path)
                    .map(|value| value.trim_start_matches('/'))
                    .filter(|value| !value.is_empty())
                    .context("installed UE4SS file is outside its module root")?;
                format!("{module_name}/{suffix}")
            };
            rrmm_archive::validate_entry_path(&archive_path, false, 32)?;
            if !archive_paths.insert(archive_path.clone()) {
                bail!("installed mod components map to the same package path");
            }
            let active_relative = member
                .active_paths
                .get(relative)
                .map(String::as_str)
                .unwrap_or(relative);
            let source = checked_game_mod_path(game_root, active_relative)?;
            let metadata = fs::symlink_metadata(&source)?;
            if !metadata.file_type().is_file() {
                bail!("installed mod changed before it could be adopted");
            }
            if let Some((expected_bytes, expected_sha256)) = member.file_identities.get(relative)
                && (metadata.len() != *expected_bytes
                    || rrmm_archive::sha256_path(&source)? != *expected_sha256)
            {
                bail!("installed mod changed before it could be adopted");
            }
            writer.start_file(archive_path, options)?;
            let mut source_file = fs::File::open(source)?;
            std::io::copy(&mut source_file, &mut writer)?;
        }
    }
    let file = writer.finish()?;
    file.sync_all()?;
    Ok(())
}

fn external_mod_groups() -> Result<Vec<ExternalModGroup>> {
    let groups: Vec<ExternalModGroup> = serde_json::from_str(EXTERNAL_MOD_GROUPS_JSON)?;
    let mut package_ids = BTreeSet::new();
    for group in &groups {
        if !package_ids.insert(group.package_id.as_str())
            || group.ue4ss_files.is_empty()
            || !is_sha256(&group.pak_sha256)
        {
            bail!("external mod group catalog contains invalid or duplicate package metadata");
        }
        if group.package_id.starts_with("nexus:")
            && group
                .nexus_page_url
                .as_deref()
                .is_none_or(|url| !is_reviewed_nexus_mod_url(url))
        {
            bail!(
                "external Nexus mod group '{}' requires a reviewed Nexus page URL",
                group.package_id
            );
        }
        let mut paths = BTreeSet::new();
        for file in &group.ue4ss_files {
            let path = Path::new(&file.path);
            if path.is_absolute()
                || path.components().count() == 0
                || path
                    .components()
                    .any(|component| !matches!(component, std::path::Component::Normal(_)))
                || !paths.insert(file.path.as_str())
                || !is_sha256(&file.sha256)
            {
                bail!("external mod group contains unsafe UE4SS file identity metadata");
            }
        }
    }
    Ok(groups)
}

fn external_mod_links() -> Result<Vec<ExternalModLink>> {
    let links: Vec<ExternalModLink> = serde_json::from_str(EXTERNAL_MOD_LINKS_JSON)?;
    if links.iter().any(|link| {
        link.display_names.is_empty()
            || link.display_names.iter().any(|name| name.trim().is_empty())
            || !is_reviewed_nexus_mod_url(&link.nexus_page_url)
    }) {
        bail!("external mod link catalog contains invalid metadata");
    }
    Ok(links)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_reviewed_nexus_mod_url(value: &str) -> bool {
    value
        .strip_prefix("https://www.nexusmods.com/retrorewindvideostoresimulator/mods/")
        .is_some_and(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()))
}

fn existing_mod_views(
    game_root: &Path,
    state_root: &Path,
    receipt: Option<&DeploymentReceipt>,
) -> Result<Vec<ExistingModView>> {
    let records_root = state_root.join(EXISTING_MODS_DIRECTORY);
    let mut records = Vec::new();
    if records_root.is_dir() {
        for entry in fs::read_dir(&records_root)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.file_type().is_dir() {
                continue;
            }
            records.push(load_existing_mod_record(&entry.path())?);
        }
    }
    let suppressed_module_roots: BTreeSet<_> = records
        .iter()
        .flat_map(|record| {
            record
                .directories
                .iter()
                .chain(record.links.iter().map(|link| &link.original_path))
        })
        .filter(|path| {
            Path::new(path)
                .parent()
                .is_some_and(|parent| parent.ends_with("Mods"))
        })
        .cloned()
        .collect();
    let mut views = active_existing_mod_views(game_root, receipt)?;
    views.extend(active_ue4ss_existing_mod_views(
        game_root,
        receipt,
        &suppressed_module_roots,
    )?);
    views.extend(active_ue4ss_link_views(
        game_root,
        &suppressed_module_roots,
    )?);
    for record in records {
        let file_identities = record
            .files
            .iter()
            .map(|file| {
                (
                    file.original_path.clone(),
                    (file.size_bytes, file.sha256.clone()),
                )
            })
            .collect();
        let primary_original_path = record.files.first().map_or_else(
            || {
                if let Some(link) = record.links.first() {
                    Ok(link.original_path.clone())
                } else {
                    record
                        .directories
                        .iter()
                        .min_by_key(|path| Path::new(path).components().count())
                        .cloned()
                        .context("disabled installed-mod record contains no paths")
                }
            },
            |file| Ok(file.original_path.clone()),
        )?;
        let primary_pak_sha256 = (record.mod_type == "pak")
            .then(|| record.files.first().map(|file| file.sha256.clone()))
            .flatten();
        views.push(ExistingModView {
            id: record.id,
            display_name: record.display_name,
            path: primary_original_path.clone(),
            related_paths: record
                .files
                .iter()
                .map(|file| file.original_path.clone())
                .collect(),
            size_bytes: record.files.iter().map(|file| file.size_bytes).sum(),
            mod_type: record.mod_type,
            origin: record.origin,
            components: record.components,
            enabled: false,
            manageable: record.state == ExistingModRecordState::Disabled,
            blocked_reason: (record.state != ExistingModRecordState::Disabled)
                .then(|| "existing_mod_operation_interrupted".to_owned()),
            nexus_page_url: record.nexus_page_url,
            group_id: None,
            group_name: None,
            stored: true,
            directories: record.directories,
            ue4ss_module_name: None,
            mods_txt_controlled: false,
            file_identities,
            pak_sha256: primary_pak_sha256,
            original_path: Some(primary_original_path),
            active_paths: BTreeMap::new(),
            symlink_target: record.links.first().map(|link| link.target.clone()),
        });
    }
    group_reviewed_hybrid_mods(game_root, &mut views)?;
    apply_external_mod_links(&mut views, &external_mod_links()?);
    views.sort_by(|left, right| {
        left.display_name
            .to_lowercase()
            .cmp(&right.display_name.to_lowercase())
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(views)
}

fn apply_external_mod_links(views: &mut [ExistingModView], links: &[ExternalModLink]) {
    for view in views {
        if view.nexus_page_url.is_some() {
            continue;
        }
        let Some(link) = links.iter().find(|link| {
            link.display_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case(&view.display_name))
                && (link.mod_types.is_empty()
                    || link.mod_types.iter().any(|kind| kind == &view.mod_type))
        }) else {
            continue;
        };
        view.nexus_page_url = Some(link.nexus_page_url.clone());
    }
}

fn active_existing_mod_views(
    game_root: &Path,
    receipt: Option<&DeploymentReceipt>,
) -> Result<Vec<ExistingModView>> {
    let unmanaged = unmanaged_pak_views(game_root, receipt)?;
    let mut views = Vec::with_capacity(unmanaged.len());
    for pak in unmanaged {
        let pak_path = checked_game_mod_path(game_root, &pak.path)?;
        let current_pak_stem = pak_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .context("installed PAK name is not valid UTF-8")?;
        let display_pak_stem = Path::new(&pak.original_path)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .context("installed PAK name is not valid UTF-8")?;
        let mut related_paths = vec![pak.original_path.clone()];
        let mut active_paths = pak.active_paths.clone();
        let mut total_size = pak.size_bytes;
        let mut blocked_reason = (!pak.manageable).then(|| "pak_companion_unsupported".to_owned());
        if let Some(parent) = pak_path.parent() {
            for entry in fs::read_dir(parent)? {
                let entry = entry?;
                let path = entry.path();
                if path == pak_path
                    || !path
                        .file_stem()
                        .and_then(|stem| stem.to_str())
                        .is_some_and(|stem| stem.eq_ignore_ascii_case(current_pak_stem))
                {
                    continue;
                }
                let extension = path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .unwrap_or_default();
                if extension.eq_ignore_ascii_case("utoc") || extension.eq_ignore_ascii_case("ucas")
                {
                    blocked_reason = Some("pak_iostore_unsupported".to_owned());
                    continue;
                }
                if !extension.eq_ignore_ascii_case("sig") {
                    continue;
                }
                let metadata = fs::symlink_metadata(&path)?;
                if !metadata.file_type().is_file() {
                    blocked_reason = Some("pak_signature_not_regular".to_owned());
                    continue;
                }
                let relative = path
                    .strip_prefix(game_root)?
                    .to_str()
                    .context("installed mod signature path is not valid UTF-8")?
                    .replace('\\', "/");
                let sha256 = rrmm_archive::sha256_path(&path)?;
                let original = receipt_original_external_path(receipt, &relative, &sha256)
                    .unwrap_or_else(|| relative.clone());
                active_paths.insert(original.clone(), relative);
                related_paths.push(original);
                total_size += metadata.len();
            }
        }
        related_paths.sort();
        views.push(ExistingModView {
            id: existing_mod_id(&pak.original_path),
            display_name: existing_mod_display_name(display_pak_stem),
            path: pak.original_path.clone(),
            related_paths,
            size_bytes: total_size,
            mod_type: "pak".to_owned(),
            origin: "external".to_owned(),
            components: vec!["pak".to_owned()],
            enabled: true,
            manageable: blocked_reason.is_none() && pak.manageable,
            blocked_reason,
            nexus_page_url: None,
            group_id: None,
            group_name: None,
            stored: false,
            directories: Vec::new(),
            ue4ss_module_name: None,
            mods_txt_controlled: false,
            file_identities: BTreeMap::new(),
            pak_sha256: Some(pak.pak_sha256),
            original_path: Some(pak.original_path),
            active_paths,
            symlink_target: None,
        });
    }
    Ok(views)
}

fn active_ue4ss_existing_mod_views(
    game_root: &Path,
    receipt: Option<&DeploymentReceipt>,
    suppressed_module_roots: &BTreeSet<String>,
) -> Result<Vec<ExistingModView>> {
    let inventory = inventory_ue4ss(game_root, &Ue4ssInventoryLimits::default())?;
    if inventory.installation_status == Ue4ssInstallationStatus::Absent {
        return Ok(Vec::new());
    }
    let activation = analyze_ue4ss_activation(
        game_root,
        &Ue4ssInventoryLimits::default(),
        &Ue4ssActivationLimits::default(),
    )?;
    let managed: BTreeSet<_> = receipt
        .into_iter()
        .flat_map(|receipt| receipt.files.iter())
        .map(|file| file.relative_path.as_str())
        .collect();
    let mut views = Vec::new();
    for module in inventory.modules {
        if suppressed_module_roots.contains(&module.relative_path) {
            continue;
        }
        let activation_state = activation
            .modules
            .iter()
            .find(|state| state.name == module.name);
        let enabled = activation_state.is_some_and(|state| {
            matches!(
                state.declared_state,
                Ue4ssDeclaredActivation::EnabledByMarker
                    | Ue4ssDeclaredActivation::EnabledByModsTxt
                    | Ue4ssDeclaredActivation::EnabledByBoth
            )
        });
        // A module directory without files is not a mod. Managed deployments can
        // legitimately leave an empty directory behind after their last file is
        // removed, and presenting that directory as an external module creates a
        // duplicate library entry for the package that owns it.
        if module.files.is_empty() {
            continue;
        }
        let mut related_paths = Vec::new();
        let mut directories = BTreeSet::new();
        directories.insert(module.relative_path.clone());
        let mut size_bytes = 0;
        let mut managed_files = 0;
        let mut blocked_reason = None;
        for file in &module.files {
            if matches!(
                file.kind,
                Ue4ssFileKind::UnsafeLink | Ue4ssFileKind::Special
            ) {
                blocked_reason = Some("ue4ss_unsafe_filesystem_entry".to_owned());
                continue;
            }
            if managed.contains(file.relative_path.as_str()) {
                managed_files += 1;
                continue;
            }
            let path = checked_game_mod_path(game_root, &file.relative_path)?;
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.file_type().is_file() {
                blocked_reason = Some("ue4ss_changed_during_inventory".to_owned());
                continue;
            }
            size_bytes += metadata.len();
            related_paths.push(file.relative_path.clone());
            let mut parent = Path::new(&file.relative_path).parent();
            while let Some(path) = parent {
                let normalized = path.to_string_lossy().replace('\\', "/");
                if !normalized.starts_with(&module.relative_path) {
                    break;
                }
                directories.insert(normalized.clone());
                if normalized == module.relative_path {
                    break;
                }
                parent = path.parent();
            }
        }
        if managed_files == module.files.len() && !module.files.is_empty() {
            continue;
        }
        if managed_files > 0 && blocked_reason.is_none() {
            blocked_reason = Some("ue4ss_mixed_ownership".to_owned());
        }
        if related_paths.is_empty() && blocked_reason.is_none() {
            blocked_reason = Some("ue4ss_no_regular_files".to_owned());
        }
        if module.kind == Ue4ssModuleKind::Indeterminate && blocked_reason.is_none() {
            blocked_reason = Some("ue4ss_module_scan_incomplete".to_owned());
        }
        let mods_txt_controlled =
            activation_state.is_some_and(|state| !state.mods_txt_lines.is_empty());
        if blocked_reason.is_none()
            && activation_state.is_some_and(|state| {
                state.mods_txt_lines.len() > 1
                    || state.enabled_txt.status == EntryStatus::Directory
                    || (state.enabled_txt.status == EntryStatus::RegularFile
                        && !state.mods_txt_lines.is_empty())
            })
        {
            blocked_reason = Some("ue4ss_activation_ambiguous".to_owned());
        }
        if blocked_reason.is_none()
            && mods_txt_controlled
            && activation.mods_txt.status != ModsTxtAnalysisStatus::Parsed
        {
            blocked_reason = Some("ue4ss_mods_txt_unparsed".to_owned());
        }
        let mod_type = match module.kind {
            Ue4ssModuleKind::Lua => "ue4ss_lua",
            Ue4ssModuleKind::Native => "ue4ss_native",
            Ue4ssModuleKind::Hybrid => "ue4ss_hybrid",
            Ue4ssModuleKind::Unknown => "ue4ss_unknown",
            Ue4ssModuleKind::Indeterminate => "ue4ss_indeterminate",
        };
        related_paths.sort();
        let display_name = if module.name == "FastTurn" {
            "FastTurn Prototype".to_owned()
        } else {
            module.name.clone()
        };
        views.push(ExistingModView {
            id: existing_mod_id(&format!("ue4ss:{}", module.relative_path)),
            display_name,
            path: module.relative_path,
            related_paths,
            size_bytes,
            mod_type: mod_type.to_owned(),
            origin: "external".to_owned(),
            components: vec![mod_type.to_owned()],
            enabled,
            manageable: blocked_reason.is_none(),
            blocked_reason,
            nexus_page_url: None,
            group_id: None,
            group_name: None,
            stored: false,
            directories: directories.into_iter().collect(),
            ue4ss_module_name: Some(module.name),
            mods_txt_controlled,
            file_identities: BTreeMap::new(),
            pak_sha256: None,
            original_path: None,
            active_paths: BTreeMap::new(),
            symlink_target: None,
        });
    }
    Ok(views)
}

fn active_ue4ss_link_views(
    game_root: &Path,
    suppressed_module_roots: &BTreeSet<String>,
) -> Result<Vec<ExistingModView>> {
    let mut views = Vec::new();
    for relative_root in [
        "RetroRewind/Binaries/Win64/ue4ss/Mods",
        "RetroRewind/Binaries/Win64/Mods",
    ] {
        let root = game_root.join(relative_root);
        let metadata = match fs::symlink_metadata(&root) {
            Ok(metadata) if metadata.file_type().is_dir() => metadata,
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_dir() {
            continue;
        }
        let mut entries: Vec<_> = fs::read_dir(&root)?.collect::<std::io::Result<_>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            if !entry.file_type()?.is_symlink() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let relative = format!("{relative_root}/{name}");
            if suppressed_module_roots.contains(&relative) {
                continue;
            }
            let target = fs::read_link(entry.path())?;
            let target = target.to_str().map(str::to_owned);
            let display_name = if name == "FastTurn" {
                "FastTurn Prototype".to_owned()
            } else {
                name.clone()
            };
            views.push(ExistingModView {
                id: existing_mod_id(&format!("ue4ss:{relative}")),
                display_name,
                path: relative,
                related_paths: Vec::new(),
                size_bytes: 0,
                mod_type: "ue4ss_link".to_owned(),
                origin: "external".to_owned(),
                components: vec!["ue4ss_link".to_owned()],
                enabled: true,
                manageable: target.is_some(),
                blocked_reason: target
                    .is_none()
                    .then(|| "ue4ss_link_target_not_unicode".to_owned()),
                nexus_page_url: None,
                group_id: None,
                group_name: None,
                pak_sha256: None,
                original_path: None,
                stored: false,
                directories: Vec::new(),
                ue4ss_module_name: Some(name),
                mods_txt_controlled: false,
                file_identities: BTreeMap::new(),
                active_paths: BTreeMap::new(),
                symlink_target: target,
            });
        }
    }
    Ok(views)
}

fn group_reviewed_hybrid_mods(game_root: &Path, views: &mut [ExistingModView]) -> Result<()> {
    group_reviewed_hybrid_mods_with_groups(game_root, views, &external_mod_groups()?)
}

fn group_reviewed_hybrid_mods_with_groups(
    game_root: &Path,
    views: &mut [ExistingModView],
    groups: &[ExternalModGroup],
) -> Result<()> {
    for group in groups {
        let mut pak_candidates = Vec::new();
        for (index, view) in views.iter().enumerate() {
            if view.mod_type != "pak"
                || !Path::new(&view.path)
                    .file_name()
                    .is_some_and(|name| name.eq_ignore_ascii_case(&group.pak_install_name))
            {
                continue;
            }
            if existing_view_file_matches(game_root, view, &view.path, None, &group.pak_sha256)? {
                pak_candidates.push(index);
            }
        }
        let module_suffix = format!("/{}", group.ue4ss_install_name);
        let mut module_candidates = Vec::new();
        for (index, view) in views.iter().enumerate() {
            let module_root =
                if view.path.ends_with(&module_suffix) || view.path == group.ue4ss_install_name {
                    Some(view.path.as_str())
                } else {
                    view.directories.iter().find_map(|path| {
                        (path.ends_with(&module_suffix) || path == &group.ue4ss_install_name)
                            .then_some(path.as_str())
                    })
                };
            if !view.mod_type.starts_with("ue4ss_")
                || module_root.is_none()
                || view.related_paths.len() != group.ue4ss_files.len()
            {
                continue;
            }
            let module_root = module_root.expect("module root checked above");
            let mut matches = true;
            for expected in &group.ue4ss_files {
                let Some(relative) = view.related_paths.iter().find(|path| {
                    path.strip_prefix(module_root)
                        .is_some_and(|rest| rest.trim_start_matches('/') == expected.path)
                }) else {
                    matches = false;
                    break;
                };
                if !existing_view_file_matches(
                    game_root,
                    view,
                    relative,
                    Some(expected.size_bytes),
                    &expected.sha256,
                )? {
                    matches = false;
                    break;
                }
            }
            if matches {
                module_candidates.push(index);
            }
        }
        if pak_candidates.len() != 1 || module_candidates.len() != 1 {
            continue;
        }
        let group_id = format!("reviewed:{}:{}", group.package_id, group.version);
        let page_url = group.nexus_page_url.clone();
        for index in [pak_candidates[0], module_candidates[0]] {
            let view = &mut views[index];
            view.group_id = Some(group_id.clone());
            view.group_name = Some(group.name.clone());
            view.nexus_page_url = page_url.clone();
            view.origin = "reviewed_external".to_owned();
        }
    }
    Ok(())
}

fn existing_view_file_matches(
    game_root: &Path,
    view: &ExistingModView,
    relative_path: &str,
    expected_size: Option<u64>,
    expected_sha256: &str,
) -> Result<bool> {
    if let Some((size, sha256)) = view.file_identities.get(relative_path) {
        return Ok(
            expected_size.is_none_or(|expected| expected == *size) && sha256 == expected_sha256
        );
    }
    let active_path = view
        .active_paths
        .get(relative_path)
        .map(String::as_str)
        .unwrap_or(relative_path);
    let path = checked_game_mod_path(game_root, active_path)?;
    let metadata = fs::symlink_metadata(&path)?;
    Ok(metadata.file_type().is_file()
        && expected_size.is_none_or(|expected| expected == metadata.len())
        && rrmm_archive::sha256_path(&path)? == expected_sha256)
}

fn existing_mod_id(path: &str) -> String {
    let digest = Sha256::digest(path.as_bytes());
    let short = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("existing-{short}")
}

fn existing_mod_display_name(stem: &str) -> String {
    let priority_length = stem
        .chars()
        .take_while(|character| character.eq_ignore_ascii_case(&'z'))
        .count();
    let without_priority = if priority_length >= 4 {
        &stem[priority_length..]
    } else {
        stem
    }
    .trim_start_matches(['_', '-', ' ']);
    let without_suffix = without_priority
        .strip_suffix("_P")
        .or_else(|| without_priority.strip_suffix("_p"))
        .unwrap_or(without_priority);
    let display = without_suffix.replace(['_', '-'], " ");
    if display.trim().is_empty() {
        stem.to_owned()
    } else {
        display.trim().to_owned()
    }
}

fn checked_game_mod_path(game_root: &Path, relative: &str) -> Result<PathBuf> {
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("installed mod path contains an unsafe component");
    }
    let pak_root = Path::new("RetroRewind/Content/Paks");
    if relative.starts_with(pak_root)
        && relative.components().count() > pak_root.components().count()
    {
        return Ok(game_root.join(relative));
    }
    for mods_root in [
        Path::new("RetroRewind/Binaries/Win64/ue4ss/Mods"),
        Path::new("RetroRewind/Binaries/Win64/Mods"),
    ] {
        if !relative.starts_with(mods_root) {
            continue;
        }
        let suffix: Vec<_> = relative
            .components()
            .skip(mods_root.components().count())
            .collect();
        if suffix.len() >= 2
            && !suffix[0]
                .as_os_str()
                .to_string_lossy()
                .eq_ignore_ascii_case("mods.txt")
        {
            return Ok(game_root.join(relative));
        }
    }
    bail!("installed mod path is outside a supported PAK or UE4SS module directory")
}

fn checked_existing_mod_directory(game_root: &Path, relative: &str) -> Result<PathBuf> {
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("installed mod directory contains an unsafe component");
    }
    for mods_root in [
        Path::new("RetroRewind/Binaries/Win64/ue4ss/Mods"),
        Path::new("RetroRewind/Binaries/Win64/Mods"),
    ] {
        if relative.starts_with(mods_root)
            && relative.components().count() > mods_root.components().count()
        {
            return Ok(game_root.join(relative));
        }
    }
    bail!("installed mod directory is outside the selected UE4SS module tree")
}

fn ensure_safe_existing_mod_parent(game_root: &Path, destination: &Path) -> Result<()> {
    let parent = destination
        .parent()
        .context("installed mod path has no parent directory")?;
    let relative = parent
        .strip_prefix(game_root)
        .context("installed mod parent is outside the game directory")?;
    let mut current = game_root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            bail!("installed mod parent contains an unsafe path component");
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("installed mod parent is missing: {}", current.display()))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            bail!(
                "installed mod parent is not a regular directory: {}",
                current.display()
            );
        }
    }
    Ok(())
}

fn existing_mod_record_directory(state_root: &Path, mod_id: &str) -> Result<PathBuf> {
    if !mod_id.starts_with("existing-")
        || !mod_id.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
    {
        bail!("installed mod identifier is invalid");
    }
    Ok(state_root.join(EXISTING_MODS_DIRECTORY).join(mod_id))
}

fn load_existing_mod_record(directory: &Path) -> Result<ExistingModRecord> {
    let directory_metadata = fs::symlink_metadata(directory).with_context(|| {
        format!(
            "failed to inspect installed-mod storage {}",
            directory.display()
        )
    })?;
    if !directory_metadata.file_type().is_dir() {
        bail!("installed-mod storage is not a regular directory");
    }
    let path = directory.join("record.json");
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("failed to inspect installed-mod record {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!(
            "installed-mod record is not a regular file: {}",
            path.display()
        );
    }
    let record: ExistingModRecord = serde_json::from_slice(&fs::read(&path)?)?;
    if !matches!(record.schema_version, 1 | 2)
        || (record.files.is_empty()
            && record.links.is_empty()
            && (!record.mod_type.starts_with("ue4ss_") || record.directories.is_empty()))
    {
        bail!("installed-mod record has an unsupported format");
    }
    if !record.id.starts_with("existing-")
        || !record.id.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
    {
        bail!("installed-mod record contains an invalid identifier");
    }
    if !matches!(
        record.mod_type.as_str(),
        "pak"
            | "ue4ss_lua"
            | "ue4ss_native"
            | "ue4ss_hybrid"
            | "ue4ss_unknown"
            | "ue4ss_indeterminate"
            | "ue4ss_link"
            | "hybrid_pak_ue4ss"
    ) || !matches!(record.origin.as_str(), "external" | "reviewed_external")
    {
        bail!("installed-mod record contains an unsupported type or origin");
    }
    let mut stored_names = BTreeSet::new();
    let mut original_paths = BTreeSet::new();
    for file in &record.files {
        let stored = Path::new(&file.stored_name);
        let active_path_safe = file.active_path.as_deref().is_none_or(|path| {
            let path = Path::new(path);
            !path.is_absolute()
                && path.components().count() > 0
                && path
                    .components()
                    .all(|component| matches!(component, std::path::Component::Normal(_)))
        });
        if stored.is_absolute()
            || stored.components().count() != 1
            || !matches!(
                stored.components().next(),
                Some(std::path::Component::Normal(_))
            )
            || !stored_names.insert(file.stored_name.as_str())
            || !original_paths.insert(file.original_path.as_str())
            || !active_path_safe
            || file.sha256.len() != 64
            || !file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("installed-mod record contains unsafe file metadata");
        }
    }
    for link in &record.links {
        let path = Path::new(&link.original_path);
        let supported_root = [
            Path::new("RetroRewind/Binaries/Win64/ue4ss/Mods"),
            Path::new("RetroRewind/Binaries/Win64/Mods"),
        ]
        .iter()
        .any(|root| {
            path.starts_with(root) && path.components().count() == root.components().count() + 1
        });
        if path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
            || !supported_root
            || !original_paths.insert(link.original_path.as_str())
            || link.target.is_empty()
        {
            bail!("installed-mod record contains unsafe link metadata");
        }
    }
    Ok(record)
}

fn write_existing_mod_record(directory: &Path, record: &ExistingModRecord) -> Result<()> {
    let path = directory.join("record.json");
    let temporary = directory.join(format!(
        ".record-{}.tmp",
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let bytes = serde_json::to_vec_pretty(record)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, &path)?;
    Ok(())
}

fn copy_existing_mod_file(source: &Path, destination: &Path, expected_sha256: &str) -> Result<()> {
    if destination.exists() {
        bail!("installed-mod storage destination already exists");
    }
    fs::copy(source, destination)?;
    fs::File::open(destination)?.sync_all()?;
    let actual = rrmm_archive::sha256_path(destination)?;
    if actual != expected_sha256 {
        let _ = fs::remove_file(destination);
        bail!("installed mod changed while it was being copied");
    }
    Ok(())
}

fn symlink_matches(path: &Path, expected_target: &str) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    Ok(metadata.file_type().is_symlink() && fs::read_link(path)? == Path::new(expected_target))
}

fn remove_filesystem_link(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(file_error) => fs::remove_dir(path).map_err(|_| file_error.into()),
    }
}

#[cfg(unix)]
fn create_module_symlink(target: &str, destination: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, destination)?;
    Ok(())
}

#[cfg(windows)]
fn create_module_symlink(target: &str, destination: &Path) -> Result<()> {
    std::os::windows::fs::symlink_dir(target, destination)?;
    Ok(())
}

fn disable_existing_mod(game_root: &Path, state_root: &Path, view: &ExistingModView) -> Result<()> {
    disable_existing_mod_with_snapshot(game_root, state_root, view, None)
}

fn disable_existing_mod_with_snapshot(
    game_root: &Path,
    state_root: &Path,
    view: &ExistingModView,
    mods_txt_edit: Option<ModsTxtEditSnapshot>,
) -> Result<()> {
    let records_root = state_root.join(EXISTING_MODS_DIRECTORY);
    fs::create_dir_all(&records_root)?;
    if !fs::symlink_metadata(&records_root)?.file_type().is_dir() {
        bail!("installed-mod storage root is not a regular directory");
    }
    let directory = existing_mod_record_directory(state_root, &view.id)?;
    if directory.exists() {
        bail!("RR Mod Manager already has stored data for this installed mod");
    }
    let staging = records_root.join(format!(".{}-staging", view.id));
    if staging.exists() {
        bail!("an earlier installed-mod staging directory requires manual review");
    }
    fs::create_dir(&staging)?;
    let result = (|| {
        let mut files = Vec::new();
        for (index, relative) in view.related_paths.iter().enumerate() {
            let active_path = view
                .active_paths
                .get(relative)
                .map(String::as_str)
                .unwrap_or(relative);
            let source = checked_game_mod_path(game_root, active_path)?;
            ensure_safe_existing_mod_parent(game_root, &source)?;
            let metadata = fs::symlink_metadata(&source)?;
            if !metadata.file_type().is_file() {
                bail!("installed mod changed before it could be disabled");
            }
            let sha256 = rrmm_archive::sha256_path(&source)?;
            let stored_name = format!("{index}.bin");
            copy_existing_mod_file(&source, &staging.join(&stored_name), &sha256)?;
            files.push(StoredExistingModFile {
                original_path: relative.clone(),
                active_path: (active_path != relative).then(|| active_path.to_owned()),
                stored_name,
                size_bytes: metadata.len(),
                sha256,
            });
        }
        let links = view
            .symlink_target
            .as_ref()
            .map(|target| {
                let path = checked_existing_mod_directory(game_root, &view.path)?;
                ensure_safe_existing_mod_parent(game_root, &path)?;
                if !symlink_matches(&path, target)? {
                    bail!("installed module link changed before it could be disabled");
                }
                Ok(StoredExistingModLink {
                    original_path: view.path.clone(),
                    target: target.clone(),
                })
            })
            .transpose()?
            .into_iter()
            .collect();
        let mut record = ExistingModRecord {
            schema_version: 2,
            id: view.id.clone(),
            display_name: view.display_name.clone(),
            mod_type: view.mod_type.clone(),
            components: view.components.clone(),
            origin: view.origin.clone(),
            directories: view.directories.clone(),
            state: ExistingModRecordState::Disabling,
            files,
            links,
            mods_txt_edit,
            nexus_page_url: view.nexus_page_url.clone(),
        };
        write_existing_mod_record(&staging, &record)?;
        fs::rename(&staging, &directory)?;
        for file in &record.files {
            let source = checked_game_mod_path(
                game_root,
                file.active_path.as_deref().unwrap_or(&file.original_path),
            )?;
            if rrmm_archive::sha256_path(&source)? != file.sha256 {
                bail!("installed mod changed before it could be removed from the game");
            }
            fs::remove_file(source)?;
        }
        for link in &record.links {
            let source = checked_existing_mod_directory(game_root, &link.original_path)?;
            if !symlink_matches(&source, &link.target)? {
                bail!("installed module link changed before it could be removed from the game");
            }
            remove_filesystem_link(&source)?;
        }
        record.state = ExistingModRecordState::Disabled;
        write_existing_mod_record(&directory, &record)?;
        Ok(())
    })();
    if result.is_err() {
        let rollback_directory = if directory.is_dir() {
            &directory
        } else {
            &staging
        };
        if rollback_directory.is_dir()
            && let Ok(record) = load_existing_mod_record(rollback_directory)
            && restore_existing_mod_files(game_root, rollback_directory, &record, true).is_ok()
        {
            let _ = fs::remove_dir_all(rollback_directory);
        }
    }
    result
}

fn restore_existing_mod_files(
    game_root: &Path,
    directory: &Path,
    record: &ExistingModRecord,
    restore_active_path: bool,
) -> Result<()> {
    let mut directories = record.directories.clone();
    directories.sort_by_key(|path| Path::new(path).components().count());
    for relative in directories {
        let path = checked_existing_mod_directory(game_root, &relative)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => bail!("a non-directory occupies an installed mod directory"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(&path)?,
            Err(error) => return Err(error.into()),
        }
    }
    for link in &record.links {
        let destination = checked_existing_mod_directory(game_root, &link.original_path)?;
        ensure_safe_existing_mod_parent(game_root, &destination)?;
        match fs::symlink_metadata(&destination) {
            Ok(metadata)
                if metadata.file_type().is_symlink()
                    && symlink_matches(&destination, &link.target)? => {}
            Ok(_) => bail!("a different entry now occupies an installed module-link path"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_module_symlink(&link.target, &destination)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    for file in &record.files {
        let relative = if restore_active_path {
            file.active_path.as_deref().unwrap_or(&file.original_path)
        } else {
            &file.original_path
        };
        let destination = checked_game_mod_path(game_root, relative)?;
        ensure_safe_existing_mod_parent(game_root, &destination)?;
        if destination.exists() {
            if rrmm_archive::sha256_path(&destination)? != file.sha256 {
                bail!("a different file now occupies an installed mod path");
            }
            continue;
        }
        let parent = destination
            .parent()
            .context("installed mod path has no parent")?;
        let temporary = parent.join(format!(".rrmm-restore-{}.tmp", record.id));
        copy_existing_mod_file(&directory.join(&file.stored_name), &temporary, &file.sha256)?;
        fs::rename(&temporary, &destination)?;
    }
    Ok(())
}

fn enable_existing_mod(game_root: &Path, state_root: &Path, mod_id: &str) -> Result<()> {
    let directory = existing_mod_record_directory(state_root, mod_id)?;
    let mut record = load_existing_mod_record(&directory)?;
    if record.id != mod_id || record.state != ExistingModRecordState::Disabled {
        bail!("installed mod is not ready to be enabled");
    }
    for file in &record.files {
        let destination = checked_game_mod_path(game_root, &file.original_path)?;
        if destination.exists() {
            bail!("another file already occupies the original installed mod path");
        }
    }
    for link in &record.links {
        let destination = checked_existing_mod_directory(game_root, &link.original_path)?;
        if fs::symlink_metadata(&destination).is_ok() {
            bail!("another entry already occupies the original installed module-link path");
        }
    }
    record.state = ExistingModRecordState::Enabling;
    write_existing_mod_record(&directory, &record)?;
    let result = (|| {
        if let Some(snapshot) = &record.mods_txt_edit {
            restore_ue4ss_mods_txt_edit(game_root, snapshot)?;
        }
        restore_existing_mod_files(game_root, &directory, &record, false)
    })();
    if let Err(error) = result {
        for file in &record.files {
            if let Ok(destination) = checked_game_mod_path(game_root, &file.original_path)
                && destination.is_file()
                && rrmm_archive::sha256_path(&destination).ok().as_deref() == Some(&file.sha256)
            {
                let _ = fs::remove_file(destination);
            }
        }
        for link in &record.links {
            if let Ok(destination) = checked_existing_mod_directory(game_root, &link.original_path)
                && symlink_matches(&destination, &link.target).unwrap_or(false)
            {
                let _ = remove_filesystem_link(&destination);
            }
        }
        if let Some(snapshot) = &record.mods_txt_edit {
            let _ = apply_ue4ss_mods_txt_edit(game_root, snapshot);
        }
        record.state = ExistingModRecordState::Disabled;
        let _ = write_existing_mod_record(&directory, &record);
        return Err(error);
    }
    fs::remove_dir_all(directory)?;
    Ok(())
}

fn enable_live_ue4ss_module(game_root: &Path, view: &ExistingModView) -> Result<()> {
    if !view.mod_type.starts_with("ue4ss_") || view.stored {
        bail!("installed mod is not an inactive live UE4SS module");
    }
    let marker_relative = format!("{}/enabled.txt", view.path.trim_end_matches('/'));
    let marker = checked_game_mod_path(game_root, &marker_relative)?;
    ensure_safe_existing_mod_parent(game_root, &marker)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
        .context("enabled.txt already exists or cannot be created safely")?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn prepare_ue4ss_mods_txt_removal(
    game_root: &Path,
    module_name: &str,
) -> Result<ModsTxtEditSnapshot> {
    let activation = analyze_ue4ss_activation(
        game_root,
        &Ue4ssInventoryLimits::default(),
        &Ue4ssActivationLimits::default(),
    )?;
    if activation.mods_txt.status != ModsTxtAnalysisStatus::Parsed || !activation.mods_txt.complete
    {
        bail!("mods.txt is not a complete canonical file and cannot be edited safely");
    }
    let module = activation
        .modules
        .iter()
        .find(|module| module.name == module_name)
        .with_context(|| format!("UE4SS module '{module_name}' is no longer available"))?;
    if module.mods_txt_lines.len() != 1 {
        bail!("UE4SS module must have exactly one mods.txt directive before it can be edited");
    }
    let relative_path = activation.mods_txt.entry.relative_path.clone();
    validate_ue4ss_mods_txt_relative_path(&relative_path)?;
    let before = read_game_relative_file(
        game_root,
        &relative_path,
        Ue4ssActivationLimits::default().max_bytes,
    )?;
    let source = std::str::from_utf8(&before).context("mods.txt is not valid UTF-8")?;
    let after = render_mods_txt_state(source, module_name, None)?.into_bytes();
    Ok(ModsTxtEditSnapshot {
        relative_path,
        before,
        after,
    })
}

fn ensure_ue4ss_mods_txt_snapshot_state(
    game_root: &Path,
    snapshot: &ModsTxtEditSnapshot,
    restore_before: bool,
) -> Result<bool> {
    let (expected, replacement) = if restore_before {
        (&snapshot.after, &snapshot.before)
    } else {
        (&snapshot.before, &snapshot.after)
    };
    let current = read_game_relative_file(
        game_root,
        &snapshot.relative_path,
        Ue4ssActivationLimits::default().max_bytes,
    )?;
    if current.as_slice() == replacement.as_slice() {
        return Ok(false);
    }
    if current.as_slice() != expected.as_slice() {
        bail!("mods.txt changed after the reviewed deletion edit");
    }
    let expected_sha256 = format!("{:x}", Sha256::digest(expected));
    replace_game_relative_file(
        game_root,
        &snapshot.relative_path,
        expected.len() as u64,
        &expected_sha256,
        replacement,
    )?;
    Ok(true)
}

fn restore_ue4ss_mods_txt_edit(game_root: &Path, snapshot: &ModsTxtEditSnapshot) -> Result<()> {
    ensure_ue4ss_mods_txt_snapshot_state(game_root, snapshot, true).map(|_| ())
}

fn apply_ue4ss_mods_txt_edit(game_root: &Path, snapshot: &ModsTxtEditSnapshot) -> Result<()> {
    ensure_ue4ss_mods_txt_snapshot_state(game_root, snapshot, false).map(|_| ())
}

fn set_ue4ss_mods_txt_state(
    game_root: &Path,
    module_name: &str,
    enabled: Option<bool>,
) -> Result<()> {
    let activation = analyze_ue4ss_activation(
        game_root,
        &Ue4ssInventoryLimits::default(),
        &Ue4ssActivationLimits::default(),
    )?;
    if activation.mods_txt.status != ModsTxtAnalysisStatus::Parsed || !activation.mods_txt.complete
    {
        bail!("mods.txt is not a complete canonical file and cannot be edited safely");
    }
    let module = activation
        .modules
        .iter()
        .find(|module| module.name == module_name)
        .with_context(|| format!("UE4SS module '{module_name}' is no longer available"))?;
    if module.mods_txt_lines.len() != 1 {
        bail!("UE4SS module must have exactly one mods.txt directive before it can be edited");
    }
    let relative = &activation.mods_txt.entry.relative_path;
    validate_ue4ss_mods_txt_relative_path(relative)?;
    let original = read_game_relative_file(
        game_root,
        relative,
        Ue4ssActivationLimits::default().max_bytes,
    )
    .context("mods.txt changed or could not be read safely")?;
    let original_hash = format!("{:x}", Sha256::digest(&original));
    let source = std::str::from_utf8(&original).context("mods.txt is not valid UTF-8")?;
    let replacement = render_mods_txt_state(source, module_name, enabled)?;
    if replacement.as_bytes() == original {
        return Ok(());
    }
    replace_game_relative_file(
        game_root,
        relative,
        original.len() as u64,
        &original_hash,
        replacement.as_bytes(),
    )
    .context("mods.txt changed or could not be replaced safely")?;
    let refreshed = analyze_ue4ss_activation(
        game_root,
        &Ue4ssInventoryLimits::default(),
        &Ue4ssActivationLimits::default(),
    )?;
    let refreshed_module = refreshed
        .modules
        .iter()
        .find(|module| module.name == module_name);
    match enabled {
        Some(expected) => {
            let actual = refreshed_module.is_some_and(|module| {
                matches!(
                    module.declared_state,
                    Ue4ssDeclaredActivation::EnabledByModsTxt
                        | Ue4ssDeclaredActivation::EnabledByBoth
                )
            });
            if actual != expected {
                bail!("mods.txt verification did not produce the requested module state");
            }
        }
        None => {
            if refreshed_module.is_some_and(|module| !module.mods_txt_lines.is_empty()) {
                bail!("mods.txt verification found a remaining module directive");
            }
        }
    }
    Ok(())
}

fn validate_ue4ss_mods_txt_relative_path(relative: &str) -> Result<()> {
    let relative = Path::new(relative);
    let supported = [
        Path::new("RetroRewind/Binaries/Win64/ue4ss/Mods/mods.txt"),
        Path::new("RetroRewind/Binaries/Win64/Mods/mods.txt"),
    ];
    if relative.is_absolute() || !supported.contains(&relative) {
        bail!("mods.txt path is outside the selected UE4SS module tree");
    }
    Ok(())
}

fn render_mods_txt_state(source: &str, module_name: &str, enabled: Option<bool>) -> Result<String> {
    let mut output = String::with_capacity(source.len().saturating_add(module_name.len() + 8));
    let mut matches = 0;
    for line in source.split_inclusive('\n') {
        let (body, ending) = if let Some(body) = line.strip_suffix("\r\n") {
            (body, "\r\n")
        } else if let Some(body) = line.strip_suffix('\n') {
            (body, "\n")
        } else {
            (line, "")
        };
        let trimmed = body.trim_matches(' ');
        let target = if trimmed.is_empty() || trimmed.starts_with(';') {
            false
        } else if let Some((name, value)) = trimmed.split_once(':') {
            !value.contains(':') && name.trim_matches(' ') == module_name
        } else {
            false
        };
        if !target {
            output.push_str(line);
            continue;
        }
        matches += 1;
        if let Some(enabled) = enabled {
            output.push_str(module_name);
            output.push_str(if enabled { " : 1" } else { " : 0" });
            output.push_str(ending);
        }
    }
    if matches != 1 {
        bail!("mods.txt target directive changed before rendering");
    }
    Ok(output)
}

fn set_existing_mod_enabled_unlocked(
    game_root: &Path,
    state_root: &Path,
    existing: &ExistingModView,
    enabled: bool,
) -> Result<()> {
    if existing.enabled == enabled {
        return Ok(());
    }
    if enabled && existing.related_paths.is_empty() {
        bail!("an empty UE4SS module directory cannot be enabled");
    }
    if enabled {
        if existing.stored {
            enable_existing_mod(game_root, state_root, &existing.id)
        } else if existing.mod_type.starts_with("ue4ss_") {
            enable_live_ue4ss_module(game_root, existing)
        } else {
            bail!("this installed mod has no stored files to enable")
        }
    } else {
        disable_existing_mod(game_root, state_root, existing)
    }
}

fn delete_existing_mod_unlocked(
    game_root: &Path,
    state_root: &Path,
    existing: &ExistingModView,
) -> Result<()> {
    if existing.enabled {
        delete_active_existing_mod(game_root, state_root, existing)
    } else if existing.stored {
        delete_disabled_existing_mod(game_root, state_root, &existing.id)
    } else {
        delete_active_existing_mod(game_root, state_root, existing)
    }
}

fn delete_existing_mod_unit_unlocked(
    game_root: &Path,
    state_root: &Path,
    unit: &BulkDeleteExternalUnit,
    reviewed_mods: &[ExistingModView],
) -> Result<Vec<String>> {
    if is_game_running() {
        bail!("Retro Rewind started before external mod deletion; close it and preview again");
    }
    if pending_recovery(state_root)? {
        bail!("an interrupted operation requires recovery before external mod deletion");
    }
    let receipt = load_receipt(state_root, INSTALLATION_ID)?;
    let all_mods = existing_mod_views(game_root, state_root, receipt.as_ref())?;
    let mut current_ids = unit.member_ids.clone();
    current_ids.sort();
    let mut members = all_mods
        .iter()
        .filter(|item| current_ids.binary_search(&item.id).is_ok())
        .cloned()
        .collect::<Vec<_>>();
    members.sort_by(|left, right| left.id.cmp(&right.id));
    let mut reviewed = reviewed_mods
        .iter()
        .filter(|item| current_ids.binary_search(&item.id).is_ok())
        .cloned()
        .collect::<Vec<_>>();
    reviewed.sort_by(|left, right| left.id.cmp(&right.id));
    if members.iter().map(|item| &item.id).collect::<Vec<_>>()
        != current_ids.iter().collect::<Vec<_>>()
    {
        bail!("one or more reviewed external mods changed or disappeared after preview");
    }
    if members != reviewed {
        bail!("one or more reviewed external mod files changed after preview");
    }
    if members.iter().any(|item| !item.manageable) {
        bail!("one or more reviewed external mods are no longer manageable");
    }

    if let Some(group_id) = &unit.group_id {
        let mut live_group_ids = all_mods
            .iter()
            .filter(|item| item.group_id.as_ref() == Some(group_id))
            .map(|item| item.id.clone())
            .collect::<Vec<_>>();
        live_group_ids.sort();
        if live_group_ids != current_ids || members.len() < 2 {
            bail!("reviewed hybrid group changed or became incomplete after preview");
        }
        if members.iter().any(|item| item.mods_txt_controlled) {
            bail!("reviewed hybrid group now uses unsupported shared mods.txt control");
        }
        let snapshot = capture_existing_group_snapshot(game_root, state_root, &members)?;
        let result: Result<()> = members
            .iter()
            .try_for_each(|item| delete_existing_mod_unlocked(game_root, state_root, item));
        if let Err(error) = result {
            rollback_existing_group_snapshot(game_root, state_root, &snapshot)
                .context("external group deletion failed and rollback could not be completed")?;
            fs::remove_dir_all(&snapshot.root)?;
            return Err(error.context("external group deletion was rolled back"));
        }
        fs::remove_dir_all(&snapshot.root)?;
        return Ok(current_ids);
    }

    let [existing] = members.as_slice() else {
        bail!("an ungrouped external deletion unit must contain exactly one mod");
    };
    if existing.group_id.is_some() {
        bail!("external mod became part of a group after preview");
    }
    if existing.mods_txt_controlled {
        let module_name = existing
            .ue4ss_module_name
            .as_deref()
            .context("UE4SS module identity is unavailable")?;
        delete_mods_txt_controlled_existing_mod(game_root, state_root, existing, module_name)?;
    } else {
        delete_existing_mod_unlocked(game_root, state_root, existing)?;
    }
    Ok(current_ids)
}

fn capture_existing_group_snapshot(
    game_root: &Path,
    state_root: &Path,
    group: &[ExistingModView],
) -> Result<ExistingGroupSnapshot> {
    fs::create_dir_all(state_root)?;
    let operations_root = state_root.join(EXISTING_GROUP_OPERATIONS_DIRECTORY);
    fs::create_dir_all(&operations_root)?;
    let temporary = tempfile::Builder::new()
        .prefix("operation-")
        .tempdir_in(&operations_root)?;
    let root = temporary.path().to_path_buf();
    let mut identities = BTreeMap::<String, String>::new();
    let mut directories = BTreeSet::new();
    for item in group {
        for directory in &item.directories {
            directories.insert(directory.clone());
        }
        for relative in &item.related_paths {
            let active_relative = item
                .active_paths
                .get(relative)
                .cloned()
                .unwrap_or_else(|| relative.clone());
            let sha256 = if let Some((_, sha256)) = item.file_identities.get(relative) {
                sha256.clone()
            } else {
                let path = checked_game_mod_path(game_root, &active_relative)?;
                if !fs::symlink_metadata(&path)?.file_type().is_file() {
                    bail!("hybrid component has no identity for '{relative}'");
                }
                rrmm_archive::sha256_path(&path)?
            };
            if identities.insert(active_relative, sha256).is_some() {
                bail!("hybrid components contain the same installed path");
            }
        }
    }
    let mut files = Vec::new();
    for (index, (relative_path, expected_sha256)) in identities.into_iter().enumerate() {
        let source = checked_game_mod_path(game_root, &relative_path)?;
        let backup_name = if source.exists() {
            let metadata = fs::symlink_metadata(&source)?;
            if !metadata.file_type().is_file()
                || rrmm_archive::sha256_path(&source)? != expected_sha256
            {
                bail!("hybrid component changed before the operation started");
            }
            let backup_name = format!("file-{index}.bin");
            let backup = root.join(&backup_name);
            fs::copy(&source, &backup)?;
            fs::File::open(&backup)?.sync_all()?;
            Some(backup_name)
        } else {
            None
        };
        files.push(ExistingGroupSnapshotFile {
            relative_path,
            expected_sha256,
            backup_name,
        });
    }
    let mut records = Vec::new();
    for item in group {
        let source = existing_mod_record_directory(state_root, &item.id)?;
        let backup_name = if source.exists() {
            let backup_name = format!("record-{}", item.id);
            let backup = root.join(&backup_name);
            copy_regular_directory(&source, &backup)?;
            Some(backup_name)
        } else {
            None
        };
        records.push(ExistingGroupSnapshotRecord {
            id: item.id.clone(),
            backup_name,
        });
    }
    let mut snapshot = ExistingGroupSnapshot {
        root: root.clone(),
        files,
        records,
        directories: directories.into_iter().collect(),
    };
    let journal = root.join("journal.json");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&journal)?;
    file.write_all(&serde_json::to_vec_pretty(&snapshot)?)?;
    file.sync_all()?;
    fs::File::open(&root)?.sync_all()?;
    fs::File::open(&operations_root)?.sync_all()?;
    snapshot.root = temporary.keep();
    Ok(snapshot)
}

fn rollback_existing_group_snapshot(
    game_root: &Path,
    state_root: &Path,
    snapshot: &ExistingGroupSnapshot,
) -> Result<()> {
    for file in &snapshot.files {
        let destination = checked_game_mod_path(game_root, &file.relative_path)?;
        if let Some(backup_name) = &file.backup_name {
            if destination.exists() {
                let metadata = fs::symlink_metadata(&destination)?;
                if !metadata.file_type().is_file()
                    || rrmm_archive::sha256_path(&destination)? != file.expected_sha256
                {
                    bail!(
                        "rollback stopped because '{}' changed externally",
                        file.relative_path
                    );
                }
                continue;
            }
            let parent = destination
                .parent()
                .context("hybrid rollback destination has no parent")?;
            fs::create_dir_all(parent)?;
            let temporary = parent.join(format!(
                ".rrmm-group-restore-{}.tmp",
                Utc::now().timestamp_nanos_opt().unwrap_or_default()
            ));
            fs::copy(snapshot.root.join(backup_name), &temporary)?;
            fs::File::open(&temporary)?.sync_all()?;
            fs::rename(temporary, &destination)?;
        } else if destination.exists() {
            let metadata = fs::symlink_metadata(&destination)?;
            if !metadata.file_type().is_file()
                || rrmm_archive::sha256_path(&destination)? != file.expected_sha256
            {
                bail!(
                    "rollback stopped because '{}' changed externally",
                    file.relative_path
                );
            }
            fs::remove_file(destination)?;
        }
    }
    for record in &snapshot.records {
        let destination = existing_mod_record_directory(state_root, &record.id)?;
        if let Some(backup_name) = &record.backup_name {
            let backup = snapshot.root.join(backup_name);
            if destination.exists() {
                if !regular_directories_equal(&destination, &backup)? {
                    bail!("rollback stopped because an installed-mod record changed externally");
                }
            } else {
                let staging = destination.with_extension(format!(
                    "group-restore-{}",
                    Utc::now().timestamp_nanos_opt().unwrap_or_default()
                ));
                copy_regular_directory(&backup, &staging)?;
                fs::rename(staging, &destination)?;
            }
        } else if destination.exists() {
            let discarded = snapshot.root.join(format!("discard-record-{}", record.id));
            fs::rename(destination, discarded)?;
        }
    }
    let mut directories = snapshot.directories.clone();
    directories.sort_by_key(|path| std::cmp::Reverse(Path::new(path).components().count()));
    for relative in directories {
        let directory = checked_existing_mod_directory(game_root, &relative)?;
        if directory.is_dir() {
            let _ = fs::remove_dir(directory);
        }
    }
    Ok(())
}

fn recover_existing_group_operations(game_root: &Path, state_root: &Path) -> Result<usize> {
    let operations_root = state_root.join(EXISTING_GROUP_OPERATIONS_DIRECTORY);
    if !operations_root.is_dir() {
        return Ok(0);
    }
    let mut entries: Vec<_> = fs::read_dir(&operations_root)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    let mut recovered = 0;
    for entry in entries {
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.file_type().is_dir() {
            bail!("hybrid recovery storage contains an unsafe entry");
        }
        let journal = entry.path().join("journal.json");
        let journal_metadata = fs::symlink_metadata(&journal)?;
        if !journal_metadata.file_type().is_file() {
            bail!("hybrid recovery journal is missing or unsafe");
        }
        let mut snapshot: ExistingGroupSnapshot = serde_json::from_slice(&fs::read(journal)?)?;
        snapshot.root = entry.path();
        rollback_existing_group_snapshot(game_root, state_root, &snapshot)?;
        fs::remove_dir_all(&snapshot.root)?;
        recovered += 1;
    }
    Ok(recovered)
}

fn regular_directories_equal(first: &Path, second: &Path) -> Result<bool> {
    fn inventory(root: &Path, current: &Path, output: &mut Vec<(PathBuf, String)>) -> Result<()> {
        let mut entries: Vec<_> = fs::read_dir(current)?.collect::<std::io::Result<_>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                inventory(root, &entry.path(), output)?;
            } else if file_type.is_file() {
                output.push((
                    entry.path().strip_prefix(root)?.to_path_buf(),
                    rrmm_archive::sha256_path(&entry.path())?,
                ));
            } else {
                bail!("hybrid record contains a filesystem link or special entry");
            }
        }
        Ok(())
    }
    let mut first_inventory = Vec::new();
    let mut second_inventory = Vec::new();
    inventory(first, first, &mut first_inventory)?;
    inventory(second, second, &mut second_inventory)?;
    Ok(first_inventory == second_inventory)
}

fn copy_regular_directory(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.file_type().is_dir() || destination.exists() {
        bail!("hybrid snapshot directory is unsafe");
    }
    fs::create_dir(destination)?;
    let mut entries: Vec<_> = fs::read_dir(source)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let file_type = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_regular_directory(&entry.path(), &target)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), &target)?;
            fs::File::open(target)?.sync_all()?;
        } else {
            bail!("hybrid snapshot contains a filesystem link or special entry");
        }
    }
    fs::File::open(destination)?.sync_all()?;
    Ok(())
}

fn delete_active_existing_mod(
    game_root: &Path,
    state_root: &Path,
    view: &ExistingModView,
) -> Result<()> {
    disable_existing_mod(game_root, state_root, view)?;
    if let Err(error) = delete_disabled_existing_mod(game_root, state_root, &view.id) {
        if view.related_paths.is_empty() {
            enable_existing_mod(game_root, state_root, &view.id)
                .context("empty module deletion failed and its directory tree was not restored")?;
        }
        return Err(error);
    }
    Ok(())
}

fn delete_mods_txt_controlled_existing_mod(
    game_root: &Path,
    state_root: &Path,
    view: &ExistingModView,
    module_name: &str,
) -> Result<()> {
    let snapshot = prepare_ue4ss_mods_txt_removal(game_root, module_name)?;
    disable_existing_mod_with_snapshot(game_root, state_root, view, Some(snapshot.clone()))?;
    if let Err(error) = apply_ue4ss_mods_txt_edit(game_root, &snapshot) {
        if let Err(rollback) = enable_existing_mod(game_root, state_root, &view.id) {
            return Err(error).context(format!(
                "mods.txt edit failed and the stored mod could not be restored: {rollback:#}"
            ));
        }
        return Err(error).context("mods.txt edit failed and the mod was restored");
    }
    if let Err(error) = delete_disabled_existing_mod(game_root, state_root, &view.id) {
        if view.related_paths.is_empty() {
            enable_existing_mod(game_root, state_root, &view.id).context(
                "empty module deletion failed and its files and mods.txt state were not restored",
            )?;
        }
        return Err(error);
    }
    Ok(())
}

fn delete_disabled_existing_mod(game_root: &Path, state_root: &Path, mod_id: &str) -> Result<()> {
    let directory = existing_mod_record_directory(state_root, mod_id)?;
    let record = load_existing_mod_record(&directory)?;
    if record.id != mod_id || record.state != ExistingModRecordState::Disabled {
        bail!("installed mod is not ready to be deleted");
    }
    let mut directories = record.directories.clone();
    directories.sort_by_key(|path| std::cmp::Reverse(Path::new(path).components().count()));
    let directories: Vec<_> = directories
        .iter()
        .map(|relative| checked_existing_mod_directory(game_root, relative))
        .collect::<Result<_>>()?;
    for path in directories {
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_dir() => fs::remove_dir(&path)?,
            Ok(_) => bail!("installed mod directory changed before deletion"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    fs::remove_dir_all(directory)?;
    Ok(())
}

fn recover_existing_mod_records(game_root: &Path, state_root: &Path) -> Result<usize> {
    let records_root = state_root.join(EXISTING_MODS_DIRECTORY);
    if !records_root.is_dir() {
        return Ok(0);
    }
    let mut recovered = 0;
    for entry in fs::read_dir(&records_root)? {
        let entry = entry?;
        let entry_name = entry.file_name();
        let entry_name = entry_name.to_string_lossy();
        if entry_name.starts_with(".existing-") && entry_name.ends_with("-staging") {
            if fs::symlink_metadata(entry.path())?.file_type().is_dir() {
                fs::remove_dir_all(entry.path())?;
                recovered += 1;
            }
            continue;
        }
        if !fs::symlink_metadata(entry.path())?.file_type().is_dir() {
            continue;
        }
        let directory = entry.path();
        let mut record = load_existing_mod_record(&directory)?;
        match record.state {
            ExistingModRecordState::Disabled => {
                let Some(snapshot) = &record.mods_txt_edit else {
                    continue;
                };
                let current = read_game_relative_file(
                    game_root,
                    &snapshot.relative_path,
                    Ue4ssActivationLimits::default().max_bytes,
                )?;
                if current == snapshot.before {
                    restore_existing_mod_files(game_root, &directory, &record, true)?;
                    fs::remove_dir_all(&directory)?;
                } else if current == snapshot.after {
                    delete_disabled_existing_mod(game_root, state_root, &record.id)?;
                } else {
                    bail!("mods.txt changed during an interrupted external mod deletion");
                }
            }
            ExistingModRecordState::Disabling => {
                restore_existing_mod_files(game_root, &directory, &record, true)?;
                fs::remove_dir_all(directory)?;
            }
            ExistingModRecordState::Enabling => {
                for file in &record.files {
                    let destination = checked_game_mod_path(game_root, &file.original_path)?;
                    if !destination.exists() {
                        continue;
                    }
                    if rrmm_archive::sha256_path(&destination)? != file.sha256 {
                        bail!(
                            "a different file occupies a path from an interrupted mod activation"
                        );
                    }
                    fs::remove_file(destination)?;
                }
                for link in &record.links {
                    let destination =
                        checked_existing_mod_directory(game_root, &link.original_path)?;
                    match fs::symlink_metadata(&destination) {
                        Ok(_) if symlink_matches(&destination, &link.target)? => {
                            remove_filesystem_link(&destination)?;
                        }
                        Ok(_) => {
                            bail!(
                                "a different entry occupies a path from an interrupted module-link activation"
                            );
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                if let Some(snapshot) = &record.mods_txt_edit {
                    apply_ue4ss_mods_txt_edit(game_root, snapshot)?;
                }
                record.state = ExistingModRecordState::Disabled;
                write_existing_mod_record(&directory, &record)?;
            }
        }
        recovered += 1;
    }
    Ok(recovered)
}

fn unmanaged_pak_views(
    game_root: &Path,
    receipt: Option<&DeploymentReceipt>,
) -> Result<Vec<UnmanagedFileView>> {
    unmanaged_pak_views_internal(game_root, receipt, None)
}

fn unmanaged_pak_views_cached(
    game_root: &Path,
    receipt: Option<&DeploymentReceipt>,
    store: &Store,
) -> Result<Vec<UnmanagedFileView>> {
    unmanaged_pak_views_internal(game_root, receipt, Some(store))
}

fn unmanaged_pak_views_internal(
    game_root: &Path,
    receipt: Option<&DeploymentReceipt>,
    store: Option<&Store>,
) -> Result<Vec<UnmanagedFileView>> {
    let pak_root = game_root.join("RetroRewind/Content/Paks");
    if !pak_root.is_dir() {
        return Ok(Vec::new());
    }
    let managed: BTreeSet<_> = receipt
        .into_iter()
        .flat_map(|receipt| receipt.files.iter())
        .map(|file| file.relative_path.as_str())
        .collect();
    let discovery = discover_paks(&pak_root)?;
    let mut views = Vec::new();
    for pak in discovery.paks {
        if pak.relative_path == Path::new("RetroRewind-Windows.pak") {
            continue;
        }
        let relative_suffix = pak.relative_path.to_string_lossy().replace('\\', "/");
        let relative_path = format!("RetroRewind/Content/Paks/{relative_suffix}");
        if managed.contains(relative_path.as_str()) {
            continue;
        }
        let metadata = fs::symlink_metadata(&pak.path)
            .with_context(|| format!("failed to inspect unmanaged PAK {}", pak.path.display()))?;
        if !metadata.file_type().is_file() {
            bail!(
                "unmanaged PAK changed during inventory: {}",
                pak.path.display()
            );
        }
        let pak_sha256 = match store {
            Some(store) => cached_file_sha256(store, &pak.path)?,
            None => rrmm_archive::sha256_path(&pak.path)?,
        };
        let original_path = receipt_original_external_path(receipt, &relative_path, &pak_sha256)
            .unwrap_or_else(|| relative_path.clone());
        let manageable = external_pak_is_manageable(&pak.path)?;
        let mut active_paths = BTreeMap::new();
        active_paths.insert(original_path.clone(), relative_path.clone());
        views.push(UnmanagedFileView {
            existing_mod_id: Some(existing_mod_id(&original_path)),
            display_name: Path::new(&original_path)
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(existing_mod_display_name),
            path: relative_path,
            size_bytes: metadata.len(),
            pak_sha256,
            original_path,
            manageable,
            active_paths,
        });
    }
    Ok(views)
}

fn receipt_original_external_path(
    receipt: Option<&DeploymentReceipt>,
    current_path: &str,
    sha256: &str,
) -> Option<String> {
    receipt?
        .external_files
        .iter()
        .find(|file| file.current_relative_path == current_path && file.sha256 == sha256)
        .map(|file| file.original_relative_path.clone())
}

fn external_pak_is_manageable(pak_path: &Path) -> Result<bool> {
    let Some(parent) = pak_path.parent() else {
        return Ok(false);
    };
    let Some(stem) = pak_path.file_stem().and_then(|stem| stem.to_str()) else {
        return Ok(false);
    };
    for entry in fs::read_dir(parent)? {
        let path = entry?.path();
        if path == pak_path
            || !path
                .file_stem()
                .and_then(|candidate| candidate.to_str())
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(stem))
        {
            continue;
        }
        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default();
        if extension.eq_ignore_ascii_case("utoc") || extension.eq_ignore_ascii_case("ucas") {
            return Ok(false);
        }
        if extension.eq_ignore_ascii_case("sig")
            && !fs::symlink_metadata(path)?.file_type().is_file()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn unmanaged_package_conflicts(
    profile: &DomainProfile,
    catalog: &[CatalogPackage],
    unmanaged_files: &[UnmanagedFileView],
) -> Vec<UnmanagedPackageConflict> {
    let selected: Vec<_> = profile
        .packages
        .iter()
        .filter(|selection| selection.enabled)
        .filter_map(|selection| {
            catalog
                .iter()
                .find(|package| package.artifact_sha256 == selection.artifact_sha256)
        })
        .collect();
    let mut conflicts = Vec::new();
    for file in unmanaged_files {
        let Some(file_name) = Path::new(&file.original_path)
            .file_name()
            .map(|name| name.to_string_lossy())
        else {
            continue;
        };
        let Some(installed) = catalog.iter().find(|package| {
            package.manifest.components.iter().any(|component| {
                component.component_type == ComponentType::Pak
                    && component
                        .install_name
                        .as_deref()
                        .is_some_and(|name| name.eq_ignore_ascii_case(&file_name))
            })
        }) else {
            continue;
        };
        for selected in &selected {
            let duplicate = selected.manifest.id == installed.manifest.id;
            let incompatible = selected
                .manifest
                .incompatibilities
                .contains(&installed.manifest.id)
                || installed
                    .manifest
                    .incompatibilities
                    .contains(&selected.manifest.id);
            let replaces = selected.manifest.replaces.contains(&installed.manifest.id)
                || installed.manifest.replaces.contains(&selected.manifest.id);
            if !duplicate && !incompatible && !replaces {
                continue;
            }
            let reason = if duplicate {
                format!(
                    "'{}' is already active outside RRMM at '{}'. Disable the unmanaged copy before activating the managed package.",
                    selected.manifest.name, file.path
                )
            } else {
                format!(
                    "Selected package '{}' overlaps the unmanaged active package '{}' at '{}'. Disable the unmanaged package or use only the reviewed combined package.",
                    selected.manifest.name, installed.manifest.name, file.path
                )
            };
            conflicts.push(UnmanagedPackageConflict {
                path: file.path.clone(),
                selected_name: selected.manifest.name.clone(),
                installed_name: installed.manifest.name.clone(),
                reason,
            });
        }
    }
    conflicts.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.selected_name.cmp(&right.selected_name))
    });
    conflicts.dedup();
    conflicts
}

fn conflict_views(
    profile: Option<&DomainProfile>,
    catalog: &[CatalogPackage],
    unmanaged_files: &[UnmanagedFileView],
) -> Result<Vec<ConflictView>> {
    let Some(profile) = profile else {
        return Ok(Vec::new());
    };
    let request = ResolveRequest {
        build_id: SUPPORTED_BUILD_ID,
        selections: profile
            .packages
            .iter()
            .filter(|package| package.enabled)
            .map(|package| ResolveSelection {
                artifact_sha256: package.artifact_sha256.clone(),
                variant: package.variant.clone(),
            })
            .collect(),
    };
    let report = resolve_packages(&request, catalog)?;
    let selected_names: Vec<_> = request
        .selections
        .iter()
        .filter_map(|selection| {
            catalog
                .iter()
                .find(|package| package.artifact_sha256 == selection.artifact_sha256)
                .map(|package| package.manifest.name.clone())
        })
        .collect();
    let mut views: Vec<_> = report
        .blockers
        .iter()
        .enumerate()
        .map(|(index, blocker)| ConflictView {
            id: format!("resolution-{index}"),
            severity: "blocker".to_owned(),
            path: "Package selection".to_owned(),
            package_names: selected_names.clone(),
            reason: resolution_blocker(blocker),
            resolution: Some(
                "Disable one conflicting package or select a reviewed combined package.".to_owned(),
            ),
        })
        .collect();
    views.extend(
        unmanaged_package_conflicts(profile, catalog, unmanaged_files)
            .into_iter()
            .enumerate()
            .map(|(index, conflict)| ConflictView {
                id: format!("unmanaged-package-{index}"),
                severity: "blocker".to_owned(),
                path: conflict.path,
                package_names: vec![conflict.selected_name, conflict.installed_name],
                reason: conflict.reason,
                resolution: Some(
                    "Preserve the existing mod set by disabling the selected managed package, or remove the unmanaged duplicate outside RRMM first."
                        .to_owned(),
                ),
            }),
    );
    Ok(views)
}

fn keybind_analysis_view(report: &LuaAdvisoryReport) -> KeybindAnalysisView {
    let mut bindings = Vec::new();
    let mut by_binding = BTreeMap::<String, Vec<String>>::new();
    let mut issues = report.issues.clone();
    for module in &report.modules {
        for script in &module.scripts {
            issues.extend(
                script
                    .issues
                    .iter()
                    .map(|issue| format!("{}: {issue}", script.relative_path)),
            );
            for finding in &script.findings {
                if finding.api != Ue4ssLuaApi::RegisterKeyBind {
                    continue;
                }
                let (binding, evidence) = match &finding.first_argument {
                    LuaAdvisoryArgument::Literal { value } => {
                        (Some(value.trim().to_owned()), "literal")
                    }
                    LuaAdvisoryArgument::Symbolic { expression } => {
                        (Some(expression.trim().to_owned()), "symbolic")
                    }
                    LuaAdvisoryArgument::DynamicUnresolved => (None, "dynamic_unresolved"),
                    LuaAdvisoryArgument::Missing => (None, "missing"),
                };
                if let Some(binding) = &binding {
                    by_binding.entry(binding.clone()).or_default().push(format!(
                        "{} ({}:{})",
                        module.name, script.relative_path, finding.line
                    ));
                }
                bindings.push(KeybindFindingView {
                    module: module.name.clone(),
                    script: script.relative_path.clone(),
                    line: finding.line,
                    binding,
                    evidence: evidence.to_owned(),
                });
            }
        }
    }
    let collisions = by_binding
        .into_iter()
        .filter_map(|(binding, modules)| {
            (modules.len() > 1).then_some(KeybindCollisionView { binding, modules })
        })
        .collect();
    KeybindAnalysisView {
        complete: report.complete,
        bindings,
        collisions,
        issues,
    }
}

fn ue4ss_view(game_root: &Path, recipe: &BuildRecipe) -> Result<Ue4ssStateView> {
    let inventory = inventory_ue4ss(game_root, &Ue4ssInventoryLimits::default())?;
    if inventory.installation_status == Ue4ssInstallationStatus::Absent {
        return Ok(Ue4ssStateView::absent(
            "No canonical UE4SS installation was detected.",
        ));
    }
    let activation = analyze_ue4ss_activation(
        game_root,
        &Ue4ssInventoryLimits::default(),
        &Ue4ssActivationLimits::default(),
    )?;
    let identity = inspect_ue4ss_loader_identity(game_root, &Ue4ssLoaderIdentityLimits::default())?;
    let recognized = identity.identity.as_ref().and_then(|identity| {
        recipe.ue4ss_loader_builds.iter().find(|build| {
            build.proxy_sha256 == identity.proxy.sha256 && build.core_sha256 == identity.core.sha256
        })
    });
    let proxy_build_id = identity.identity.as_ref().and_then(|identity| {
        recipe
            .ue4ss_loader_builds
            .iter()
            .find(|build| build.proxy_sha256 == identity.proxy.sha256)
            .map(|build| build.id.clone())
    });
    let core_build_id = identity.identity.as_ref().and_then(|identity| {
        recipe
            .ue4ss_loader_builds
            .iter()
            .find(|build| build.core_sha256 == identity.core.sha256)
            .map(|build| build.id.clone())
    });
    let mixed_installation = recognized.is_none()
        && proxy_build_id.is_some()
        && core_build_id.is_some()
        && proxy_build_id != core_build_id;
    let modules = inventory
        .modules
        .iter()
        .map(|module| {
            let enabled = activation
                .modules
                .iter()
                .find(|state| state.name == module.name)
                .is_some_and(|state| {
                    matches!(
                        state.declared_state,
                        Ue4ssDeclaredActivation::EnabledByMarker
                            | Ue4ssDeclaredActivation::EnabledByModsTxt
                            | Ue4ssDeclaredActivation::EnabledByBoth
                    )
                });
            Ue4ssModuleView {
                id: module.name.clone(),
                name: module.name.clone(),
                version: "unknown".to_owned(),
                enabled,
                source_package: "Installed module tree".to_owned(),
            }
        })
        .collect();
    let health = ue4ss_loader_health(
        identity.status,
        recognized.map(|build| build.id.as_str()),
        recipe,
    );
    let message = recognized.map_or_else(
        || match identity.status {
            Ue4ssLoaderIdentityStatus::Exact => {
                "A complete loader was found, but its proxy/core pair does not match a reviewed UE4SS build."
                    .to_owned()
            }
            _ => format!("Loader identity status: {:?}.", identity.status),
        },
        |build| format!("Exact reviewed loader pair: {}.", build.id),
    );
    let root_path = match inventory.ue4ss_root.status {
        EntryStatus::Directory => Some(
            game_root
                .join(&inventory.ue4ss_root.relative_path)
                .display()
                .to_string(),
        ),
        _ => None,
    };
    Ok(Ue4ssStateView {
        installed: true,
        version: recognized.map(|build| build.id.clone()),
        health,
        root_path,
        modules,
        message,
        proxy_build_id,
        core_build_id,
        mixed_installation,
        expected_version: TARGET_UE4SS_BUILD_ID.to_owned(),
        installation_action: if recognized.is_some_and(|build| build.id == TARGET_UE4SS_BUILD_ID)
            && health == HealthLevel::Ready
            && !mixed_installation
        {
            "none"
        } else {
            "repair"
        }
        .to_owned(),
    })
}

fn ue4ss_loader_health(
    identity_status: Ue4ssLoaderIdentityStatus,
    recognized_build_id: Option<&str>,
    recipe: &BuildRecipe,
) -> HealthLevel {
    match identity_status {
        Ue4ssLoaderIdentityStatus::Exact if recognized_build_id == Some(TARGET_UE4SS_BUILD_ID) => {
            HealthLevel::Ready
        }
        Ue4ssLoaderIdentityStatus::Exact
            if recognized_build_id.is_some_and(|build_id| {
                recipe.ue4ss_loader_policies.iter().any(|policy| {
                    policy
                        .known_unsafe_build_ids
                        .iter()
                        .any(|id| id == build_id)
                })
            }) =>
        {
            HealthLevel::Blocked
        }
        Ue4ssLoaderIdentityStatus::Unsafe | Ue4ssLoaderIdentityStatus::Ambiguous => {
            HealthLevel::Blocked
        }
        _ => HealthLevel::Attention,
    }
}

fn reconcile_recognized_ue4ss_receipt(
    game_root: &Path,
    state_root: &Path,
    transaction_id: &str,
    receipt: Option<DeploymentReceipt>,
    recipe: &BuildRecipe,
) -> Result<Option<DeploymentReceipt>> {
    let Some(receipt) = receipt else {
        return Ok(None);
    };
    let identity = inspect_ue4ss_loader_identity(game_root, &Ue4ssLoaderIdentityLimits::default())?;
    let Some(pair) = identity
        .identity
        .filter(|_| identity.status == Ue4ssLoaderIdentityStatus::Exact)
    else {
        return Ok(Some(receipt));
    };
    if !recipe.ue4ss_loader_builds.iter().any(|build| {
        build.proxy_sha256 == pair.proxy.sha256 && build.core_sha256 == pair.core.sha256
    }) {
        return Ok(Some(receipt));
    }
    let observations = [pair.proxy, pair.core];
    let identities: BTreeMap<_, _> = observations
        .into_iter()
        .filter(|observation| {
            receipt.files.iter().any(|file| {
                file.relative_path == observation.relative_path
                    && (file.bytes != observation.bytes || file.sha256 != observation.sha256)
            })
        })
        .map(|observation| {
            (
                observation.relative_path,
                DisplacedFile {
                    bytes: observation.bytes,
                    sha256: observation.sha256,
                },
            )
        })
        .collect();
    if identities.is_empty() {
        return Ok(Some(receipt));
    }
    Ok(Some(reconcile_managed_file_identities(
        state_root,
        UE4SS_LOADER_INSTALLATION_ID,
        game_root,
        transaction_id,
        &identities,
    )?))
}

fn diagnostics(
    game: &GameInstallationView,
    ue4ss: &Ue4ssStateView,
    recovery: bool,
    paths: &DesktopPaths,
    unmanaged_pak_count: usize,
) -> Vec<DiagnosticView> {
    let mut views = vec![
        DiagnosticView {
            id: "game-build".to_owned(),
            label: "Retro Rewind build".to_owned(),
            level: game.health,
            detail: if game.detected {
                format!(
                    "Detected build {}; expected {}.",
                    game.build_id.as_deref().unwrap_or("unknown"),
                    game.expected_build_id
                )
            } else {
                "No Steam installation was detected in native or Flatpak locations.".to_owned()
            },
        },
        DiagnosticView {
            id: "local-state".to_owned(),
            label: "Local manager state".to_owned(),
            level: HealthLevel::Ready,
            detail: format!("Offline state is stored at {}.", paths.data_root.display()),
        },
        DiagnosticView {
            id: "ue4ss".to_owned(),
            label: "UE4SS evidence".to_owned(),
            level: ue4ss.health,
            detail: ue4ss.message.clone(),
        },
        DiagnosticView {
            id: "recovery".to_owned(),
            label: "Deployment journal".to_owned(),
            level: if recovery {
                HealthLevel::Blocked
            } else {
                HealthLevel::Ready
            },
            detail: if recovery {
                "Interrupted deployment evidence requires confirmed recovery.".to_owned()
            } else {
                "No pending deployment journal was found.".to_owned()
            },
        },
    ];
    views.push(DiagnosticView {
        id: "unmanaged-paks".to_owned(),
        label: "Unmanaged mod PAKs".to_owned(),
        level: if unmanaged_pak_count == 0 {
            HealthLevel::Ready
        } else {
            HealthLevel::Attention
        },
        detail: if unmanaged_pak_count == 0 {
            "No active mod PAKs outside RRMM control were found.".to_owned()
        } else {
            format!(
                "{unmanaged_pak_count} active mod PAK{} will be preserved outside RRMM control.",
                if unmanaged_pak_count == 1 { "" } else { "s" }
            )
        },
    });
    views
}

fn archive_preflight_view(
    token: String,
    report: &ArchivePreflightReport,
    source_path: &Path,
    recognized_package_name: Option<String>,
    conflicts: Vec<ConflictView>,
    conflict_check_complete: bool,
) -> ArchivePreflightView {
    const MAX_UI_ENTRIES: usize = 500;
    let manifest_found = report
        .entries
        .iter()
        .any(|entry| entry.path == "rrmm-manifest.json");
    let has_pak = report
        .entries
        .iter()
        .any(|entry| entry.path.to_ascii_lowercase().ends_with(".pak"));
    let has_ue4ss = report.entries.iter().any(|entry| {
        entry
            .path
            .to_ascii_lowercase()
            .ends_with("/scripts/main.lua")
    });
    let package_kind = match (has_pak, has_ue4ss) {
        (true, true) => "hybrid",
        (true, false) => "pak",
        (false, true) => "ue4ss",
        (false, false) => "unknown",
    };
    let mut warnings = Vec::new();
    let executables = report
        .entries
        .iter()
        .filter(|entry| entry.executable_payload)
        .count();
    if executables > 0 {
        warnings.push(UiNoticeView {
            code: "executable_candidates".to_owned(),
            path: None,
            count: Some(executables),
        });
    }
    ArchivePreflightView {
        token,
        archive_path: source_path.display().to_string(),
        display_name: source_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("Selected archive")
            .to_owned(),
        format: match report.format {
            rrmm_archive::ArchiveFormat::Zip => "zip",
            rrmm_archive::ArchiveFormat::SevenZip => "7z",
        }
        .to_owned(),
        accepted: report.accepted,
        package_kind: package_kind.to_owned(),
        file_count: report.entry_count,
        unpacked_size_bytes: report.expanded_bytes,
        warnings,
        blocked_reasons: report
            .rejections
            .iter()
            .map(|rejection| UiNoticeView {
                code: rejection.code.clone(),
                path: rejection.path.clone(),
                count: None,
            })
            .collect(),
        manifest_found,
        recognized_package_name,
        conflicts,
        conflict_check_complete,
        entries: report
            .entries
            .iter()
            .take(MAX_UI_ENTRIES)
            .map(|entry| ArchiveEntryView {
                path: entry.path.clone(),
                expanded_bytes: entry.expanded_bytes,
                directory: entry.directory,
                executable_payload: entry.executable_payload,
            })
            .collect(),
        entries_truncated: report.entries.len() > MAX_UI_ENTRIES,
    }
}

fn activation_preview_view(
    profile_name: &str,
    plan: &DeploymentPlan,
    package_blockers: &[String],
    unmanaged_count: usize,
    pak_conflicts: &[PakConflictView],
    recipes: &RecipePreviewView,
    disableable_package_ids: &BTreeSet<String>,
) -> ActivationPreviewView {
    let mut changes =
        plan.changes
            .iter()
            .filter(|change| change.kind != DeploymentChangeKind::UnchangedManaged)
            .map(|change| ActivationChangeView {
                operation: match change.kind {
                    DeploymentChangeKind::RemoveManaged
                    | DeploymentChangeKind::RestoreUnmanaged => "remove",
                    DeploymentChangeKind::UnchangedManaged => "keep",
                    _ => "install",
                }
                .to_owned(),
                path: change.relative_path.clone(),
                package_id: change.owner_id.clone(),
                package_name: change.owner_name.clone(),
            })
            .collect::<Vec<_>>();
    changes.extend(
        plan.external_moves
            .iter()
            .map(|movement| ActivationChangeView {
                operation: "move".to_owned(),
                path: format!(
                    "{} -> {}",
                    movement.source_relative_path, movement.target_relative_path
                ),
                package_id: movement.owner_id.clone(),
                package_name: movement.owner_name.clone(),
            }),
    );
    let mut blockers: Vec<_> = plan.blockers.iter().map(deployment_blocker).collect();
    blockers.extend_from_slice(package_blockers);
    ActivationPreviewView {
        preview_id: plan.transaction_id.clone(),
        profile_id: plan.profile_id.clone(),
        profile_name: profile_name.to_owned(),
        blocked: !plan.ready() || !package_blockers.is_empty(),
        requires_apply: plan.previous_receipt.as_ref() != Some(&plan.target_receipt),
        blockers,
        changes,
        unmanaged_files_preserved: unmanaged_count,
        allow_unmanaged: plan.allow_unmanaged,
        pak_conflicts: pak_conflicts.to_vec(),
        blocking_links: blocking_link_views(plan).unwrap_or_default(),
        managed_file_issues: managed_file_issue_views(plan, disableable_package_ids),
        recipes: recipes.clone(),
    }
}

fn managed_file_issue_views(
    plan: &DeploymentPlan,
    disableable_package_ids: &BTreeSet<String>,
) -> Vec<ManagedFileIssueView> {
    let owned = plan
        .previous_receipt
        .as_ref()
        .map(|receipt| {
            receipt
                .files
                .iter()
                .map(|file| (file.relative_path.as_str(), file))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    plan.blockers
        .iter()
        .filter_map(|blocker| {
            let (path, expected_sha256, current_sha256) = match blocker {
                DeploymentBlocker::ManagedFileMissing { relative_path } => {
                    let file = owned.get(relative_path.as_str())?;
                    (relative_path, file.sha256.clone(), None)
                }
                DeploymentBlocker::ManagedFileDrifted {
                    relative_path,
                    expected_sha256,
                    actual_sha256,
                } => (
                    relative_path,
                    expected_sha256.clone(),
                    Some(actual_sha256.clone()),
                ),
                _ => return None,
            };
            let file = owned.get(path.as_str())?;
            let mut allowed_actions = Vec::new();
            if managed_file_restore_approval(plan, path).is_some() {
                allowed_actions.push("restore_managed".to_owned());
            }
            if file
                .package_id
                .as_ref()
                .is_some_and(|package_id| disableable_package_ids.contains(package_id))
            {
                allowed_actions.push("disable_package".to_owned());
            }
            Some(ManagedFileIssueView {
                path: path.clone(),
                expected_sha256,
                current_sha256,
                package_id: file.package_id.clone(),
                package_name: file.package_name.clone(),
                allowed_actions,
            })
        })
        .collect()
}

fn managed_file_restore_approval(
    plan: &DeploymentPlan,
    relative_path: &str,
) -> Option<ManagedFileRestoreApproval> {
    let owned = plan
        .previous_receipt
        .as_ref()?
        .files
        .iter()
        .find(|file| file.relative_path == relative_path)?;
    let desired = plan
        .files
        .iter()
        .find(|file| file.relative_path == relative_path)?;
    let current_sha256 = plan.blockers.iter().find_map(|blocker| match blocker {
        DeploymentBlocker::ManagedFileMissing {
            relative_path: path,
        } if path == relative_path => Some(None),
        DeploymentBlocker::ManagedFileDrifted {
            relative_path: path,
            actual_sha256,
            ..
        } if path == relative_path => Some(Some(actual_sha256.clone())),
        _ => None,
    })?;
    Some(ManagedFileRestoreApproval {
        relative_path: relative_path.to_owned(),
        expected_sha256: owned.sha256.clone(),
        current_sha256,
        restore_sha256: desired.sha256.clone(),
    })
}

fn exact_disableable_package_ids(
    profile: &DomainProfile,
    catalog: &[CatalogPackage],
    plan: &DeploymentPlan,
) -> BTreeSet<String> {
    let issue_package_ids: BTreeSet<_> = plan
        .previous_receipt
        .iter()
        .flat_map(|receipt| &receipt.files)
        .filter_map(|file| file.package_id.clone())
        .collect();
    issue_package_ids
        .into_iter()
        .filter(|package_id| {
            profile
                .packages
                .iter()
                .filter(|selection| selection.enabled)
                .filter(|selection| {
                    catalog.iter().any(|package| {
                        package.artifact_sha256 == selection.artifact_sha256
                            && package.manifest.id == *package_id
                    })
                })
                .count()
                == 1
        })
        .collect()
}

fn blocking_link_views(plan: &DeploymentPlan) -> Result<Vec<BlockingLinkView>> {
    let ue4ss_root = Path::new("RetroRewind/Binaries/Win64/ue4ss/Mods");
    let mut links = BTreeMap::new();
    for blocker in &plan.blockers {
        let DeploymentBlocker::UnsafeFilesystemEntry { relative_path, .. } = blocker else {
            continue;
        };
        let relative = Path::new(relative_path);
        let Some(parent) = relative.parent() else {
            continue;
        };
        let mut current = plan.game_root.clone();
        for component in parent.components() {
            let std::path::Component::Normal(component) = component else {
                break;
            };
            current.push(component);
            let Ok(metadata) = fs::symlink_metadata(&current) else {
                continue;
            };
            if !metadata.file_type().is_symlink() {
                continue;
            }
            let relative_link = current.strip_prefix(&plan.game_root)?;
            if !relative_link.starts_with(ue4ss_root)
                || relative_link.components().count() != ue4ss_root.components().count() + 1
            {
                continue;
            }
            let relative_path = relative_link.to_string_lossy().replace('\\', "/");
            let display_name = relative_link
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| relative_path.clone());
            links.insert(
                relative_path.clone(),
                BlockingLinkView {
                    relative_path,
                    display_name,
                },
            );
            break;
        }
    }
    Ok(links.into_values().collect())
}

fn remove_reviewed_filesystem_link(game_root: &Path, relative_path: &str) -> Result<()> {
    let relative = Path::new(relative_path);
    let mods_root = Path::new("RetroRewind/Binaries/Win64/ue4ss/Mods");
    if !relative.starts_with(mods_root)
        || relative.components().count() != mods_root.components().count() + 1
    {
        bail!("filesystem link is outside the UE4SS module root");
    }
    let path = checked_existing_mod_directory(game_root, relative_path)?;
    ensure_safe_existing_mod_parent(game_root, &path)?;
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_symlink() {
        bail!("filesystem link changed after the reviewed preview");
    }
    fs::remove_file(path)?;
    Ok(())
}

fn deployment_blocker(blocker: &DeploymentBlocker) -> String {
    match blocker {
        DeploymentBlocker::GameRunning => {
            "Retro Rewind is running. Close the game before activation.".to_owned()
        }
        DeploymentBlocker::UnmanagedPath { relative_path, .. } => format!(
            "An unmanaged file already exists at '{relative_path}'. Review and allow replacement explicitly."
        ),
        DeploymentBlocker::PathCollision {
            planned_path,
            existing_path,
        } => format!("Filesystem path collision between '{planned_path}' and '{existing_path}'."),
        DeploymentBlocker::ManagedFileMissing { relative_path } => {
            format!("Managed file '{relative_path}' is missing; recovery is required.")
        }
        DeploymentBlocker::ManagedFileDrifted { relative_path, .. } => format!(
            "Managed file '{relative_path}' changed outside RR Mod Manager; recovery is required."
        ),
        DeploymentBlocker::UnsafeFilesystemEntry {
            relative_path,
            detail,
        } => format!("Unsafe filesystem entry '{relative_path}': {detail}"),
        DeploymentBlocker::ExternalTargetOccupied { relative_path } => {
            format!("A file already occupies the external PAK load-order target '{relative_path}'.")
        }
    }
}

fn resolution_blocker(blocker: &ResolutionBlocker) -> String {
    match blocker {
        ResolutionBlocker::UnknownArtifact { artifact_sha256 } => format!(
            "Archive {} has no reviewed package record and cannot be activated.",
            &artifact_sha256[..artifact_sha256.len().min(12)]
        ),
        ResolutionBlocker::UnsupportedBuild {
            package_id,
            build_id,
        } => format!("Package '{package_id}' does not support game build {build_id}."),
        ResolutionBlocker::Incompatible { first, second } => {
            format!("Packages '{first}' and '{second}' are declared incompatible.")
        }
        ResolutionBlocker::MissingRequirement {
            package_id,
            requirement,
        } => format!("Package '{package_id}' requires '{requirement}'."),
        ResolutionBlocker::UnreviewedInference { package_id, .. } => format!(
            "Package '{package_id}' was inferred locally and has not been reviewed for activation."
        ),
        other => format!("Package resolution blocker: {other:?}"),
    }
}

fn resolution_blockers(blockers: &[ResolutionBlocker]) -> Vec<String> {
    blockers.iter().map(resolution_blocker).collect()
}

fn recipe_application_blockers(blockers: &[RecipeApplicationBlocker]) -> Vec<String> {
    blockers
        .iter()
        .map(|blocker| match blocker {
            RecipeApplicationBlocker::CombinedPackageUnavailable {
                recipe_id,
                artifact_sha256,
            } => format!(
                "Compatibility recipe '{recipe_id}' requires the exact reviewed patch artifact {artifact_sha256}, but it has not been imported. Import that exact patch archive and preview again."
            ),
            RecipeApplicationBlocker::OverlappingRecipes { first, second } => format!(
                "Compatibility recipes '{first}' and '{second}' overlap. Update RR Mod Manager before applying this profile."
            ),
            RecipeApplicationBlocker::OperationTargetMissing { recipe_id, target } => format!(
                "Compatibility recipe '{recipe_id}' cannot find required target '{target}'. Import the exact reviewed package versions or update RR Mod Manager."
            ),
            RecipeApplicationBlocker::CombinedResolutionBlocked { recipe_id, blockers } => format!(
                "Compatibility recipe '{recipe_id}' selected its exact patch, but package resolution is still blocked: {}",
                resolution_blockers(blockers).join("; ")
            ),
            RecipeApplicationBlocker::ConflictingInstallName { package_id } => format!(
                "Compatibility recipe install-name rules conflict for package '{package_id}'. Update RR Mod Manager before applying."
            ),
            RecipeApplicationBlocker::ConflictingWinner { resource } => format!(
                "Compatibility recipes select conflicting winners for '{resource}'. Update RR Mod Manager before applying."
            ),
            RecipeApplicationBlocker::ResolutionNotReady => {
                "The selected exact package versions could not be resolved after applying compatibility recipes. Review the package blockers below.".to_owned()
            }
        })
        .collect()
}

fn pending_recovery(state_root: &Path) -> Result<bool> {
    let journals = state_root.join("journals");
    match fs::read_dir(&journals) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_symlink() {
                    bail!("deployment journal directory contains a filesystem link");
                }
                if file_type.is_file()
                    && entry
                        .path()
                        .extension()
                        .is_some_and(|extension| extension == "json")
                {
                    return Ok(true);
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let operations = state_root.join(EXISTING_GROUP_OPERATIONS_DIRECTORY);
    match fs::read_dir(operations) {
        Ok(mut entries) => {
            if let Some(entry) = entries.next() {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    bail!("hybrid recovery storage contains an unsafe entry");
                }
                return Ok(true);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(false)
}

fn package_kind(kind: PackageKind) -> &'static str {
    match kind {
        PackageKind::PakOnly => "pak",
        PackageKind::Ue4ssOnly => "ue4ss",
        PackageKind::Hybrid => "hybrid",
        PackageKind::Unknown => "unknown",
    }
}

fn component_type_name(component_type: ComponentType) -> &'static str {
    match component_type {
        ComponentType::Pak => "pak",
        ComponentType::Ue4ss => "ue4ss",
        ComponentType::Config => "config",
        ComponentType::Documentation => "documentation",
        ComponentType::Native => "native",
    }
}

fn now() -> String {
    Utc::now().to_rfc3339()
}

fn timestamp_from_unix(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .unwrap_or_else(Utc::now)
        .to_rfc3339()
}

fn run_json_worker<Request, Response>(
    worker: &Path,
    label: &str,
    request: &Request,
    timeout: Duration,
) -> Result<Response>
where
    Request: Serialize,
    Response: DeserializeOwned,
{
    const MAX_RESPONSE_BYTES: u64 = 128 * 1024 * 1024;
    let mut child = Command::new(worker)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to start {label} {}", worker.display()))?;
    child
        .stdin
        .take()
        .context("worker stdin is unavailable")?
        .write_all(&serde_json::to_vec(request)?)?;
    let stdout = child
        .stdout
        .take()
        .context("worker stdout is unavailable")?;
    let reader = thread::spawn(move || {
        let mut output = Vec::new();
        stdout
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut output)
            .map(|_| output)
    });
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= timeout {
            child.kill()?;
            child.wait()?;
            let _ = reader.join();
            bail!("{label} timed out after {} seconds", timeout.as_secs());
        }
        thread::sleep(Duration::from_millis(20));
    };
    let output = reader
        .join()
        .map_err(|_| anyhow::anyhow!("{label} output reader panicked"))??;
    if output.len() as u64 > MAX_RESPONSE_BYTES {
        bail!("{label} response exceeded 128 MiB");
    }
    serde_json::from_slice(&output)
        .with_context(|| format!("{label} returned invalid JSON with status {status}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::{OsRng, RngCore};
    use rrmm_recipes::{
        DelegatedOnlineKey, DetachedSignature, RecipeCatalog, RootMetadata, SignatureAlgorithm,
        catalog_signing_payload, root_signing_payload,
    };
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;

    fn import_test_app(temporary: &TempDir) -> DesktopApplication {
        import_test_app_with_workers(
            temporary,
            PathBuf::from(":in-process-archive-worker:"),
            PathBuf::from(":in-process-pak-worker:"),
        )
    }

    fn import_test_app_with_workers(
        temporary: &TempDir,
        archive_worker: PathBuf,
        pak_worker: PathBuf,
    ) -> DesktopApplication {
        let app = DesktopApplication::new(
            DesktopPaths::under(temporary.path().join("state")),
            archive_worker,
            pak_worker,
        )
        .unwrap();
        let steam_root = temporary.path().join("steam");
        let game_root = steam_root.join("steamapps/common/Retro Rewind");
        let manifest_path = steam_root.join("steamapps/appmanifest_3552140.acf");
        fs::create_dir_all(game_root.join("RetroRewind/Content/Paks")).unwrap();
        fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        fs::write(
            &manifest_path,
            format!(
                "\"AppState\"\n{{\n\"appid\" \"3552140\"\n\"buildid\" \"{}\"\n\"StateFlags\" \"4\"\n\"installdir\" \"Retro Rewind\"\n}}",
                SUPPORTED_BUILD_ID
            ),
        )
        .unwrap();
        let store = app.store().unwrap();
        store
            .upsert_installation(&rrmm_domain::InstallationInspection {
                installation: rrmm_domain::GameInstallation {
                    app_id: rrmm_domain::RETRO_REWIND_APP_ID,
                    build_id: SUPPORTED_BUILD_ID,
                    state_flags: 4,
                    install_dir_name: "Retro Rewind".to_owned(),
                    steam_root: steam_root.clone(),
                    library_root: steam_root.clone(),
                    manifest_path,
                    game_root,
                    source: InstallationSource::UserOverride,
                },
                layout_status: LayoutStatus::Complete,
                build_status: BuildStatus::SupportedExact,
                game_running: false,
                writable_hint: true,
                critical_files: Vec::new(),
                warnings: Vec::new(),
            })
            .unwrap();
        app.ensure_default_profile().unwrap();
        app
    }

    fn materialize_synthetic_exact_installation(app: &mut DesktopApplication) -> PathBuf {
        let stored = selected_installation(&app.store().unwrap())
            .unwrap()
            .unwrap();
        let game_root = stored.installation.game_root.clone();
        for (relative, bytes) in [
            (
                "RetroRewind.exe",
                b"synthetic bootstrap executable".as_slice(),
            ),
            (
                "RetroRewind/Binaries/Win64/RetroRewind-Win64-Shipping.exe",
                b"synthetic shipping executable".as_slice(),
            ),
            (
                "RetroRewind/Content/Paks/RetroRewind-Windows.pak",
                b"synthetic vanilla pak".as_slice(),
            ),
        ] {
            let path = game_root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }

        let mut recipe = build_recipe().unwrap();
        recipe.critical_files = [
            "RetroRewind.exe",
            "RetroRewind/Binaries/Win64/RetroRewind-Win64-Shipping.exe",
        ]
        .into_iter()
        .map(|relative| {
            let path = game_root.join(relative);
            rrmm_domain::CriticalFileRecipe {
                relative_path: relative.into(),
                size: fs::metadata(&path).unwrap().len(),
                sha256: rrmm_archive::sha256_path(&path).unwrap(),
            }
        })
        .collect();
        let exact = inspect_manifest(
            &stored.installation.manifest_path,
            &stored.installation.steam_root,
            &stored.installation.library_root,
            stored.installation.source,
            Some(&recipe),
            true,
        )
        .unwrap();
        assert_eq!(exact.layout_status, LayoutStatus::Complete);
        assert_eq!(exact.build_status, BuildStatus::SupportedExact);
        app.store().unwrap().upsert_installation(&exact).unwrap();
        app.deployment_build_recipe_override = Some(recipe);
        game_root
    }

    fn write_test_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let mut writer = zip::ZipWriter::new(fs::File::create(path).unwrap());
        for (name, bytes) in entries {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
    }

    #[test]
    fn persists_only_the_last_twenty_redacted_operation_failures_and_clears_them() {
        let temporary = TempDir::new().unwrap();
        let paths = DesktopPaths::under(temporary.path().join("state"));
        let app = DesktopApplication::new(
            paths.clone(),
            PathBuf::from(":in-process-archive-worker:"),
            PathBuf::from(":in-process-pak-worker:"),
        )
        .unwrap();

        for index in 0..22 {
            let operation_id = format!("operation-{index}");
            app.begin_operation(&operation_id, &operation_id);
            app.operation_stage(&operation_id, "download_and_verify_archive");
            app.operation_detail(
                &operation_id,
                "nested",
                serde_json::json!({
                    "path": "C:\\Users\\Alice\\RetroRewind\\private.log",
                    "url": "https://example.invalid/file?token=supersecret"
                }),
            );
            app.fail_operation(
                &operation_id,
                &anyhow::anyhow!("download failed for /home/alice/private.log?api_key=supersecret"),
            );
        }

        assert_eq!(app.operation_failure_count().unwrap(), 20);
        let failures = app.operation_failures().unwrap();
        assert_eq!(failures.first().unwrap().operation, "operation-2");
        assert_eq!(failures.last().unwrap().operation, "operation-21");
        assert_eq!(
            failures.last().unwrap().stage,
            "download_and_verify_archive"
        );
        assert_eq!(failures.last().unwrap().category, "network");
        let serialized = serde_json::to_string(&failures).unwrap();
        for secret in ["Alice", "alice", "supersecret", "/home/"] {
            assert!(!serialized.contains(secret), "secret remained: {secret}");
        }

        drop(app);
        let reopened = DesktopApplication::new(
            paths,
            PathBuf::from(":in-process-archive-worker:"),
            PathBuf::from(":in-process-pak-worker:"),
        )
        .unwrap();
        assert_eq!(reopened.operation_failure_count().unwrap(), 20);
        assert_eq!(reopened.clear_diagnostic_history().unwrap(), 20);
        assert_eq!(reopened.operation_failure_count().unwrap(), 0);
    }

    #[test]
    fn ignores_a_corrupted_optional_operation_history() {
        let temporary = TempDir::new().unwrap();
        let app = DesktopApplication::new(
            DesktopPaths::under(temporary.path().join("state")),
            PathBuf::from(":in-process-archive-worker:"),
            PathBuf::from(":in-process-pak-worker:"),
        )
        .unwrap();
        app.store()
            .unwrap()
            .set_setting(
                OPERATION_FAILURES_KEY,
                &serde_json::json!({ "invalid": true }),
            )
            .unwrap();

        assert_eq!(app.operation_failure_count().unwrap(), 0);
        assert_eq!(app.clear_diagnostic_history().unwrap(), 0);
    }

    #[test]
    fn classifies_localized_windows_access_denied_as_filesystem_failure() {
        assert_eq!(
            operation_error_category("Acesso negado. (os error 5)"),
            "filesystem"
        );
    }

    #[test]
    fn classifies_windows_process_security_errors_as_sandbox_failures() {
        assert_eq!(
            operation_error_category(
                "archive worker rejected the operation: failed to configure process security attribute (child-process policy): Windows error 24"
            ),
            "sandbox"
        );
    }

    fn test_pak_bytes(payload: &[u8]) -> Vec<u8> {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let output = temporary.reopen().unwrap();
        let mut writer = repak_trumank::PakBuilder::new().writer(
            output,
            repak_trumank::Version::V11,
            "../../../".to_owned(),
            Some(0x6493_4de7),
        );
        writer
            .write_file("RetroRewind/Content/Test/Review.uasset", false, payload)
            .unwrap();
        writer.write_index().unwrap().sync_all().unwrap();
        fs::read(temporary.path()).unwrap()
    }

    fn confirmed(review: &ArchiveImportReviewView) -> ImportArchiveConfirmationView {
        ImportArchiveConfirmationView {
            review_sha256: review.review_sha256.clone(),
            executable_payloads_acknowledged: true,
        }
    }

    struct SignedCatalogFixture {
        roots: String,
        root: String,
        catalog: String,
        root_metadata: SignedRootMetadata,
        online_signing: SigningKey,
    }

    fn ephemeral_signing_key() -> SigningKey {
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    fn signed_catalog_fixture(sequence: u64, expired: bool) -> SignedCatalogFixture {
        let root_signing = ephemeral_signing_key();
        let online_signing = ephemeral_signing_key();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires_at = if expired {
            now.saturating_sub(1)
        } else {
            now + 3_600
        };
        let issued_at = if expired {
            now.saturating_sub(3_600)
        } else {
            now.saturating_sub(1)
        };
        let online_key_id = format!(
            "ed25519-{:x}",
            Sha256::digest(online_signing.verifying_key().as_bytes())
        );
        let metadata = RootMetadata {
            schema_version: 1,
            generation: 1,
            expires_at,
            online_keys: vec![DelegatedOnlineKey {
                key_id: online_key_id.clone(),
                public_key: STANDARD.encode(online_signing.verifying_key().as_bytes()),
                valid_from: issued_at,
                valid_until: expires_at,
            }],
            revoked_online_key_ids: Vec::new(),
        };
        let root_signature = root_signing
            .sign(&root_signing_payload(&metadata).unwrap())
            .to_bytes();
        let root_metadata = SignedRootMetadata {
            signed: metadata,
            signatures: vec![DetachedSignature {
                key_id: "test-root".to_owned(),
                algorithm: SignatureAlgorithm::Ed25519,
                signature: STANDARD.encode(root_signature),
            }],
        };
        let catalog = RecipeCatalog {
            schema_version: 1,
            sequence,
            issued_at,
            expires_at,
            recipes: vec![
                serde_json::from_str(include_str!("../../../fixtures/recipe.valid.json")).unwrap(),
            ],
        };
        let signed_catalog = SignedRecipeCatalog {
            signed: catalog.clone(),
            signatures: vec![DetachedSignature {
                key_id: online_key_id,
                algorithm: SignatureAlgorithm::Ed25519,
                signature: STANDARD.encode(
                    online_signing
                        .sign(&catalog_signing_payload(&catalog).unwrap())
                        .to_bytes(),
                ),
            }],
        };
        let roots = vec![TrustedRootKey {
            key_id: "test-root".to_owned(),
            public_key: STANDARD.encode(root_signing.verifying_key().as_bytes()),
        }];
        SignedCatalogFixture {
            roots: serde_json::to_string(&roots).unwrap(),
            root: serde_json::to_string(&root_metadata).unwrap(),
            catalog: serde_json::to_string(&signed_catalog).unwrap(),
            root_metadata,
            online_signing,
        }
    }

    fn resign_catalog(fixture: &SignedCatalogFixture, sequence: u64) -> String {
        let root = &fixture.root_metadata.signed;
        let catalog = RecipeCatalog {
            schema_version: 1,
            sequence,
            issued_at: root.online_keys[0].valid_from,
            expires_at: root.expires_at,
            recipes: vec![
                serde_json::from_str(include_str!("../../../fixtures/recipe.valid.json")).unwrap(),
            ],
        };
        serde_json::to_string(&SignedRecipeCatalog {
            signatures: vec![DetachedSignature {
                key_id: root.online_keys[0].key_id.clone(),
                algorithm: SignatureAlgorithm::Ed25519,
                signature: STANDARD.encode(
                    fixture
                        .online_signing
                        .sign(&catalog_signing_payload(&catalog).unwrap())
                        .to_bytes(),
                ),
            }],
            signed: catalog,
        })
        .unwrap()
    }

    #[test]
    fn embedded_catalog_loader_accepts_valid_signatures_and_persists_rollback_floor() {
        let temporary = TempDir::new().unwrap();
        let store = Store::open(&temporary.path().join("state.sqlite3")).unwrap();
        let fixture = signed_catalog_fixture(2, false);
        let EmbeddedRecipeCatalog::Verified { catalog, floor } = verify_embedded_recipe_catalog(
            &store,
            &fixture.roots,
            &fixture.root,
            &fixture.catalog,
            true,
        ) else {
            panic!("valid ephemeral catalog was rejected");
        };
        assert_eq!(catalog.recipes().len(), 1);
        assert_eq!(floor.catalog_sequence, 2);
        assert_eq!(
            store
                .catalog_trust_state(RECIPE_CATALOG_CHANNEL)
                .unwrap()
                .unwrap()
                .catalog_sequence,
            2
        );
    }

    #[test]
    fn embedded_catalog_loader_blocks_tampering_expiry_and_rollback() {
        let temporary = TempDir::new().unwrap();
        let store = Store::open(&temporary.path().join("state.sqlite3")).unwrap();
        let fixture = signed_catalog_fixture(2, false);
        let mut tampered: serde_json::Value = serde_json::from_str(&fixture.catalog).unwrap();
        tampered["signed"]["sequence"] = serde_json::json!(3);
        assert!(matches!(
            verify_embedded_recipe_catalog(
                &store,
                &fixture.roots,
                &fixture.root,
                &tampered.to_string(),
                true,
            ),
            EmbeddedRecipeCatalog::Rejected(message) if message.contains("signature")
        ));

        let expired = signed_catalog_fixture(1, true);
        assert!(matches!(
            verify_embedded_recipe_catalog(
                &Store::open(&temporary.path().join("expired.sqlite3")).unwrap(),
                &expired.roots,
                &expired.root,
                &expired.catalog,
                true,
            ),
            EmbeddedRecipeCatalog::Rejected(message) if message.contains("expired")
        ));

        assert!(matches!(
            verify_embedded_recipe_catalog(
                &store,
                &fixture.roots,
                &fixture.root,
                &fixture.catalog,
                true,
            ),
            EmbeddedRecipeCatalog::Verified { .. }
        ));
        let older_catalog = resign_catalog(&fixture, 1);
        assert!(matches!(
            verify_embedded_recipe_catalog(
                &store,
                &fixture.roots,
                &fixture.root,
                &older_catalog,
                true,
            ),
            EmbeddedRecipeCatalog::Rejected(message) if message.contains("rollback")
        ));
    }

    #[test]
    fn embedded_catalog_loader_keeps_debug_usable_without_roots() {
        let temporary = TempDir::new().unwrap();
        let store = Store::open(&temporary.path().join("state.sqlite3")).unwrap();
        assert!(matches!(
            verify_embedded_recipe_catalog(&store, "[]", "{}", "{}", true),
            EmbeddedRecipeCatalog::Unavailable(message) if message.contains("not included")
        ));
    }

    #[test]
    fn reviewed_zip_is_not_published_until_confirmed_and_then_matches_source() {
        let temporary = TempDir::new().unwrap();
        let app = import_test_app(&temporary);
        let archive = temporary.path().join("Example.zip");
        let pak_bytes = test_pak_bytes(b"pak payload");
        write_test_zip(&archive, &[("Example_P.pak", &pak_bytes)]);
        let preflight = app.preflight_archive(&archive).unwrap();
        let review = app.review_archive(&preflight.token).unwrap();

        assert_eq!(review.package_kind, "pak");
        assert!(review.activation_supported);
        assert_eq!(review.package_name, "Example");
        assert_eq!(
            review.files[0].planned_destination.as_deref(),
            Some("RetroRewind/Content/Paks/Example_P.pak")
        );
        assert!(app.store().unwrap().artifacts().unwrap().is_empty());
        assert!(!app.paths.artifact_store.join("artifacts").exists());
        assert!(app.review_archive(&preflight.token).is_err());
        assert!(
            app.import_reviewed_archive(&preflight.token, confirmed(&review))
                .is_err()
        );

        let result = app
            .import_reviewed_archive(&review.token, confirmed(&review))
            .unwrap();
        let artifact_root = app
            .paths
            .artifact_store
            .join("artifacts")
            .join(&result.artifact_sha256[..2])
            .join(&result.artifact_sha256);
        assert_eq!(
            fs::read(artifact_root.join("files/Example_P.pak")).unwrap(),
            pak_bytes
        );
        assert!(!artifact_root.join("source.zip").exists());
        assert!(
            app.import_reviewed_archive(&review.token, confirmed(&review))
                .is_err()
        );
    }

    #[test]
    fn managed_mod_toggle_updates_only_the_selected_profile() {
        let temporary = TempDir::new().unwrap();
        let app = import_test_app(&temporary);
        let archive = temporary.path().join("Direct.zip");
        let pak_bytes = test_pak_bytes(b"direct toggle");
        write_test_zip(&archive, &[("Direct_P.pak", &pak_bytes)]);
        let preflight = app.preflight_archive(&archive).unwrap();
        let review = app.review_archive(&preflight.token).unwrap();
        let imported = app
            .import_reviewed_archive(&review.token, confirmed(&review))
            .unwrap();
        let game_root = selected_installation(&app.store().unwrap())
            .unwrap()
            .unwrap()
            .installation
            .game_root;
        let deployed = game_root.join("RetroRewind/Content/Paks/Direct_P.pak");

        let result = app
            .set_profile_mods_enabled(
                "default",
                std::slice::from_ref(&imported.artifact_sha256),
                true,
            )
            .unwrap();

        assert!(result.packages[0].enabled);
        assert!(!deployed.exists());
        assert!(
            app.store()
                .unwrap()
                .profile("default")
                .unwrap()
                .unwrap()
                .packages[0]
                .enabled
        );
    }

    #[test]
    fn selecting_a_profile_does_not_apply_it() {
        let temporary = TempDir::new().unwrap();
        let app = import_test_app(&temporary);
        let second = app.create_profile("Second").unwrap();

        app.select_profile(&second.id).unwrap();

        assert_eq!(
            app.store()
                .unwrap()
                .active_profile(INSTALLATION_ID)
                .unwrap()
                .unwrap()
                .id,
            second.id
        );
        assert!(
            load_receipt(&app.paths.deployment_state, INSTALLATION_ID)
                .unwrap()
                .is_none()
        );
        let snapshot = app.snapshot().unwrap();
        assert_eq!(
            snapshot.deployment.selected_profile_id.as_deref(),
            Some(second.id.as_str())
        );
        assert!(snapshot.deployment.applied_profile_id.is_none());
    }

    #[test]
    fn adopts_an_external_pak_into_the_selected_profile_without_changing_the_game() {
        let temporary = TempDir::new().unwrap();
        let app = import_test_app(&temporary);
        let game_root = selected_installation(&app.store().unwrap())
            .unwrap()
            .unwrap()
            .installation
            .game_root;
        let pak = game_root.join("RetroRewind/Content/Paks/~mods/LocalExample_P.pak");
        fs::create_dir_all(pak.parent().unwrap()).unwrap();
        let bytes = test_pak_bytes(b"adopted external pak");
        fs::write(&pak, &bytes).unwrap();
        let existing = existing_mod_views(&game_root, &app.paths.deployment_state, None)
            .unwrap()
            .remove(0);

        let adopted = app.adopt_existing_mod(&existing.id).unwrap();

        assert_eq!(fs::read(&pak).unwrap(), bytes);
        assert!(
            app.store()
                .unwrap()
                .artifact(&adopted.artifact_sha256)
                .unwrap()
                .is_some()
        );
        let profile = app.store().unwrap().profile("default").unwrap().unwrap();
        assert!(profile.packages.iter().any(|selection| {
            selection.artifact_sha256 == adopted.artifact_sha256 && selection.enabled
        }));
        assert!(
            load_receipt(&app.paths.deployment_state, INSTALLATION_ID)
                .unwrap()
                .is_none()
        );
        assert!(app.snapshot().unwrap().deployment.existing_mods.is_empty());
    }

    #[test]
    fn unchanged_profile_selection_does_not_touch_the_game() {
        let temporary = TempDir::new().unwrap();
        let app = import_test_app(&temporary);
        let archive = temporary.path().join("Direct.zip");
        let pak_bytes = test_pak_bytes(b"direct reconciliation");
        write_test_zip(&archive, &[("Direct_P.pak", &pak_bytes)]);
        let preflight = app.preflight_archive(&archive).unwrap();
        let review = app.review_archive(&preflight.token).unwrap();
        let imported = app
            .import_reviewed_archive(&review.token, confirmed(&review))
            .unwrap();
        app.update_profile_package("default", &imported.artifact_sha256, false)
            .unwrap();
        let result = app
            .set_profile_mods_enabled(
                "default",
                std::slice::from_ref(&imported.artifact_sha256),
                false,
            )
            .unwrap();

        assert!(!result.packages[0].enabled);
        assert!(
            !app.store()
                .unwrap()
                .profile("default")
                .unwrap()
                .unwrap()
                .packages[0]
                .enabled
        );
    }

    #[test]
    fn review_freezes_real_candidate_external_pak_conflicts_and_revalidates_them() {
        let temporary = TempDir::new().unwrap();
        let app = import_test_app(&temporary);
        let game_root = selected_installation(&app.store().unwrap())
            .unwrap()
            .unwrap()
            .installation
            .game_root;
        let external = game_root.join("RetroRewind/Content/Paks/Candidate_P.pak");
        fs::write(&external, test_pak_bytes(b"external version")).unwrap();
        let archive = temporary.path().join("Candidate.zip");
        let candidate = test_pak_bytes(b"candidate version");
        write_test_zip(&archive, &[("Candidate_P.pak", &candidate)]);

        let preflight = app.preflight_archive(&archive).unwrap();
        let review = app.review_archive(&preflight.token).unwrap();

        assert!(review.conflict_check_complete);
        assert!(review.blocked_reasons.is_empty());
        assert_eq!(review.pak_conflicts.len(), 1);
        assert_eq!(review.destination_conflicts.len(), 1);
        assert_eq!(
            review.destination_conflicts[0].outcome,
            "occupied_unmanaged_destination"
        );
        assert!(!review.destination_conflicts[0].blocking);
        let conflict = &review.pak_conflicts[0];
        assert!(
            conflict.first.source_kind == "candidate" || conflict.second.source_kind == "candidate"
        );
        assert!(
            conflict.first.source_kind == "external" || conflict.second.source_kind == "external"
        );
        assert!(conflict.first.destination.is_some());
        assert!(conflict.second.destination.is_some());

        fs::write(&external, test_pak_bytes(b"changed external version")).unwrap();
        let error = app
            .import_reviewed_archive(&review.token, confirmed(&review))
            .unwrap_err();
        assert!(error.to_string().contains("conflict evidence changed"));
        assert!(app.store().unwrap().artifacts().unwrap().is_empty());
    }

    #[test]
    fn private_snapshot_freezes_selected_bytes_and_survives_source_removal() {
        let temporary = TempDir::new().unwrap();
        let app = import_test_app(&temporary);
        let archive = temporary.path().join("Drift.zip");
        let pak_bytes = test_pak_bytes(b"stable");
        write_test_zip(&archive, &[("Drift_P.pak", &pak_bytes)]);
        let preflight = app.preflight_archive(&archive).unwrap();
        assert_eq!(preflight.archive_path, archive.display().to_string());
        assert_eq!(preflight.display_name, "Drift.zip");
        fs::write(&archive, b"source changed after selection").unwrap();
        let review = app.review_archive(&preflight.token).unwrap();

        let wrong = ImportArchiveConfirmationView {
            review_sha256: "0".repeat(64),
            executable_payloads_acknowledged: false,
        };
        assert!(app.import_reviewed_archive(&review.token, wrong).is_err());
        assert!(
            app.pending_import_reviews
                .lock()
                .unwrap()
                .contains_key(&review.token)
        );

        fs::remove_file(&archive).unwrap();
        let imported = app
            .import_reviewed_archive(&review.token, confirmed(&review))
            .unwrap();
        assert_eq!(imported.artifact_sha256, review.archive_sha256);
        assert!(fs::read_dir(&app.paths.staging).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(ARCHIVE_INPUT_PREFIX)
        }));
    }

    #[test]
    fn private_snapshot_tampering_is_rejected_and_cleaned_before_review() {
        let temporary = TempDir::new().unwrap();
        let app = import_test_app(&temporary);
        let archive = temporary.path().join("Snapshot-Tamper.zip");
        let pak_bytes = test_pak_bytes(b"original");
        write_test_zip(&archive, &[("Snapshot-Tamper_P.pak", &pak_bytes)]);
        let preflight = app.preflight_archive(&archive).unwrap();
        let snapshot = app
            .pending_archives
            .lock()
            .unwrap()
            .get(&preflight.token)
            .unwrap()
            .snapshot
            .clone();
        fs::OpenOptions::new()
            .append(true)
            .open(&snapshot.archive_path)
            .unwrap()
            .write_all(b"tampered")
            .unwrap();

        let error = app.review_archive(&preflight.token).unwrap_err();
        assert!(error.to_string().contains("snapshot"));
        assert!(!snapshot.root.exists());
    }

    #[test]
    fn rejected_preflight_and_snapshot_size_limit_leave_no_private_input() {
        let temporary = TempDir::new().unwrap();
        let app = import_test_app(&temporary);
        let rejected = temporary.path().join("Rejected.zip");
        write_test_zip(&rejected, &[("../escape.pak", b"blocked")]);

        let preflight = app.preflight_archive(&rejected).unwrap();
        assert!(!preflight.accepted);
        assert!(!preflight.blocked_reasons.is_empty());
        let json = serde_json::to_value(&preflight).unwrap();
        assert_eq!(json.get("accepted"), Some(&serde_json::json!(false)));
        assert!(
            json["blockedReasons"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
        );
        assert!(app.pending_archives.lock().unwrap().is_empty());
        assert!(fs::read_dir(&app.paths.staging).unwrap().next().is_none());

        let oversized = temporary.path().join("Oversized.zip");
        fs::write(&oversized, b"four").unwrap();
        let mut limits = desktop_archive_limits();
        limits.max_archive_bytes = 3;
        let error = create_archive_snapshot(
            &app.paths,
            &fs::canonicalize(&oversized).unwrap(),
            "oversized",
            &limits,
        )
        .unwrap_err();
        assert!(error.to_string().contains("configured limit"));
        assert!(fs::read_dir(&app.paths.staging).unwrap().next().is_none());
    }

    #[test]
    fn pending_preflight_eviction_and_restart_cleanup_remove_private_inputs() {
        let temporary = TempDir::new().unwrap();
        let app = import_test_app(&temporary);
        let archive = temporary.path().join("Pending.zip");
        let pak_bytes = test_pak_bytes(b"pending");
        write_test_zip(&archive, &[("Pending_P.pak", &pak_bytes)]);
        let mut first_snapshot = None;
        for _ in 0..=MAX_PENDING_ARCHIVE_PREFLIGHTS {
            let preflight = app.preflight_archive(&archive).unwrap();
            if first_snapshot.is_none() {
                first_snapshot = Some(
                    app.pending_archives
                        .lock()
                        .unwrap()
                        .get(&preflight.token)
                        .unwrap()
                        .snapshot
                        .root
                        .clone(),
                );
            }
        }
        assert_eq!(
            app.pending_archives.lock().unwrap().len(),
            MAX_PENDING_ARCHIVE_PREFLIGHTS
        );
        assert!(!first_snapshot.unwrap().exists());
        drop(app);

        let orphan = temporary
            .path()
            .join("state/staging")
            .join(format!("{ARCHIVE_INPUT_PREFIX}orphan"));
        fs::create_dir(&orphan).unwrap();
        fs::write(orphan.join("archive.bin"), b"orphan").unwrap();
        let restarted = import_test_app(&temporary);
        assert!(!orphan.exists());
        drop(restarted);
    }

    #[test]
    fn staging_tampering_is_rejected_and_discard_cleans_private_files() {
        let temporary = TempDir::new().unwrap();
        let app = import_test_app(&temporary);
        let archive = temporary.path().join("Tamper.zip");
        let pak_bytes = test_pak_bytes(b"original");
        write_test_zip(&archive, &[("Tamper_P.pak", &pak_bytes)]);
        let preflight = app.preflight_archive(&archive).unwrap();
        let preflight_json = serde_json::to_value(&preflight).unwrap();
        assert_eq!(
            preflight_json.get("accepted"),
            Some(&serde_json::json!(true))
        );
        assert!(preflight_json.get("blockedReasons").is_some());
        assert!(preflight_json.get("blocked_reasons").is_none());
        let review = app.review_archive(&preflight.token).unwrap();
        let staging = app
            .pending_import_reviews
            .lock()
            .unwrap()
            .get(&review.token)
            .unwrap()
            .extraction
            .staging_root
            .clone();
        let snapshot_root = app
            .pending_import_reviews
            .lock()
            .unwrap()
            .get(&review.token)
            .unwrap()
            .snapshot
            .root
            .clone();
        fs::write(staging.join("Tamper_P.pak"), b"tampered").unwrap();

        assert!(
            app.import_reviewed_archive(&review.token, confirmed(&review))
                .is_err()
        );
        assert!(app.store().unwrap().artifacts().unwrap().is_empty());
        assert!(staging.exists());
        app.discard_archive_review(&review.token).unwrap();
        assert!(!staging.exists());
        assert!(!snapshot_root.exists());
        assert!(app.discard_archive_review(&review.token).is_err());
    }

    #[test]
    fn extensionless_native_payload_remains_unknown_and_requires_acknowledgement() {
        let temporary = TempDir::new().unwrap();
        let app = import_test_app(&temporary);
        let archive = temporary.path().join("Native.zip");
        write_test_zip(&archive, &[("tools/native-helper", b"\x7fELFfixture")]);
        let preflight = app.preflight_archive(&archive).unwrap();
        assert_eq!(preflight.package_kind, "unknown");
        let review = app.review_archive(&preflight.token).unwrap();

        assert_eq!(review.package_kind, "unknown");
        assert!(!review.activation_supported);
        assert!(review.layout.requires_review);
        assert!(review.executable_acknowledgement_required);
        assert!(review.files[0].native_binary);
        assert!(!review.files[0].executable_payload);
        assert!(review.files[0].planned_destination.is_none());
        assert!(
            review
                .warnings
                .iter()
                .any(|item| item.code == "native_binaries")
        );
        assert!(
            review
                .warnings
                .iter()
                .any(|item| item.code == "unknown_layout")
        );
        assert!(review.blocked_reasons.is_empty());

        let missing_ack = ImportArchiveConfirmationView {
            review_sha256: review.review_sha256.clone(),
            executable_payloads_acknowledged: false,
        };
        assert!(
            app.import_reviewed_archive(&review.token, missing_ack)
                .is_err()
        );
        assert!(
            app.import_reviewed_archive(&review.token, confirmed(&review))
                .is_ok()
        );
    }

    #[test]
    fn incomplete_ue4ss_layout_is_visible_but_not_activatable() {
        let temporary = TempDir::new().unwrap();
        let app = import_test_app(&temporary);
        let archive = temporary.path().join("Lua.zip");
        write_test_zip(&archive, &[("LuaMod/Scripts/main.lua", b"return true")]);
        let preflight = app.preflight_archive(&archive).unwrap();
        let review = app.review_archive(&preflight.token).unwrap();

        assert_eq!(review.package_kind, "ue4ss");
        assert!(!review.activation_supported);
        assert!(review.layout.requires_review);
        assert!(review.warnings.iter().any(|item| {
            item.code == "missing_enabled_marker" && item.path.as_deref() == Some("LuaMod")
        }));
        assert!(review.blocked_reasons.is_empty());
    }

    #[test]
    fn pending_review_map_is_limited_and_eviction_cleans_staging() {
        let temporary = TempDir::new().unwrap();
        let app = import_test_app(&temporary);
        let archive = temporary.path().join("Many.zip");
        let pak_bytes = test_pak_bytes(b"pak");
        write_test_zip(&archive, &[("Many_P.pak", &pak_bytes)]);
        let mut reviews = Vec::new();
        let mut first_snapshot = None;
        for _ in 0..=MAX_PENDING_IMPORT_REVIEWS {
            let preflight = app.preflight_archive(&archive).unwrap();
            let review = app.review_archive(&preflight.token).unwrap();
            if first_snapshot.is_none() {
                first_snapshot = Some(
                    app.pending_import_reviews
                        .lock()
                        .unwrap()
                        .get(&review.token)
                        .unwrap()
                        .snapshot
                        .root
                        .clone(),
                );
            }
            reviews.push(review);
        }
        let first_staging = app.paths.staging.join(&reviews[0].token);

        assert_eq!(app.pending_import_reviews.lock().unwrap().len(), 8);
        assert!(
            !app.pending_import_reviews
                .lock()
                .unwrap()
                .contains_key(&reviews[0].token)
        );
        assert!(!first_staging.exists());
        assert!(!first_snapshot.unwrap().exists());
        assert!(
            app.import_reviewed_archive(&reviews[0].token, confirmed(&reviews[0]))
                .is_err()
        );
    }

    #[test]
    fn import_confirmation_rejects_unknown_fields_and_review_uses_camel_case() {
        assert!(
            serde_json::from_value::<ImportArchiveConfirmationView>(serde_json::json!({
                "reviewSha256": "a".repeat(64),
                "executablePayloadsAcknowledged": false,
                "extra": true
            }))
            .is_err()
        );
        let temporary = TempDir::new().unwrap();
        let app = import_test_app(&temporary);
        let archive = temporary.path().join("Contract.zip");
        let pak_bytes = test_pak_bytes(b"pak");
        write_test_zip(&archive, &[("Contract_P.pak", &pak_bytes)]);
        let preflight = app.preflight_archive(&archive).unwrap();
        let review = app.review_archive(&preflight.token).unwrap();
        let json = serde_json::to_value(review).unwrap();
        assert!(json.get("reviewSha256").is_some());
        assert!(json.get("archiveSha256").is_some());
        assert!(json.get("activationSupported").is_some());
        assert!(json.get("executableAcknowledgementRequired").is_some());
        assert!(json.get("review_sha256").is_none());
    }

    #[test]
    fn empty_state_creates_a_safe_default_profile() {
        let temporary = TempDir::new().unwrap();
        let app = DesktopApplication::new(
            DesktopPaths::under(temporary.path().join("state")),
            temporary.path().join("missing-worker"),
            temporary.path().join("missing-pak-worker"),
        )
        .unwrap();
        app.ensure_default_profile().unwrap();
        let snapshot = app.snapshot().unwrap();
        assert!(!snapshot.game.detected);
        assert_eq!(snapshot.profiles.len(), 1);
        assert_eq!(snapshot.profiles[0].id, "default");
        assert!(snapshot.artifacts.is_empty());
    }

    #[test]
    fn selects_and_persists_a_user_chosen_game_folder() {
        let temporary = TempDir::new().unwrap();
        let library = temporary.path().join("SteamLibrary");
        let steamapps = library.join("steamapps");
        let game = steamapps.join("common/RetroRewind");
        fs::create_dir_all(&game).unwrap();
        fs::write(
            steamapps.join("appmanifest_3552140.acf"),
            format!(
                "\"AppState\"\n{{\n\"appid\" \"3552140\"\n\"buildid\" \"{}\"\n\"StateFlags\" \"4\"\n\"installdir\" \"RetroRewind\"\n}}",
                SUPPORTED_BUILD_ID
            ),
        )
        .unwrap();
        let app = DesktopApplication::new(
            DesktopPaths::under(temporary.path().join("state")),
            temporary.path().join("missing-worker"),
            temporary.path().join("missing-pak-worker"),
        )
        .unwrap();
        app.ensure_default_profile().unwrap();

        let snapshot = app.select_game_folder(&game).unwrap();

        assert_eq!(snapshot.game.root_path, Some(game.display().to_string()));
        assert_eq!(
            app.store()
                .unwrap()
                .setting(SELECTED_GAME_ROOT_KEY)
                .unwrap(),
            Some(serde_json::Value::String(game.display().to_string()))
        );
        assert_eq!(
            app.store()
                .unwrap()
                .installation_binding(INSTALLATION_ID)
                .unwrap(),
            Some((steamapps.join("appmanifest_3552140.acf"), game))
        );
    }

    #[cfg(unix)]
    #[test]
    fn accepts_canonical_aliases_for_an_existing_installation_binding() {
        use std::os::unix::fs::symlink;

        let temporary = TempDir::new().unwrap();
        let real = temporary.path().join("real");
        let alias = temporary.path().join("alias");
        let game = real.join("steamapps/common/RetroRewind");
        let manifest = real.join("steamapps/appmanifest_3552140.acf");
        fs::create_dir_all(&game).unwrap();
        fs::write(&manifest, b"manifest").unwrap();
        symlink(&real, &alias).unwrap();
        let aliased_game = alias.join("steamapps/common/RetroRewind");
        let aliased_manifest = alias.join("steamapps/appmanifest_3552140.acf");
        assert!(paths_refer_to_same_entry(&game, &aliased_game));
        assert!(paths_refer_to_same_entry(&manifest, &aliased_manifest));

        let store = Store::open(&temporary.path().join("rrmm.sqlite3")).unwrap();
        store
            .bind_installation_id(INSTALLATION_ID, &manifest, &game)
            .unwrap();
        ensure_desktop_installation_binding(
            &store,
            INSTALLATION_ID,
            &aliased_manifest,
            &aliased_game,
        )
        .unwrap();
    }

    #[test]
    fn bug_report_export_preserves_the_frozen_preview_after_a_failed_destination() {
        let temporary = TempDir::new().unwrap();
        let app = DesktopApplication::new(
            DesktopPaths::under(temporary.path().join("state")),
            temporary.path().join("missing-worker"),
            temporary.path().join("missing-pak-worker"),
        )
        .unwrap();
        let marker = app.mark_game_incident().unwrap();
        assert!(chrono::DateTime::parse_from_rfc3339(&marker.recorded_at).is_ok());
        let preview = app
            .preview_bug_report(BugReportRequestView {
                subject_kind: crate::BugReportSubjectKind::Mod,
                affected_mod: "Example Mod".to_owned(),
                problem_summary: "Example failure".to_owned(),
                steps_to_reproduce: "Launch".to_owned(),
                expected_behavior: "Runs".to_owned(),
                observed_behavior: "Stops".to_owned(),
                reproducibility: "Always".to_owned(),
                occurred_at: Some(marker.recorded_at.clone()),
                include_active_mods: false,
                include_full_ue4ss_log: false,
            })
            .unwrap();
        assert_eq!(preview.files.len(), 3);
        assert!(preview.files[1].content.contains(&marker.id));
        assert!(preview.files[1].content.contains("managerState"));
        assert!(preview.files[1].content.contains("managedFileCount"));
        assert!(!preview.files[1].content.contains("/state"));
        assert_eq!(preview.files[2].name, "rrmm-operations.json");
        assert!(preview.files[2].content.contains("maximumEntries"));

        let unsafe_destination = temporary.path().join("directory.zip");
        fs::create_dir(&unsafe_destination).unwrap();
        assert!(
            app.export_bug_report(&preview.token, &unsafe_destination)
                .is_err()
        );

        let destination = temporary.path().join("report.zip");
        app.export_bug_report(&preview.token, &destination).unwrap();
        let mut archive = zip::ZipArchive::new(fs::File::open(destination).unwrap()).unwrap();
        for expected in &preview.files {
            let mut content = String::new();
            archive
                .by_name(&expected.name)
                .unwrap()
                .read_to_string(&mut content)
                .unwrap();
            assert_eq!(content, expected.content);
        }
        assert!(
            app.export_bug_report(&preview.token, temporary.path())
                .is_err()
        );
    }

    #[test]
    fn profile_updates_require_an_imported_artifact() {
        let temporary = TempDir::new().unwrap();
        let app = DesktopApplication::new(
            DesktopPaths::under(temporary.path().join("state")),
            temporary.path().join("missing-worker"),
            temporary.path().join("missing-pak-worker"),
        )
        .unwrap();
        app.ensure_default_profile().unwrap();
        let error = app
            .update_profile_package("default", &"a".repeat(64), true)
            .unwrap_err();
        assert!(error.to_string().contains("no longer installed"));
    }

    #[test]
    fn authored_catalog_marks_packages_without_embedded_manifests_as_reviewed_inferences() {
        let catalog = authored_package_catalog().unwrap();

        assert!(!catalog.is_empty());
        assert!(
            catalog
                .iter()
                .all(|package| package.manifest.id != "local:smart-shelf-organizer")
        );
        assert!(
            catalog
                .iter()
                .all(|package| !package.manifest.version.contains("-dev"))
        );
        assert!(catalog.iter().all(|package| matches!(
            &package.provenance,
            ManifestProvenance::Inferred { reviewed: true, .. }
        )));
    }

    #[test]
    fn enables_an_imported_manifest_free_pak_through_the_effective_catalog() {
        let temporary = TempDir::new().unwrap();
        let paths = DesktopPaths::under(temporary.path().join("state"));
        let app = DesktopApplication::new(
            paths.clone(),
            temporary.path().join("missing-worker"),
            temporary.path().join("missing-pak-worker"),
        )
        .unwrap();
        app.ensure_default_profile().unwrap();
        let sha256 = "a".repeat(64);
        let artifact = ArtifactManifest {
            schema_version: 1,
            sha256: sha256.clone(),
            format: rrmm_archive::ArchiveFormat::Zip,
            archive_bytes: 8,
            expanded_bytes: 8,
            files: vec![rrmm_archive::ExtractedFileReport {
                path: "ChronologicalNewReleases_P.pak".to_owned(),
                bytes: 8,
                sha256: "b".repeat(64),
                executable_payload: false,
                native_binary: false,
            }],
            layout: rrmm_archive::PackageLayoutInference {
                kind: PackageKind::PakOnly,
                pak_files: vec!["ChronologicalNewReleases_P.pak".to_owned()],
                ue4ss_mod_roots: Vec::new(),
                documentation_files: Vec::new(),
                executable_files: Vec::new(),
                requires_review: false,
                issues: Vec::new(),
            },
        };
        let root = paths.artifact_store.join("artifacts/aa").join(&sha256);
        fs::create_dir_all(&root).unwrap();
        app.store()
            .unwrap()
            .upsert_artifact(&sha256, &root, &serde_json::to_value(&artifact).unwrap())
            .unwrap();

        let profile = app
            .update_profile_package("default", &sha256, true)
            .unwrap();
        let snapshot = app.snapshot().unwrap();

        assert!(profile.packages[0].enabled);
        assert!(snapshot.artifacts[0].activation_supported);
        assert!(!snapshot.artifacts[0].verified);
        assert_eq!(snapshot.artifacts[0].name, "Chronological New Releases");
    }

    #[test]
    fn infers_a_manifest_free_pak_and_signature_as_an_activatable_local_mod() {
        let artifact = ArtifactManifest {
            schema_version: 1,
            sha256: "a".repeat(64),
            format: rrmm_archive::ArchiveFormat::Zip,
            archive_bytes: 12,
            expanded_bytes: 12,
            files: vec![
                rrmm_archive::ExtractedFileReport {
                    path: "Download/My_Cool_Mod_P.pak".to_owned(),
                    bytes: 8,
                    sha256: "b".repeat(64),
                    executable_payload: false,
                    native_binary: false,
                },
                rrmm_archive::ExtractedFileReport {
                    path: "Download/My_Cool_Mod_P.sig".to_owned(),
                    bytes: 4,
                    sha256: "c".repeat(64),
                    executable_payload: false,
                    native_binary: false,
                },
            ],
            layout: rrmm_archive::PackageLayoutInference {
                kind: PackageKind::PakOnly,
                pak_files: vec!["Download/My_Cool_Mod_P.pak".to_owned()],
                ue4ss_mod_roots: Vec::new(),
                documentation_files: Vec::new(),
                executable_files: Vec::new(),
                requires_review: false,
                issues: Vec::new(),
            },
        };

        let package = inferred_local_package(&artifact).unwrap();

        assert_eq!(package.manifest.name, "My Cool Mod");
        assert_eq!(package.manifest.components.len(), 1);
        assert!(matches!(
            package.provenance,
            ManifestProvenance::Inferred { reviewed: true, .. }
        ));
    }

    #[test]
    fn artifact_revisions_require_the_same_complete_destination_set() {
        let pak_artifact = |sha256: &str, pak: &str| ArtifactManifest {
            schema_version: 1,
            sha256: sha256.repeat(64),
            format: rrmm_archive::ArchiveFormat::Zip,
            archive_bytes: 8,
            expanded_bytes: 8,
            files: vec![rrmm_archive::ExtractedFileReport {
                path: pak.to_owned(),
                bytes: 8,
                sha256: sha256.repeat(64),
                executable_payload: false,
                native_binary: false,
            }],
            layout: rrmm_archive::PackageLayoutInference {
                kind: PackageKind::PakOnly,
                pak_files: vec![pak.to_owned()],
                ue4ss_mod_roots: Vec::new(),
                documentation_files: Vec::new(),
                executable_files: Vec::new(),
                requires_review: false,
                issues: Vec::new(),
            },
        };
        let first = pak_artifact("a", "Downloads/SameMod_P.pak");
        let second = pak_artifact("b", "SameMod_P.pak");
        let unrelated = pak_artifact("c", "OtherMod_P.pak");
        let authored = Vec::new();

        assert!(artifact_revisions_match(&first, &second, &authored));
        assert!(!artifact_revisions_match(&first, &unrelated, &authored));

        let mut partial_overlap = second.clone();
        partial_overlap.layout.kind = PackageKind::Hybrid;
        partial_overlap
            .layout
            .ue4ss_mod_roots
            .push("SameMod".to_owned());
        partial_overlap.files.extend([
            rrmm_archive::ExtractedFileReport {
                path: "SameMod/Scripts/main.lua".to_owned(),
                bytes: 8,
                sha256: "d".repeat(64),
                executable_payload: false,
                native_binary: false,
            },
            rrmm_archive::ExtractedFileReport {
                path: "SameMod/enabled.txt".to_owned(),
                bytes: 0,
                sha256: "e".repeat(64),
                executable_payload: false,
                native_binary: false,
            },
        ]);
        assert!(!artifact_revisions_match(
            &first,
            &partial_overlap,
            &authored
        ));
    }

    #[test]
    fn profile_revision_replacement_merges_duplicates_and_preserves_enabled_state() {
        let old = ["a".repeat(64), "b".repeat(64)]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let replacement = "c".repeat(64);
        let mut profile = DomainProfile {
            schema_version: 1,
            id: "default".to_owned(),
            name: "Default".to_owned(),
            revision: 2,
            packages: vec![
                ProfilePackageSelection {
                    artifact_sha256: "a".repeat(64),
                    variant: None,
                    enabled: false,
                },
                ProfilePackageSelection {
                    artifact_sha256: replacement.clone(),
                    variant: None,
                    enabled: false,
                },
                ProfilePackageSelection {
                    artifact_sha256: "b".repeat(64),
                    variant: None,
                    enabled: true,
                },
            ],
            pak_load_order: Vec::new(),
        };

        replace_profile_artifact_revisions(&mut profile, &old, &replacement, None);

        assert_eq!(profile.packages.len(), 1);
        assert_eq!(profile.packages[0].artifact_sha256, replacement);
        assert!(profile.packages[0].enabled);
    }

    #[test]
    fn consolidates_inactive_existing_revisions_to_the_latest_confirmed_import() {
        let temporary = TempDir::new().unwrap();
        let paths = DesktopPaths::under(temporary.path().join("state"));
        let app = DesktopApplication::new(
            paths.clone(),
            temporary.path().join("missing-worker"),
            temporary.path().join("missing-pak-worker"),
        )
        .unwrap();
        app.ensure_default_profile().unwrap();
        let manifest = |sha256: &str, file_sha256: &str| ArtifactManifest {
            schema_version: 1,
            sha256: sha256.to_owned(),
            format: rrmm_archive::ArchiveFormat::Zip,
            archive_bytes: 8,
            expanded_bytes: 8,
            files: vec![rrmm_archive::ExtractedFileReport {
                path: "SameMod_P.pak".to_owned(),
                bytes: 8,
                sha256: file_sha256.to_owned(),
                executable_payload: false,
                native_binary: false,
            }],
            layout: rrmm_archive::PackageLayoutInference {
                kind: PackageKind::PakOnly,
                pak_files: vec!["SameMod_P.pak".to_owned()],
                ue4ss_mod_roots: Vec::new(),
                documentation_files: Vec::new(),
                executable_files: Vec::new(),
                requires_review: false,
                issues: Vec::new(),
            },
        };
        let old_sha256 = "a".repeat(64);
        let new_sha256 = "b".repeat(64);
        let old_root = paths.artifact_store.join("artifacts/aa").join(&old_sha256);
        let new_root = paths.artifact_store.join("artifacts/bb").join(&new_sha256);
        fs::create_dir_all(&old_root).unwrap();
        fs::create_dir_all(&new_root).unwrap();
        let mut store = app.store().unwrap();
        store
            .replace_artifacts_and_update_profiles(
                &[
                    StoredArtifact {
                        sha256: old_sha256.clone(),
                        root: old_root.clone(),
                        manifest: serde_json::to_value(manifest(&old_sha256, &"c".repeat(64)))
                            .unwrap(),
                        accepted_at: 10,
                    },
                    StoredArtifact {
                        sha256: new_sha256.clone(),
                        root: new_root,
                        manifest: serde_json::to_value(manifest(&new_sha256, &"d".repeat(64)))
                            .unwrap(),
                        accepted_at: 20,
                    },
                ],
                &[],
                &[],
            )
            .unwrap();
        drop(store);
        app.update_profile_package("default", &old_sha256, false)
            .unwrap();

        app.consolidate_inactive_artifact_revisions().unwrap();

        let store = app.store().unwrap();
        let artifacts = store.artifacts().unwrap();
        let profile = store.profile("default").unwrap().unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].sha256, new_sha256);
        assert_eq!(profile.packages.len(), 1);
        assert_eq!(profile.packages[0].artifact_sha256, new_sha256);
        assert!(!profile.packages[0].enabled);
        assert!(!old_root.exists());
    }

    #[test]
    fn missing_optional_manifest_is_not_an_archive_warning() {
        let report = ArchivePreflightReport {
            accepted: true,
            format: rrmm_archive::ArchiveFormat::Zip,
            archive_path: PathBuf::from("Example.zip"),
            archive_sha256: Some("a".repeat(64)),
            archive_bytes: 8,
            expanded_bytes: 8,
            entry_count: 1,
            entries: vec![rrmm_archive::ArchiveEntryReport {
                path: "Example_P.pak".to_owned(),
                expanded_bytes: 8,
                compressed_bytes: 8,
                directory: false,
                executable_payload: false,
            }],
            rejections: Vec::new(),
        };

        let view = archive_preflight_view(
            "review".to_owned(),
            &report,
            &report.archive_path,
            None,
            Vec::new(),
            false,
        );

        assert!(!view.manifest_found);
        assert!(view.accepted);
        assert!(view.warnings.is_empty());
        assert!(view.blocked_reasons.is_empty());
    }

    #[test]
    fn reports_actual_required_and_available_space_instead_of_a_size_cap() {
        let temporary = TempDir::new().unwrap();
        let paths = DesktopPaths::under(temporary.path().join("state"));
        fs::create_dir_all(&paths.data_root).unwrap();
        let report = ArchivePreflightReport {
            accepted: true,
            format: rrmm_archive::ArchiveFormat::Zip,
            archive_path: PathBuf::from("Large-Mod.zip"),
            archive_sha256: Some("a".repeat(64)),
            archive_bytes: 1 << 40,
            expanded_bytes: 1 << 50,
            entry_count: 1,
            entries: Vec::new(),
            rejections: Vec::new(),
        };

        let error = ensure_import_disk_space(&paths, &report, &"a".repeat(64)).unwrap_err();

        assert!(error.to_string().contains("import requires"));
        assert!(error.to_string().contains("bytes are available"));
    }

    #[test]
    fn local_inference_keeps_native_and_incomplete_ue4ss_packages_blocked() {
        let native = ArtifactManifest {
            schema_version: 1,
            sha256: "a".repeat(64),
            format: rrmm_archive::ArchiveFormat::Zip,
            archive_bytes: 1,
            expanded_bytes: 1,
            files: vec![rrmm_archive::ExtractedFileReport {
                path: "Mod/Scripts/main.lua".to_owned(),
                bytes: 1,
                sha256: "b".repeat(64),
                executable_payload: false,
                native_binary: false,
            }],
            layout: rrmm_archive::PackageLayoutInference {
                kind: PackageKind::Ue4ssOnly,
                pak_files: Vec::new(),
                ue4ss_mod_roots: vec!["Mod".to_owned()],
                documentation_files: Vec::new(),
                executable_files: Vec::new(),
                requires_review: false,
                issues: Vec::new(),
            },
        };
        assert!(inferred_local_package(&native).is_none());

        let mut native = native;
        native.files.push(rrmm_archive::ExtractedFileReport {
            path: "Mod/enabled.txt".to_owned(),
            bytes: 0,
            sha256: "c".repeat(64),
            executable_payload: false,
            native_binary: false,
        });
        native.files.push(rrmm_archive::ExtractedFileReport {
            path: "Mod/dlls/main.dll".to_owned(),
            bytes: 1,
            sha256: "d".repeat(64),
            executable_payload: true,
            native_binary: true,
        });
        native.expanded_bytes = 2;
        native.layout.executable_files = vec!["Mod/dlls/main.dll".to_owned()];
        assert!(inferred_local_package(&native).is_none());
    }

    #[test]
    fn infers_a_manifest_free_hybrid_pak_and_lua_package() {
        let files = [
            ("BetterMovieDatabase_P.pak", 8, "b"),
            ("BetterMovieDatabase/Scripts/main.lua", 10, "c"),
            ("BetterMovieDatabase/enabled.txt", 0, "d"),
            ("README.md", 4, "e"),
        ]
        .into_iter()
        .map(|(path, bytes, hash)| rrmm_archive::ExtractedFileReport {
            path: path.to_owned(),
            bytes,
            sha256: hash.repeat(64),
            executable_payload: false,
            native_binary: false,
        })
        .collect();
        let artifact = ArtifactManifest {
            schema_version: 1,
            sha256: "a".repeat(64),
            format: rrmm_archive::ArchiveFormat::Zip,
            archive_bytes: 22,
            expanded_bytes: 22,
            files,
            layout: rrmm_archive::PackageLayoutInference {
                kind: PackageKind::Hybrid,
                pak_files: vec!["BetterMovieDatabase_P.pak".to_owned()],
                ue4ss_mod_roots: vec!["BetterMovieDatabase".to_owned()],
                documentation_files: vec!["README.md".to_owned()],
                executable_files: Vec::new(),
                requires_review: false,
                issues: Vec::new(),
            },
        };

        let package = inferred_local_package(&artifact).unwrap();

        assert_eq!(package.manifest.name, "Better Movie Database");
        assert_eq!(package.manifest.components.len(), 2);
        assert_eq!(
            package
                .manifest
                .runtime_requirements
                .ue4ss_loader_policy
                .as_deref(),
            Some(LOCAL_UE4SS_POLICY_ID)
        );
    }

    #[test]
    fn deletes_a_disabled_undeployed_managed_artifact() {
        let temporary = TempDir::new().unwrap();
        let paths = DesktopPaths::under(temporary.path().join("state"));
        let app = DesktopApplication::new(
            paths.clone(),
            temporary.path().join("missing-worker"),
            temporary.path().join("missing-pak-worker"),
        )
        .unwrap();
        app.ensure_default_profile().unwrap();
        let sha256 = "a".repeat(64);
        let artifact_root = paths.artifact_store.join("artifacts/aa").join(&sha256);
        fs::create_dir_all(&artifact_root).unwrap();
        let manifest = serde_json::json!({
            "schema_version": 1,
            "sha256": sha256,
            "format": "zip",
            "archive_bytes": 0,
            "expanded_bytes": 0,
            "files": [],
            "layout": {
                "kind": "pak_only",
                "pak_files": [],
                "ue4ss_mod_roots": [],
                "documentation_files": [],
                "executable_files": [],
                "requires_review": false,
                "issues": []
            }
        });
        app.store()
            .unwrap()
            .upsert_artifact(&sha256, &artifact_root, &manifest)
            .unwrap();

        app.delete_artifact(&sha256).unwrap();

        assert!(!artifact_root.exists());
        assert!(app.store().unwrap().artifact(&sha256).unwrap().is_none());
    }

    #[test]
    fn bulk_delete_prepares_profiles_before_removing_an_undeployed_artifact() {
        let temporary = TempDir::new().unwrap();
        let paths = DesktopPaths::under(temporary.path().join("state"));
        let app = DesktopApplication::new(
            paths.clone(),
            temporary.path().join("missing-worker"),
            temporary.path().join("missing-pak-worker"),
        )
        .unwrap();
        app.ensure_default_profile().unwrap();
        let sha256 = "b".repeat(64);
        let artifact_root = paths.artifact_store.join("artifacts/bb").join(&sha256);
        fs::create_dir_all(&artifact_root).unwrap();
        let manifest = serde_json::json!({
            "schema_version": 1,
            "sha256": sha256,
            "format": "zip",
            "archive_bytes": 0,
            "expanded_bytes": 0,
            "files": [],
            "layout": {
                "kind": "pak_only",
                "pak_files": [],
                "ue4ss_mod_roots": [],
                "documentation_files": [],
                "executable_files": [],
                "requires_review": false,
                "issues": []
            }
        });
        let store = app.store().unwrap();
        store
            .upsert_artifact(&sha256, &artifact_root, &manifest)
            .unwrap();
        let mut profile = store.profiles().unwrap().remove(0);
        profile.packages.push(ProfilePackageSelection {
            artifact_sha256: sha256.clone(),
            variant: None,
            enabled: true,
        });
        let revision = profile.revision;
        store.update_profile(&profile, revision).unwrap();

        let preview = app
            .preview_bulk_delete(&[], std::slice::from_ref(&sha256))
            .unwrap();
        assert!(!preview.blocked, "{:?}", preview.blockers);
        assert_eq!(preview.affected_profiles.len(), 1);
        let result = app.apply_bulk_delete(&preview.token).unwrap();

        assert_eq!(result.status, "completed");
        assert_eq!(result.managed_artifact_sha256, vec![sha256.clone()]);
        assert!(!artifact_root.exists());
        assert!(app.store().unwrap().artifact(&sha256).unwrap().is_none());
        assert!(
            app.store().unwrap().profiles().unwrap()[0]
                .packages
                .is_empty()
        );
    }

    #[test]
    fn inventories_all_external_paks_recursively_but_excludes_vanilla() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("RetroRewind");
        let paks = game.join("RetroRewind/Content/Paks");
        fs::create_dir_all(paks.join("~mods/nested")).unwrap();
        fs::create_dir_all(paks.join("~mods-disabled-test")).unwrap();
        fs::write(paks.join("RetroRewind-Windows.pak"), b"vanilla").unwrap();
        fs::write(paks.join("DirectMod_P.pak"), b"direct").unwrap();
        fs::write(paks.join("~mods/nested/ActiveMod_P.pak"), b"active").unwrap();
        fs::write(
            paks.join("~mods-disabled-test/DisabledMod_P.pak"),
            b"disabled",
        )
        .unwrap();

        let views = unmanaged_pak_views(&game, None).unwrap();
        let paths: Vec<_> = views.iter().map(|view| view.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "RetroRewind/Content/Paks/DirectMod_P.pak",
                "RetroRewind/Content/Paks/~mods-disabled-test/DisabledMod_P.pak",
                "RetroRewind/Content/Paks/~mods/nested/ActiveMod_P.pak",
            ]
        );
        assert!(views.iter().all(|view| view.pak_sha256.len() == 64));
    }

    #[test]
    fn activation_pak_inputs_use_materialized_sources_and_effective_install_names() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let state = temporary.path().join("state");
        let source = temporary.path().join("artifact/Plain.pak");
        let external = game.join("RetroRewind/Content/Paks/~mods/External_P.pak");
        let replaced = game.join("RetroRewind/Content/Paks/zzzzzzzz_Managed_9999_P.pak");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::create_dir_all(external.parent().unwrap()).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(&source, b"managed").unwrap();
        fs::write(&external, b"external").unwrap();
        fs::write(&replaced, b"replaced").unwrap();
        let replaced_sha256 = rrmm_archive::sha256_path(&replaced).unwrap();
        let plan = DeploymentPlan {
            schema_version: 2,
            transaction_id: "test".to_owned(),
            installation_id: "installation".to_owned(),
            profile_id: "profile".to_owned(),
            game_root: game.clone(),
            state_root: state,
            files: vec![rrmm_deploy::DeploymentFile {
                source: source.clone(),
                relative_path: "RetroRewind/Content/Paks/zzzzzzzz_Managed_9999_P.pak".to_owned(),
                bytes: 7,
                sha256: "a".repeat(64),
                package_id: Some("managed-test".to_owned()),
                package_name: Some("Managed test".to_owned()),
            }],
            external_files: Vec::new(),
            external_moves: Vec::new(),
            allow_unmanaged: true,
            managed_file_restore_approvals: Vec::new(),
            changes: Vec::new(),
            blockers: Vec::new(),
            previous_receipt: None,
            target_receipt: DeploymentReceipt {
                schema_version: 1,
                profile_id: "profile".to_owned(),
                game_root: game.clone(),
                files: Vec::new(),
                external_files: Vec::new(),
            },
        };
        let external_sha256 = rrmm_archive::sha256_path(&external).unwrap();
        let inputs = activation_pak_inputs(
            &plan,
            &[
                UnmanagedFileView {
                    path: "RetroRewind/Content/Paks/~mods/External_P.pak".to_owned(),
                    size_bytes: 8,
                    pak_sha256: external_sha256,
                    original_path: "RetroRewind/Content/Paks/~mods/External_P.pak".to_owned(),
                    existing_mod_id: Some("existing-test".to_owned()),
                    display_name: Some("External".to_owned()),
                    manageable: true,
                    active_paths: BTreeMap::new(),
                },
                UnmanagedFileView {
                    path: "RetroRewind/Content/Paks/zzzzzzzz_Managed_9999_P.pak".to_owned(),
                    size_bytes: 8,
                    pak_sha256: replaced_sha256,
                    original_path: "RetroRewind/Content/Paks/zzzzzzzz_Managed_9999_P.pak"
                        .to_owned(),
                    existing_mod_id: Some("replaced-test".to_owned()),
                    display_name: Some("Replaced".to_owned()),
                    manageable: true,
                    active_paths: BTreeMap::new(),
                },
            ],
            temporary.path(),
            &[],
        )
        .unwrap();

        assert_eq!(inputs.len(), 2);
        assert!(
            inputs
                .iter()
                .all(|input| input.owner.display_name != "Replaced")
        );
        let managed = inputs
            .iter()
            .find(|input| input.display_path.contains("Managed"))
            .unwrap();
        assert_eq!(managed.read_path, fs::canonicalize(source).unwrap());
        assert_eq!(
            managed.effective_path.file_name().unwrap(),
            "zzzzzzzz_Managed_9999_P.pak"
        );
        assert_eq!(
            parse_priority_hint(
                managed
                    .effective_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .as_ref()
            )
            .explicit_number,
            Some(9999)
        );
    }

    #[test]
    fn activation_preview_omits_files_that_are_already_unchanged() {
        let plan = DeploymentPlan {
            schema_version: 2,
            transaction_id: "test".to_owned(),
            installation_id: "installation".to_owned(),
            profile_id: "profile".to_owned(),
            game_root: PathBuf::from("/game"),
            state_root: PathBuf::from("/state"),
            files: Vec::new(),
            external_files: Vec::new(),
            external_moves: Vec::new(),
            allow_unmanaged: false,
            managed_file_restore_approvals: Vec::new(),
            changes: vec![rrmm_deploy::DeploymentChange {
                relative_path: "RetroRewind/Content/Paks/Already_P.pak".to_owned(),
                kind: DeploymentChangeKind::UnchangedManaged,
                previous_sha256: Some("a".repeat(64)),
                next_sha256: Some("a".repeat(64)),
                owner_id: Some("managed-test".to_owned()),
                owner_name: Some("Managed test".to_owned()),
            }],
            blockers: Vec::new(),
            previous_receipt: None,
            target_receipt: DeploymentReceipt {
                schema_version: 1,
                profile_id: "profile".to_owned(),
                game_root: PathBuf::from("/game"),
                files: Vec::new(),
                external_files: Vec::new(),
            },
        };

        let recipes = RecipePreviewView {
            available: true,
            applied_recipe_ids: Vec::new(),
            effects: Vec::new(),
            notice: None,
        };
        let preview =
            activation_preview_view("Profile", &plan, &[], 0, &[], &recipes, &BTreeSet::new());
        assert!(preview.changes.is_empty());
        assert!(!preview.blocked);
        assert!(preview.requires_apply);

        let mut synchronized = plan.clone();
        synchronized.previous_receipt = Some(synchronized.target_receipt.clone());
        let preview = activation_preview_view(
            "Profile",
            &synchronized,
            &[],
            0,
            &[],
            &recipes,
            &BTreeSet::new(),
        );
        assert!(!preview.requires_apply);
    }

    #[test]
    fn prepared_preview_detects_same_size_file_replacement() {
        let temporary = TempDir::new().unwrap();
        let watched = temporary.path().join("watched.pak");
        fs::write(&watched, b"first").unwrap();
        let snapshot = capture_file_snapshot(&watched).unwrap();
        assert!(validate_file_snapshots(std::slice::from_ref(&snapshot)).is_ok());

        let replacement = temporary.path().join("replacement.pak");
        fs::write(&replacement, b"other").unwrap();
        fs::rename(&replacement, &watched).unwrap();

        assert!(validate_file_snapshots(&[snapshot]).is_err());
    }

    #[test]
    fn selecting_an_artifact_disables_other_editions_with_the_same_package_id() {
        let mut catalog = package_catalog().unwrap();
        let first = catalog[0].clone();
        let mut second = first.clone();
        second.artifact_sha256 = "f".repeat(64);
        catalog = vec![first.clone(), second.clone()];
        let mut profile = DomainProfile {
            schema_version: 1,
            id: "profile".to_owned(),
            name: "Profile".to_owned(),
            revision: 0,
            packages: vec![
                ProfilePackageSelection {
                    artifact_sha256: first.artifact_sha256.clone(),
                    variant: None,
                    enabled: true,
                },
                ProfilePackageSelection {
                    artifact_sha256: second.artifact_sha256.clone(),
                    variant: None,
                    enabled: false,
                },
            ],
            pak_load_order: Vec::new(),
        };

        update_profile_selection(&mut profile, &second.artifact_sha256, true, &catalog);

        assert!(!profile.packages[0].enabled);
        assert!(profile.packages[1].enabled);
    }

    #[test]
    fn ue4ss_loader_descriptor_is_pinned_to_the_supported_build() {
        let artifact = ue4ss_loader_artifact().unwrap();
        assert_eq!(artifact.build_id, SUPPORTED_BUILD_ID);
        assert_eq!(artifact.loader_build_id, TARGET_UE4SS_BUILD_ID);
        assert_eq!(
            artifact.url,
            "https://github.com/UE4SS-RE/RE-UE4SS/releases/download/experimental/UE4SS_v3.0.1-1018-g662df915.zip"
        );
        assert_eq!(
            artifact.archive_sha256,
            "590ae4c6463db61497123b9ed35373596c39fb27f736e2078a02b476599671ba"
        );
    }

    #[test]
    fn ue4ss_loader_health_blocks_known_unsafe_builds() {
        let recipe = build_recipe().unwrap();
        assert_eq!(
            ue4ss_loader_health(
                Ue4ssLoaderIdentityStatus::Exact,
                Some(TARGET_UE4SS_BUILD_ID),
                &recipe,
            ),
            HealthLevel::Ready
        );
        assert_eq!(
            ue4ss_loader_health(
                Ue4ssLoaderIdentityStatus::Exact,
                Some("ue4ss-0196ef294f8525d6a492ae0b41b0c18ad5ccd84b"),
                &recipe,
            ),
            HealthLevel::Blocked
        );
        assert_eq!(
            ue4ss_loader_health(
                Ue4ssLoaderIdentityStatus::Exact,
                Some("ue4ss-v3.0.1-stable"),
                &recipe,
            ),
            HealthLevel::Attention
        );
    }

    #[test]
    fn offline_mode_blocks_a_cache_miss_before_network_access() {
        let temporary = TempDir::new().unwrap();
        let app = DesktopApplication::new(
            DesktopPaths::under(temporary.path().join("state")),
            temporary.path().join("missing-worker"),
            temporary.path().join("missing-pak-worker"),
        )
        .unwrap();
        app.set_offline_mode(true).unwrap();

        let error = app
            .download_ue4ss_archive(&ue4ss_loader_artifact().unwrap())
            .unwrap_err();

        assert!(error.to_string().contains("offline mode is enabled"));
    }

    #[test]
    fn ue4ss_download_stream_writes_each_received_byte_once() {
        let input = (0..(64 * 1024 + 137))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let expected_sha256 = format!("{:x}", Sha256::digest(&input));
        let mut output = Vec::new();

        let bytes = copy_verified_ue4ss_download(
            std::io::Cursor::new(&input),
            &mut output,
            input.len() as u64,
            &expected_sha256,
        )
        .unwrap();

        assert_eq!(bytes, input.len() as u64);
        assert_eq!(output, input);
    }

    #[test]
    fn ue4ss_download_stream_rejects_size_and_hash_mismatches() {
        let input = b"verified UE4SS archive bytes";
        let expected_sha256 = format!("{:x}", Sha256::digest(input));

        let oversized = copy_verified_ue4ss_download(
            std::io::Cursor::new(input),
            Vec::new(),
            input.len() as u64 - 1,
            &expected_sha256,
        )
        .unwrap_err();
        assert!(oversized.to_string().contains("exceeded"));

        let bad_hash = copy_verified_ue4ss_download(
            std::io::Cursor::new(input),
            Vec::new(),
            input.len() as u64,
            &"0".repeat(64),
        )
        .unwrap_err();
        assert!(bad_hash.to_string().contains("SHA-256"));
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires the real Windows archive worker and pinned UE4SS archive"]
    fn windows_real_worker_completes_the_full_ue4ss_installation() {
        let worker = PathBuf::from(
            std::env::var_os("RRMM_WINDOWS_ARCHIVE_WORKER")
                .expect("RRMM_WINDOWS_ARCHIVE_WORKER must point to the real Windows worker"),
        );
        let archive = PathBuf::from(
            std::env::var_os("RRMM_WINDOWS_UE4SS_ARCHIVE")
                .expect("RRMM_WINDOWS_UE4SS_ARCHIVE must point to the pinned UE4SS ZIP"),
        );
        assert!(worker.is_file(), "missing worker: {}", worker.display());
        assert!(archive.is_file(), "missing archive: {}", archive.display());

        let temporary = TempDir::new().unwrap();
        let app = import_test_app_with_workers(
            &temporary,
            worker,
            temporary.path().join("unused-pak-worker.exe"),
        );
        let game_root = temporary.path().join("steam/steamapps/common/Retro Rewind");
        let nested = game_root.join("RetroRewind/Binaries/Win64/ue4ss");
        let settings = nested.join("UE4SS-settings.ini");
        let existing_module = nested.join("Mods/ExistingMod/Scripts/main.lua");
        fs::create_dir_all(existing_module.parent().unwrap()).unwrap();
        fs::write(&settings, b"preserve these settings").unwrap();
        fs::write(&existing_module, b"print('preserve this module')").unwrap();

        let descriptor = ue4ss_loader_artifact().unwrap();
        let cache = app.paths().data_root.join("downloads");
        fs::create_dir_all(&cache).unwrap();
        fs::copy(&archive, cache.join(&descriptor.filename)).unwrap();

        let installed = app.install_or_repair_ue4ss().unwrap();
        assert_eq!(installed.health, HealthLevel::Ready);
        assert_eq!(installed.version.as_deref(), Some(TARGET_UE4SS_BUILD_ID));
        assert!(!installed.mixed_installation);
        assert_eq!(
            rrmm_archive::sha256_path(&game_root.join("RetroRewind/Binaries/Win64/dwmapi.dll"))
                .unwrap(),
            descriptor.proxy_sha256
        );
        assert_eq!(
            rrmm_archive::sha256_path(&nested.join("UE4SS.dll")).unwrap(),
            descriptor.core_sha256
        );
        assert_eq!(fs::read(&settings).unwrap(), b"preserve these settings");
        assert_eq!(
            fs::read(&existing_module).unwrap(),
            b"print('preserve this module')"
        );
        assert!(nested.join("Mods/mods.txt").is_file());
        assert!(!pending_recovery(&app.paths().deployment_state).unwrap());
        assert_eq!(fs::read_dir(&app.paths().staging).unwrap().count(), 0);

        let repaired_again = app.install_or_repair_ue4ss().unwrap();
        assert_eq!(repaired_again.health, HealthLevel::Ready);
        assert_eq!(
            repaired_again.version.as_deref(),
            Some(TARGET_UE4SS_BUILD_ID)
        );
        assert_eq!(fs::read(&settings).unwrap(), b"preserve these settings");
        assert_eq!(
            fs::read(&existing_module).unwrap(),
            b"print('preserve this module')"
        );
        assert!(!pending_recovery(&app.paths().deployment_state).unwrap());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires the real Windows archive and PAK workers"]
    fn windows_real_workers_import_and_deploy_a_generated_mod_end_to_end() {
        let archive_worker = PathBuf::from(
            std::env::var_os("RRMM_WINDOWS_ARCHIVE_WORKER")
                .expect("RRMM_WINDOWS_ARCHIVE_WORKER must point to the real Windows worker"),
        );
        let pak_worker = PathBuf::from(
            std::env::var_os("RRMM_WINDOWS_PAK_WORKER")
                .expect("RRMM_WINDOWS_PAK_WORKER must point to the real Windows worker"),
        );
        assert!(archive_worker.is_file());
        assert!(pak_worker.is_file());

        let temporary = TempDir::new().unwrap();
        let archive = temporary.path().join("Generated.zip");
        let pak_bytes = test_pak_bytes(b"real Windows worker integration");
        write_test_zip(&archive, &[("Generated_P.pak", &pak_bytes)]);
        let expected_sha256 = rrmm_archive::sha256_path(&archive).unwrap();
        let mut app = import_test_app_with_workers(&temporary, archive_worker, pak_worker);
        let game_root = materialize_synthetic_exact_installation(&mut app);

        let preflight = app.preflight_archive(&archive).unwrap();
        assert!(preflight.accepted, "{:?}", preflight.blocked_reasons);
        let review = app.review_archive(&preflight.token).unwrap();
        assert_eq!(review.package_kind, "pak");
        assert!(review.activation_supported);
        assert!(review.blocked_reasons.is_empty());

        let imported = app
            .import_reviewed_archive(&review.token, confirmed(&review))
            .unwrap();
        assert_eq!(imported.artifact_sha256, expected_sha256);
        app.set_profile_mods_enabled(
            "default",
            std::slice::from_ref(&imported.artifact_sha256),
            true,
        )
        .unwrap();
        let preview = app.preview_activation(false).unwrap();
        assert!(!preview.blocked, "{:?}", preview.blockers);
        app.apply_activation(&preview.preview_id).unwrap();

        assert_eq!(
            fs::read(game_root.join("RetroRewind/Content/Paks/Generated_P.pak")).unwrap(),
            pak_bytes
        );
        assert!(!pending_recovery(&app.paths().deployment_state).unwrap());
        assert!(fs::read_dir(&app.paths.staging).unwrap().next().is_none());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires the real Windows workers, pinned UE4SS archive, and a mod archive selected through UNC"]
    fn windows_real_workers_import_a_unc_mod_archive_end_to_end() {
        let archive_worker = PathBuf::from(
            std::env::var_os("RRMM_WINDOWS_ARCHIVE_WORKER")
                .expect("RRMM_WINDOWS_ARCHIVE_WORKER must point to the real Windows worker"),
        );
        let pak_worker = PathBuf::from(
            std::env::var_os("RRMM_WINDOWS_PAK_WORKER")
                .expect("RRMM_WINDOWS_PAK_WORKER must point to the real Windows worker"),
        );
        let archive = PathBuf::from(
            std::env::var_os("RRMM_WINDOWS_MOD_ARCHIVE")
                .expect("RRMM_WINDOWS_MOD_ARCHIVE must point to the selected mod archive"),
        );
        let ue4ss_archive = PathBuf::from(
            std::env::var_os("RRMM_WINDOWS_UE4SS_ARCHIVE")
                .expect("RRMM_WINDOWS_UE4SS_ARCHIVE must point to the pinned UE4SS ZIP"),
        );
        let source_game_root = PathBuf::from(
            std::env::var_os("RRMM_WINDOWS_GAME_ROOT")
                .expect("RRMM_WINDOWS_GAME_ROOT must point to the exact supported game"),
        );
        assert!(archive_worker.is_file());
        assert!(pak_worker.is_file());
        assert!(archive.is_file(), "missing archive: {}", archive.display());
        assert!(
            ue4ss_archive.is_file(),
            "missing UE4SS archive: {}",
            ue4ss_archive.display()
        );
        assert!(source_game_root.is_dir());

        let expected_sha256 = rrmm_archive::sha256_path(&archive).unwrap();
        let temporary = TempDir::new().unwrap();
        let app = import_test_app_with_workers(&temporary, archive_worker, pak_worker);
        let game_root = selected_installation(&app.store().unwrap())
            .unwrap()
            .unwrap()
            .installation
            .game_root;
        for relative in [
            "RetroRewind.exe",
            "RetroRewind/Binaries/Win64/RetroRewind-Win64-Shipping.exe",
        ] {
            let destination = game_root.join(relative);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::copy(source_game_root.join(relative), destination).unwrap();
        }
        let vanilla_pak = game_root.join("RetroRewind/Content/Paks/RetroRewind-Windows.pak");
        fs::create_dir_all(vanilla_pak.parent().unwrap()).unwrap();
        fs::write(vanilla_pak, []).unwrap();
        let descriptor = ue4ss_loader_artifact().unwrap();
        let cache = app.paths().data_root.join("downloads");
        fs::create_dir_all(&cache).unwrap();
        fs::copy(&ue4ss_archive, cache.join(&descriptor.filename)).unwrap();
        let loader = app.install_or_repair_ue4ss().unwrap();
        assert_eq!(loader.health, HealthLevel::Ready);

        let preflight = app.preflight_archive(&archive).unwrap();
        assert_eq!(preflight.archive_path, archive.display().to_string());
        assert!(preflight.accepted);
        assert_eq!(preflight.package_kind, "hybrid");
        assert!(preflight.blocked_reasons.is_empty());

        let review = app.review_archive(&preflight.token).unwrap();
        assert_eq!(review.archive_sha256, expected_sha256);
        assert_eq!(review.package_kind, "hybrid");
        assert!(review.activation_supported);
        assert!(review.conflict_check_complete);
        assert!(review.blocked_reasons.is_empty());
        assert!(
            review
                .files
                .iter()
                .any(|file| file.path == "zzzzzzzz_FasterReturns_P.pak")
        );
        assert!(
            review
                .files
                .iter()
                .any(|file| file.path == "FasterReturns/Scripts/main.lua")
        );

        let imported = app
            .import_reviewed_archive(&review.token, confirmed(&review))
            .unwrap();
        assert_eq!(imported.artifact_sha256, expected_sha256);
        let artifact = app
            .store()
            .unwrap()
            .artifacts()
            .unwrap()
            .into_iter()
            .find(|artifact| artifact.sha256 == expected_sha256)
            .expect("imported artifact was not persisted");
        assert!(
            artifact
                .root
                .join("files/zzzzzzzz_FasterReturns_P.pak")
                .is_file()
        );
        assert!(
            artifact
                .root
                .join("files/FasterReturns/Scripts/main.lua")
                .is_file()
        );
        app.set_profile_mods_enabled(
            "default",
            std::slice::from_ref(&imported.artifact_sha256),
            true,
        )
        .unwrap();
        let preview = app.preview_activation(false).unwrap();
        assert!(!preview.blocked, "{:?}", preview.blockers);
        assert!(preview.requires_apply);
        app.apply_activation(&preview.preview_id).unwrap();

        assert!(
            game_root
                .join("RetroRewind/Content/Paks/zzzzzzzz_FasterReturns_P.pak")
                .is_file()
        );
        assert!(
            game_root
                .join("RetroRewind/Binaries/Win64/ue4ss/Mods/FasterReturns/Scripts/main.lua")
                .is_file()
        );
        assert!(
            game_root
                .join("RetroRewind/Binaries/Win64/ue4ss/Mods/FasterReturns/enabled.txt")
                .is_file()
        );
        let deployment = app.snapshot().unwrap().deployment;
        assert_eq!(deployment.applied_profile_id.as_deref(), Some("default"));
        assert!(fs::read_dir(&app.paths.staging).unwrap().next().is_none());
    }

    #[cfg(windows)]
    #[test]
    fn windows_does_not_open_directories_to_finalize_downloads() {
        let temporary = TempDir::new().unwrap();
        sync_directory_if_supported(temporary.path()).unwrap();
    }

    #[test]
    fn keybind_view_reports_only_exact_resolved_duplicates() {
        let report: LuaAdvisoryReport = serde_json::from_value(serde_json::json!({
            "schema_version": 2,
            "game_root": "/game",
            "complete": true,
            "modules": [
                {"name": "First", "relative_path": "Mods/First", "scripts": [{"relative_path": "Scripts/main.lua", "bytes": 10, "complete": true, "findings": [{"api": "register_key_bind", "line": 2, "column": 1, "first_argument": {"kind": "symbolic", "expression": "Key.F8"}}], "property_writes": [], "issues": []}]},
                {"name": "Second", "relative_path": "Mods/Second", "scripts": [{"relative_path": "Scripts/main.lua", "bytes": 10, "complete": true, "findings": [{"api": "register_key_bind", "line": 3, "column": 1, "first_argument": {"kind": "symbolic", "expression": "Key.F8"}}, {"api": "register_key_bind", "line": 4, "column": 1, "first_argument": {"kind": "dynamic_unresolved"}}], "property_writes": [], "issues": []}]}
            ],
            "issues": []
        }))
        .unwrap();

        let view = keybind_analysis_view(&report);

        assert_eq!(view.bindings.len(), 3);
        assert_eq!(view.collisions.len(), 1);
        assert_eq!(view.collisions[0].binding, "Key.F8");
        assert!(view.bindings[2].binding.is_none());
    }

    #[test]
    fn ue4ss_deployment_preserves_existing_settings_but_replaces_runtime_files() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let staging = temporary.path().join("staging");
        let settings = game.join("RetroRewind/Binaries/Win64/ue4ss/UE4SS-settings.ini");
        fs::create_dir_all(settings.parent().unwrap()).unwrap();
        fs::create_dir_all(staging.join("ue4ss")).unwrap();
        fs::write(&settings, b"custom settings").unwrap();
        fs::write(staging.join("dwmapi.dll"), b"proxy").unwrap();
        fs::write(staging.join("ue4ss/UE4SS.dll"), b"core").unwrap();
        fs::write(staging.join("ue4ss/UE4SS-settings.ini"), b"stock settings").unwrap();
        let artifact = Ue4ssLoaderArtifact {
            build_id: SUPPORTED_BUILD_ID,
            loader_build_id: TARGET_UE4SS_BUILD_ID.to_owned(),
            filename: "loader.zip".to_owned(),
            url: "https://github.com/example".to_owned(),
            archive_size: 1,
            archive_sha256: "a".repeat(64),
            proxy_path: "dwmapi.dll".to_owned(),
            proxy_sha256: rrmm_archive::sha256_path(&staging.join("dwmapi.dll")).unwrap(),
            core_path: "ue4ss/UE4SS.dll".to_owned(),
            core_sha256: rrmm_archive::sha256_path(&staging.join("ue4ss/UE4SS.dll")).unwrap(),
        };
        let extraction = ArchiveExtractionReport {
            archive_sha256: artifact.archive_sha256.clone(),
            format: rrmm_archive::ArchiveFormat::Zip,
            staging_root: staging.clone(),
            expanded_bytes: 29,
            files: ["dwmapi.dll", "ue4ss/UE4SS.dll", "ue4ss/UE4SS-settings.ini"]
                .into_iter()
                .map(|path| {
                    let source = staging.join(path);
                    rrmm_archive::ExtractedFileReport {
                        path: path.to_owned(),
                        bytes: fs::metadata(&source).unwrap().len(),
                        sha256: rrmm_archive::sha256_path(&source).unwrap(),
                        executable_payload: path.ends_with(".dll"),
                        native_binary: path.ends_with(".dll"),
                    }
                })
                .collect(),
            layout: rrmm_archive::PackageLayoutInference {
                kind: PackageKind::Unknown,
                pak_files: Vec::new(),
                ue4ss_mod_roots: Vec::new(),
                documentation_files: Vec::new(),
                executable_files: Vec::new(),
                requires_review: true,
                issues: Vec::new(),
            },
        };

        let files = ue4ss_deployment_files(&game, &extraction, &artifact).unwrap();
        let proxy = files
            .iter()
            .find(|file| file.relative_path.ends_with("dwmapi.dll"))
            .unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(proxy.source, staging.join("dwmapi.dll"));
        assert_eq!(fs::read(&settings).unwrap(), b"custom settings");

        fs::remove_file(&settings).unwrap();
        let files = ue4ss_deployment_files(&game, &extraction, &artifact).unwrap();
        assert_eq!(files.len(), 3);
        assert!(!settings.exists());
        let state = temporary.path().join("state");
        let plan = plan_deployment(
            DeploymentRequest {
                transaction_id: "ue4ss-stock-test".to_owned(),
                installation_id: "ue4ss-stock-test".to_owned(),
                profile_id: "ue4ss-loader".to_owned(),
                game_root: game.clone(),
                state_root: state.clone(),
                files,
                external_files: Vec::new(),
                allow_unmanaged: true,
                game_running: false,
            },
            None,
        )
        .unwrap();
        activate_deployment(&plan, || false).unwrap();
        assert_eq!(fs::read(settings).unwrap(), b"stock settings");
        assert_eq!(
            load_receipt(&state, "ue4ss-stock-test")
                .unwrap()
                .unwrap()
                .files
                .len(),
            3
        );
    }

    #[test]
    fn ue4ss_repair_replaces_the_known_unsafe_pair_and_preserves_nested_modules() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let staging = temporary.path().join("staging");
        let win64 = game.join("RetroRewind/Binaries/Win64");
        let nested = win64.join("ue4ss");
        let module = nested.join("Mods/PlayerMod/Scripts/main.lua");
        let settings = nested.join("UE4SS-settings.ini");
        fs::create_dir_all(module.parent().unwrap()).unwrap();
        fs::create_dir_all(staging.join("ue4ss")).unwrap();
        fs::write(&module, b"print('player mod')").unwrap();
        fs::write(&settings, b"player settings").unwrap();
        fs::write(win64.join("dwmapi.dll"), b"0196 proxy").unwrap();
        fs::write(nested.join("UE4SS.dll"), b"0196 core").unwrap();
        fs::write(staging.join("dwmapi.dll"), b"662df proxy").unwrap();
        fs::write(staging.join("ue4ss/UE4SS.dll"), b"662df core").unwrap();
        let artifact = Ue4ssLoaderArtifact {
            build_id: SUPPORTED_BUILD_ID,
            loader_build_id: TARGET_UE4SS_BUILD_ID.to_owned(),
            filename: "loader.zip".to_owned(),
            url: "https://github.com/example".to_owned(),
            archive_size: 1,
            archive_sha256: "a".repeat(64),
            proxy_path: "dwmapi.dll".to_owned(),
            proxy_sha256: rrmm_archive::sha256_path(&staging.join("dwmapi.dll")).unwrap(),
            core_path: "ue4ss/UE4SS.dll".to_owned(),
            core_sha256: rrmm_archive::sha256_path(&staging.join("ue4ss/UE4SS.dll")).unwrap(),
        };
        let extraction = ArchiveExtractionReport {
            archive_sha256: artifact.archive_sha256.clone(),
            format: rrmm_archive::ArchiveFormat::Zip,
            staging_root: staging.clone(),
            expanded_bytes: 23,
            files: ["dwmapi.dll", "ue4ss/UE4SS.dll"]
                .into_iter()
                .map(|path| {
                    let source = staging.join(path);
                    rrmm_archive::ExtractedFileReport {
                        path: path.to_owned(),
                        bytes: fs::metadata(&source).unwrap().len(),
                        sha256: rrmm_archive::sha256_path(&source).unwrap(),
                        executable_payload: true,
                        native_binary: true,
                    }
                })
                .collect(),
            layout: rrmm_archive::PackageLayoutInference {
                kind: PackageKind::Unknown,
                pak_files: Vec::new(),
                ue4ss_mod_roots: Vec::new(),
                documentation_files: Vec::new(),
                executable_files: Vec::new(),
                requires_review: true,
                issues: Vec::new(),
            },
        };

        reject_ambiguous_ue4ss_layout(&game).unwrap();
        let files = ue4ss_deployment_files(&game, &extraction, &artifact).unwrap();
        let plan = plan_deployment(
            DeploymentRequest {
                transaction_id: "known-unsafe-upgrade".to_owned(),
                installation_id: UE4SS_LOADER_INSTALLATION_ID.to_owned(),
                profile_id: "ue4ss-loader".to_owned(),
                game_root: game.clone(),
                state_root: temporary.path().join("state"),
                files,
                external_files: Vec::new(),
                allow_unmanaged: true,
                game_running: false,
            },
            None,
        )
        .unwrap();
        activate_deployment(&plan, || false).unwrap();

        assert_eq!(fs::read(win64.join("dwmapi.dll")).unwrap(), b"662df proxy");
        assert_eq!(fs::read(nested.join("UE4SS.dll")).unwrap(), b"662df core");
        assert_eq!(fs::read(settings).unwrap(), b"player settings");
        assert_eq!(fs::read(module).unwrap(), b"print('player mod')");
    }

    #[test]
    fn automatic_ue4ss_repair_rejects_legacy_loader_layouts() {
        let temporary = TempDir::new().unwrap();
        let win64 = temporary.path().join("RetroRewind/Binaries/Win64");
        fs::create_dir_all(&win64).unwrap();
        fs::write(win64.join("xinput1_3.dll"), b"legacy").unwrap();
        assert!(reject_ambiguous_ue4ss_layout(temporary.path()).is_err());
    }

    #[test]
    fn disables_and_reenables_an_existing_pak_with_its_signature() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("RetroRewind");
        let state = temporary.path().join("state/deployment");
        let paks = game.join("RetroRewind/Content/Paks/~mods");
        fs::create_dir_all(&paks).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(paks.join("zzzz_Test_Mod_P.pak"), b"pak bytes").unwrap();
        fs::write(paks.join("zzzz_Test_Mod_P.sig"), b"signature").unwrap();

        let active = existing_mod_views(&game, &state, None).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].display_name, "Test Mod");
        assert_eq!(active[0].related_paths.len(), 2);
        assert!(active[0].enabled);

        disable_existing_mod(&game, &state, &active[0]).unwrap();
        assert!(!paks.join("zzzz_Test_Mod_P.pak").exists());
        assert!(!paks.join("zzzz_Test_Mod_P.sig").exists());
        let disabled = existing_mod_views(&game, &state, None).unwrap();
        assert_eq!(disabled.len(), 1);
        assert!(!disabled[0].enabled);
        assert!(unmanaged_pak_views(&game, None).unwrap().is_empty());

        enable_existing_mod(&game, &state, &disabled[0].id).unwrap();
        assert_eq!(
            fs::read(paks.join("zzzz_Test_Mod_P.pak")).unwrap(),
            b"pak bytes"
        );
        assert_eq!(
            fs::read(paks.join("zzzz_Test_Mod_P.sig")).unwrap(),
            b"signature"
        );
        assert!(existing_mod_views(&game, &state, None).unwrap()[0].enabled);
    }

    #[test]
    fn delete_removes_active_and_disabled_existing_mods() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("RetroRewind");
        let state = temporary.path().join("state/deployment");
        let paks = game.join("RetroRewind/Content/Paks/~mods");
        fs::create_dir_all(&paks).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(paks.join("Delete_Me_P.pak"), b"delete me").unwrap();

        let active = existing_mod_views(&game, &state, None).unwrap().remove(0);
        delete_active_existing_mod(&game, &state, &active).unwrap();
        assert!(!paks.join("Delete_Me_P.pak").exists());
        assert!(existing_mod_views(&game, &state, None).unwrap().is_empty());

        fs::write(paks.join("Disable_Then_Delete_P.pak"), b"delete later").unwrap();
        let second = existing_mod_views(&game, &state, None).unwrap().remove(0);
        disable_existing_mod(&game, &state, &second).unwrap();
        delete_disabled_existing_mod(&game, &state, &second.id).unwrap();
        assert!(existing_mod_views(&game, &state, None).unwrap().is_empty());
    }

    #[test]
    fn enabling_never_overwrites_a_new_file_at_the_original_path() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("RetroRewind");
        let state = temporary.path().join("state/deployment");
        let paks = game.join("RetroRewind/Content/Paks/~mods");
        fs::create_dir_all(&paks).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(paks.join("Collision_P.pak"), b"original").unwrap();

        let existing = existing_mod_views(&game, &state, None).unwrap().remove(0);
        disable_existing_mod(&game, &state, &existing).unwrap();
        fs::write(paks.join("Collision_P.pak"), b"replacement").unwrap();
        let error = enable_existing_mod(&game, &state, &existing.id).unwrap_err();

        assert!(error.to_string().contains("already occupies"));
        assert_eq!(
            fs::read(paks.join("Collision_P.pak")).unwrap(),
            b"replacement"
        );
        assert!(
            existing_mod_record_directory(&state, &existing.id)
                .unwrap()
                .is_dir()
        );
    }

    #[test]
    fn inventories_disables_and_reenables_a_marker_based_ue4ss_module() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("RetroRewind");
        let state = temporary.path().join("state/deployment");
        let scripts = game.join("RetroRewind/Binaries/Win64/ue4ss/Mods/TestLua/Scripts");
        fs::create_dir_all(&scripts).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(scripts.join("main.lua"), b"return true").unwrap();
        fs::write(scripts.parent().unwrap().join("enabled.txt"), b"").unwrap();

        let active = active_ue4ss_existing_mod_views(&game, None, &BTreeSet::new()).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].display_name, "TestLua");
        assert_eq!(active[0].mod_type, "ue4ss_lua");
        assert!(active[0].enabled);
        assert!(active[0].manageable, "{:?}", active[0].blocked_reason);

        disable_existing_mod(&game, &state, &active[0]).unwrap();
        assert!(!scripts.join("main.lua").exists());
        let disabled = existing_mod_views(&game, &state, None).unwrap();
        assert_eq!(disabled.len(), 1);
        assert!(!disabled[0].enabled);
        assert!(disabled[0].stored);

        enable_existing_mod(&game, &state, &disabled[0].id).unwrap();
        assert_eq!(fs::read(scripts.join("main.lua")).unwrap(), b"return true");
        let restored = existing_mod_views(&game, &state, None).unwrap();
        assert_eq!(restored.len(), 1);
        assert!(restored[0].enabled);

        delete_active_existing_mod(&game, &state, &restored[0]).unwrap();
        assert!(!scripts.parent().unwrap().exists());
        assert!(existing_mod_views(&game, &state, None).unwrap().is_empty());
    }

    #[test]
    fn ignores_an_empty_ue4ss_module_tree() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("RetroRewind");
        let state = temporary.path().join("state/deployment");
        let module = game.join("RetroRewind/Binaries/Win64/ue4ss/Mods/KismetDebugger");
        fs::create_dir_all(module.join("Scripts/Generated")).unwrap();
        fs::create_dir_all(&state).unwrap();

        let existing = existing_mod_views(&game, &state, None).unwrap();
        assert!(existing.is_empty());
        assert!(
            module.is_dir(),
            "inventory must not delete external directories"
        );
    }

    #[test]
    fn enables_an_unlisted_lua_module_with_a_canonical_marker() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("RetroRewind");
        let scripts = game.join("RetroRewind/Binaries/Win64/ue4ss/Mods/UnlistedLua/Scripts");
        fs::create_dir_all(&scripts).unwrap();
        fs::write(scripts.join("main.lua"), b"return true").unwrap();

        let inactive = active_ue4ss_existing_mod_views(&game, None, &BTreeSet::new()).unwrap();
        assert_eq!(inactive.len(), 1);
        assert!(!inactive[0].enabled);
        assert!(inactive[0].manageable);
        enable_live_ue4ss_module(&game, &inactive[0]).unwrap();

        assert!(scripts.parent().unwrap().join("enabled.txt").is_file());
        let enabled = active_ue4ss_existing_mod_views(&game, None, &BTreeSet::new()).unwrap();
        assert!(enabled[0].enabled);
    }

    #[test]
    fn allows_explicit_management_of_a_regular_native_module() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("RetroRewind");
        let module = game.join("RetroRewind/Binaries/Win64/ue4ss/Mods/NativeMod");
        fs::create_dir_all(module.join("dlls")).unwrap();
        fs::write(module.join("dlls/main.dll"), b"native fixture").unwrap();

        let inactive = active_ue4ss_existing_mod_views(&game, None, &BTreeSet::new()).unwrap();
        assert_eq!(inactive.len(), 1);
        assert_eq!(inactive[0].mod_type, "ue4ss_native");
        assert!(!inactive[0].enabled);
        assert!(inactive[0].manageable, "{:?}", inactive[0].blocked_reason);

        enable_live_ue4ss_module(&game, &inactive[0]).unwrap();
        assert!(module.join("enabled.txt").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn an_unrelated_incomplete_inventory_does_not_block_a_safe_module() {
        use std::os::unix::fs::symlink;

        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("RetroRewind");
        let mods = game.join("RetroRewind/Binaries/Win64/ue4ss/Mods");
        let safe = mods.join("SafeModule/Scripts");
        fs::create_dir_all(&safe).unwrap();
        fs::write(safe.join("main.lua"), b"return true").unwrap();
        fs::write(safe.parent().unwrap().join("enabled.txt"), b"").unwrap();
        symlink(temporary.path(), mods.join("UnsafeLinkedModule")).unwrap();

        let views = active_ue4ss_existing_mod_views(&game, None, &BTreeSet::new()).unwrap();
        let safe = views
            .iter()
            .find(|view| view.display_name == "SafeModule")
            .unwrap();
        assert!(safe.manageable, "{:?}", safe.blocked_reason);
    }

    #[cfg(unix)]
    #[test]
    fn inventories_disables_reenables_and_deletes_a_linked_ue4ss_module() {
        use std::os::unix::fs::symlink;

        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("RetroRewind");
        let state = temporary.path().join("state/deployment");
        let mods = game.join("RetroRewind/Binaries/Win64/ue4ss/Mods");
        let target = temporary.path().join("FastTurn");
        fs::create_dir_all(target.join("Scripts")).unwrap();
        fs::create_dir_all(&mods).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(target.join("Scripts/main.lua"), b"return true").unwrap();
        fs::write(target.join("enabled.txt"), b"").unwrap();
        let link = mods.join("FastTurn");
        symlink(&target, &link).unwrap();

        let active = existing_mod_views(&game, &state, None).unwrap();
        let linked = active
            .iter()
            .find(|view| view.display_name == "FastTurn Prototype")
            .unwrap();
        assert!(linked.enabled);
        assert!(linked.manageable, "{:?}", linked.blocked_reason);
        assert_eq!(linked.mod_type, "ue4ss_link");
        assert_eq!(linked.symlink_target.as_deref(), target.to_str());

        disable_existing_mod(&game, &state, linked).unwrap();
        assert!(fs::symlink_metadata(&link).is_err());
        assert!(target.join("Scripts/main.lua").is_file());
        let disabled = existing_mod_views(&game, &state, None).unwrap();
        assert_eq!(disabled.len(), 1);
        assert!(!disabled[0].enabled);
        assert!(disabled[0].stored);

        enable_existing_mod(&game, &state, &disabled[0].id).unwrap();
        assert_eq!(fs::read_link(&link).unwrap(), target);
        let restored = existing_mod_views(&game, &state, None).unwrap();
        let linked = restored
            .iter()
            .find(|view| view.display_name == "FastTurn Prototype")
            .unwrap();
        delete_active_existing_mod(&game, &state, linked).unwrap();
        assert!(fs::symlink_metadata(&link).is_err());
        assert!(target.join("Scripts/main.lua").is_file());
        assert!(existing_mod_views(&game, &state, None).unwrap().is_empty());
    }

    #[test]
    fn groups_and_manages_a_verified_pak_and_ue4ss_pack_as_one_mod() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("RetroRewind");
        let state = temporary.path().join("state/deployment");
        let paks = game.join("RetroRewind/Content/Paks/~mods");
        let scripts = game.join("RetroRewind/Binaries/Win64/ue4ss/Mods/HybridTest/Scripts");
        fs::create_dir_all(&paks).unwrap();
        fs::create_dir_all(&scripts).unwrap();
        fs::create_dir_all(&state).unwrap();
        let pak_path = paks.join("HybridTest_P.pak");
        let script_path = scripts.join("main.lua");
        let marker_path = scripts.parent().unwrap().join("enabled.txt");
        fs::write(&pak_path, b"reviewed pak").unwrap();
        fs::write(&script_path, b"return 'reviewed'").unwrap();
        fs::write(&marker_path, b"").unwrap();
        let group = ExternalModGroup {
            package_id: "test:hybrid".to_owned(),
            name: "Hybrid Test".to_owned(),
            version: "1.0.0".to_owned(),
            nexus_page_url: None,
            pak_install_name: "HybridTest_P.pak".to_owned(),
            pak_sha256: rrmm_archive::sha256_path(&pak_path).unwrap(),
            ue4ss_install_name: "HybridTest".to_owned(),
            ue4ss_files: vec![
                ExternalModGroupFile {
                    path: "Scripts/main.lua".to_owned(),
                    size_bytes: fs::metadata(&script_path).unwrap().len(),
                    sha256: rrmm_archive::sha256_path(&script_path).unwrap(),
                },
                ExternalModGroupFile {
                    path: "enabled.txt".to_owned(),
                    size_bytes: 0,
                    sha256: rrmm_archive::sha256_path(&marker_path).unwrap(),
                },
            ],
        };
        let mut views = active_existing_mod_views(&game, None).unwrap();
        views.extend(active_ue4ss_existing_mod_views(&game, None, &BTreeSet::new()).unwrap());
        group_reviewed_hybrid_mods_with_groups(&game, &mut views, std::slice::from_ref(&group))
            .unwrap();

        assert_eq!(views.len(), 2);
        assert!(views.iter().all(|view| view.group_id.is_some()));
        assert!(
            views
                .iter()
                .all(|view| view.group_name.as_deref() == Some("Hybrid Test"))
        );
        let pak = views.iter().find(|view| view.mod_type == "pak").unwrap();
        let module = views
            .iter()
            .find(|view| view.mod_type == "ue4ss_lua")
            .unwrap();
        let snapshot = capture_existing_group_snapshot(&game, &state, &views).unwrap();
        disable_existing_mod(&game, &state, pak).unwrap();
        assert_eq!(recover_existing_group_operations(&game, &state).unwrap(), 1);
        assert!(!snapshot.root.exists());
        assert_eq!(fs::read(&pak_path).unwrap(), b"reviewed pak");
        assert_eq!(fs::read(&script_path).unwrap(), b"return 'reviewed'");
        assert!(
            !existing_mod_record_directory(&state, &pak.id)
                .unwrap()
                .exists()
        );

        disable_existing_mod(&game, &state, pak).unwrap();
        disable_existing_mod(&game, &state, module).unwrap();
        assert!(!pak_path.exists());
        assert!(!script_path.exists());
        let mut disabled = existing_mod_views(&game, &state, None).unwrap();
        group_reviewed_hybrid_mods_with_groups(&game, &mut disabled, std::slice::from_ref(&group))
            .unwrap();
        assert_eq!(disabled.len(), 2);
        assert!(
            disabled.iter().all(|view| view.group_id.is_some()),
            "disabled views were not regrouped: {disabled:#?}"
        );
        for view in &disabled {
            enable_existing_mod(&game, &state, &view.id).unwrap();
        }
        assert_eq!(fs::read(pak_path).unwrap(), b"reviewed pak");
        assert_eq!(fs::read(script_path).unwrap(), b"return 'reviewed'");
    }

    #[test]
    fn atomically_edits_only_the_target_module_in_shared_mods_txt() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("RetroRewind");
        let mods = game.join("RetroRewind/Binaries/Win64/ue4ss/Mods");
        fs::create_dir_all(mods.join("ListedModule/Scripts")).unwrap();
        fs::write(mods.join("ListedModule/Scripts/main.lua"), b"return true").unwrap();
        fs::write(
            mods.join("mods.txt"),
            b"; keep this comment\r\nListedModule : 1\r\nUnknownModule : 0\r\n",
        )
        .unwrap();

        let views = active_ue4ss_existing_mod_views(&game, None, &BTreeSet::new()).unwrap();
        assert_eq!(views.len(), 1);
        assert!(views[0].enabled);
        assert!(views[0].manageable, "{:?}", views[0].blocked_reason);
        assert!(views[0].mods_txt_controlled);

        set_ue4ss_mods_txt_state(&game, "ListedModule", Some(false)).unwrap();
        assert_eq!(
            fs::read(mods.join("mods.txt")).unwrap(),
            b"; keep this comment\r\nListedModule : 0\r\nUnknownModule : 0\r\n"
        );
        set_ue4ss_mods_txt_state(&game, "ListedModule", Some(true)).unwrap();
        set_ue4ss_mods_txt_state(&game, "ListedModule", None).unwrap();
        assert_eq!(
            fs::read(mods.join("mods.txt")).unwrap(),
            b"; keep this comment\r\nUnknownModule : 0\r\n"
        );
    }

    #[test]
    fn restores_the_exact_mods_txt_bytes_after_a_failed_deletion_edit() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("RetroRewind");
        let mods = game.join("RetroRewind/Binaries/Win64/ue4ss/Mods");
        fs::create_dir_all(mods.join("ListedModule/Scripts")).unwrap();
        fs::write(mods.join("ListedModule/Scripts/main.lua"), b"return true").unwrap();
        let original = b"; keep this comment\r\nListedModule : 1\r\nUnknownModule : 0\r\n";
        fs::write(mods.join("mods.txt"), original).unwrap();
        let snapshot = prepare_ue4ss_mods_txt_removal(&game, "ListedModule").unwrap();

        set_ue4ss_mods_txt_state(&game, "ListedModule", None).unwrap();
        restore_ue4ss_mods_txt_edit(&game, &snapshot).unwrap();

        assert_eq!(fs::read(mods.join("mods.txt")).unwrap(), original);
    }

    #[test]
    fn stored_mod_restores_files_and_mods_txt_after_an_interrupted_deletion() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("RetroRewind");
        let state = temporary.path().join("state/deployment");
        let mods = game.join("RetroRewind/Binaries/Win64/ue4ss/Mods");
        let script = mods.join("ListedModule/Scripts/main.lua");
        fs::create_dir_all(script.parent().unwrap()).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(&script, b"return true").unwrap();
        let original = b"ListedModule : 1\r\nUnknownModule : 0\r\n";
        fs::write(mods.join("mods.txt"), original).unwrap();
        let existing = existing_mod_views(&game, &state, None)
            .unwrap()
            .into_iter()
            .find(|view| view.display_name == "ListedModule")
            .unwrap();
        let snapshot = prepare_ue4ss_mods_txt_removal(&game, "ListedModule").unwrap();
        disable_existing_mod_with_snapshot(&game, &state, &existing, Some(snapshot.clone()))
            .unwrap();
        apply_ue4ss_mods_txt_edit(&game, &snapshot).unwrap();

        assert!(!script.exists());
        assert!(
            !fs::read(mods.join("mods.txt"))
                .unwrap()
                .windows(b"ListedModule".len())
                .any(|window| window == b"ListedModule")
        );

        enable_existing_mod(&game, &state, &existing.id).unwrap();

        assert_eq!(fs::read(script).unwrap(), b"return true");
        assert_eq!(fs::read(mods.join("mods.txt")).unwrap(), original);
    }

    #[test]
    fn blocks_a_selected_package_replaced_by_an_unmanaged_combined_pak() {
        let catalog = package_catalog().unwrap();
        let selected = catalog
            .iter()
            .find(|package| package.manifest.id == "nexus:unrewound-tape-fee")
            .unwrap();
        let profile = DomainProfile {
            schema_version: 1,
            id: "test-profile".to_owned(),
            name: "Test".to_owned(),
            revision: 0,
            packages: vec![ProfilePackageSelection {
                artifact_sha256: selected.artifact_sha256.clone(),
                variant: None,
                enabled: true,
            }],
            pak_load_order: Vec::new(),
        };
        let unmanaged = vec![UnmanagedFileView {
            path: "RetroRewind/Content/Paks/~mods/RRMM_eeeeeeeeeeeeeeee_2_P.pak".to_owned(),
            size_bytes: 1,
            pak_sha256: "e".repeat(64),
            original_path:
                "RetroRewind/Content/Paks/~mods/zzzzzzzz_UnrewoundTapeFee_EmployeeFeePolicy_P.pak"
                    .to_owned(),
            existing_mod_id: Some("existing-test".to_owned()),
            display_name: Some("Combined".to_owned()),
            manageable: true,
            active_paths: BTreeMap::new(),
        }];

        let conflicts = unmanaged_package_conflicts(&profile, &catalog, &unmanaged);
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].reason.contains("reviewed combined package"));
    }

    #[test]
    fn replaces_all_reviewed_pak_preferences_from_one_global_order() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let c = "c".repeat(64);
        let d = "d".repeat(64);
        let e = "e".repeat(64);
        let party = |name: &str, sha256: &str, load_order| PakConflictPartyView {
            archive: format!("{name}_P.pak"),
            display_name: name.to_owned(),
            package_id: Some(name.to_owned()),
            pak_sha256: sha256.to_owned(),
            source_kind: "managed".to_owned(),
            artifact_sha256: Some(sha256.to_owned()),
            existing_mod_id: None,
            manageable: true,
            load_order,
            destination: Some(format!("{name}_P.pak")),
        };
        let conflict =
            |id: &str, first: PakConflictPartyView, second: PakConflictPartyView| PakConflictView {
                conflict_id: id.to_owned(),
                first_archive: first.archive.clone(),
                second_archive: second.archive.clone(),
                first,
                second,
                winner_pak_sha256: None,
                selected_winner_pak_sha256: None,
                outcome: "unknown_order".to_owned(),
                winner: None,
                order_confidence: "unknown".to_owned(),
                winner_reason: String::new(),
                domains: vec!["test".to_owned()],
                affected_member_count: 1,
                affected_package_count: 1,
                split_package: false,
            };
        let conflicts = vec![
            conflict("a-b", party("A", &a, 1), party("B", &b, 2)),
            conflict("b-c", party("B", &b, 2), party("C", &c, 3)),
        ];
        let mut profile = DomainProfile {
            schema_version: 1,
            id: "test".to_owned(),
            name: "Test".to_owned(),
            revision: 0,
            packages: Vec::new(),
            pak_load_order: vec![
                PakLoadOrderPreference {
                    build_id: SUPPORTED_BUILD_ID,
                    first_pak_sha256: a.clone(),
                    second_pak_sha256: b.clone(),
                    winner_pak_sha256: a.clone(),
                },
                PakLoadOrderPreference {
                    build_id: SUPPORTED_BUILD_ID,
                    first_pak_sha256: d.clone(),
                    second_pak_sha256: e.clone(),
                    winner_pak_sha256: e.clone(),
                },
            ],
        };

        apply_profile_pak_load_order(
            &mut profile,
            SUPPORTED_BUILD_ID,
            &conflicts,
            &[a.clone(), b.clone(), c.clone()],
        )
        .unwrap();

        assert_eq!(profile.pak_load_order.len(), 3);
        assert_eq!(
            selected_pak_winner(SUPPORTED_BUILD_ID, &profile.pak_load_order, &a, &b),
            Some(b.clone())
        );
        assert_eq!(
            selected_pak_winner(SUPPORTED_BUILD_ID, &profile.pak_load_order, &b, &c),
            Some(c.clone())
        );
        assert_eq!(
            selected_pak_winner(SUPPORTED_BUILD_ID, &profile.pak_load_order, &d, &e),
            Some(e)
        );
        assert!(
            apply_profile_pak_load_order(
                &mut profile.clone(),
                SUPPORTED_BUILD_ID,
                &conflicts,
                &[a.clone(), b.clone()]
            )
            .is_err()
        );
        assert!(
            apply_profile_pak_load_order(
                &mut profile,
                SUPPORTED_BUILD_ID,
                &conflicts,
                &[a, b.clone(), b]
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn removes_only_the_reviewed_ue4ss_module_link() {
        use std::os::unix::fs::symlink;

        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let target = temporary.path().join("FasterReturns");
        let mods = game.join("RetroRewind/Binaries/Win64/ue4ss/Mods");
        let link = mods.join("FasterReturns");
        fs::create_dir_all(&mods).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("main.lua"), b"return true").unwrap();
        symlink(&target, &link).unwrap();
        let relative_link = "RetroRewind/Binaries/Win64/ue4ss/Mods/FasterReturns";
        let plan = DeploymentPlan {
            schema_version: 2,
            transaction_id: "test".to_owned(),
            installation_id: "installation".to_owned(),
            profile_id: "profile".to_owned(),
            game_root: game.clone(),
            state_root: temporary.path().join("state"),
            files: Vec::new(),
            external_files: Vec::new(),
            external_moves: Vec::new(),
            allow_unmanaged: false,
            managed_file_restore_approvals: Vec::new(),
            changes: Vec::new(),
            blockers: ["Scripts/main.lua", "config.lua"]
                .into_iter()
                .map(|child| DeploymentBlocker::UnsafeFilesystemEntry {
                    relative_path: format!("{relative_link}/{child}"),
                    detail: "symlink".to_owned(),
                })
                .collect(),
            previous_receipt: None,
            target_receipt: DeploymentReceipt {
                schema_version: 1,
                profile_id: "profile".to_owned(),
                game_root: game.clone(),
                files: Vec::new(),
                external_files: Vec::new(),
            },
        };

        assert_eq!(
            blocking_link_views(&plan).unwrap(),
            vec![BlockingLinkView {
                relative_path: relative_link.to_owned(),
                display_name: "FasterReturns".to_owned(),
            }]
        );

        remove_reviewed_filesystem_link(&game, relative_link).unwrap();

        assert!(fs::symlink_metadata(&link).is_err());
        assert_eq!(fs::read(target.join("main.lua")).unwrap(), b"return true");
        assert!(
            remove_reviewed_filesystem_link(
                &game,
                "RetroRewind/Binaries/Win64/ue4ss/Mods/../FasterReturns"
            )
            .is_err()
        );
    }

    #[test]
    fn canonical_preferences_select_either_winner_and_reject_a_cycle() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let c = "c".repeat(64);
        assert_eq!(canonical_pak_pair(&b, &a).unwrap(), (a.clone(), b.clone()));
        assert!(selected_pak_winner(SUPPORTED_BUILD_ID, &[], &a, &b).is_none());
        let first_party = PakConflictPartyView {
            archive: "First_P.pak".to_owned(),
            display_name: "First".to_owned(),
            package_id: Some("first".to_owned()),
            pak_sha256: a.clone(),
            source_kind: "managed".to_owned(),
            artifact_sha256: Some("d".repeat(64)),
            existing_mod_id: None,
            manageable: true,
            load_order: 1,
            destination: Some("First_P.pak".to_owned()),
        };
        let second_party = PakConflictPartyView {
            archive: "Second_P.pak".to_owned(),
            display_name: "Second".to_owned(),
            package_id: None,
            pak_sha256: b.clone(),
            source_kind: "external".to_owned(),
            artifact_sha256: None,
            existing_mod_id: Some("existing-second".to_owned()),
            manageable: true,
            load_order: 2,
            destination: Some("Second_P.pak".to_owned()),
        };
        let mut identical_party = second_party.clone();
        identical_party.pak_sha256 = first_party.pak_sha256.clone();
        assert!(pak_conflict_identity(&first_party, &identical_party).is_ok());
        assert!(
            pak_conflict_selection_blocker(
                PakConflictOutcome::UnknownOrder,
                &first_party,
                &second_party,
                None,
                None,
            )
            .is_some()
        );
        assert!(
            pak_conflict_selection_blocker(
                PakConflictOutcome::OrderedWithLoss,
                &first_party,
                &second_party,
                Some(&b),
                Some(&b),
            )
            .is_none()
        );
        assert!(
            pak_conflict_selection_blocker(
                PakConflictOutcome::BenignDuplicate,
                &first_party,
                &second_party,
                None,
                None,
            )
            .is_none()
        );

        let preferences = vec![PakLoadOrderPreference {
            build_id: SUPPORTED_BUILD_ID,
            first_pak_sha256: a.clone(),
            second_pak_sha256: b.clone(),
            winner_pak_sha256: b.clone(),
        }];
        assert_eq!(
            selected_pak_winner(SUPPORTED_BUILD_ID, &preferences, &a, &b),
            Some(b.clone())
        );
        let pair_hashes = [a.clone(), b.clone()].into_iter().collect();
        let pair_nodes = [a.clone(), b.clone()]
            .into_iter()
            .map(|pak_sha256| PakLoadOrderNode { pak_sha256 })
            .collect::<Vec<_>>();
        let first_order = resolve_pak_load_order(
            &pair_nodes,
            &active_pak_constraints(SUPPORTED_BUILD_ID, &preferences, &pair_hashes).unwrap(),
        )
        .unwrap();
        assert!(first_order.slots[&b] > first_order.slots[&a]);
        let opposite = vec![PakLoadOrderPreference {
            build_id: SUPPORTED_BUILD_ID,
            first_pak_sha256: a.clone(),
            second_pak_sha256: b.clone(),
            winner_pak_sha256: a.clone(),
        }];
        let opposite_order = resolve_pak_load_order(
            &pair_nodes,
            &active_pak_constraints(SUPPORTED_BUILD_ID, &opposite, &pair_hashes).unwrap(),
        )
        .unwrap();
        assert!(opposite_order.slots[&a] > opposite_order.slots[&b]);
        let hashes = [a.clone(), b.clone(), c.clone()].into_iter().collect();
        let mut cyclic = preferences;
        cyclic.push(PakLoadOrderPreference {
            build_id: SUPPORTED_BUILD_ID,
            first_pak_sha256: b.clone(),
            second_pak_sha256: c.clone(),
            winner_pak_sha256: c.clone(),
        });
        cyclic.push(PakLoadOrderPreference {
            build_id: SUPPORTED_BUILD_ID,
            first_pak_sha256: a.clone(),
            second_pak_sha256: c.clone(),
            winner_pak_sha256: a.clone(),
        });
        let constraints = active_pak_constraints(SUPPORTED_BUILD_ID, &cyclic, &hashes).unwrap();
        let nodes = [a, b, c]
            .into_iter()
            .map(|pak_sha256| PakLoadOrderNode { pak_sha256 })
            .collect::<Vec<_>>();
        assert!(resolve_pak_load_order(&nodes, &constraints).is_err());
    }

    #[test]
    fn ordering_renames_managed_and_external_paks_with_their_signatures() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let external_pak = game.join("RetroRewind/Content/Paks/~mods/External_P.pak");
        let external_sig = game.join("RetroRewind/Content/Paks/~mods/External_P.sig");
        fs::create_dir_all(external_pak.parent().unwrap()).unwrap();
        fs::write(&external_pak, b"external pak").unwrap();
        fs::write(&external_sig, b"external sig").unwrap();
        let external_hash = rrmm_archive::sha256_path(&external_pak).unwrap();
        let managed_hash = "a".repeat(64);
        let mut deployment = DeploymentRequest {
            transaction_id: "test".to_owned(),
            installation_id: "installation".to_owned(),
            profile_id: "profile".to_owned(),
            game_root: game,
            state_root: temporary.path().join("state"),
            files: vec![
                DeploymentFile {
                    source: temporary.path().join("Managed_P.pak"),
                    relative_path: "RetroRewind/Content/Paks/Managed_P.pak".to_owned(),
                    bytes: 1,
                    sha256: managed_hash.clone(),
                    package_id: Some("managed".to_owned()),
                    package_name: Some("Managed".to_owned()),
                },
                DeploymentFile {
                    source: temporary.path().join("Managed_P.sig"),
                    relative_path: "RetroRewind/Content/Paks/Managed_P.sig".to_owned(),
                    bytes: 1,
                    sha256: "d".repeat(64),
                    package_id: Some("managed".to_owned()),
                    package_name: Some("Managed".to_owned()),
                },
            ],
            external_files: Vec::new(),
            allow_unmanaged: true,
            game_running: false,
        };
        let unmanaged = vec![UnmanagedFileView {
            path: "RetroRewind/Content/Paks/~mods/External_P.pak".to_owned(),
            size_bytes: fs::metadata(&external_pak).unwrap().len(),
            pak_sha256: external_hash.clone(),
            original_path: "RetroRewind/Content/Paks/~mods/External_P.pak".to_owned(),
            existing_mod_id: Some("existing-external".to_owned()),
            display_name: Some("External".to_owned()),
            manageable: true,
            active_paths: BTreeMap::new(),
        }];
        let slots = [(managed_hash.clone(), 1), (external_hash.clone(), 2)]
            .into_iter()
            .collect();

        apply_pak_ordering(&mut deployment, &unmanaged, None, &slots).unwrap();

        assert!(deployment.files[0].relative_path.ends_with("_1_P.pak"));
        assert!(deployment.files[1].relative_path.ends_with("_1_P.sig"));
        assert_eq!(deployment.external_files.len(), 2);
        assert!(
            deployment.external_files[0]
                .target_relative_path
                .ends_with("_2_P.pak")
        );
        assert!(
            deployment.external_files[1]
                .target_relative_path
                .ends_with("_2_P.sig")
        );
    }

    #[test]
    fn ordered_external_identity_is_stable_and_reenable_restores_original_names() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let state = temporary.path().join("state");
        let original_pak = "RetroRewind/Content/Paks/~mods/Stable_P.pak";
        let original_sig = "RetroRewind/Content/Paks/~mods/Stable_P.sig";
        let current_pak = "RetroRewind/Content/Paks/~mods/RRMM_deadbeefdeadbeef_2_P.pak";
        let current_sig = "RetroRewind/Content/Paks/~mods/RRMM_deadbeefdeadbeef_2_P.sig";
        fs::create_dir_all(game.join(current_pak).parent().unwrap()).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(game.join(current_pak), b"pak").unwrap();
        fs::write(game.join(current_sig), b"sig").unwrap();
        let pak_hash = rrmm_archive::sha256_path(&game.join(current_pak)).unwrap();
        let sig_hash = rrmm_archive::sha256_path(&game.join(current_sig)).unwrap();
        let receipt = DeploymentReceipt {
            schema_version: 1,
            profile_id: "profile".to_owned(),
            game_root: game.clone(),
            files: Vec::new(),
            external_files: vec![
                rrmm_deploy::OrderedExternalFile {
                    original_relative_path: original_pak.to_owned(),
                    current_relative_path: current_pak.to_owned(),
                    bytes: 3,
                    sha256: pak_hash,
                    owner_id: Some("existing-stable".to_owned()),
                    owner_name: Some("Stable".to_owned()),
                },
                rrmm_deploy::OrderedExternalFile {
                    original_relative_path: original_sig.to_owned(),
                    current_relative_path: current_sig.to_owned(),
                    bytes: 3,
                    sha256: sig_hash,
                    owner_id: Some("existing-stable".to_owned()),
                    owner_name: Some("Stable".to_owned()),
                },
            ],
        };
        let view = active_existing_mod_views(&game, Some(&receipt))
            .unwrap()
            .remove(0);
        assert_eq!(view.path, original_pak);
        assert_eq!(view.display_name, "Stable");
        assert_eq!(view.id, existing_mod_id(original_pak));
        assert_eq!(view.related_paths, vec![original_pak, original_sig]);

        disable_existing_mod(&game, &state, &view).unwrap();
        assert!(!game.join(current_pak).exists());
        let mut deployment = DeploymentRequest {
            transaction_id: "test".to_owned(),
            installation_id: "installation".to_owned(),
            profile_id: "profile".to_owned(),
            game_root: game.clone(),
            state_root: state.clone(),
            files: Vec::new(),
            external_files: Vec::new(),
            allow_unmanaged: true,
            game_running: false,
        };
        restore_unneeded_external_ordering(&mut deployment, Some(&receipt), &BTreeSet::new())
            .unwrap();
        assert!(deployment.external_files.is_empty());
        enable_existing_mod(&game, &state, &view.id).unwrap();
        assert!(game.join(original_pak).is_file());
        assert!(game.join(original_sig).is_file());
        assert!(!game.join(current_pak).exists());
    }

    #[test]
    fn exposes_only_reviewed_nexus_page_urls() {
        let catalog = package_catalog().unwrap();
        let faster_returns = catalog
            .iter()
            .find(|package| package.manifest.id == "nexus:faster-returns")
            .unwrap();
        assert_eq!(
            nexus_page_url(faster_returns).as_deref(),
            Some("https://www.nexusmods.com/retrorewindvideostoresimulator/mods/271")
        );
    }

    #[test]
    fn startup_restores_an_interrupted_artifact_quarantine() {
        let temporary = TempDir::new().unwrap();
        let paths = DesktopPaths::under(temporary.path().join("state"));
        paths.ensure().unwrap();
        let store = Store::open(&paths.database).unwrap();
        let sha256 = "a".repeat(64);
        let original = paths
            .artifact_store
            .join("artifacts")
            .join(&sha256[..2])
            .join(&sha256);
        fs::create_dir_all(&original).unwrap();
        fs::write(original.join("payload.bin"), b"payload").unwrap();
        store
            .upsert_artifact(&sha256, &original, &serde_json::json!({}))
            .unwrap();
        let artifact = store.artifacts().unwrap().remove(0);
        let quarantine = paths
            .staging
            .join(format!("{BULK_DELETE_QUARANTINE_PREFIX}test"));
        fs::create_dir(&quarantine).unwrap();
        write_artifact_quarantine_journal(&quarantine, &[artifact]).unwrap();
        fs::rename(&original, quarantine.join(&sha256)).unwrap();

        assert_eq!(recover_artifact_quarantines(&paths, &store).unwrap(), 1);
        assert_eq!(fs::read(original.join("payload.bin")).unwrap(), b"payload");
        assert!(!quarantine.exists());
    }

    #[test]
    fn external_delete_revalidates_file_identity_after_preview() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let state = temporary.path().join("state");
        let pak = game.join("RetroRewind/Content/Paks/~mods/Changed_P.pak");
        fs::create_dir_all(pak.parent().unwrap()).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(&pak, b"reviewed").unwrap();
        let reviewed = existing_mod_views(&game, &state, None).unwrap().remove(0);
        let unit = BulkDeleteExternalUnit {
            group_id: None,
            member_ids: vec![reviewed.id.clone()],
        };
        fs::write(&pak, b"changed").unwrap();

        let error =
            delete_existing_mod_unit_unlocked(&game, &state, &unit, &[reviewed]).unwrap_err();
        assert!(error.to_string().contains("changed after preview"));
        assert_eq!(fs::read(pak).unwrap(), b"changed");
    }
}
