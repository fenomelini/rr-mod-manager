use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use rrmm_archive::{ArchiveLimits, ArchiveWorkerRequest, ArchiveWorkerResponse};
use rrmm_artifacts::{accept_artifact, load_verified_artifact};
use rrmm_conflicts::{CrossLayerLimits, CrossLayerPolicy, UnrealMountAlias, correlate_pak_ue4ss};
use rrmm_deploy::{
    DeploymentPlan, DeploymentReceipt, DeploymentRequest, activate_deployment,
    inventory_game_files, load_receipt, plan_deployment, recover_incomplete,
};
use rrmm_domain::{BuildRecipe, InstallationSource, Profile};
use rrmm_manifest::{
    CatalogPackage, ManifestProvenance, ResolveRequest, infer_manifest, load_manifest,
    resolve_packages,
};
use rrmm_pak::{
    MemberHashEvidence, PakInventory, PakLimits, PakWorkerRequest, PakWorkerResponse,
    analyze_conflicts, discover_paks, overlapping_member_hash_requests,
    validate_inventory_contract,
};
use rrmm_recipes::{
    CatalogTrustFloor, SignedRecipeCatalog, SignedRootMetadata, TrustedRootKey, load_recipe,
    resolve_and_apply_verified_recipes, verify_signed_catalog,
};
use rrmm_steam::{
    DiscoveryOptions, discover_installations, inspect_manifest, is_game_running,
    launch_game_via_steam, load_build_recipe, validate_build_recipe,
};
use rrmm_store::{CatalogTrustState, PakCacheFingerprint, Store};
use rrmm_ue4ss::{
    LuaAdvisoryLimits, Ue4ssActivationLimits, Ue4ssInventoryLimits, Ue4ssLoaderIdentityLimits,
    Ue4ssRuntimeLogLimits, analyze_ue4ss_activation, analyze_ue4ss_lua, analyze_ue4ss_runtime_logs,
    inspect_ue4ss_loader_identity, inventory_ue4ss,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};

use rrmm_application::{
    DeploymentMetadata, RecipeCatalogValidation, RecipeDeploymentPlan, RecipeDeploymentResolution,
    materialize_deployment_request, validate_recipe_deployment_target,
};

const EMBEDDED_BUILD_RECIPE: &str = include_str!("../../../recipes/builds/23896268.json");
const EMBEDDED_TRUSTED_ROOTS: &str = include_str!("../../../trust/production-roots.json");
const RECIPE_CATALOG_CHANNEL: &str = "stable";

#[derive(Debug, Parser)]
#[command(name = "rrmm", version, about = "Retro Rewind Mod Manager core CLI")]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Discover Retro Rewind in Steam libraries without modifying it.
    Discover {
        #[arg(long)]
        steam_root: Option<PathBuf>,
        #[arg(long)]
        recipe: Option<PathBuf>,
        #[arg(long)]
        deep: bool,
        #[arg(long)]
        database: Option<PathBuf>,
    },
    /// Inspect one Steam app manifest and its installation.
    Inspect {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        steam_root: Option<PathBuf>,
        #[arg(long)]
        library_root: Option<PathBuf>,
        #[arg(long)]
        recipe: Option<PathBuf>,
        #[arg(long)]
        deep: bool,
    },
    /// Create or migrate the RRMM SQLite database.
    DatabaseInit {
        #[arg(long)]
        database: PathBuf,
    },
    /// Inspect ZIP or 7z metadata using the hostile-archive policy; never extracts.
    ArchivePreflight {
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        worker: Option<PathBuf>,
        #[arg(long, default_value_t = 120)]
        timeout_seconds: u64,
    },
    /// Extract an accepted ZIP or 7z into a new or empty quarantine staging directory.
    ArchiveExtract {
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        staging: PathBuf,
        #[arg(long)]
        worker: Option<PathBuf>,
        #[arg(long, default_value_t = 120)]
        timeout_seconds: u64,
    },
    /// Verify, extract, normalize, and atomically accept an archive into the local store.
    ArchiveImport {
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        database: Option<PathBuf>,
        #[arg(long)]
        worker: Option<PathBuf>,
        #[arg(long, default_value_t = 120)]
        timeout_seconds: u64,
    },
    /// Inspect a PAK and optionally hash one member without extracting it.
    PakInspect {
        #[arg(long)]
        pak: PathBuf,
        #[arg(long)]
        hash_member: Option<String>,
        #[arg(long)]
        worker: Option<PathBuf>,
        #[arg(long, default_value_t = 120)]
        timeout_seconds: u64,
    },
    /// Analyze member and cooked-package conflicts across two or more PAKs.
    PakConflicts {
        #[arg(long, required = true, num_args = 2..)]
        pak: Vec<PathBuf>,
        #[arg(long)]
        worker: Option<PathBuf>,
        #[arg(long, default_value_t = 120)]
        timeout_seconds: u64,
    },
    /// Correlate PAK cooked packages with literal UE4SS hook and notifier targets.
    PakUe4ssCorrelate {
        #[arg(long, required = true)]
        pak: Vec<PathBuf>,
        #[arg(long)]
        game_root: PathBuf,
        #[arg(long)]
        build_id: u64,
        #[arg(long)]
        worker: Option<PathBuf>,
        #[arg(long, default_value_t = 120)]
        timeout_seconds: u64,
    },
    /// Cache one build-specific PAK inventory after validating its index fingerprint.
    PakCache {
        #[arg(long)]
        pak: PathBuf,
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        build_id: u64,
        #[arg(long)]
        worker: Option<PathBuf>,
        #[arg(long, default_value_t = 120)]
        timeout_seconds: u64,
    },
    /// Recursively discover PAK candidates without following filesystem links.
    PakDiscover {
        #[arg(long)]
        root: PathBuf,
    },
    /// Inventory UE4SS loader candidates and module trees without executing or modifying them.
    Ue4ssInventory {
        #[arg(long)]
        game_root: PathBuf,
    },
    /// Hash an unambiguous canonical UE4SS proxy/core pair without following filesystem links.
    Ue4ssIdentity {
        #[arg(long)]
        game_root: PathBuf,
    },
    /// Reconcile bounded mods.txt and enabled.txt evidence for the selected UE4SS module tree.
    Ue4ssState {
        #[arg(long)]
        game_root: PathBuf,
    },
    /// Extract mutable runtime evidence from bounded UE4SS.log candidates without modifying them.
    Ue4ssLog {
        #[arg(long)]
        game_root: PathBuf,
    },
    /// Statically extract bounded advisory evidence from installed UE4SS Lua without executing it.
    Ue4ssAnalyze {
        #[arg(long)]
        game_root: PathBuf,
    },
    /// Create an empty managed profile.
    ProfileCreate {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: String,
    },
    /// Clone an existing managed profile.
    ProfileClone {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        source_id: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: String,
    },
    /// Replace profile selections using a version-checked JSON profile.
    ProfileEdit {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        expected_revision: u64,
    },
    /// List all managed profiles.
    ProfileList {
        #[arg(long)]
        database: PathBuf,
    },
    /// Select a profile for an installation without deploying it.
    ProfileSelect {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        installation_id: String,
        #[arg(long)]
        profile_id: String,
    },
    /// Delete an inactive managed profile.
    ProfileDelete {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        id: String,
    },
    /// Preview a complete deployment request without changing the game.
    DeployPreview {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        receipt: Option<PathBuf>,
        #[arg(long)]
        allow_unmanaged: bool,
    },
    /// Apply a reviewed deployment plan transactionally.
    DeployApply {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        confirm: bool,
    },
    /// Recover or clean all incomplete deployment journals.
    DeployRecover {
        #[arg(long)]
        state_root: PathBuf,
        #[arg(long)]
        confirm: bool,
    },
    /// Inventory managed, unmanaged, drifted, and unsafe game files.
    DeployInventory {
        #[arg(long)]
        game_root: PathBuf,
        #[arg(long)]
        state_root: PathBuf,
        #[arg(long)]
        installation_id: String,
    },
    /// Launch Retro Rewind through Steam with fixed App ID arguments.
    Launch {
        #[arg(long)]
        steam_executable: PathBuf,
    },
    /// Validate a strict rrmm-manifest JSON document.
    ManifestValidate {
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Infer a review-required manifest from an accepted artifact manifest.
    ManifestInfer {
        #[arg(long)]
        artifact_root: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        build_id: u64,
    },
    /// Resolve exact artifacts, variants, and package requirements.
    ManifestResolve {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        catalog: PathBuf,
    },
    /// Validate one declarative compatibility recipe without applying it.
    RecipeValidate {
        #[arg(long)]
        recipe: PathBuf,
    },
    /// Verify a signed recipe catalog and produce its next rollback floor.
    RecipeCatalogVerify {
        #[arg(long, hide = !cfg!(debug_assertions))]
        trusted_roots: Option<PathBuf>,
        #[arg(long)]
        root_metadata: PathBuf,
        #[arg(long)]
        recipe_catalog: PathBuf,
        #[arg(long)]
        database: PathBuf,
    },
    /// Verify and atomically preview recipe effects on a resolved package set.
    RecipeApply {
        #[arg(long, hide = !cfg!(debug_assertions))]
        trusted_roots: Option<PathBuf>,
        #[arg(long)]
        root_metadata: PathBuf,
        #[arg(long)]
        recipe_catalog: PathBuf,
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        package_catalog: PathBuf,
        #[arg(long)]
        artifact_store: PathBuf,
    },
    /// Verify recipes and materialize a reviewable deployment plan without changing the game.
    RecipeDeployPreview {
        #[arg(long, hide = !cfg!(debug_assertions))]
        trusted_roots: Option<PathBuf>,
        #[arg(long)]
        root_metadata: PathBuf,
        #[arg(long)]
        recipe_catalog: PathBuf,
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        package_catalog: PathBuf,
        #[arg(long)]
        artifact_store: PathBuf,
        #[arg(long)]
        game_root: PathBuf,
        #[arg(long)]
        state_root: PathBuf,
        #[arg(long)]
        installation_id: String,
        #[arg(long)]
        profile_id: String,
        #[arg(long)]
        transaction_id: String,
        #[arg(long)]
        receipt: Option<PathBuf>,
        #[arg(long)]
        allow_unmanaged: bool,
    },
    /// Reverify and apply an unchanged recipe deployment preview transactionally.
    RecipeDeployApply {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long, hide = !cfg!(debug_assertions))]
        trusted_roots: Option<PathBuf>,
        #[arg(long)]
        root_metadata: PathBuf,
        #[arg(long)]
        recipe_catalog: PathBuf,
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        package_catalog: PathBuf,
        #[arg(long)]
        artifact_store: PathBuf,
        #[arg(long)]
        confirm: bool,
    },
}

fn main() -> Result<()> {
    let arguments = Arguments::parse();
    match arguments.command {
        Command::Discover {
            steam_root,
            recipe,
            deep,
            database,
        } => {
            let recipe = resolve_recipe(recipe.as_deref())?;
            let report = discover_installations(DiscoveryOptions {
                steam_root_override: steam_root.as_deref(),
                recipe: Some(&recipe),
                deep,
            });
            if let Some(database) = database {
                let store = Store::open(&database)
                    .with_context(|| format!("failed to open {}", database.display()))?;
                for inspection in &report.installations {
                    store.upsert_installation(inspection)?;
                }
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Inspect {
            manifest,
            steam_root,
            library_root,
            recipe,
            deep,
        } => {
            let inferred_library = infer_library_root(&manifest)?;
            let library_root = library_root.as_deref().unwrap_or(&inferred_library);
            let steam_root = steam_root.as_deref().unwrap_or(library_root);
            let recipe = resolve_recipe(recipe.as_deref())?;
            let inspection = inspect_manifest(
                &manifest,
                steam_root,
                library_root,
                InstallationSource::UserOverride,
                Some(&recipe),
                deep,
            )?;
            println!("{}", serde_json::to_string_pretty(&inspection)?);
        }
        Command::DatabaseInit { database } => {
            let store = Store::open(&database)
                .with_context(|| format!("failed to open {}", database.display()))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "database": database,
                    "schema_version": store.schema_version()?,
                }))?
            );
        }
        Command::ArchivePreflight {
            archive,
            worker,
            timeout_seconds,
        } => {
            let response = run_archive_worker(
                worker.as_deref(),
                ArchiveWorkerRequest::Preflight {
                    archive: archive.clone(),
                    limits: ArchiveLimits::default(),
                },
                Duration::from_secs(timeout_seconds),
            )?;
            if !response.ok {
                bail!(
                    "{}",
                    response.error.unwrap_or_else(|| format!(
                        "archive preflight rejected {}",
                        archive.display()
                    ))
                );
            }
            let report = response
                .preflight
                .context("archive worker omitted its preflight report")?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.accepted {
                bail!(
                    "archive preflight rejected {} with {} policy issue(s)",
                    archive.display(),
                    report.rejections.len()
                );
            }
        }
        Command::ArchiveExtract {
            archive,
            staging,
            worker,
            timeout_seconds,
        } => {
            validate_owned_staging(&staging)?;
            let response = match run_archive_worker(
                worker.as_deref(),
                ArchiveWorkerRequest::Extract {
                    archive,
                    staging: staging.clone(),
                    limits: ArchiveLimits::default(),
                },
                Duration::from_secs(timeout_seconds),
            ) {
                Ok(response) => response,
                Err(error) => {
                    remove_owned_staging(&staging)?;
                    return Err(error);
                }
            };
            if let Some(report) = response.extraction {
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            if !response.ok {
                remove_owned_staging(&staging)?;
                bail!(
                    "{}",
                    response
                        .error
                        .unwrap_or_else(|| "archive extraction failed".to_owned())
                );
            }
        }
        Command::ArchiveImport {
            archive,
            store,
            database,
            worker,
            timeout_seconds,
        } => {
            let work_root = store.join(".work");
            std::fs::create_dir_all(&work_root)
                .with_context(|| format!("failed to create {}", work_root.display()))?;
            let staging = tempfile::Builder::new()
                .prefix("extract-")
                .tempdir_in(&work_root)
                .with_context(|| format!("failed to create staging in {}", work_root.display()))?;
            let response = run_archive_worker(
                worker.as_deref(),
                ArchiveWorkerRequest::Extract {
                    archive: archive.clone(),
                    staging: staging.path().to_path_buf(),
                    limits: ArchiveLimits::default(),
                },
                Duration::from_secs(timeout_seconds),
            )?;
            if !response.ok {
                bail!(
                    "{}",
                    response
                        .error
                        .unwrap_or_else(|| "archive extraction failed".to_owned())
                );
            }
            let extraction = response
                .extraction
                .context("archive worker omitted its extraction report")?;
            let artifact =
                accept_artifact(&archive, &extraction, &store, &ArchiveLimits::default())?;
            if let Some(database) = database {
                let state = Store::open(&database)
                    .with_context(|| format!("failed to open {}", database.display()))?;
                state.upsert_artifact(
                    &artifact.manifest.sha256,
                    &artifact.root,
                    &serde_json::to_value(&artifact.manifest)?,
                )?;
            }
            println!("{}", serde_json::to_string_pretty(&artifact)?);
        }
        Command::PakInspect {
            pak,
            hash_member: requested_member,
            worker,
            timeout_seconds,
        } => {
            let response = run_pak_worker(
                worker.as_deref(),
                PakWorkerRequest::Inspect {
                    pak,
                    limits: PakLimits::default(),
                    hash_members: requested_member.into_iter().collect(),
                },
                Duration::from_secs(timeout_seconds),
            )?;
            if !response.ok {
                bail!(
                    "{}",
                    response
                        .error
                        .unwrap_or_else(|| "PAK inspection failed".to_owned())
                );
            }
            let inventory = response
                .inventory
                .context("PAK worker omitted its inventory")?;
            if let Some(digest) = response.member_digests.into_iter().next() {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "inventory": inventory,
                        "member_digest": digest,
                    }))?
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&inventory)?);
            }
        }
        Command::PakConflicts {
            pak: pak_paths,
            worker,
            timeout_seconds,
        } => {
            let unique: BTreeSet<_> = pak_paths.iter().collect();
            if unique.len() != pak_paths.len() {
                bail!("pak-conflicts requires distinct PAK paths");
            }
            let timeout = Duration::from_secs(timeout_seconds);
            let limits = PakLimits::default();
            let mut inventories = Vec::with_capacity(pak_paths.len());
            for pak in &pak_paths {
                let response = run_pak_worker(
                    worker.as_deref(),
                    PakWorkerRequest::Inspect {
                        pak: pak.clone(),
                        limits: limits.clone(),
                        hash_members: Vec::new(),
                    },
                    timeout,
                )?;
                if !response.ok {
                    bail!(
                        "{}",
                        response
                            .error
                            .unwrap_or_else(|| format!("failed to inspect {}", pak.display()))
                    );
                }
                inventories.push(
                    response
                        .inventory
                        .context("PAK worker omitted its inventory")?,
                );
            }

            let requests = overlapping_member_hash_requests(&inventories);
            let mut by_archive = BTreeMap::<PathBuf, Vec<_>>::new();
            for request in &requests {
                by_archive
                    .entry(request.archive_path.clone())
                    .or_default()
                    .push(request);
            }
            let mut evidence = Vec::with_capacity(requests.len());
            for (pak, requests) in by_archive {
                let response = run_pak_worker(
                    worker.as_deref(),
                    PakWorkerRequest::Inspect {
                        pak: pak.clone(),
                        limits: limits.clone(),
                        hash_members: requests
                            .iter()
                            .map(|request| request.stored_path.clone())
                            .collect(),
                    },
                    timeout,
                )?;
                if !response.ok {
                    bail!(
                        "{}",
                        response
                            .error
                            .unwrap_or_else(|| format!("failed to hash {}", pak.display()))
                    );
                }
                let current_inventory = response
                    .inventory
                    .context("PAK worker omitted its inventory while hashing")?;
                let previous_inventory = inventories
                    .iter()
                    .find(|inventory| inventory.archive_path == pak)
                    .context("PAK hash response did not match an inventory")?;
                if current_inventory != *previous_inventory {
                    bail!("PAK inventory changed while analyzing {}", pak.display());
                }
                let digests: BTreeMap<_, _> = response
                    .member_digests
                    .into_iter()
                    .map(|digest| (digest.stored_path, digest.sha256))
                    .collect();
                for request in requests {
                    let sha256 = digests
                        .get(&request.stored_path)
                        .with_context(|| {
                            format!("PAK worker omitted hash for {}", request.stored_path)
                        })?
                        .clone();
                    evidence.push(MemberHashEvidence {
                        archive_path: pak.clone(),
                        collision_key: request.collision_key.clone(),
                        sha256,
                    });
                }
            }
            let graph = analyze_conflicts(&inventories, &evidence);
            println!("{}", serde_json::to_string_pretty(&graph)?);
        }
        Command::PakUe4ssCorrelate {
            pak: pak_paths,
            game_root,
            build_id,
            worker,
            timeout_seconds,
        } => {
            let build_recipe: BuildRecipe = serde_json::from_str(EMBEDDED_BUILD_RECIPE)
                .context("embedded build recipe is invalid")?;
            if build_id != build_recipe.build_id {
                bail!(
                    "pak-ue4ss-correlate has no mount policy for build {build_id}; supported build is {}",
                    build_recipe.build_id
                );
            }
            let correlation_limits = CrossLayerLimits::default();
            if pak_paths.len() > correlation_limits.max_paks {
                bail!(
                    "pak-ue4ss-correlate accepts at most {} PAKs, received {}",
                    correlation_limits.max_paks,
                    pak_paths.len()
                );
            }
            let mut canonical_paks = Vec::with_capacity(pak_paths.len());
            let mut unique_paks = BTreeSet::new();
            for pak in pak_paths {
                let canonical = std::fs::canonicalize(&pak)
                    .with_context(|| format!("failed to resolve {}", pak.display()))?;
                if !unique_paks.insert(canonical.clone()) {
                    bail!(
                        "pak-ue4ss-correlate requires distinct canonical PAK paths: {}",
                        canonical.display()
                    );
                }
                canonical_paks.push(canonical);
            }
            let timeout = Duration::from_secs(timeout_seconds);
            let limits = PakLimits::default();
            let mut inventories = Vec::with_capacity(canonical_paks.len());
            let mut package_count = 0_usize;
            for pak in canonical_paks {
                let observed_bytes = std::fs::metadata(&pak)
                    .with_context(|| format!("failed to inspect {}", pak.display()))?
                    .len();
                let response = run_pak_worker(
                    worker.as_deref(),
                    PakWorkerRequest::Inspect {
                        pak: pak.clone(),
                        limits: limits.clone(),
                        hash_members: Vec::new(),
                    },
                    timeout,
                )?;
                if !response.ok {
                    bail!(
                        "{}",
                        response
                            .error
                            .unwrap_or_else(|| format!("failed to inspect {}", pak.display()))
                    );
                }
                if response.error.is_some()
                    || !response.member_digests.is_empty()
                    || response.index_metadata_sha256.is_some()
                {
                    bail!(
                        "PAK worker returned fields inconsistent with an inventory-only request for {}",
                        pak.display()
                    );
                }
                let inventory = response
                    .inventory
                    .context("PAK worker omitted its inventory")?;
                validate_inventory_contract(&inventory, &pak, observed_bytes, &limits)
                    .with_context(|| {
                        format!(
                            "PAK worker returned an incoherent inventory for {}",
                            pak.display()
                        )
                    })?;
                if inventory.version != format!("V{}", build_recipe.pak_version) {
                    bail!(
                        "PAK {} reports container version {}; build {} requires V{}",
                        pak.display(),
                        inventory.version,
                        build_id,
                        build_recipe.pak_version
                    );
                }
                package_count = package_count
                    .checked_add(inventory.packages.len())
                    .context("cumulative cooked package count overflowed")?;
                if package_count > correlation_limits.max_packages {
                    bail!(
                        "pak-ue4ss-correlate cooked package count exceeds limit: {} > {}",
                        package_count,
                        correlation_limits.max_packages
                    );
                }
                inventories.push(inventory);
            }
            let lua = analyze_ue4ss_lua(
                &game_root,
                &Ue4ssInventoryLimits::default(),
                &LuaAdvisoryLimits::default(),
            )?;
            let activation = analyze_ue4ss_activation(
                &game_root,
                &Ue4ssInventoryLimits::default(),
                &Ue4ssActivationLimits::default(),
            )?;
            let report = correlate_pak_ue4ss(
                &inventories,
                &lua,
                Some(&activation),
                &CrossLayerPolicy {
                    build_id,
                    mount_aliases: vec![UnrealMountAlias {
                        object_root: "/Game".to_owned(),
                        virtual_root: "RetroRewind/Content".to_owned(),
                    }],
                },
                &correlation_limits,
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::PakCache {
            pak,
            database,
            build_id,
            worker,
            timeout_seconds,
        } => {
            let canonical_path = std::fs::canonicalize(&pak)
                .with_context(|| format!("failed to resolve {}", pak.display()))?;
            let before = pak_file_state(&canonical_path)?;
            let limits = PakLimits::default();
            let timeout = Duration::from_secs(timeout_seconds);
            let fingerprint_response = run_pak_worker(
                worker.as_deref(),
                PakWorkerRequest::Fingerprint {
                    pak: canonical_path.clone(),
                    limits: limits.clone(),
                },
                timeout,
            )?;
            if !fingerprint_response.ok {
                bail!(
                    "{}",
                    fingerprint_response
                        .error
                        .unwrap_or_else(|| "PAK fingerprint failed".to_owned())
                );
            }
            let index_metadata_sha256 = fingerprint_response
                .index_metadata_sha256
                .context("PAK worker omitted its index fingerprint")?;
            if pak_file_state(&canonical_path)? != before {
                bail!(
                    "PAK metadata changed while fingerprinting {}",
                    canonical_path.display()
                );
            }
            let fingerprint = PakCacheFingerprint {
                canonical_path: canonical_path.clone(),
                build_id,
                archive_bytes: before.archive_bytes,
                modified_ns: before.modified_ns,
                index_metadata_sha256: index_metadata_sha256.clone(),
            };
            let store = Store::open(&database)
                .with_context(|| format!("failed to open {}", database.display()))?;
            if let Some(inventory) = store.pak_inventory::<PakInventory>(&fingerprint)? {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "cache_hit": true,
                        "build_id": build_id,
                        "index_metadata_sha256": index_metadata_sha256,
                        "inventory": inventory,
                    }))?
                );
            } else {
                let response = run_pak_worker(
                    worker.as_deref(),
                    PakWorkerRequest::Inspect {
                        pak: canonical_path.clone(),
                        limits,
                        hash_members: Vec::new(),
                    },
                    timeout,
                )?;
                if !response.ok {
                    bail!(
                        "{}",
                        response
                            .error
                            .unwrap_or_else(|| "PAK inventory failed".to_owned())
                    );
                }
                let inventory = response
                    .inventory
                    .context("PAK worker omitted its inventory")?;
                if inventory.integrity.index_metadata_sha256 != index_metadata_sha256 {
                    bail!(
                        "PAK index changed while inventorying {}",
                        canonical_path.display()
                    );
                }
                if pak_file_state(&canonical_path)? != before {
                    bail!(
                        "PAK metadata changed while inventorying {}",
                        canonical_path.display()
                    );
                }
                store.upsert_pak_inventory(&fingerprint, &inventory)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "cache_hit": false,
                        "build_id": build_id,
                        "index_metadata_sha256": index_metadata_sha256,
                        "inventory": inventory,
                    }))?
                );
            }
        }
        Command::PakDiscover { root } => {
            let report = discover_paks(&root)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Ue4ssInventory { game_root } => {
            let report = inventory_ue4ss(&game_root, &Ue4ssInventoryLimits::default())?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Ue4ssIdentity { game_root } => {
            let report =
                inspect_ue4ss_loader_identity(&game_root, &Ue4ssLoaderIdentityLimits::default())?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Ue4ssState { game_root } => {
            let report = analyze_ue4ss_activation(
                &game_root,
                &Ue4ssInventoryLimits::default(),
                &Ue4ssActivationLimits::default(),
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Ue4ssLog { game_root } => {
            let report = analyze_ue4ss_runtime_logs(&game_root, &Ue4ssRuntimeLogLimits::default())?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Ue4ssAnalyze { game_root } => {
            let report = analyze_ue4ss_lua(
                &game_root,
                &Ue4ssInventoryLimits::default(),
                &LuaAdvisoryLimits::default(),
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::ProfileCreate { database, id, name } => {
            let store = open_store(&database)?;
            let profile = Profile {
                schema_version: 1,
                id,
                name,
                revision: 0,
                packages: Vec::new(),
                pak_load_order: Vec::new(),
            };
            store.create_profile(&profile)?;
            println!("{}", serde_json::to_string_pretty(&profile)?);
        }
        Command::ProfileClone {
            database,
            source_id,
            id,
            name,
        } => {
            let store = open_store(&database)?;
            let profile = store.clone_profile(&source_id, &id, &name)?;
            println!("{}", serde_json::to_string_pretty(&profile)?);
        }
        Command::ProfileEdit {
            database,
            profile,
            expected_revision,
        } => {
            let store = open_store(&database)?;
            let profile: Profile = read_json(&profile)?;
            let updated = store.update_profile(&profile, expected_revision)?;
            println!("{}", serde_json::to_string_pretty(&updated)?);
        }
        Command::ProfileList { database } => {
            let store = open_store(&database)?;
            println!("{}", serde_json::to_string_pretty(&store.profiles()?)?);
        }
        Command::ProfileSelect {
            database,
            installation_id,
            profile_id,
        } => {
            let store = open_store(&database)?;
            store.set_active_profile(&installation_id, &profile_id)?;
            let profile = store
                .active_profile(&installation_id)?
                .context("selected profile disappeared")?;
            println!("{}", serde_json::to_string_pretty(&profile)?);
        }
        Command::ProfileDelete { database, id } => {
            let store = open_store(&database)?;
            store.delete_profile(&id)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({ "deleted": id }))?
            );
        }
        Command::DeployPreview {
            request,
            receipt,
            allow_unmanaged,
        } => {
            let mut request: DeploymentRequest = read_json(&request)?;
            request.game_running = is_game_running();
            request.allow_unmanaged = allow_unmanaged;
            let receipt = match receipt {
                Some(path) => Some(read_json::<DeploymentReceipt>(&path)?),
                None => load_receipt(&request.state_root, &request.installation_id)?,
            };
            let plan = plan_deployment(request, receipt.as_ref())?;
            println!("{}", serde_json::to_string_pretty(&plan)?);
        }
        Command::DeployApply { plan, confirm } => {
            if !confirm {
                bail!("deploy-apply requires --confirm after reviewing the plan");
            }
            let plan: DeploymentPlan = read_json(&plan)?;
            let report = activate_deployment(&plan, is_game_running)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::DeployRecover {
            state_root,
            confirm,
        } => {
            if !confirm {
                bail!("deploy-recover requires --confirm");
            }
            let reports = recover_incomplete(&state_root, is_game_running)?;
            println!("{}", serde_json::to_string_pretty(&reports)?);
        }
        Command::DeployInventory {
            game_root,
            state_root,
            installation_id,
        } => {
            let receipt = load_receipt(&state_root, &installation_id)?;
            let report = inventory_game_files(&game_root, receipt.as_ref())?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Launch { steam_executable } => {
            let report = launch_game_via_steam(&steam_executable)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::ManifestValidate { manifest } => {
            let manifest = load_manifest(&manifest)?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
        Command::ManifestInfer {
            artifact_root,
            id,
            name,
            version,
            build_id,
        } => {
            let artifact = load_verified_artifact(&artifact_root)?;
            let inferred = infer_manifest(&artifact, &id, &name, &version, build_id)?;
            let catalog_package = CatalogPackage {
                artifact_sha256: artifact.sha256,
                manifest: inferred.manifest,
                provenance: ManifestProvenance::Inferred {
                    confidence: inferred.confidence,
                    reviewed: false,
                    issues: inferred.issues,
                },
            };
            println!("{}", serde_json::to_string_pretty(&catalog_package)?);
        }
        Command::ManifestResolve { request, catalog } => {
            let request: ResolveRequest = read_json(&request)?;
            let catalog: Vec<CatalogPackage> = read_json(&catalog)?;
            let report = resolve_packages(&request, &catalog)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::RecipeValidate { recipe } => {
            let recipe = load_recipe(&recipe)?;
            println!("{}", serde_json::to_string_pretty(&recipe)?);
        }
        Command::RecipeCatalogVerify {
            trusted_roots,
            root_metadata,
            recipe_catalog,
            database,
        } => {
            let roots = load_trusted_roots(trusted_roots.as_deref())?;
            let root: SignedRootMetadata = read_json(&root_metadata)?;
            let catalog: SignedRecipeCatalog = read_json(&recipe_catalog)?;
            let store = open_store(&database)?;
            let floor = catalog_trust_floor(&store, RECIPE_CATALOG_CHANNEL)?;
            let verified = verify_signed_catalog(&roots, &root, &catalog, &floor)?;
            let next_floor = verified.trust_floor();
            persist_catalog_trust_floor(&store, RECIPE_CATALOG_CHANNEL, &next_floor)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "channel": RECIPE_CATALOG_CHANNEL,
                    "next_trust_floor": next_floor,
                    "verified_catalog": verified,
                }))?
            );
        }
        Command::RecipeApply {
            trusted_roots,
            root_metadata,
            recipe_catalog,
            database,
            request,
            package_catalog,
            artifact_store,
        } => {
            let roots = load_trusted_roots(trusted_roots.as_deref())?;
            let root: SignedRootMetadata = read_json(&root_metadata)?;
            let signed_catalog: SignedRecipeCatalog = read_json(&recipe_catalog)?;
            let store = open_store(&database)?;
            let floor = catalog_trust_floor(&store, RECIPE_CATALOG_CHANNEL)?;
            let request: ResolveRequest = read_json(&request)?;
            let package_catalog: Vec<CatalogPackage> = read_json(&package_catalog)?;
            let verified = verify_signed_catalog(&roots, &root, &signed_catalog, &floor)?;
            let next_floor = verified.trust_floor();
            persist_catalog_trust_floor(&store, RECIPE_CATALOG_CHANNEL, &next_floor)?;
            let report = resolve_and_apply_verified_recipes(
                &artifact_store,
                &request,
                &package_catalog,
                &verified,
                &floor,
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "channel": RECIPE_CATALOG_CHANNEL,
                    "next_trust_floor": next_floor,
                    "application": report,
                }))?
            );
        }
        Command::RecipeDeployPreview {
            trusted_roots,
            root_metadata,
            recipe_catalog,
            database,
            request,
            package_catalog,
            artifact_store,
            game_root,
            state_root,
            installation_id,
            profile_id,
            transaction_id,
            receipt,
            allow_unmanaged,
        } => {
            let roots = load_trusted_roots(trusted_roots.as_deref())?;
            let root: SignedRootMetadata = read_json(&root_metadata)?;
            let signed_catalog: SignedRecipeCatalog = read_json(&recipe_catalog)?;
            let store = open_store(&database)?;
            let floor = catalog_trust_floor(&store, RECIPE_CATALOG_CHANNEL)?;
            let request: ResolveRequest = read_json(&request)?;
            let package_catalog: Vec<CatalogPackage> = read_json(&package_catalog)?;
            let build_recipe = resolve_recipe(None)?;
            let verified = verify_signed_catalog(&roots, &root, &signed_catalog, &floor)?;
            let next_floor = verified.trust_floor();
            persist_catalog_trust_floor(&store, RECIPE_CATALOG_CHANNEL, &next_floor)?;
            let report = resolve_and_apply_verified_recipes(
                &artifact_store,
                &request,
                &package_catalog,
                &verified,
                &floor,
            )?;
            let validation = validate_recipe_deployment_target(
                &store,
                &installation_id,
                &profile_id,
                &game_root,
                RecipeDeploymentResolution {
                    request: &request,
                    package_catalog: &package_catalog,
                    report: &report,
                },
                &build_recipe,
                RecipeCatalogValidation {
                    trust_floor: next_floor.clone(),
                    valid_until: verified.valid_until(),
                },
            )?;
            let authorized_ue4ss_policies = validation
                .ue4ss
                .as_ref()
                .map(|validation| validation.required_policies.iter().cloned().collect())
                .unwrap_or_default();
            let deployment = materialize_deployment_request(
                &artifact_store,
                &package_catalog,
                &report,
                &authorized_ue4ss_policies,
                DeploymentMetadata {
                    transaction_id,
                    installation_id,
                    profile_id,
                    game_root,
                    state_root,
                    allow_unmanaged,
                    game_running: is_game_running(),
                },
            )?;
            let receipt = match receipt {
                Some(path) => Some(read_json::<DeploymentReceipt>(&path)?),
                None => load_receipt(&deployment.state_root, &deployment.installation_id)?,
            };
            let plan = plan_deployment(deployment, receipt.as_ref())?;
            store.bind_installation_id(
                &plan.installation_id,
                &validation.manifest_path,
                &validation.game_root,
            )?;
            let preview = RecipeDeploymentPlan {
                schema_version: 1,
                plan,
                validation,
            };
            println!("{}", serde_json::to_string_pretty(&preview)?);
        }
        Command::RecipeDeployApply {
            plan,
            trusted_roots,
            root_metadata,
            recipe_catalog,
            database,
            package_catalog,
            artifact_store,
            confirm,
        } => {
            if !confirm {
                bail!("recipe-deploy-apply requires --confirm after reviewing the preview");
            }
            let preview: RecipeDeploymentPlan = read_json(&plan)?;
            if preview.schema_version != 1 {
                bail!(
                    "unsupported recipe deployment plan schema {}",
                    preview.schema_version
                );
            }
            let roots = load_trusted_roots(trusted_roots.as_deref())?;
            let root: SignedRootMetadata = read_json(&root_metadata)?;
            let signed_catalog: SignedRecipeCatalog = read_json(&recipe_catalog)?;
            let package_catalog: Vec<CatalogPackage> = read_json(&package_catalog)?;
            let store = open_store(&database)?;
            let floor = catalog_trust_floor(&store, RECIPE_CATALOG_CHANNEL)?;
            let verified = verify_signed_catalog(&roots, &root, &signed_catalog, &floor)?;
            let accepted_floor = verified.trust_floor();
            if accepted_floor != preview.validation.catalog.trust_floor
                || verified.valid_until() != preview.validation.catalog.valid_until
            {
                bail!("signed recipe catalog differs from the reviewed preview");
            }
            persist_catalog_trust_floor(&store, RECIPE_CATALOG_CHANNEL, &accepted_floor)?;
            let build_recipe = resolve_recipe(None)?;
            let report = resolve_and_apply_verified_recipes(
                &artifact_store,
                &preview.validation.request,
                &package_catalog,
                &verified,
                &floor,
            )?;
            let current_validation = validate_recipe_deployment_target(
                &store,
                &preview.plan.installation_id,
                &preview.plan.profile_id,
                &preview.plan.game_root,
                RecipeDeploymentResolution {
                    request: &preview.validation.request,
                    package_catalog: &package_catalog,
                    report: &report,
                },
                &build_recipe,
                RecipeCatalogValidation {
                    trust_floor: accepted_floor,
                    valid_until: verified.valid_until(),
                },
            )?;
            if current_validation != preview.validation {
                bail!("recipe deployment validation changed after preview");
            }
            store.validate_installation_binding(
                &preview.plan.installation_id,
                &current_validation.manifest_path,
                &current_validation.game_root,
            )?;
            let authorized_ue4ss_policies = current_validation
                .ue4ss
                .as_ref()
                .map(|validation| validation.required_policies.iter().cloned().collect())
                .unwrap_or_default();
            let deployment = materialize_deployment_request(
                &artifact_store,
                &package_catalog,
                &report,
                &authorized_ue4ss_policies,
                DeploymentMetadata {
                    transaction_id: preview.plan.transaction_id.clone(),
                    installation_id: preview.plan.installation_id.clone(),
                    profile_id: preview.plan.profile_id.clone(),
                    game_root: preview.plan.game_root.clone(),
                    state_root: preview.plan.state_root.clone(),
                    allow_unmanaged: preview.plan.allow_unmanaged,
                    game_running: is_game_running(),
                },
            )?;
            let receipt = load_receipt(&deployment.state_root, &deployment.installation_id)?;
            let current_plan = plan_deployment(deployment, receipt.as_ref())?;
            if current_plan != preview.plan {
                bail!("recipe deployment plan changed after preview");
            }
            let activation = activate_deployment(&preview.plan, is_game_running)?;
            println!("{}", serde_json::to_string_pretty(&activation)?);
        }
    }
    Ok(())
}

fn run_archive_worker(
    explicit_worker: Option<&Path>,
    request: ArchiveWorkerRequest,
    timeout: Duration,
) -> Result<ArchiveWorkerResponse> {
    let response: ArchiveWorkerResponse = run_json_worker(
        explicit_worker,
        "rrmm-archive-worker",
        "archive worker",
        &request,
        timeout,
    )?;
    if response.ok && !response.sandboxed {
        bail!("archive worker completed without the required OS sandbox");
    }
    Ok(response)
}

fn run_pak_worker(
    explicit_worker: Option<&Path>,
    request: PakWorkerRequest,
    timeout: Duration,
) -> Result<PakWorkerResponse> {
    let response: PakWorkerResponse = run_json_worker(
        explicit_worker,
        "rrmm-pak-worker",
        "PAK worker",
        &request,
        timeout,
    )?;
    if response.ok && !response.sandboxed {
        bail!("PAK worker completed without the required OS sandbox");
    }
    Ok(response)
}

fn run_json_worker<Request, Response>(
    explicit_worker: Option<&Path>,
    default_binary: &str,
    worker_label: &str,
    request: &Request,
    timeout: Duration,
) -> Result<Response>
where
    Request: Serialize,
    Response: DeserializeOwned,
{
    const MAX_RESPONSE_BYTES: u64 = 128 * 1024 * 1024;
    let worker = match explicit_worker {
        Some(path) => path.to_path_buf(),
        None => {
            let mut path = std::env::current_exe().context("failed to locate the RRMM CLI")?;
            path.set_file_name(format!("{default_binary}{}", std::env::consts::EXE_SUFFIX));
            path
        }
    };
    let mut child = ProcessCommand::new(&worker)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to start {worker_label} {}", worker.display()))?;

    let request_json = serde_json::to_vec(&request)?;
    child
        .stdin
        .take()
        .with_context(|| format!("{worker_label} stdin is unavailable"))?
        .write_all(&request_json)
        .with_context(|| format!("failed to send {worker_label} request"))?;
    let stdout = child
        .stdout
        .take()
        .with_context(|| format!("{worker_label} stdout is unavailable"))?;
    let output_reader = thread::spawn(move || {
        let mut output = Vec::new();
        stdout
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut output)
            .map(|_| output)
    });

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("failed to poll {worker_label}"))?
        {
            break status;
        }
        if started.elapsed() >= timeout {
            child
                .kill()
                .with_context(|| format!("failed to terminate timed-out {worker_label}"))?;
            child
                .wait()
                .with_context(|| format!("failed to reap timed-out {worker_label}"))?;
            let _ = output_reader.join();
            bail!(
                "{worker_label} timed out after {} seconds",
                timeout.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(20));
    };
    let output = output_reader
        .join()
        .map_err(|_| anyhow::anyhow!("{worker_label} output reader panicked"))??;
    if output.len() as u64 > MAX_RESPONSE_BYTES {
        bail!("{worker_label} response exceeded 128 MiB");
    }
    serde_json::from_slice(&output)
        .with_context(|| format!("{worker_label} returned invalid JSON with status {status}"))
}

fn validate_owned_staging(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!("staging must be a real directory: {}", path.display());
            }
            let mut entries = std::fs::read_dir(path)
                .with_context(|| format!("failed to inspect staging {}", path.display()))?;
            if entries.next().is_some() {
                bail!("staging must be empty: {}", path.display());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect staging {}", path.display()));
        }
    }
    Ok(())
}

fn remove_owned_staging(path: &Path) -> Result<()> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to clean staging {}", path.display()))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PakFileState {
    archive_bytes: u64,
    modified_ns: i64,
}

fn pak_file_state(path: &Path) -> Result<PakFileState> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("failed to inspect {}", path.display()))?;
    if !metadata.is_file() {
        bail!("PAK path is not a regular file: {}", path.display());
    }
    let modified = metadata
        .modified()
        .with_context(|| format!("failed to read modification time for {}", path.display()))?;
    let modified_ns = modified
        .duration_since(UNIX_EPOCH)
        .context("PAK modification time predates the Unix epoch")?
        .as_nanos()
        .try_into()
        .context("PAK modification time exceeds SQLite integer range")?;
    Ok(PakFileState {
        archive_bytes: metadata.len(),
        modified_ns,
    })
}

fn open_store(path: &Path) -> Result<Store> {
    Store::open(path).with_context(|| format!("failed to open {}", path.display()))
}

fn catalog_trust_floor(store: &Store, channel: &str) -> Result<CatalogTrustFloor> {
    Ok(match store.catalog_trust_state(channel)? {
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

fn persist_catalog_trust_floor(
    store: &Store,
    channel: &str,
    floor: &CatalogTrustFloor,
) -> Result<()> {
    let root_payload_sha256 = floor
        .root_payload_sha256
        .clone()
        .context("verified root metadata omitted its payload hash")?;
    let catalog_payload_sha256 = floor
        .catalog_payload_sha256
        .clone()
        .context("verified recipe catalog omitted its payload hash")?;
    store.advance_catalog_trust_state(
        channel,
        &CatalogTrustState {
            root_generation: floor.root_generation,
            root_payload_sha256,
            catalog_sequence: floor.catalog_sequence,
            catalog_payload_sha256,
        },
    )?;
    Ok(())
}

fn read_json<T>(path: &Path) -> Result<T>
where
    T: DeserializeOwned,
{
    let input = std::fs::read(path)
        .with_context(|| format!("failed to read JSON from {}", path.display()))?;
    serde_json::from_slice(&input).with_context(|| format!("invalid JSON in {}", path.display()))
}

fn load_trusted_roots(explicit: Option<&Path>) -> Result<Vec<TrustedRootKey>> {
    if let Some(path) = explicit {
        #[cfg(debug_assertions)]
        {
            let roots: Vec<TrustedRootKey> = read_json(path)?;
            if roots.is_empty() {
                bail!("development trusted-root override must not be empty");
            }
            return Ok(roots);
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = path;
            bail!("release builds reject external trusted-root overrides");
        }
    }
    let roots: Vec<TrustedRootKey> = serde_json::from_str(EMBEDDED_TRUSTED_ROOTS)
        .context("embedded production roots are invalid")?;
    if roots.is_empty() {
        bail!("no production root is embedded in this build");
    }
    Ok(roots)
}

fn resolve_recipe(path: Option<&Path>) -> Result<BuildRecipe> {
    match path {
        Some(path) => load_build_recipe(path).map_err(Into::into),
        None => {
            let recipe = serde_json::from_str(EMBEDDED_BUILD_RECIPE)
                .context("the embedded build recipe is invalid")?;
            validate_build_recipe(&recipe)?;
            Ok(recipe)
        }
    }
}

fn infer_library_root(manifest: &Path) -> Result<PathBuf> {
    let Some(steamapps) = manifest.parent() else {
        bail!("manifest path has no parent directory");
    };
    if !steamapps
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("steamapps"))
    {
        bail!("manifest path must be directly inside a steamapps directory");
    }
    let Some(library) = steamapps.parent() else {
        bail!("manifest path must be inside a steamapps directory");
    };
    Ok(library.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_catalog_commands_do_not_require_an_external_root_path() {
        assert!(
            Arguments::try_parse_from([
                "rrmm",
                "recipe-catalog-verify",
                "--root-metadata",
                "root.json",
                "--recipe-catalog",
                "catalog.json",
                "--database",
                "rrmm.sqlite",
            ])
            .is_ok()
        );
    }

    #[test]
    fn embedded_build_recipe_contains_the_reviewed_smart_shelf_policy() {
        let recipe = resolve_recipe(None).unwrap();
        let policy = recipe
            .ue4ss_loader_policies
            .iter()
            .find(|policy| policy.id == "ue4ss:smart-shelf-662df915-compatible")
            .unwrap();
        assert_eq!(policy.allowed_build_ids.len(), 1);
        assert_eq!(policy.known_unsafe_build_ids.len(), 1);

        let catalog: Vec<CatalogPackage> =
            serde_json::from_str(include_str!("../../../catalogs/packages/23896268.json")).unwrap();
        for package in catalog {
            if let Some(policy_id) = package.manifest.runtime_requirements.ue4ss_loader_policy {
                assert!(
                    recipe
                        .ue4ss_loader_policies
                        .iter()
                        .any(|policy| policy.id == policy_id),
                    "missing embedded UE4SS policy {policy_id}"
                );
            }
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    fn debug_builds_load_an_explicit_root_override() {
        let temporary = tempfile::TempDir::new().unwrap();
        let path = temporary.path().join("roots.json");
        let expected = vec![TrustedRootKey {
            key_id: "development-root".to_owned(),
            public_key: "development-public-key".to_owned(),
        }];
        std::fs::write(&path, serde_json::to_vec(&expected).unwrap()).unwrap();

        assert_eq!(load_trusted_roots(Some(&path)).unwrap(), expected);
    }
}
