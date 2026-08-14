use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use rrmm_archive::validate_entry_path;
use rrmm_artifacts::load_verified_artifact;
use rrmm_manifest::{
    CatalogPackage, ComponentType, ManifestProvenance, ResolutionBlocker, ResolutionReport,
    ResolveRequest, ResolveSelection, load_manifest, resolve_packages,
    validate_catalog_package_artifact, validate_manifest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const ROOT_CONTEXT: &[u8] = b"RRMM-ROOT-METADATA-v1\0";
const CATALOG_CONTEXT: &[u8] = b"RRMM-RECIPE-CATALOG-v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityRecipe {
    pub schema_version: u32,
    pub id: String,
    pub game_build: String,
    pub matches: Vec<RecipeMatch>,
    pub operations: Vec<RecipeOperation>,
    pub verification: RecipeVerification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeMatch {
    pub package_id: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecipeOperation {
    SelectWinner {
        winner_package_id: String,
        resource: String,
    },
    ReplaceWithCombined {
        remove_package_ids: Vec<String>,
        combined_package_id: String,
        combined_sha256: String,
    },
    RequireInstallName {
        package_id: String,
        install_name: String,
    },
    DisableComponent {
        package_id: String,
        component_id: String,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeVerification {
    pub offline: Vec<String>,
    pub in_game: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedRootKey {
    pub key_id: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedOnlineKey {
    pub key_id: String,
    pub public_key: String,
    pub valid_from: u64,
    pub valid_until: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootMetadata {
    pub schema_version: u32,
    pub generation: u64,
    pub expires_at: u64,
    pub online_keys: Vec<DelegatedOnlineKey>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_online_key_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeCatalog {
    pub schema_version: u32,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub recipes: Vec<CompatibilityRecipe>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachedSignature {
    pub key_id: String,
    pub algorithm: SignatureAlgorithm,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRootMetadata {
    pub signed: RootMetadata,
    pub signatures: Vec<DetachedSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRecipeCatalog {
    pub signed: RecipeCatalog,
    pub signatures: Vec<DetachedSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedRecipeCatalog {
    root_generation: u64,
    root_payload_sha256: String,
    sequence: u64,
    payload_sha256: String,
    valid_from: u64,
    valid_until: u64,
    recipes: Vec<CompatibilityRecipe>,
    signing_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogTrustFloor {
    pub root_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_payload_sha256: Option<String>,
    pub catalog_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_payload_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedRootMetadata {
    pub generation: u64,
    pub payload_sha256: String,
}

impl VerifiedRecipeCatalog {
    pub fn trust_floor(&self) -> CatalogTrustFloor {
        CatalogTrustFloor {
            root_generation: self.root_generation,
            root_payload_sha256: Some(self.root_payload_sha256.clone()),
            catalog_sequence: self.sequence,
            catalog_payload_sha256: Some(self.payload_sha256.clone()),
        }
    }

    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }

    pub fn recipes(&self) -> &[CompatibilityRecipe] {
        &self.recipes
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinnerDecision {
    pub recipe_id: String,
    pub winner_package_id: String,
    pub resource: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallNameOverride {
    pub recipe_id: String,
    pub package_id: String,
    pub install_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisabledComponent {
    pub recipe_id: String,
    pub package_id: String,
    pub component_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum RecipeApplicationBlocker {
    ResolutionNotReady,
    OverlappingRecipes {
        first: String,
        second: String,
    },
    OperationTargetMissing {
        recipe_id: String,
        target: String,
    },
    CombinedPackageUnavailable {
        recipe_id: String,
        artifact_sha256: String,
    },
    CombinedResolutionBlocked {
        recipe_id: String,
        blockers: Vec<ResolutionBlocker>,
    },
    ConflictingInstallName {
        package_id: String,
    },
    ConflictingWinner {
        resource: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeApplicationReport {
    pub ready: bool,
    pub resolution: ResolutionReport,
    pub applied_recipe_ids: Vec<String>,
    pub winner_decisions: Vec<WinnerDecision>,
    pub install_name_overrides: Vec<InstallNameOverride>,
    pub disabled_components: Vec<DisabledComponent>,
    pub blockers: Vec<RecipeApplicationBlocker>,
}

#[derive(Debug, Error)]
pub enum RecipeError {
    #[error("recipe JSON failed at {path}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("recipe I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid recipe or catalog: {0}")]
    Invalid(String),
    #[error("root metadata generation {actual} is below required generation {minimum}")]
    RootRollback { actual: u64, minimum: u64 },
    #[error("catalog sequence {actual} is below required sequence {minimum}")]
    CatalogRollback { actual: u64, minimum: u64 },
    #[error("signed metadata differs at an already accepted generation or sequence")]
    SameVersionMismatch,
    #[error("signed metadata is not valid at Unix time {0}")]
    Expired(u64),
    #[error("no trusted signature verified")]
    UntrustedSignature,
    #[error("system clock is before the Unix epoch")]
    InvalidSystemTime,
}

pub fn load_recipe(path: &Path) -> Result<CompatibilityRecipe, RecipeError> {
    let input = fs::read(path).map_err(|source| RecipeError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let recipe = serde_json::from_slice(&input).map_err(|source| RecipeError::Json {
        path: path.to_path_buf(),
        source,
    })?;
    validate_recipe(&recipe)?;
    Ok(recipe)
}

pub fn validate_recipe(recipe: &CompatibilityRecipe) -> Result<(), RecipeError> {
    if recipe.schema_version != 1 {
        return invalid(format!(
            "unsupported recipe schema {}",
            recipe.schema_version
        ));
    }
    validate_package_id(&recipe.id)?;
    let build = recipe
        .game_build
        .parse::<u64>()
        .map_err(|_| RecipeError::Invalid(format!("invalid game build '{}'", recipe.game_build)))?;
    if build == 0 || build.to_string() != recipe.game_build {
        return invalid(format!("non-canonical game build '{}'", recipe.game_build));
    }
    if recipe.matches.is_empty() || recipe.operations.is_empty() {
        return invalid("matches and operations must not be empty");
    }
    let mut package_ids = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    for matched in &recipe.matches {
        validate_package_id(&matched.package_id)?;
        validate_sha256(&matched.sha256)?;
        if !package_ids.insert(matched.package_id.clone()) || !hashes.insert(matched.sha256.clone())
        {
            return invalid("recipe matches must use unique package IDs and hashes");
        }
    }
    for operation in &recipe.operations {
        validate_operation(operation, &package_ids)?;
    }
    validate_verification(&recipe.verification)?;
    Ok(())
}

pub fn validate_root_metadata(metadata: &RootMetadata) -> Result<(), RecipeError> {
    validate_root_metadata_inner(metadata)
}

pub fn validate_recipe_catalog(catalog: &RecipeCatalog) -> Result<(), RecipeError> {
    validate_catalog(catalog)
}

pub fn root_signing_payload(metadata: &RootMetadata) -> Result<Vec<u8>, RecipeError> {
    validate_root_metadata_inner(metadata)?;
    signing_payload(ROOT_CONTEXT, metadata)
}

pub fn catalog_signing_payload(catalog: &RecipeCatalog) -> Result<Vec<u8>, RecipeError> {
    validate_catalog(catalog)?;
    signing_payload(CATALOG_CONTEXT, catalog)
}

pub fn verify_signed_catalog(
    trusted_roots: &[TrustedRootKey],
    root: &SignedRootMetadata,
    catalog: &SignedRecipeCatalog,
    floor: &CatalogTrustFloor,
) -> Result<VerifiedRecipeCatalog, RecipeError> {
    validate_trust_floor(floor)?;
    verify_signed_catalog_at(trusted_roots, root, catalog, system_unix_time()?, floor)
}

pub fn authenticate_historical_root_metadata_for_authoring(
    trusted_roots: &[TrustedRootKey],
    root: &SignedRootMetadata,
) -> Result<AuthenticatedRootMetadata, RecipeError> {
    validate_root_metadata_inner(&root.signed)?;
    let payload = root_signing_payload(&root.signed)?;
    verify_any_signature(trusted_roots, &root.signatures, &payload)?;
    Ok(AuthenticatedRootMetadata {
        generation: root.signed.generation,
        payload_sha256: format!("{:x}", Sha256::digest(&payload)),
    })
}

pub fn authenticate_historical_recipe_catalog_for_authoring(
    trusted_roots: &[TrustedRootKey],
    root: &SignedRootMetadata,
    catalog: &SignedRecipeCatalog,
) -> Result<CatalogTrustFloor, RecipeError> {
    let authenticated_root =
        authenticate_historical_root_metadata_for_authoring(trusted_roots, root)?;
    validate_catalog(&catalog.signed)?;
    let payload = catalog_signing_payload(&catalog.signed)?;
    let delegated: Vec<_> = root
        .signed
        .online_keys
        .iter()
        .map(|key| TrustedRootKey {
            key_id: key.key_id.clone(),
            public_key: key.public_key.clone(),
        })
        .collect();
    let signing_key_id = verify_any_signature(&delegated, &catalog.signatures, &payload)?;
    let signing_key = root
        .signed
        .online_keys
        .iter()
        .find(|key| key.key_id == signing_key_id)
        .ok_or(RecipeError::UntrustedSignature)?;
    if catalog.signed.issued_at < signing_key.valid_from
        || catalog.signed.expires_at > signing_key.valid_until
        || catalog.signed.expires_at > root.signed.expires_at
    {
        return invalid("catalog validity is not contained by root and delegated key validity");
    }
    Ok(CatalogTrustFloor {
        root_generation: authenticated_root.generation,
        root_payload_sha256: Some(authenticated_root.payload_sha256),
        catalog_sequence: catalog.signed.sequence,
        catalog_payload_sha256: Some(format!("{:x}", Sha256::digest(&payload))),
    })
}

fn verify_signed_catalog_at(
    trusted_roots: &[TrustedRootKey],
    root: &SignedRootMetadata,
    catalog: &SignedRecipeCatalog,
    now: u64,
    floor: &CatalogTrustFloor,
) -> Result<VerifiedRecipeCatalog, RecipeError> {
    validate_trust_floor(floor)?;
    validate_root_metadata_inner(&root.signed)?;
    if root.signed.generation < floor.root_generation {
        return Err(RecipeError::RootRollback {
            actual: root.signed.generation,
            minimum: floor.root_generation,
        });
    }
    if now > root.signed.expires_at {
        return Err(RecipeError::Expired(now));
    }
    let root_payload = signing_payload(ROOT_CONTEXT, &root.signed)?;
    let root_payload_sha256 = format!("{:x}", Sha256::digest(&root_payload));
    if root.signed.generation == floor.root_generation
        && floor
            .root_payload_sha256
            .as_ref()
            .is_some_and(|expected| expected != &root_payload_sha256)
    {
        return Err(RecipeError::SameVersionMismatch);
    }
    verify_any_signature(trusted_roots, &root.signatures, &root_payload)?;

    validate_catalog(&catalog.signed)?;
    if root.signed.generation == floor.root_generation
        && catalog.signed.sequence < floor.catalog_sequence
    {
        return Err(RecipeError::CatalogRollback {
            actual: catalog.signed.sequence,
            minimum: floor.catalog_sequence,
        });
    }
    if now < catalog.signed.issued_at || now > catalog.signed.expires_at {
        return Err(RecipeError::Expired(now));
    }
    let catalog_payload = signing_payload(CATALOG_CONTEXT, &catalog.signed)?;
    let payload_sha256 = format!("{:x}", Sha256::digest(&catalog_payload));
    if root.signed.generation == floor.root_generation
        && catalog.signed.sequence == floor.catalog_sequence
        && floor
            .catalog_payload_sha256
            .as_ref()
            .is_some_and(|expected| expected != &payload_sha256)
    {
        return Err(RecipeError::SameVersionMismatch);
    }
    let delegated: Vec<_> = root
        .signed
        .online_keys
        .iter()
        .filter(|key| now >= key.valid_from && now <= key.valid_until)
        .map(|key| TrustedRootKey {
            key_id: key.key_id.clone(),
            public_key: key.public_key.clone(),
        })
        .collect();
    let signing_key_id = verify_any_signature(&delegated, &catalog.signatures, &catalog_payload)?;
    let signing_key = root
        .signed
        .online_keys
        .iter()
        .find(|key| key.key_id == signing_key_id)
        .ok_or(RecipeError::UntrustedSignature)?;
    if catalog.signed.issued_at < signing_key.valid_from
        || catalog.signed.expires_at > signing_key.valid_until
        || catalog.signed.expires_at > root.signed.expires_at
    {
        return invalid("catalog validity is not contained by root and delegated key validity");
    }
    Ok(VerifiedRecipeCatalog {
        root_generation: root.signed.generation,
        root_payload_sha256,
        sequence: catalog.signed.sequence,
        payload_sha256,
        valid_from: catalog.signed.issued_at.max(signing_key.valid_from),
        valid_until: root
            .signed
            .expires_at
            .min(catalog.signed.expires_at)
            .min(signing_key.valid_until),
        recipes: catalog.signed.recipes.clone(),
        signing_key_id,
    })
}

pub fn resolve_and_apply_verified_recipes(
    artifact_store: &Path,
    request: &ResolveRequest,
    package_catalog: &[CatalogPackage],
    catalog: &VerifiedRecipeCatalog,
    floor: &CatalogTrustFloor,
) -> Result<RecipeApplicationReport, RecipeError> {
    validate_trust_floor(floor)?;
    for package in package_catalog
        .iter()
        .filter(|package| package.provenance == ManifestProvenance::Declared)
    {
        validate_declared_package_in_store(artifact_store, package)?;
    }
    let resolution = resolve_packages(request, package_catalog)
        .map_err(|error| RecipeError::Invalid(error.to_string()))?;
    apply_verified_recipes_at(
        &resolution,
        package_catalog,
        catalog,
        system_unix_time()?,
        floor,
    )
}

pub fn validate_declared_package_in_store(
    artifact_store: &Path,
    package: &CatalogPackage,
) -> Result<(), RecipeError> {
    if package.provenance != ManifestProvenance::Declared {
        return invalid(format!(
            "recipe application requires an embedded declared manifest for '{}'",
            package.manifest.id
        ));
    }
    validate_sha256(&package.artifact_sha256)?;
    let artifact_root = artifact_store
        .join("artifacts")
        .join(&package.artifact_sha256[..2])
        .join(&package.artifact_sha256);
    let artifact = load_verified_artifact(&artifact_root)
        .map_err(|error| RecipeError::Invalid(error.to_string()))?;
    validate_catalog_package_artifact(package, &artifact)
        .map_err(|error| RecipeError::Invalid(error.to_string()))?;
    if !artifact
        .files
        .iter()
        .any(|file| file.path == "rrmm-manifest.json")
    {
        return invalid(format!(
            "artifact '{}' has no embedded rrmm-manifest.json",
            package.artifact_sha256
        ));
    }
    let embedded = load_manifest(&artifact_root.join("files/rrmm-manifest.json"))
        .map_err(|error| RecipeError::Invalid(error.to_string()))?;
    if embedded != package.manifest {
        return invalid(format!(
            "catalog manifest for '{}' differs from its embedded manifest",
            package.manifest.id
        ));
    }
    Ok(())
}

fn apply_verified_recipes_at(
    resolution: &ResolutionReport,
    package_catalog: &[CatalogPackage],
    catalog: &VerifiedRecipeCatalog,
    now: u64,
    floor: &CatalogTrustFloor,
) -> Result<RecipeApplicationReport, RecipeError> {
    validate_verified_catalog(catalog, now, floor)?;
    apply_recipe_set(resolution, package_catalog, &catalog.recipes)
}

fn validate_verified_catalog(
    catalog: &VerifiedRecipeCatalog,
    now: u64,
    floor: &CatalogTrustFloor,
) -> Result<(), RecipeError> {
    if now < catalog.valid_from || now > catalog.valid_until {
        return Err(RecipeError::Expired(now));
    }
    if catalog.root_generation < floor.root_generation {
        return Err(RecipeError::RootRollback {
            actual: catalog.root_generation,
            minimum: floor.root_generation,
        });
    }
    if catalog.root_generation == floor.root_generation && catalog.sequence < floor.catalog_sequence
    {
        return Err(RecipeError::CatalogRollback {
            actual: catalog.sequence,
            minimum: floor.catalog_sequence,
        });
    }
    if catalog.root_generation == floor.root_generation
        && floor
            .root_payload_sha256
            .as_ref()
            .is_some_and(|expected| expected != &catalog.root_payload_sha256)
    {
        return Err(RecipeError::SameVersionMismatch);
    }
    if catalog.root_generation == floor.root_generation
        && catalog.sequence == floor.catalog_sequence
        && floor
            .catalog_payload_sha256
            .as_ref()
            .is_some_and(|expected| expected != &catalog.payload_sha256)
    {
        return Err(RecipeError::SameVersionMismatch);
    }
    Ok(())
}

fn validate_trust_floor(floor: &CatalogTrustFloor) -> Result<(), RecipeError> {
    match (floor.root_generation, &floor.root_payload_sha256) {
        (0, None) => {}
        (0, Some(_)) | (_, None) => {
            return invalid("root trust floor version and hash must be present together");
        }
        (_, Some(hash)) => validate_sha256(hash)?,
    }
    match (floor.catalog_sequence, &floor.catalog_payload_sha256) {
        (0, None) => {}
        (0, Some(_)) | (_, None) => {
            return invalid("catalog trust floor version and hash must be present together");
        }
        (_, Some(hash)) => validate_sha256(hash)?,
    }
    Ok(())
}

fn apply_recipe_set(
    resolution: &ResolutionReport,
    package_catalog: &[CatalogPackage],
    recipes: &[CompatibilityRecipe],
) -> Result<RecipeApplicationReport, RecipeError> {
    for recipe in recipes {
        validate_recipe(recipe)?;
    }
    let mut matched: Vec<_> = recipes
        .iter()
        .filter(|recipe| recipe_matches(recipe, resolution))
        .collect();
    matched.sort_by(|left, right| left.id.cmp(&right.id));
    if !resolution.ready && !blocked_incompatibilities_are_replaced(resolution, &matched) {
        return Ok(blocked_report(
            resolution,
            RecipeApplicationBlocker::ResolutionNotReady,
        ));
    }
    let mut claimed = BTreeMap::<String, String>::new();
    for recipe in &matched {
        for package in &recipe.matches {
            if let Some(first) = claimed.insert(package.package_id.clone(), recipe.id.clone()) {
                return Ok(blocked_report(
                    resolution,
                    RecipeApplicationBlocker::OverlappingRecipes {
                        first,
                        second: recipe.id.clone(),
                    },
                ));
            }
        }
    }

    let original = resolution.clone();
    let mut working = resolution.clone();
    let mut winners = BTreeMap::<String, WinnerDecision>::new();
    let mut install_names = BTreeMap::<String, InstallNameOverride>::new();
    let mut disabled = Vec::new();
    let mut blockers = Vec::new();
    for replacements in [true, false] {
        for recipe in &matched {
            for operation in recipe.operations.iter().filter(|operation| {
                matches!(operation, RecipeOperation::ReplaceWithCombined { .. }) == replacements
            }) {
                apply_operation(
                    recipe,
                    operation,
                    &mut OperationContext {
                        package_catalog,
                        resolution: &mut working,
                        winners: &mut winners,
                        install_names: &mut install_names,
                        disabled: &mut disabled,
                        blockers: &mut blockers,
                    },
                )?;
            }
        }
    }
    for decision in winners.values() {
        if !has_package(&working, &decision.winner_package_id) {
            blockers.push(RecipeApplicationBlocker::OperationTargetMissing {
                recipe_id: decision.recipe_id.clone(),
                target: decision.winner_package_id.clone(),
            });
        }
    }
    for override_value in install_names.values() {
        if !has_package(&working, &override_value.package_id) {
            blockers.push(RecipeApplicationBlocker::OperationTargetMissing {
                recipe_id: override_value.recipe_id.clone(),
                target: override_value.package_id.clone(),
            });
        }
    }
    for disabled_component in &disabled {
        let remains_enabled = working.packages.iter().any(|package| {
            package.package_id == disabled_component.package_id
                && package
                    .component_ids
                    .contains(&disabled_component.component_id)
        });
        if remains_enabled {
            blockers.push(RecipeApplicationBlocker::OperationTargetMissing {
                recipe_id: disabled_component.recipe_id.clone(),
                target: format!(
                    "{}:{} remained enabled",
                    disabled_component.package_id, disabled_component.component_id
                ),
            });
        }
    }
    if !working.ready || !working.blockers.is_empty() {
        blockers.push(RecipeApplicationBlocker::ResolutionNotReady);
    }
    let applied: Vec<_> = matched.iter().map(|recipe| recipe.id.clone()).collect();
    if !blockers.is_empty() {
        return Ok(RecipeApplicationReport {
            ready: false,
            resolution: original,
            applied_recipe_ids: Vec::new(),
            winner_decisions: Vec::new(),
            install_name_overrides: Vec::new(),
            disabled_components: Vec::new(),
            blockers,
        });
    }
    Ok(RecipeApplicationReport {
        ready: true,
        resolution: working,
        applied_recipe_ids: applied,
        winner_decisions: winners.into_values().collect(),
        install_name_overrides: install_names.into_values().collect(),
        disabled_components: disabled,
        blockers,
    })
}

fn blocked_incompatibilities_are_replaced(
    resolution: &ResolutionReport,
    matched: &[&CompatibilityRecipe],
) -> bool {
    !resolution.blockers.is_empty()
        && resolution.blockers.iter().all(|blocker| {
            let ResolutionBlocker::Incompatible { first, second } = blocker else {
                return false;
            };
            matched.iter().any(|recipe| {
                recipe.operations.iter().any(|operation| {
                    let RecipeOperation::ReplaceWithCombined {
                        remove_package_ids, ..
                    } = operation
                    else {
                        return false;
                    };
                    remove_package_ids.contains(first) && remove_package_ids.contains(second)
                })
            })
        })
}

struct OperationContext<'a> {
    package_catalog: &'a [CatalogPackage],
    resolution: &'a mut ResolutionReport,
    winners: &'a mut BTreeMap<String, WinnerDecision>,
    install_names: &'a mut BTreeMap<String, InstallNameOverride>,
    disabled: &'a mut Vec<DisabledComponent>,
    blockers: &'a mut Vec<RecipeApplicationBlocker>,
}

fn apply_operation(
    recipe: &CompatibilityRecipe,
    operation: &RecipeOperation,
    context: &mut OperationContext<'_>,
) -> Result<(), RecipeError> {
    let package_catalog = context.package_catalog;
    let resolution = &mut *context.resolution;
    let winners = &mut *context.winners;
    let install_names = &mut *context.install_names;
    let disabled = &mut *context.disabled;
    let blockers = &mut *context.blockers;
    match operation {
        RecipeOperation::SelectWinner {
            winner_package_id,
            resource,
        } => {
            if !has_package(resolution, winner_package_id) {
                blockers.push(RecipeApplicationBlocker::OperationTargetMissing {
                    recipe_id: recipe.id.clone(),
                    target: winner_package_id.clone(),
                });
            } else {
                let resource_key = validate_entry_path(resource, false, 64)
                    .map_err(|error| RecipeError::Invalid(error.to_string()))?
                    .collision_key;
                let decision = WinnerDecision {
                    recipe_id: recipe.id.clone(),
                    winner_package_id: winner_package_id.clone(),
                    resource: resource.clone(),
                };
                if winners.insert(resource_key, decision).is_some() {
                    blockers.push(RecipeApplicationBlocker::ConflictingWinner {
                        resource: resource.clone(),
                    });
                }
            }
        }
        RecipeOperation::RequireInstallName {
            package_id,
            install_name,
        } => {
            if !has_package(resolution, package_id) {
                blockers.push(RecipeApplicationBlocker::OperationTargetMissing {
                    recipe_id: recipe.id.clone(),
                    target: package_id.clone(),
                });
            } else if !install_override_is_safe(
                package_id,
                install_name,
                resolution,
                package_catalog,
                install_names,
            )? {
                blockers.push(RecipeApplicationBlocker::ConflictingInstallName {
                    package_id: package_id.clone(),
                });
            } else {
                let override_value = InstallNameOverride {
                    recipe_id: recipe.id.clone(),
                    package_id: package_id.clone(),
                    install_name: install_name.clone(),
                };
                if install_names
                    .insert(package_id.clone(), override_value)
                    .is_some()
                {
                    blockers.push(RecipeApplicationBlocker::ConflictingInstallName {
                        package_id: package_id.clone(),
                    });
                }
            }
        }
        RecipeOperation::DisableComponent {
            package_id,
            component_id,
            reason,
        } => {
            let Some(package) = resolution
                .packages
                .iter_mut()
                .find(|package| package.package_id == *package_id)
            else {
                blockers.push(RecipeApplicationBlocker::OperationTargetMissing {
                    recipe_id: recipe.id.clone(),
                    target: package_id.clone(),
                });
                return Ok(());
            };
            let Some(position) = package
                .component_ids
                .iter()
                .position(|component| component == component_id)
            else {
                blockers.push(RecipeApplicationBlocker::OperationTargetMissing {
                    recipe_id: recipe.id.clone(),
                    target: format!("{package_id}:{component_id}"),
                });
                return Ok(());
            };
            package.component_ids.remove(position);
            disabled.push(DisabledComponent {
                recipe_id: recipe.id.clone(),
                package_id: package_id.clone(),
                component_id: component_id.clone(),
                reason: reason.clone(),
            });
        }
        RecipeOperation::ReplaceWithCombined {
            remove_package_ids,
            combined_package_id,
            combined_sha256,
        } => {
            let Some(combined) = package_catalog.iter().find(|package| {
                package.artifact_sha256 == *combined_sha256
                    && package.manifest.id == *combined_package_id
            }) else {
                blockers.push(RecipeApplicationBlocker::CombinedPackageUnavailable {
                    recipe_id: recipe.id.clone(),
                    artifact_sha256: combined_sha256.clone(),
                });
                return Ok(());
            };
            validate_manifest(&combined.manifest)
                .map_err(|error| RecipeError::Invalid(error.to_string()))?;
            if matches!(
                combined.provenance,
                ManifestProvenance::Inferred {
                    reviewed: false,
                    ..
                }
            ) {
                blockers.push(RecipeApplicationBlocker::CombinedPackageUnavailable {
                    recipe_id: recipe.id.clone(),
                    artifact_sha256: combined_sha256.clone(),
                });
                return Ok(());
            }
            if remove_package_ids
                .iter()
                .any(|id| !has_package(resolution, id))
            {
                blockers.push(RecipeApplicationBlocker::OperationTargetMissing {
                    recipe_id: recipe.id.clone(),
                    target: remove_package_ids.join(","),
                });
                return Ok(());
            }
            let mut selections: Vec<_> = resolution
                .packages
                .iter()
                .filter(|package| {
                    !package.automatically_selected
                        && !remove_package_ids.contains(&package.package_id)
                })
                .map(|package| ResolveSelection {
                    artifact_sha256: package.artifact_sha256.clone(),
                    variant: package.variant.clone(),
                })
                .collect();
            selections.push(ResolveSelection {
                artifact_sha256: combined_sha256.clone(),
                variant: None,
            });
            let next = resolve_packages(
                &ResolveRequest {
                    build_id: resolution.build_id,
                    selections,
                },
                package_catalog,
            )
            .map_err(|error| RecipeError::Invalid(error.to_string()))?;
            if !next.ready || remove_package_ids.iter().any(|id| has_package(&next, id)) {
                blockers.push(RecipeApplicationBlocker::CombinedResolutionBlocked {
                    recipe_id: recipe.id.clone(),
                    blockers: next.blockers,
                });
            } else {
                *resolution = next;
            }
        }
    }
    Ok(())
}

fn install_override_is_safe(
    package_id: &str,
    install_name: &str,
    resolution: &ResolutionReport,
    package_catalog: &[CatalogPackage],
    overrides: &BTreeMap<String, InstallNameOverride>,
) -> Result<bool, RecipeError> {
    let requested = validate_entry_path(install_name, false, 1)
        .map_err(|error| RecipeError::Invalid(error.to_string()))?;
    let Some(target) = resolution
        .packages
        .iter()
        .find(|package| package.package_id == package_id)
    else {
        return Ok(false);
    };
    let Some(target_manifest) = package_catalog.iter().find(|package| {
        package.artifact_sha256 == target.artifact_sha256
            && package.manifest.id == target.package_id
    }) else {
        return Ok(false);
    };
    let target_paks = target_manifest
        .manifest
        .components
        .iter()
        .filter(|component| {
            component.component_type == ComponentType::Pak
                && target.component_ids.contains(&component.id)
        })
        .count();
    if target_paks != 1 {
        return Ok(false);
    }

    for package in &resolution.packages {
        if package.package_id == package_id {
            continue;
        }
        if let Some(existing_override) = overrides.get(&package.package_id) {
            let existing = validate_entry_path(&existing_override.install_name, false, 1)
                .map_err(|error| RecipeError::Invalid(error.to_string()))?;
            if existing.collision_key == requested.collision_key {
                return Ok(false);
            }
            continue;
        }
        let Some(catalog_package) = package_catalog.iter().find(|candidate| {
            candidate.artifact_sha256 == package.artifact_sha256
                && candidate.manifest.id == package.package_id
        }) else {
            return Ok(false);
        };
        for component in &catalog_package.manifest.components {
            if component.component_type != ComponentType::Pak
                || !package.component_ids.contains(&component.id)
            {
                continue;
            }
            let Some(existing_name) = &component.install_name else {
                return Ok(false);
            };
            let existing = validate_entry_path(existing_name, false, 1)
                .map_err(|error| RecipeError::Invalid(error.to_string()))?;
            if existing.collision_key == requested.collision_key {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn recipe_matches(recipe: &CompatibilityRecipe, resolution: &ResolutionReport) -> bool {
    recipe.game_build == resolution.build_id.to_string()
        && recipe.matches.iter().all(|matched| {
            resolution.packages.iter().any(|package| {
                package.package_id == matched.package_id
                    && package.artifact_sha256 == matched.sha256
            })
        })
}

fn has_package(resolution: &ResolutionReport, package_id: &str) -> bool {
    resolution
        .packages
        .iter()
        .any(|package| package.package_id == package_id)
}

fn blocked_report(
    resolution: &ResolutionReport,
    blocker: RecipeApplicationBlocker,
) -> RecipeApplicationReport {
    RecipeApplicationReport {
        ready: false,
        resolution: resolution.clone(),
        applied_recipe_ids: Vec::new(),
        winner_decisions: Vec::new(),
        install_name_overrides: Vec::new(),
        disabled_components: Vec::new(),
        blockers: vec![blocker],
    }
}

fn validate_operation(
    operation: &RecipeOperation,
    matched_packages: &BTreeSet<String>,
) -> Result<(), RecipeError> {
    match operation {
        RecipeOperation::SelectWinner {
            winner_package_id,
            resource,
        } => {
            require_match(winner_package_id, matched_packages)?;
            let normalized = validate_entry_path(resource, false, 64)
                .map_err(|error| RecipeError::Invalid(error.to_string()))?;
            if normalized.path != *resource {
                return invalid(format!("non-normalized winner resource '{resource}'"));
            }
        }
        RecipeOperation::ReplaceWithCombined {
            remove_package_ids,
            combined_package_id,
            combined_sha256,
        } => {
            if remove_package_ids.len() < 2 {
                return invalid("replace_with_combined requires at least two packages");
            }
            let mut unique = BTreeSet::new();
            for id in remove_package_ids {
                require_match(id, matched_packages)?;
                if !unique.insert(id) {
                    return invalid("replace_with_combined package IDs must be unique");
                }
            }
            validate_package_id(combined_package_id)?;
            if matched_packages.contains(combined_package_id) {
                return invalid("combined package must differ from matched packages");
            }
            validate_sha256(combined_sha256)?;
        }
        RecipeOperation::RequireInstallName {
            package_id,
            install_name,
        } => {
            require_match(package_id, matched_packages)?;
            let normalized = validate_entry_path(install_name, false, 1)
                .map_err(|error| RecipeError::Invalid(error.to_string()))?;
            if normalized.path != *install_name {
                return invalid(format!("non-normalized install name '{install_name}'"));
            }
            if !install_name.to_ascii_lowercase().ends_with(".pak") {
                return invalid("required install name must be a PAK filename");
            }
        }
        RecipeOperation::DisableComponent {
            package_id,
            component_id,
            reason,
        } => {
            require_match(package_id, matched_packages)?;
            validate_component_id(component_id)?;
            validate_text("disable reason", reason, 500)?;
        }
    }
    Ok(())
}

fn validate_verification(verification: &RecipeVerification) -> Result<(), RecipeError> {
    if verification.offline.is_empty() || verification.in_game.is_empty() {
        return invalid("offline and in_game verification must not be empty");
    }
    validate_text_list("offline verification", &verification.offline)?;
    validate_text_list("in-game verification", &verification.in_game)
}

fn validate_root_metadata_inner(metadata: &RootMetadata) -> Result<(), RecipeError> {
    if metadata.schema_version != 1
        || metadata.generation == 0
        || metadata.generation > i64::MAX as u64
        || metadata.expires_at == 0
        || metadata.online_keys.is_empty()
    {
        return invalid("invalid root metadata header");
    }
    let mut ids = BTreeSet::new();
    for key in &metadata.online_keys {
        validate_derived_key_id(&key.key_id)?;
        let verifying_key = decode_verifying_key(&key.public_key)?;
        let expected_key_id = format!("ed25519-{:x}", Sha256::digest(verifying_key.as_bytes()));
        if key.key_id != expected_key_id {
            return invalid("delegated online key ID does not match its public key");
        }
        if key.valid_from > key.valid_until
            || key.valid_until > metadata.expires_at
            || !ids.insert(&key.key_id)
        {
            return invalid("invalid or duplicate delegated online key");
        }
    }
    let mut revoked = BTreeSet::new();
    for key_id in &metadata.revoked_online_key_ids {
        validate_derived_key_id(key_id)?;
        if ids.contains(key_id) || !revoked.insert(key_id) {
            return invalid("revoked online key IDs must be unique and not delegated");
        }
    }
    Ok(())
}

fn validate_catalog(catalog: &RecipeCatalog) -> Result<(), RecipeError> {
    if catalog.schema_version != 1
        || catalog.sequence == 0
        || catalog.sequence > i64::MAX as u64
        || catalog.issued_at > catalog.expires_at
    {
        return invalid("invalid recipe catalog header");
    }
    let mut ids = BTreeSet::new();
    for recipe in &catalog.recipes {
        validate_recipe(recipe)?;
        if !ids.insert(&recipe.id) {
            return invalid(format!("duplicate recipe ID '{}'", recipe.id));
        }
    }
    Ok(())
}

fn verify_any_signature(
    keys: &[TrustedRootKey],
    signatures: &[DetachedSignature],
    payload: &[u8],
) -> Result<String, RecipeError> {
    for key in keys {
        validate_key_id(&key.key_id)?;
        decode_verifying_key(&key.public_key)?;
    }
    let key_map: BTreeMap<_, _> = keys.iter().map(|key| (&key.key_id, key)).collect();
    if key_map.len() != keys.len() {
        return invalid("duplicate trusted key ID");
    }
    for detached in signatures {
        if detached.algorithm != SignatureAlgorithm::Ed25519 {
            continue;
        }
        if validate_key_id(&detached.key_id).is_err() {
            continue;
        }
        let Some(key) = key_map.get(&detached.key_id) else {
            continue;
        };
        let verifying_key = decode_verifying_key(&key.public_key)?;
        let Ok(signature_bytes) = STANDARD.decode(&detached.signature) else {
            continue;
        };
        let Ok(signature) = Signature::from_slice(&signature_bytes) else {
            continue;
        };
        if verifying_key.verify_strict(payload, &signature).is_ok() {
            return Ok(detached.key_id.clone());
        }
    }
    Err(RecipeError::UntrustedSignature)
}

fn decode_verifying_key(value: &str) -> Result<VerifyingKey, RecipeError> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| RecipeError::Invalid("invalid base64 public key".to_owned()))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| RecipeError::Invalid("invalid Ed25519 public key length".to_owned()))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| RecipeError::Invalid("invalid Ed25519 public key".to_owned()))
}

fn signing_payload<T: Serialize>(context: &[u8], value: &T) -> Result<Vec<u8>, RecipeError> {
    let json = serde_json::to_vec(value).map_err(|error| {
        RecipeError::Invalid(format!("failed to serialize signed payload: {error}"))
    })?;
    let mut payload = Vec::with_capacity(context.len() + json.len());
    payload.extend_from_slice(context);
    payload.extend_from_slice(&json);
    Ok(payload)
}

fn require_match(id: &str, matches: &BTreeSet<String>) -> Result<(), RecipeError> {
    validate_package_id(id)?;
    if !matches.contains(id) {
        return invalid(format!("operation references unmatched package '{id}'"));
    }
    Ok(())
}

fn validate_text_list(field: &str, values: &[String]) -> Result<(), RecipeError> {
    let mut unique = BTreeSet::new();
    for value in values {
        validate_text(field, value, 500)?;
        if !unique.insert(value) {
            return invalid(format!("duplicate {field} entry"));
        }
    }
    Ok(())
}

fn validate_text(field: &str, value: &str, max: usize) -> Result<(), RecipeError> {
    if value.trim().is_empty() || value.chars().count() > max || value.contains(['\0', '\r', '\n'])
    {
        return invalid(format!("invalid {field}"));
    }
    Ok(())
}

fn validate_package_id(value: &str) -> Result<(), RecipeError> {
    if !(3..=128).contains(&value.len())
        || !value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
    {
        return invalid(format!("invalid package or recipe ID '{value}'"));
    }
    Ok(())
}

fn validate_component_id(value: &str) -> Result<(), RecipeError> {
    if !(2..=64).contains(&value.len())
        || !value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return invalid(format!("invalid component ID '{value}'"));
    }
    Ok(())
}

fn validate_key_id(value: &str) -> Result<(), RecipeError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return invalid(format!("invalid key ID '{value}'"));
    }
    Ok(())
}

fn validate_derived_key_id(value: &str) -> Result<(), RecipeError> {
    let Some(hash) = value.strip_prefix("ed25519-") else {
        return invalid(format!("invalid derived key ID '{value}'"));
    };
    validate_sha256(hash)
        .map_err(|_| RecipeError::Invalid(format!("invalid derived key ID '{value}'")))
}

fn validate_sha256(value: &str) -> Result<(), RecipeError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(format!("invalid lowercase SHA-256 '{value}'"));
    }
    Ok(())
}

fn invalid<T>(detail: impl Into<String>) -> Result<T, RecipeError> {
    Err(RecipeError::Invalid(detail.into()))
}

fn system_unix_time() -> Result<u64, RecipeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| RecipeError::InvalidSystemTime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rrmm_archive::{ArchiveLimits, extract_zip_to_staging};
    use rrmm_artifacts::accept_artifact;
    use rrmm_manifest::{ComponentType, ManifestComponent, ManifestGame, PackageManifest};
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;

    #[test]
    fn validates_the_phase_zero_recipe_and_rejects_unsafe_operations() {
        let fixture = include_str!("../../../fixtures/recipe.valid.json");
        let recipe: CompatibilityRecipe = serde_json::from_str(fixture).unwrap();
        validate_recipe(&recipe).unwrap();

        let mut value: serde_json::Value = serde_json::from_str(fixture).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<CompatibilityRecipe>(value).is_err());
        let mut value: serde_json::Value = serde_json::from_str(fixture).unwrap();
        value["operations"][0]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<CompatibilityRecipe>(value).is_err());

        let mut unsafe_recipe = recipe;
        unsafe_recipe.operations = vec![RecipeOperation::RequireInstallName {
            package_id: "local:example-a".to_owned(),
            install_name: "../outside.pak".to_owned(),
        }];
        assert!(matches!(
            validate_recipe(&unsafe_recipe),
            Err(RecipeError::Invalid(_))
        ));
    }

    #[test]
    fn verifies_root_delegation_catalog_signature_expiry_and_rollback() {
        let root_signing = SigningKey::from_bytes(&[1_u8; 32]);
        let online_signing = SigningKey::from_bytes(&[2_u8; 32]);
        let online_key_id = format!(
            "ed25519-{:x}",
            Sha256::digest(online_signing.verifying_key().as_bytes())
        );
        let root_metadata = RootMetadata {
            schema_version: 1,
            generation: 3,
            expires_at: 200,
            online_keys: vec![DelegatedOnlineKey {
                key_id: online_key_id.clone(),
                public_key: STANDARD.encode(online_signing.verifying_key().as_bytes()),
                valid_from: 50,
                valid_until: 150,
            }],
            revoked_online_key_ids: Vec::new(),
        };
        let catalog = RecipeCatalog {
            schema_version: 1,
            sequence: 7,
            issued_at: 80,
            expires_at: 140,
            recipes: vec![fixture_recipe()],
        };
        let signed_root = SignedRootMetadata {
            signatures: vec![sign(
                "root-1",
                &root_signing,
                &signing_payload(ROOT_CONTEXT, &root_metadata).unwrap(),
            )],
            signed: root_metadata,
        };
        let signed_catalog = SignedRecipeCatalog {
            signatures: vec![sign(
                &online_key_id,
                &online_signing,
                &signing_payload(CATALOG_CONTEXT, &catalog).unwrap(),
            )],
            signed: catalog,
        };
        let roots = vec![TrustedRootKey {
            key_id: "root-1".to_owned(),
            public_key: STANDARD.encode(root_signing.verifying_key().as_bytes()),
        }];

        let authenticated_root =
            authenticate_historical_root_metadata_for_authoring(&roots, &signed_root).unwrap();
        assert_eq!(authenticated_root.generation, 3);
        let authenticated_catalog = authenticate_historical_recipe_catalog_for_authoring(
            &roots,
            &signed_root,
            &signed_catalog,
        )
        .unwrap();
        assert_eq!(authenticated_catalog.root_generation, 3);
        assert_eq!(authenticated_catalog.catalog_sequence, 7);

        assert!(matches!(
            verify_signed_catalog_at(
                &roots,
                &signed_root,
                &signed_catalog,
                100,
                &CatalogTrustFloor {
                    root_generation: 3,
                    root_payload_sha256: None,
                    catalog_sequence: 0,
                    catalog_payload_sha256: None,
                }
            ),
            Err(RecipeError::Invalid(_))
        ));

        let verified =
            verify_signed_catalog_at(&roots, &signed_root, &signed_catalog, 100, &floor(0, 0))
                .unwrap();
        let accepted_floor = verified.trust_floor();
        assert_eq!(verified.sequence, 7);
        assert_eq!(verified.signing_key_id, online_key_id);
        assert_eq!(verified.recipes.len(), 1);

        let recovery_online = SigningKey::from_bytes(&[3_u8; 32]);
        let recovery_key_id = format!(
            "ed25519-{:x}",
            Sha256::digest(recovery_online.verifying_key().as_bytes())
        );
        let mut recovery_root = signed_root.clone();
        recovery_root.signed.generation = 4;
        recovery_root.signed.online_keys = vec![DelegatedOnlineKey {
            key_id: recovery_key_id.clone(),
            public_key: STANDARD.encode(recovery_online.verifying_key().as_bytes()),
            valid_from: 50,
            valid_until: 150,
        }];
        recovery_root.signed.revoked_online_key_ids = vec![online_key_id.clone()];
        recovery_root.signatures = vec![sign(
            "root-1",
            &root_signing,
            &signing_payload(ROOT_CONTEXT, &recovery_root.signed).unwrap(),
        )];
        let mut recovery_catalog = signed_catalog.clone();
        recovery_catalog.signed.sequence = 1;
        recovery_catalog.signatures = vec![sign(
            &recovery_key_id,
            &recovery_online,
            &signing_payload(CATALOG_CONTEXT, &recovery_catalog.signed).unwrap(),
        )];
        let poisoned_floor = CatalogTrustFloor {
            root_generation: accepted_floor.root_generation,
            root_payload_sha256: accepted_floor.root_payload_sha256.clone(),
            catalog_sequence: i64::MAX as u64,
            catalog_payload_sha256: Some("0".repeat(64)),
        };
        let recovered = verify_signed_catalog_at(
            &roots,
            &recovery_root,
            &recovery_catalog,
            100,
            &poisoned_floor,
        )
        .unwrap();
        assert_eq!(recovered.trust_floor().root_generation, 4);
        assert_eq!(recovered.trust_floor().catalog_sequence, 1);

        let mut revoked_catalog = recovery_catalog.clone();
        revoked_catalog.signatures = vec![sign(
            &online_key_id,
            &online_signing,
            &signing_payload(CATALOG_CONTEXT, &revoked_catalog.signed).unwrap(),
        )];
        assert!(matches!(
            verify_signed_catalog_at(
                &roots,
                &recovery_root,
                &revoked_catalog,
                100,
                &poisoned_floor
            ),
            Err(RecipeError::UntrustedSignature)
        ));

        let mut overlong_catalog = signed_catalog.clone();
        overlong_catalog.signed.expires_at = 160;
        overlong_catalog.signatures = vec![sign(
            &online_key_id,
            &online_signing,
            &signing_payload(CATALOG_CONTEXT, &overlong_catalog.signed).unwrap(),
        )];
        assert!(matches!(
            verify_signed_catalog_at(&roots, &signed_root, &overlong_catalog, 100, &floor(0, 0)),
            Err(RecipeError::Invalid(_))
        ));

        let mut overlong_delegation = signed_root.clone();
        overlong_delegation.signed.online_keys[0].valid_until = 201;
        overlong_delegation.signatures = vec![sign(
            "root-1",
            &root_signing,
            &signing_payload(ROOT_CONTEXT, &overlong_delegation.signed).unwrap(),
        )];
        assert!(matches!(
            verify_signed_catalog_at(
                &roots,
                &overlong_delegation,
                &signed_catalog,
                100,
                &floor(0, 0)
            ),
            Err(RecipeError::Invalid(_))
        ));

        assert!(matches!(
            verify_signed_catalog_at(
                &roots,
                &signed_root,
                &signed_catalog,
                100,
                &CatalogTrustFloor {
                    root_generation: 4,
                    ..accepted_floor.clone()
                }
            ),
            Err(RecipeError::RootRollback { .. })
        ));
        assert!(matches!(
            verify_signed_catalog_at(
                &roots,
                &signed_root,
                &signed_catalog,
                100,
                &CatalogTrustFloor {
                    catalog_sequence: 8,
                    ..accepted_floor.clone()
                }
            ),
            Err(RecipeError::CatalogRollback { .. })
        ));
        assert!(matches!(
            verify_signed_catalog_at(&roots, &signed_root, &signed_catalog, 151, &accepted_floor),
            Err(RecipeError::Expired(_)) | Err(RecipeError::UntrustedSignature)
        ));

        let mut tampered = signed_catalog.clone();
        tampered.signed.sequence = 8;
        assert!(matches!(
            verify_signed_catalog_at(&roots, &signed_root, &tampered, 100, &accepted_floor),
            Err(RecipeError::UntrustedSignature)
        ));

        let mismatched_floor = CatalogTrustFloor {
            root_generation: 3,
            root_payload_sha256: Some("0".repeat(64)),
            catalog_sequence: 7,
            catalog_payload_sha256: accepted_floor.catalog_payload_sha256.clone(),
        };
        assert!(matches!(
            verify_signed_catalog_at(
                &roots,
                &signed_root,
                &signed_catalog,
                100,
                &mismatched_floor
            ),
            Err(RecipeError::SameVersionMismatch)
        ));

        let mut with_malformed = signed_catalog.clone();
        with_malformed.signatures.insert(
            0,
            DetachedSignature {
                key_id: online_key_id,
                algorithm: SignatureAlgorithm::Ed25519,
                signature: "!".to_owned(),
            },
        );
        assert!(
            verify_signed_catalog_at(&roots, &signed_root, &with_malformed, 100, &accepted_floor)
                .is_ok()
        );
    }

    #[test]
    fn applies_an_exact_combined_replacement_atomically() {
        let a = catalog_package("local:example-a", "a");
        let b = catalog_package("local:example-b", "b");
        let combined = catalog_package("local:example-combined", "c");
        let resolution = ResolutionReport {
            build_id: 23_896_268,
            ready: true,
            packages: vec![resolved(&a), resolved(&b)],
            blockers: Vec::new(),
        };

        let verified = verified_catalog(vec![fixture_recipe()]);
        let package_catalog = vec![a, b, combined];
        assert!(matches!(
            apply_verified_recipes_at(&resolution, &package_catalog, &verified, 201, &floor(1, 1)),
            Err(RecipeError::Expired(201))
        ));
        let report =
            apply_verified_recipes_at(&resolution, &package_catalog, &verified, 100, &floor(1, 1))
                .unwrap();

        assert!(report.ready);
        assert_eq!(
            report.applied_recipe_ids,
            vec!["compat:example-a-example-b"]
        );
        assert_eq!(report.resolution.packages.len(), 1);
        assert_eq!(
            report.resolution.packages[0].package_id,
            "local:example-combined"
        );
    }

    #[test]
    fn exact_combined_replacement_can_repair_declared_incompatibility() {
        let mut a = catalog_package("local:example-a", "a");
        let mut b = catalog_package("local:example-b", "b");
        let mut combined = catalog_package("local:example-combined", "c");
        a.manifest.incompatibilities = vec![b.manifest.id.clone()];
        b.manifest.incompatibilities = vec![a.manifest.id.clone()];
        combined.manifest.replaces = vec![a.manifest.id.clone(), b.manifest.id.clone()];
        let package_catalog = vec![a, b, combined];
        let resolution = resolve_packages(
            &ResolveRequest {
                build_id: 23_896_268,
                selections: vec![
                    ResolveSelection {
                        artifact_sha256: "a".repeat(64),
                        variant: None,
                    },
                    ResolveSelection {
                        artifact_sha256: "b".repeat(64),
                        variant: None,
                    },
                ],
            },
            &package_catalog,
        )
        .unwrap();
        assert!(!resolution.ready);
        assert!(
            resolution
                .blockers
                .iter()
                .all(|blocker| matches!(blocker, ResolutionBlocker::Incompatible { .. }))
        );

        let report = apply_verified_recipes_at(
            &resolution,
            &package_catalog,
            &verified_catalog(vec![fixture_recipe()]),
            100,
            &floor(1, 1),
        )
        .unwrap();

        assert!(report.ready);
        assert_eq!(report.resolution.packages.len(), 1);
        assert_eq!(
            report.resolution.packages[0].package_id,
            "local:example-combined"
        );
    }

    #[test]
    fn authored_combined_recipe_repairs_its_exact_catalog_incompatibility() {
        let package_catalog: Vec<CatalogPackage> =
            serde_json::from_str(include_str!("../../../catalogs/packages/23896268.json")).unwrap();
        let recipe: CompatibilityRecipe = serde_json::from_str(include_str!(
            "../../../recipes/compatibility/23896268/unrewound-tape-fee--employee-fee-policy.json"
        ))
        .unwrap();
        let resolution = resolve_packages(
            &ResolveRequest {
                build_id: 23_896_268,
                selections: recipe
                    .matches
                    .iter()
                    .map(|matched| ResolveSelection {
                        artifact_sha256: matched.sha256.clone(),
                        variant: None,
                    })
                    .collect(),
            },
            &package_catalog,
        )
        .unwrap();
        assert!(!resolution.ready);

        let report = apply_recipe_set(&resolution, &package_catalog, &[recipe]).unwrap();

        assert!(report.ready);
        assert_eq!(
            report.resolution.packages[0].package_id,
            "nexus:unrewound-tape-fee-employee-fee-policy"
        );
        assert_eq!(
            report.resolution.packages[0].artifact_sha256,
            "8a151b1f80c6e43444e303711fb5470058875a7816dd141864452a1d73ad47d9"
        );
    }

    #[test]
    fn applies_declarative_decisions_and_rejects_overlapping_recipes() {
        let a = catalog_package("local:example-a", "a");
        let b = catalog_package("local:example-b", "b");
        let resolution = ResolutionReport {
            build_id: 23_896_268,
            ready: true,
            packages: vec![resolved(&a), resolved(&b)],
            blockers: Vec::new(),
        };
        let recipe = CompatibilityRecipe {
            schema_version: 1,
            id: "compat:decisions".to_owned(),
            game_build: "23896268".to_owned(),
            matches: vec![
                RecipeMatch {
                    package_id: "local:example-a".to_owned(),
                    sha256: "a".repeat(64),
                },
                RecipeMatch {
                    package_id: "local:example-b".to_owned(),
                    sha256: "b".repeat(64),
                },
            ],
            operations: vec![
                RecipeOperation::SelectWinner {
                    winner_package_id: "local:example-a".to_owned(),
                    resource: "test/resource".to_owned(),
                },
                RecipeOperation::RequireInstallName {
                    package_id: "local:example-a".to_owned(),
                    install_name: "Example_9999_P.pak".to_owned(),
                },
                RecipeOperation::DisableComponent {
                    package_id: "local:example-b".to_owned(),
                    component_id: "pak".to_owned(),
                    reason: "known unsafe component".to_owned(),
                },
            ],
            verification: verification(),
        };
        let verified = verified_catalog(vec![recipe.clone()]);
        let report =
            apply_verified_recipes_at(&resolution, &[a, b], &verified, 100, &floor(1, 1)).unwrap();
        assert!(report.ready);
        assert_eq!(report.winner_decisions.len(), 1);
        assert_eq!(report.install_name_overrides.len(), 1);
        assert_eq!(report.disabled_components.len(), 1);
        assert!(report.resolution.packages[1].component_ids.is_empty());

        let mut overlap = recipe;
        overlap.id = "compat:overlap".to_owned();
        let verified = verified_catalog(vec![overlap.clone(), {
            let mut second = overlap;
            second.id = "compat:overlap-two".to_owned();
            second
        }]);
        let report =
            apply_verified_recipes_at(&resolution, &[], &verified, 100, &floor(1, 1)).unwrap();
        assert!(!report.ready);
        assert!(matches!(
            report.blockers.as_slice(),
            [RecipeApplicationBlocker::OverlappingRecipes { .. }]
        ));
    }

    #[test]
    fn replacements_precede_other_operations_and_install_names_cannot_collide() {
        let a = catalog_package("local:example-a", "a");
        let b = catalog_package("local:example-b", "b");
        let combined = catalog_package("local:example-combined", "c");
        let retained = catalog_package("local:retained", "d");
        let resolution = ResolutionReport {
            build_id: 23_896_268,
            ready: true,
            packages: vec![resolved(&a), resolved(&b), resolved(&retained)],
            blockers: Vec::new(),
        };
        let recipe = CompatibilityRecipe {
            schema_version: 1,
            id: "compat:ordered".to_owned(),
            game_build: "23896268".to_owned(),
            matches: vec![
                RecipeMatch {
                    package_id: "local:example-a".to_owned(),
                    sha256: "a".repeat(64),
                },
                RecipeMatch {
                    package_id: "local:example-b".to_owned(),
                    sha256: "b".repeat(64),
                },
                RecipeMatch {
                    package_id: "local:retained".to_owned(),
                    sha256: "d".repeat(64),
                },
            ],
            operations: vec![
                RecipeOperation::DisableComponent {
                    package_id: "local:retained".to_owned(),
                    component_id: "pak".to_owned(),
                    reason: "disable after replacement".to_owned(),
                },
                RecipeOperation::ReplaceWithCombined {
                    remove_package_ids: vec![
                        "local:example-a".to_owned(),
                        "local:example-b".to_owned(),
                    ],
                    combined_package_id: "local:example-combined".to_owned(),
                    combined_sha256: "c".repeat(64),
                },
            ],
            verification: verification(),
        };
        let package_catalog = vec![a, b, combined, retained];
        let report = apply_verified_recipes_at(
            &resolution,
            &package_catalog,
            &verified_catalog(vec![recipe]),
            100,
            &floor(1, 1),
        )
        .unwrap();
        assert!(report.ready);
        assert!(
            report
                .resolution
                .packages
                .iter()
                .find(|package| package.package_id == "local:retained")
                .unwrap()
                .component_ids
                .is_empty()
        );

        let collision = CompatibilityRecipe {
            schema_version: 1,
            id: "compat:name-collision".to_owned(),
            game_build: "23896268".to_owned(),
            matches: vec![
                RecipeMatch {
                    package_id: "local:example-a".to_owned(),
                    sha256: "a".repeat(64),
                },
                RecipeMatch {
                    package_id: "local:example-b".to_owned(),
                    sha256: "b".repeat(64),
                },
            ],
            operations: vec![RecipeOperation::RequireInstallName {
                package_id: "local:example-a".to_owned(),
                install_name: "example_p.PAK".to_owned(),
            }],
            verification: verification(),
        };
        let a = catalog_package("local:example-a", "a");
        let b = catalog_package("local:example-b", "b");
        let resolution = ResolutionReport {
            build_id: 23_896_268,
            ready: true,
            packages: vec![resolved(&a), resolved(&b)],
            blockers: Vec::new(),
        };
        let report = apply_verified_recipes_at(
            &resolution,
            &[a, b],
            &verified_catalog(vec![collision]),
            100,
            &floor(1, 1),
        )
        .unwrap();
        assert!(!report.ready);
        assert!(matches!(
            report.blockers.as_slice(),
            [RecipeApplicationBlocker::ConflictingInstallName { .. }]
        ));
    }

    #[test]
    fn public_application_binds_catalog_semantics_to_an_embedded_manifest() {
        let temporary = TempDir::new().unwrap();
        let archive = temporary.path().join("embedded.zip");
        let staging = temporary.path().join("staging");
        let pak_hash = format!("{:x}", Sha256::digest(b"pak"));
        let mut embedded = catalog_package("local:embedded", "0").manifest;
        embedded.components[0].root = "Example_P.pak".to_owned();
        embedded.components[0].sha256 = Some(pak_hash);
        let file = fs::File::create(&archive).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file("Example_P.pak", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"pak").unwrap();
        writer
            .start_file("rrmm-manifest.json", SimpleFileOptions::default())
            .unwrap();
        writer
            .write_all(&serde_json::to_vec_pretty(&embedded).unwrap())
            .unwrap();
        writer.finish().unwrap();
        let limits = ArchiveLimits::default();
        let extraction = extract_zip_to_staging(&archive, &staging, &limits).unwrap();
        let accepted = accept_artifact(
            &archive,
            &extraction,
            &temporary.path().join("store"),
            &limits,
        )
        .unwrap();
        let package = CatalogPackage {
            artifact_sha256: accepted.manifest.sha256.clone(),
            manifest: embedded,
            provenance: ManifestProvenance::Declared,
        };
        let request = ResolveRequest {
            build_id: 23_896_268,
            selections: vec![ResolveSelection {
                artifact_sha256: accepted.manifest.sha256,
                variant: None,
            }],
        };
        let now = system_unix_time().unwrap();
        let mut verified = verified_catalog(Vec::new());
        verified.valid_from = now.saturating_sub(1);
        verified.valid_until = now + 60;

        let report = resolve_and_apply_verified_recipes(
            &temporary.path().join("store"),
            &request,
            std::slice::from_ref(&package),
            &verified,
            &floor(1, 1),
        )
        .unwrap();
        assert!(report.ready);

        let mut forged = package;
        forged.manifest.name = "Forged semantics".to_owned();
        assert!(matches!(
            resolve_and_apply_verified_recipes(
                &temporary.path().join("store"),
                &request,
                &[forged],
                &verified,
                &floor(1, 1)
            ),
            Err(RecipeError::Invalid(_))
        ));
    }

    #[test]
    fn public_application_preserves_reviewed_local_inference_outside_recipes() {
        let temporary = TempDir::new().unwrap();
        let mut package = catalog_package("local:inferred", "a");
        package.provenance = ManifestProvenance::Inferred {
            confidence: rrmm_manifest::InferenceConfidence::High,
            reviewed: true,
            issues: Vec::new(),
        };
        let request = ResolveRequest {
            build_id: 23_896_268,
            selections: vec![ResolveSelection {
                artifact_sha256: package.artifact_sha256.clone(),
                variant: None,
            }],
        };
        let now = system_unix_time().unwrap();
        let mut verified = verified_catalog(Vec::new());
        verified.valid_from = now.saturating_sub(1);
        verified.valid_until = now + 60;

        let report = resolve_and_apply_verified_recipes(
            &temporary.path().join("store"),
            &request,
            &[package],
            &verified,
            &floor(1, 1),
        )
        .unwrap();

        assert!(report.ready);
        assert!(report.applied_recipe_ids.is_empty());
    }

    fn fixture_recipe() -> CompatibilityRecipe {
        serde_json::from_str(include_str!("../../../fixtures/recipe.valid.json")).unwrap()
    }

    fn verification() -> RecipeVerification {
        RecipeVerification {
            offline: vec!["verify hashes".to_owned()],
            in_game: vec!["exercise behavior".to_owned()],
        }
    }

    fn floor(root_generation: u64, catalog_sequence: u64) -> CatalogTrustFloor {
        CatalogTrustFloor {
            root_generation,
            root_payload_sha256: (root_generation > 0).then(|| "a".repeat(64)),
            catalog_sequence,
            catalog_payload_sha256: (catalog_sequence > 0).then(|| "b".repeat(64)),
        }
    }

    fn verified_catalog(recipes: Vec<CompatibilityRecipe>) -> VerifiedRecipeCatalog {
        VerifiedRecipeCatalog {
            root_generation: 1,
            root_payload_sha256: "a".repeat(64),
            sequence: 1,
            payload_sha256: "b".repeat(64),
            valid_from: 50,
            valid_until: 200,
            recipes,
            signing_key_id: "online-test".to_owned(),
        }
    }

    fn catalog_package(id: &str, hash: &str) -> CatalogPackage {
        CatalogPackage {
            artifact_sha256: hash.repeat(64),
            provenance: ManifestProvenance::Declared,
            manifest: PackageManifest {
                schema_version: 1,
                id: id.to_owned(),
                name: id.to_owned(),
                version: "1.0.0".to_owned(),
                game: ManifestGame {
                    steam_app_id: 3_552_140,
                    supported_build_ids: vec!["23896268".to_owned()],
                    unreal_engine: "5.4.4".to_owned(),
                },
                source: None,
                components: vec![ManifestComponent {
                    id: "pak".to_owned(),
                    component_type: ComponentType::Pak,
                    root: "payload/Example_P.pak".to_owned(),
                    required: true,
                    install_name: Some("Example_P.pak".to_owned()),
                    sha256: Some(hash.repeat(64)),
                }],
                variants: Vec::new(),
                requirements: Vec::new(),
                runtime_requirements: rrmm_manifest::ManifestRuntimeRequirements::default(),
                incompatibilities: Vec::new(),
                replaces: Vec::new(),
                persistent_effects: Vec::new(),
                install_notes: Vec::new(),
            },
        }
    }

    fn resolved(package: &CatalogPackage) -> rrmm_manifest::ResolvedPackage {
        rrmm_manifest::ResolvedPackage {
            package_id: package.manifest.id.clone(),
            artifact_sha256: package.artifact_sha256.clone(),
            variant: None,
            component_ids: vec!["pak".to_owned()],
            automatically_selected: false,
        }
    }

    fn sign(key_id: &str, key: &SigningKey, payload: &[u8]) -> DetachedSignature {
        DetachedSignature {
            key_id: key_id.to_owned(),
            algorithm: SignatureAlgorithm::Ed25519,
            signature: STANDARD.encode(key.sign(payload).to_bytes()),
        }
    }
}
