use rrmm_archive::{PackageKind, validate_entry_path};
use rrmm_artifacts::ArtifactManifest;
use rrmm_domain::RETRO_REWIND_APP_ID;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

const MAX_COMPONENT_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageManifest {
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub version: String,
    pub game: ManifestGame,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<ManifestSource>,
    pub components: Vec<ManifestComponent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variants: Vec<ManifestVariant>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requirements: Vec<PackageRequirement>,
    #[serde(default, skip_serializing_if = "ManifestRuntimeRequirements::is_empty")]
    pub runtime_requirements: ManifestRuntimeRequirements,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incompatibilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub persistent_effects: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub install_notes: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestRuntimeRequirements {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ue4ss_loader_policy: Option<String>,
}

impl ManifestRuntimeRequirements {
    pub fn is_empty(&self) -> bool {
        self.ue4ss_loader_policy.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestGame {
    pub steam_app_id: u32,
    pub supported_build_ids: Vec<String>,
    pub unreal_engine: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSource {
    pub provider: SourceProvider,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub game_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mod_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceProvider {
    Nexus,
    Github,
    Local,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestComponent {
    pub id: String,
    #[serde(rename = "type")]
    pub component_type: ComponentType,
    pub root: String,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentType {
    Pak,
    Ue4ss,
    Config,
    Documentation,
    Native,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestVariant {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub default: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requirements: Vec<PackageRequirement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incompatibilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PackageRequirement {
    Package(String),
    OneOf(OneOfRequirement),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OneOfRequirement {
    pub one_of: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceConfidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferredManifest {
    pub manifest: PackageManifest,
    pub confidence: InferenceConfidence,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogPackage {
    pub artifact_sha256: String,
    pub manifest: PackageManifest,
    pub provenance: ManifestProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ManifestProvenance {
    Declared,
    Inferred {
        confidence: InferenceConfidence,
        reviewed: bool,
        issues: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveSelection {
    pub artifact_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveRequest {
    pub build_id: u64,
    pub selections: Vec<ResolveSelection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedPackage {
    pub package_id: String,
    pub artifact_sha256: String,
    pub variant: Option<String>,
    pub component_ids: Vec<String>,
    pub automatically_selected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum ResolutionBlocker {
    UnknownArtifact {
        artifact_sha256: String,
    },
    UnsupportedBuild {
        package_id: String,
        build_id: u64,
    },
    DuplicatePackage {
        package_id: String,
    },
    ConflictingSelection {
        package_id: String,
        variants: Vec<String>,
    },
    UnknownVariant {
        package_id: String,
        variant: String,
    },
    VariantRequired {
        package_id: String,
    },
    MissingRequirement {
        package_id: String,
        requirement: String,
    },
    AmbiguousRequirement {
        package_id: String,
        candidates: Vec<String>,
    },
    Incompatible {
        first: String,
        second: String,
    },
    DependencyCycle {
        packages: Vec<String>,
    },
    UnreviewedInference {
        package_id: String,
        confidence: InferenceConfidence,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionReport {
    pub build_id: u64,
    pub ready: bool,
    pub packages: Vec<ResolvedPackage>,
    pub blockers: Vec<ResolutionBlocker>,
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("manifest JSON failed at {path}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("manifest I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid manifest: {0}")]
    Invalid(String),
    #[error("artifact cannot be inferred as a deployable package: {0}")]
    CannotInfer(String),
}

pub fn load_manifest(path: &Path) -> Result<PackageManifest, ManifestError> {
    let input = fs::read(path).map_err(|source| ManifestError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let manifest = serde_json::from_slice(&input).map_err(|source| ManifestError::Json {
        path: path.to_path_buf(),
        source,
    })?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

pub fn validate_manifest(manifest: &PackageManifest) -> Result<(), ManifestError> {
    if manifest.schema_version != 1 {
        return invalid(format!(
            "unsupported schema version {}",
            manifest.schema_version
        ));
    }
    validate_package_id(&manifest.id)?;
    validate_text("name", &manifest.name, 200)?;
    validate_text("version", &manifest.version, 100)?;
    if manifest.game.steam_app_id != RETRO_REWIND_APP_ID {
        return invalid(format!(
            "Steam App ID {} is not Retro Rewind",
            manifest.game.steam_app_id
        ));
    }
    if manifest.game.unreal_engine != "5.4.4" {
        return invalid(format!(
            "unsupported Unreal Engine version '{}'",
            manifest.game.unreal_engine
        ));
    }
    if manifest.game.supported_build_ids.is_empty() {
        return invalid("supported_build_ids must not be empty");
    }
    let mut builds = BTreeSet::new();
    for build in &manifest.game.supported_build_ids {
        let parsed = build
            .parse::<u64>()
            .map_err(|_| ManifestError::Invalid(format!("invalid build ID '{build}'")))?;
        if parsed == 0 || !builds.insert(parsed) {
            return invalid(format!("invalid or duplicate build ID '{build}'"));
        }
    }
    validate_source(manifest.source.as_ref())?;
    if manifest.components.is_empty() {
        return invalid("components must not be empty");
    }

    let mut component_ids = BTreeSet::new();
    let mut component_roots = BTreeSet::new();
    let mut install_names = BTreeSet::new();
    for component in &manifest.components {
        validate_component_id(&component.id)?;
        if !component_ids.insert(component.id.clone()) {
            return invalid(format!("duplicate component ID '{}'", component.id));
        }
        let root = validate_entry_path(&component.root, true, MAX_COMPONENT_DEPTH)
            .map_err(|error| ManifestError::Invalid(error.to_string()))?;
        if root.path != component.root || !component_roots.insert(root.collision_key) {
            return invalid(format!(
                "duplicate or non-normalized component root '{}'",
                component.root
            ));
        }
        if let Some(hash) = &component.sha256 {
            validate_sha256(hash)?;
        }
        validate_component_install_name(component, &mut install_names)?;
    }

    let mut variant_ids = BTreeSet::new();
    let mut defaults = 0_usize;
    for variant in &manifest.variants {
        validate_component_id(&variant.id)?;
        validate_text("variant name", &variant.name, 200)?;
        if !variant_ids.insert(variant.id.clone()) {
            return invalid(format!("duplicate variant ID '{}'", variant.id));
        }
        if variant.default {
            defaults += 1;
        }
        validate_unique_ids("variant components", &variant.components)?;
        for component in &variant.components {
            if !component_ids.contains(component) {
                return invalid(format!(
                    "variant '{}' references unknown component '{component}'",
                    variant.id
                ));
            }
        }
        validate_requirements(&variant.requirements, &manifest.id)?;
        validate_package_ids("variant incompatibilities", &variant.incompatibilities)?;
    }
    if defaults > 1 {
        return invalid("only one variant may be the default");
    }
    validate_requirements(&manifest.requirements, &manifest.id)?;
    if let Some(policy_id) = &manifest.runtime_requirements.ue4ss_loader_policy {
        validate_package_id(policy_id).map_err(|_| {
            ManifestError::Invalid(format!("invalid UE4SS loader policy ID '{policy_id}'"))
        })?;
    }
    validate_package_ids("incompatibilities", &manifest.incompatibilities)?;
    validate_package_ids("replaces", &manifest.replaces)?;
    validate_unique_text("persistent_effects", &manifest.persistent_effects)?;
    validate_unique_text("install_notes", &manifest.install_notes)?;
    Ok(())
}

pub fn infer_manifest(
    artifact: &ArtifactManifest,
    package_id: &str,
    name: &str,
    version: &str,
    build_id: u64,
) -> Result<InferredManifest, ManifestError> {
    validate_package_id(package_id)?;
    validate_text("name", name, 200)?;
    validate_text("version", version, 100)?;
    if build_id == 0 {
        return invalid("build ID must be non-zero");
    }
    if artifact.schema_version != 1 {
        return Err(ManifestError::CannotInfer(format!(
            "unsupported artifact schema version {}",
            artifact.schema_version
        )));
    }
    validate_sha256(&artifact.sha256)?;
    let mut expanded_bytes = 0_u64;
    for file in &artifact.files {
        validate_sha256(&file.sha256)?;
        let normalized = validate_entry_path(&file.path, false, MAX_COMPONENT_DEPTH)
            .map_err(|error| ManifestError::CannotInfer(error.to_string()))?;
        if normalized.path != file.path {
            return Err(ManifestError::CannotInfer(format!(
                "artifact path '{}' is not normalized",
                file.path
            )));
        }
        expanded_bytes = expanded_bytes.checked_add(file.bytes).ok_or_else(|| {
            ManifestError::CannotInfer("artifact expanded size overflowed".to_owned())
        })?;
    }
    if expanded_bytes != artifact.expanded_bytes {
        return Err(ManifestError::CannotInfer(
            "artifact expanded size does not match its files".to_owned(),
        ));
    }
    let by_path: BTreeMap<_, _> = artifact
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    if by_path.len() != artifact.files.len() {
        return Err(ManifestError::CannotInfer(
            "artifact contains duplicate file paths".to_owned(),
        ));
    }
    let mut classified = BTreeSet::new();
    let mut components = Vec::new();
    for (index, path) in artifact.layout.pak_files.iter().enumerate() {
        let file = by_path.get(path.as_str()).ok_or_else(|| {
            ManifestError::CannotInfer(format!(
                "layout PAK '{path}' is missing from artifact files"
            ))
        })?;
        classified.insert(path.as_str());
        let install_name = path.rsplit('/').next().unwrap_or(path);
        components.push(ManifestComponent {
            id: component_id("pak", index),
            component_type: ComponentType::Pak,
            root: path.clone(),
            required: true,
            install_name: Some(install_name.to_owned()),
            sha256: Some(file.sha256.clone()),
        });
    }
    for (index, root) in artifact.layout.ue4ss_mod_roots.iter().enumerate() {
        let prefix = format!("{root}/");
        let module_files: Vec<_> = by_path
            .keys()
            .copied()
            .filter(|path| path.starts_with(&prefix))
            .collect();
        if module_files.is_empty()
            || !module_files
                .iter()
                .any(|path| path.eq_ignore_ascii_case(&format!("{root}/Scripts/main.lua")))
        {
            return Err(ManifestError::CannotInfer(format!(
                "UE4SS root '{root}' has no Scripts/main.lua"
            )));
        }
        classified.extend(module_files);
        components.push(ManifestComponent {
            id: component_id("ue4ss", index),
            component_type: ComponentType::Ue4ss,
            root: root.clone(),
            required: true,
            install_name: root.rsplit('/').next().map(str::to_owned),
            sha256: None,
        });
    }
    if components.is_empty() {
        return Err(ManifestError::CannotInfer(
            "no PAK or UE4SS module was recognized".to_owned(),
        ));
    }
    let mut issues = artifact.layout.issues.clone();
    let documentation: BTreeSet<_> = artifact
        .layout
        .documentation_files
        .iter()
        .map(String::as_str)
        .collect();
    if documentation.iter().any(|path| !by_path.contains_key(path)) {
        return Err(ManifestError::CannotInfer(
            "layout documentation path is missing from artifact files".to_owned(),
        ));
    }
    let unclassified: Vec<_> = by_path
        .keys()
        .copied()
        .filter(|path| !classified.contains(path) && !documentation.contains(path))
        .collect();
    for path in &unclassified {
        issues.push(format!(
            "unclassified artifact file '{path}' requires manual mapping"
        ));
    }
    if artifact.layout.kind == PackageKind::Hybrid {
        issues.push("hybrid package destinations require review".to_owned());
    }
    if !artifact.layout.executable_files.is_empty() {
        issues.push("native or executable content requires manual review".to_owned());
    }
    issues.sort();
    issues.dedup();
    let confidence = if !artifact.layout.executable_files.is_empty()
        || !unclassified.is_empty()
        || artifact.layout.kind == PackageKind::Unknown
    {
        InferenceConfidence::Low
    } else if artifact.layout.kind == PackageKind::Hybrid || artifact.layout.requires_review {
        InferenceConfidence::Medium
    } else {
        InferenceConfidence::High
    };
    let manifest = PackageManifest {
        schema_version: 1,
        id: package_id.to_owned(),
        name: name.to_owned(),
        version: version.to_owned(),
        game: ManifestGame {
            steam_app_id: RETRO_REWIND_APP_ID,
            supported_build_ids: vec![build_id.to_string()],
            unreal_engine: "5.4.4".to_owned(),
        },
        source: Some(ManifestSource {
            provider: SourceProvider::Local,
            game_domain: None,
            mod_id: None,
            file_id: None,
            url: None,
        }),
        components,
        variants: Vec::new(),
        requirements: Vec::new(),
        runtime_requirements: ManifestRuntimeRequirements::default(),
        incompatibilities: Vec::new(),
        replaces: Vec::new(),
        persistent_effects: Vec::new(),
        install_notes: vec!["locally inferred; author intent is not declared".to_owned()],
    };
    validate_manifest(&manifest)?;
    Ok(InferredManifest {
        manifest,
        confidence,
        issues,
    })
}

pub fn validate_catalog_package_artifact(
    package: &CatalogPackage,
    artifact: &ArtifactManifest,
) -> Result<(), ManifestError> {
    validate_sha256(&package.artifact_sha256)?;
    validate_manifest(&package.manifest)?;
    if package.artifact_sha256 != artifact.sha256 {
        return invalid(format!(
            "catalog artifact hash {} does not match stored artifact {}",
            package.artifact_sha256, artifact.sha256
        ));
    }
    let by_path: BTreeMap<_, _> = artifact
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    if by_path.len() != artifact.files.len() {
        return invalid("stored artifact contains duplicate paths");
    }
    for component in &package.manifest.components {
        let exact = by_path.get(component.root.as_str()).copied();
        let prefix = format!("{}/", component.root);
        let descendants: Vec<_> = by_path
            .iter()
            .filter(|(path, _)| path.starts_with(&prefix))
            .map(|(_, file)| *file)
            .collect();
        match component.component_type {
            ComponentType::Pak => {
                let file = exact.ok_or_else(|| {
                    ManifestError::Invalid(format!(
                        "PAK component '{}' is missing artifact file '{}'",
                        component.id, component.root
                    ))
                })?;
                if component.sha256.as_ref() != Some(&file.sha256) {
                    return invalid(format!(
                        "PAK component '{}' hash does not match its artifact file",
                        component.id
                    ));
                }
            }
            ComponentType::Ue4ss => {
                if descendants.is_empty()
                    || !descendants.iter().any(|file| {
                        file.path
                            .eq_ignore_ascii_case(&format!("{}/Scripts/main.lua", component.root))
                    })
                {
                    return invalid(format!(
                        "UE4SS component '{}' has no stored Scripts/main.lua",
                        component.id
                    ));
                }
                if component.sha256.is_some() {
                    return invalid(format!(
                        "directory component '{}' cannot declare one file hash",
                        component.id
                    ));
                }
            }
            _ => {
                if exact.is_none() && descendants.is_empty() {
                    return invalid(format!(
                        "component '{}' root '{}' is absent from the stored artifact",
                        component.id, component.root
                    ));
                }
                if let (Some(expected), Some(file)) = (&component.sha256, exact)
                    && expected != &file.sha256
                {
                    return invalid(format!(
                        "component '{}' hash does not match its artifact file",
                        component.id
                    ));
                }
                if component.sha256.is_some() && exact.is_none() {
                    return invalid(format!(
                        "directory component '{}' cannot declare one file hash",
                        component.id
                    ));
                }
            }
        }
    }
    Ok(())
}

pub fn resolve_packages(
    request: &ResolveRequest,
    catalog: &[CatalogPackage],
) -> Result<ResolutionReport, ManifestError> {
    if request.build_id == 0 {
        return invalid("resolution build ID must be non-zero");
    }
    let mut by_artifact = BTreeMap::new();
    for package in catalog {
        validate_sha256(&package.artifact_sha256)?;
        validate_manifest(&package.manifest)?;
        if by_artifact
            .insert(package.artifact_sha256.clone(), package)
            .is_some()
        {
            return invalid(format!(
                "duplicate catalog artifact '{}'",
                package.artifact_sha256
            ));
        }
    }

    let mut blockers = Vec::new();
    let mut selected = BTreeMap::<String, SelectedPackage>::new();
    for selection in &request.selections {
        let Some(package) = by_artifact.get(&selection.artifact_sha256).copied() else {
            blockers.push(ResolutionBlocker::UnknownArtifact {
                artifact_sha256: selection.artifact_sha256.clone(),
            });
            continue;
        };
        add_selected(
            package,
            selection.variant.as_deref(),
            false,
            request.build_id,
            &mut selected,
            &mut blockers,
        );
    }

    let mut processed = BTreeSet::new();
    loop {
        let pending: Vec<_> = selected
            .keys()
            .filter(|id| !processed.contains(*id))
            .cloned()
            .collect();
        if pending.is_empty() {
            break;
        }
        for package_id in pending {
            processed.insert(package_id.clone());
            let current = selected.get(&package_id).cloned().expect("selected key");
            for requirement in active_requirements(&current) {
                let targets = selected_requirement_targets(requirement, &selected);
                if targets.len() == 1 {
                    continue;
                }
                if targets.len() > 1 {
                    blockers.push(ResolutionBlocker::AmbiguousRequirement {
                        package_id: package_id.clone(),
                        candidates: targets,
                    });
                    continue;
                }
                let candidate_ids = requirement_ids(requirement);
                let mut candidates = BTreeMap::new();
                for candidate in catalog.iter().filter(|candidate| {
                    candidate_ids.contains(&candidate.manifest.id)
                        || candidate
                            .manifest
                            .replaces
                            .iter()
                            .any(|replaced| candidate_ids.contains(replaced))
                }) {
                    if supports_build(&candidate.manifest, request.build_id) {
                        candidates.insert(candidate.artifact_sha256.clone(), candidate);
                    }
                }
                if candidates.is_empty() {
                    blockers.push(ResolutionBlocker::MissingRequirement {
                        package_id: package_id.clone(),
                        requirement: candidate_ids.join(" | "),
                    });
                } else if candidates.len() > 1 {
                    blockers.push(ResolutionBlocker::AmbiguousRequirement {
                        package_id: package_id.clone(),
                        candidates: candidates.keys().cloned().collect(),
                    });
                } else {
                    let candidate = candidates.into_values().next().expect("one candidate");
                    add_selected(
                        candidate,
                        None,
                        true,
                        request.build_id,
                        &mut selected,
                        &mut blockers,
                    );
                }
            }
        }
    }

    validate_selected_requirements(&selected, &mut blockers);
    detect_incompatibilities(&selected, &mut blockers);
    detect_dependency_cycles(&selected, &mut blockers);
    blockers.sort_by_key(|blocker| format!("{blocker:?}"));
    blockers.dedup();
    let packages = selected
        .into_values()
        .map(|selected| ResolvedPackage {
            package_id: selected.package.manifest.id.clone(),
            artifact_sha256: selected.package.artifact_sha256.clone(),
            variant: selected.variant.map(|variant| variant.id.clone()),
            component_ids: selected_component_ids(&selected),
            automatically_selected: selected.automatic,
        })
        .collect();
    Ok(ResolutionReport {
        build_id: request.build_id,
        ready: blockers.is_empty(),
        packages,
        blockers,
    })
}

#[derive(Clone)]
struct SelectedPackage<'a> {
    package: &'a CatalogPackage,
    variant: Option<&'a ManifestVariant>,
    automatic: bool,
}

fn add_selected<'a>(
    package: &'a CatalogPackage,
    requested_variant: Option<&str>,
    automatic: bool,
    build_id: u64,
    selected: &mut BTreeMap<String, SelectedPackage<'a>>,
    blockers: &mut Vec<ResolutionBlocker>,
) {
    let package_id = package.manifest.id.clone();
    if !supports_build(&package.manifest, build_id) {
        blockers.push(ResolutionBlocker::UnsupportedBuild {
            package_id: package_id.clone(),
            build_id,
        });
    }
    let variant = match requested_variant {
        Some(id) => match package
            .manifest
            .variants
            .iter()
            .find(|variant| variant.id == id)
        {
            Some(variant) => Some(variant),
            None => {
                blockers.push(ResolutionBlocker::UnknownVariant {
                    package_id: package_id.clone(),
                    variant: id.to_owned(),
                });
                None
            }
        },
        None => {
            let default = package
                .manifest
                .variants
                .iter()
                .find(|variant| variant.default);
            if default.is_none() && !package.manifest.variants.is_empty() {
                blockers.push(ResolutionBlocker::VariantRequired {
                    package_id: package_id.clone(),
                });
            }
            default
        }
    };
    if let Some(existing) = selected.get_mut(&package_id) {
        if existing.package.artifact_sha256 != package.artifact_sha256 {
            blockers.push(ResolutionBlocker::DuplicatePackage { package_id });
            return;
        }
        let existing_variant = existing.variant.map(|variant| variant.id.as_str());
        let next_variant = variant.map(|variant| variant.id.as_str());
        if existing_variant != next_variant {
            blockers.push(ResolutionBlocker::ConflictingSelection {
                package_id,
                variants: vec![
                    existing_variant.unwrap_or("<none>").to_owned(),
                    next_variant.unwrap_or("<none>").to_owned(),
                ],
            });
        } else if !automatic {
            existing.automatic = false;
        }
        return;
    }
    if let ManifestProvenance::Inferred {
        confidence,
        reviewed: false,
        ..
    } = &package.provenance
    {
        blockers.push(ResolutionBlocker::UnreviewedInference {
            package_id: package_id.clone(),
            confidence: *confidence,
        });
    }
    selected.insert(
        package_id,
        SelectedPackage {
            package,
            variant,
            automatic,
        },
    );
}

fn active_requirements<'a>(selected: &'a SelectedPackage<'a>) -> Vec<&'a PackageRequirement> {
    selected
        .package
        .manifest
        .requirements
        .iter()
        .chain(
            selected
                .variant
                .into_iter()
                .flat_map(|variant| variant.requirements.iter()),
        )
        .collect()
}

fn requirement_ids(requirement: &PackageRequirement) -> Vec<String> {
    let mut ids = match requirement {
        PackageRequirement::Package(id) => vec![id.clone()],
        PackageRequirement::OneOf(requirement) => requirement.one_of.clone(),
    };
    ids.sort();
    ids.dedup();
    ids
}

fn selected_requirement_targets(
    requirement: &PackageRequirement,
    selected: &BTreeMap<String, SelectedPackage<'_>>,
) -> Vec<String> {
    let required = requirement_ids(requirement);
    selected
        .iter()
        .filter(|(id, package)| {
            required.contains(id)
                || package
                    .package
                    .manifest
                    .replaces
                    .iter()
                    .any(|replaced| required.contains(replaced))
        })
        .map(|(id, _)| id.clone())
        .collect()
}

fn validate_selected_requirements(
    selected: &BTreeMap<String, SelectedPackage<'_>>,
    blockers: &mut Vec<ResolutionBlocker>,
) {
    for (package_id, package) in selected {
        for requirement in active_requirements(package) {
            let targets = selected_requirement_targets(requirement, selected);
            if targets.len() > 1 {
                blockers.push(ResolutionBlocker::AmbiguousRequirement {
                    package_id: package_id.clone(),
                    candidates: targets,
                });
            }
        }
    }
}

fn supports_build(manifest: &PackageManifest, build_id: u64) -> bool {
    manifest
        .game
        .supported_build_ids
        .iter()
        .any(|build| build == &build_id.to_string())
}

fn selected_component_ids(selected: &SelectedPackage<'_>) -> Vec<String> {
    let optional = selected
        .variant
        .map(|variant| variant.components.iter().collect::<BTreeSet<_>>())
        .unwrap_or_default();
    selected
        .package
        .manifest
        .components
        .iter()
        .filter(|component| component.required || optional.contains(&component.id))
        .map(|component| component.id.clone())
        .collect()
}

fn detect_incompatibilities(
    selected: &BTreeMap<String, SelectedPackage<'_>>,
    blockers: &mut Vec<ResolutionBlocker>,
) {
    for (id, package) in selected {
        let incompatible = package.package.manifest.incompatibilities.iter().chain(
            package
                .variant
                .into_iter()
                .flat_map(|variant| variant.incompatibilities.iter()),
        );
        for other in incompatible {
            if selected.contains_key(other) {
                let (first, second) = if id < other {
                    (id.clone(), other.clone())
                } else {
                    (other.clone(), id.clone())
                };
                blockers.push(ResolutionBlocker::Incompatible { first, second });
            }
        }
        for replaced in &package.package.manifest.replaces {
            if selected.contains_key(replaced) {
                let (first, second) = if id < replaced {
                    (id.clone(), replaced.clone())
                } else {
                    (replaced.clone(), id.clone())
                };
                blockers.push(ResolutionBlocker::Incompatible { first, second });
            }
        }
    }
}

fn detect_dependency_cycles(
    selected: &BTreeMap<String, SelectedPackage<'_>>,
    blockers: &mut Vec<ResolutionBlocker>,
) {
    fn visit(
        id: &str,
        selected: &BTreeMap<String, SelectedPackage<'_>>,
        visiting: &mut Vec<String>,
        visited: &mut BTreeSet<String>,
        cycles: &mut BTreeSet<Vec<String>>,
    ) {
        if let Some(position) = visiting.iter().position(|current| current == id) {
            let mut cycle = visiting[position..].to_vec();
            cycle.sort();
            cycle.dedup();
            cycles.insert(cycle);
            return;
        }
        if !visited.insert(id.to_owned()) {
            return;
        }
        visiting.push(id.to_owned());
        if let Some(package) = selected.get(id) {
            for requirement in active_requirements(package) {
                let targets = selected_requirement_targets(requirement, selected);
                if targets.len() == 1 {
                    visit(&targets[0], selected, visiting, visited, cycles);
                }
            }
        }
        visiting.pop();
    }

    let mut visited = BTreeSet::new();
    let mut cycles = BTreeSet::new();
    for id in selected.keys() {
        visit(id, selected, &mut Vec::new(), &mut visited, &mut cycles);
    }
    blockers.extend(
        cycles
            .into_iter()
            .map(|packages| ResolutionBlocker::DependencyCycle { packages }),
    );
}

fn validate_source(source: Option<&ManifestSource>) -> Result<(), ManifestError> {
    let Some(source) = source else {
        return Ok(());
    };
    if source.mod_id == Some(0) || source.file_id == Some(0) {
        return invalid("source IDs must be non-zero");
    }
    if source.provider == SourceProvider::Nexus
        && (source.game_domain.as_deref().is_none_or(str::is_empty) || source.mod_id.is_none())
    {
        return invalid("Nexus source requires game_domain and mod_id");
    }
    if let Some(url) = &source.url
        && !is_valid_http_url(url)
    {
        return invalid("source URL must be an absolute HTTP or HTTPS URL");
    }
    Ok(())
}

fn validate_component_install_name(
    component: &ManifestComponent,
    install_names: &mut BTreeSet<String>,
) -> Result<(), ManifestError> {
    if let Some(name) = &component.install_name {
        let normalized = validate_entry_path(name, false, MAX_COMPONENT_DEPTH)
            .map_err(|error| ManifestError::Invalid(error.to_string()))?;
        if normalized.path != *name {
            return invalid(format!("non-normalized install_name '{name}'"));
        }
    }
    match component.component_type {
        ComponentType::Pak => {
            let name = component.install_name.as_deref().ok_or_else(|| {
                ManifestError::Invalid(format!(
                    "PAK component '{}' requires install_name",
                    component.id
                ))
            })?;
            let normalized = validate_entry_path(name, false, 1)
                .map_err(|error| ManifestError::Invalid(error.to_string()))?;
            if normalized.path != name || !name.to_ascii_lowercase().ends_with(".pak") {
                return invalid(format!("invalid PAK install_name '{name}'"));
            }
            if !install_names.insert(normalized.collision_key) {
                return invalid(format!("duplicate install_name '{name}'"));
            }
            if component.sha256.is_none() {
                return invalid(format!("PAK component '{}' requires sha256", component.id));
            }
        }
        ComponentType::Ue4ss => {
            let name = component.install_name.as_deref().ok_or_else(|| {
                ManifestError::Invalid(format!(
                    "UE4SS component '{}' requires install_name",
                    component.id
                ))
            })?;
            let normalized = validate_entry_path(name, false, 1)
                .map_err(|error| ManifestError::Invalid(error.to_string()))?;
            if !install_names.insert(format!("ue4ss:{}", normalized.collision_key)) {
                return invalid(format!("duplicate UE4SS install_name '{name}'"));
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_requirements(
    requirements: &[PackageRequirement],
    own_id: &str,
) -> Result<(), ManifestError> {
    let mut keys = BTreeSet::new();
    for requirement in requirements {
        let mut ids = requirement_ids(requirement);
        if ids.is_empty() {
            return invalid("one_of requirement must not be empty");
        }
        for id in &ids {
            validate_package_id(id)?;
            if id == own_id {
                return invalid("package cannot require itself");
            }
        }
        let original_len = match requirement {
            PackageRequirement::Package(_) => 1,
            PackageRequirement::OneOf(requirement) => requirement.one_of.len(),
        };
        if ids.len() != original_len {
            return invalid("one_of requirement contains duplicate package IDs");
        }
        ids.sort();
        ids.dedup();
        let key = ids.join("|");
        if !keys.insert(key) {
            return invalid("duplicate requirement");
        }
    }
    Ok(())
}

fn validate_package_ids(field: &str, values: &[String]) -> Result<(), ManifestError> {
    let mut seen = BTreeSet::new();
    for value in values {
        validate_package_id(value)?;
        if !seen.insert(value) {
            return invalid(format!("duplicate {field} entry '{value}'"));
        }
    }
    Ok(())
}

fn validate_unique_ids(field: &str, values: &[String]) -> Result<(), ManifestError> {
    let mut seen = BTreeSet::new();
    for value in values {
        validate_component_id(value)?;
        if !seen.insert(value) {
            return invalid(format!("duplicate {field} entry '{value}'"));
        }
    }
    Ok(())
}

fn validate_unique_text(field: &str, values: &[String]) -> Result<(), ManifestError> {
    let mut seen = BTreeSet::new();
    for value in values {
        validate_text(field, value, 500)?;
        if !seen.insert(value) {
            return invalid(format!("duplicate {field} entry '{value}'"));
        }
    }
    Ok(())
}

fn validate_package_id(value: &str) -> Result<(), ManifestError> {
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
        return invalid(format!("invalid package ID '{value}'"));
    }
    Ok(())
}

fn validate_component_id(value: &str) -> Result<(), ManifestError> {
    if !(2..=64).contains(&value.len())
        || !value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return invalid(format!("invalid component or variant ID '{value}'"));
    }
    Ok(())
}

fn validate_text(field: &str, value: &str, max: usize) -> Result<(), ManifestError> {
    if value.trim().is_empty() || value.chars().count() > max || value.contains(['\0', '\r', '\n'])
    {
        return invalid(format!(
            "{field} must contain 1 to {max} single-line characters"
        ));
    }
    Ok(())
}

fn is_valid_http_url(value: &str) -> bool {
    let Some(rest) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    !host.is_empty()
        && !host.starts_with(':')
        && !value.chars().any(char::is_whitespace)
        && !value.contains(['\0', '\r', '\n'])
}

fn validate_sha256(value: &str) -> Result<(), ManifestError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(format!("invalid lowercase SHA-256 '{value}'"));
    }
    Ok(())
}

fn component_id(prefix: &str, index: usize) -> String {
    if index == 0 {
        prefix.to_owned()
    } else {
        format!("{prefix}_{}", index + 1)
    }
}

fn default_true() -> bool {
    true
}

fn invalid<T>(detail: impl Into<String>) -> Result<T, ManifestError> {
    Err(ManifestError::Invalid(detail.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrmm_archive::{ArchiveFormat, ExtractedFileReport, PackageLayoutInference};

    #[test]
    fn accepts_the_phase_zero_fixture_and_rejects_unknown_fields() {
        let fixture = include_str!("../../../fixtures/manifest.valid.json");
        let manifest: PackageManifest = serde_json::from_str(fixture).unwrap();
        validate_manifest(&manifest).unwrap();

        let mut value: serde_json::Value = serde_json::from_str(fixture).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PackageManifest>(value).is_err());

        let mut value: serde_json::Value = serde_json::from_str(fixture).unwrap();
        value["requirements"] = serde_json::json!([{
            "one_of": ["mod:first", "mod:first"],
            "minimum_version": "1.0"
        }]);
        assert!(serde_json::from_value::<PackageManifest>(value).is_err());
    }

    #[test]
    fn accepts_only_normalized_ue4ss_loader_policy_requirements() {
        let mut manifest = package("mod:ue4ss-policy", "a");
        manifest.runtime_requirements.ue4ss_loader_policy =
            Some("ue4ss:smart-shelf-662df915-compatible".to_owned());
        validate_manifest(&manifest).unwrap();

        manifest.runtime_requirements.ue4ss_loader_policy = Some("Git SHA >= 662df915".to_owned());
        assert!(validate_manifest(&manifest).is_err());

        let mut value = serde_json::to_value(package("mod:ue4ss-policy", "a")).unwrap();
        value["runtime_requirements"] = serde_json::json!({
            "ue4ss_loader_policy": "ue4ss:test-policy",
            "minimum_git_sha": "662df915"
        });
        assert!(serde_json::from_value::<PackageManifest>(value).is_err());
    }

    #[test]
    fn validates_variants_component_references_and_paths() {
        let mut manifest = package("mod:variants", "a");
        manifest.components.push(ManifestComponent {
            id: "optional".to_owned(),
            component_type: ComponentType::Config,
            root: "config/settings.ini".to_owned(),
            required: false,
            install_name: None,
            sha256: None,
        });
        manifest.variants.push(ManifestVariant {
            id: "standard".to_owned(),
            name: "Standard".to_owned(),
            default: true,
            components: vec!["optional".to_owned()],
            requirements: Vec::new(),
            incompatibilities: Vec::new(),
        });
        validate_manifest(&manifest).unwrap();

        manifest.variants[0].components = vec!["missing".to_owned()];
        assert!(matches!(
            validate_manifest(&manifest),
            Err(ManifestError::Invalid(_))
        ));
        manifest.variants[0].components = vec!["optional".to_owned()];
        manifest.components[1].root = "../outside.ini".to_owned();
        assert!(matches!(
            validate_manifest(&manifest),
            Err(ManifestError::Invalid(_))
        ));
    }

    #[test]
    fn infers_pak_and_hybrid_manifests_without_claiming_author_intent() {
        let pak = extracted("Example_P.pak", "b");
        let pak_artifact = artifact(
            vec![pak],
            PackageLayoutInference {
                kind: PackageKind::PakOnly,
                pak_files: vec!["Example_P.pak".to_owned()],
                ue4ss_mod_roots: Vec::new(),
                documentation_files: Vec::new(),
                executable_files: Vec::new(),
                requires_review: false,
                issues: Vec::new(),
            },
        );
        let inferred =
            infer_manifest(&pak_artifact, "local:example", "Example", "1.0", 23_896_268).unwrap();
        assert_eq!(inferred.confidence, InferenceConfidence::High);
        assert_eq!(
            inferred.manifest.components[0].install_name.as_deref(),
            Some("Example_P.pak")
        );
        assert!(inferred.manifest.install_notes[0].contains("inferred"));

        let hybrid = artifact(
            vec![
                extracted("Example_P.pak", "b"),
                extracted("Example/Scripts/main.lua", "c"),
            ],
            PackageLayoutInference {
                kind: PackageKind::Hybrid,
                pak_files: vec!["Example_P.pak".to_owned()],
                ue4ss_mod_roots: vec!["Example".to_owned()],
                documentation_files: Vec::new(),
                executable_files: Vec::new(),
                requires_review: false,
                issues: Vec::new(),
            },
        );
        let inferred =
            infer_manifest(&hybrid, "local:hybrid", "Hybrid", "1.0", 23_896_268).unwrap();
        assert_eq!(inferred.confidence, InferenceConfidence::Medium);
        assert_eq!(inferred.manifest.components.len(), 2);
        assert!(inferred.issues.iter().any(|issue| issue.contains("hybrid")));

        let unclassified = artifact(
            vec![
                extracted("Example_P.pak", "b"),
                extracted("required/settings.ini", "c"),
            ],
            PackageLayoutInference {
                kind: PackageKind::PakOnly,
                pak_files: vec!["Example_P.pak".to_owned()],
                ue4ss_mod_roots: Vec::new(),
                documentation_files: Vec::new(),
                executable_files: Vec::new(),
                requires_review: false,
                issues: Vec::new(),
            },
        );
        let inferred = infer_manifest(
            &unclassified,
            "local:unclassified",
            "Unclassified",
            "1.0",
            23_896_268,
        )
        .unwrap();
        assert_eq!(inferred.confidence, InferenceConfidence::Low);
        assert!(
            inferred
                .issues
                .iter()
                .any(|issue| issue.contains("required/settings.ini"))
        );
    }

    #[test]
    fn resolves_default_variants_and_unique_requirements() {
        let mut primary = package("mod:primary", "a");
        primary.components.push(ManifestComponent {
            id: "optional".to_owned(),
            component_type: ComponentType::Config,
            root: "config/optional.ini".to_owned(),
            required: false,
            install_name: None,
            sha256: None,
        });
        primary.variants.push(ManifestVariant {
            id: "standard".to_owned(),
            name: "Standard".to_owned(),
            default: true,
            components: vec!["optional".to_owned()],
            requirements: vec![PackageRequirement::OneOf(OneOfRequirement {
                one_of: vec!["mod:dependency".to_owned(), "mod:alternative".to_owned()],
            })],
            incompatibilities: Vec::new(),
        });
        let dependency = package("mod:dependency", "b");
        let catalog = vec![record("a", primary), record("b", dependency)];

        let report = resolve_packages(
            &ResolveRequest {
                build_id: 23_896_268,
                selections: vec![ResolveSelection {
                    artifact_sha256: "a".repeat(64),
                    variant: None,
                }],
            },
            &catalog,
        )
        .unwrap();

        assert!(report.ready);
        assert_eq!(report.packages.len(), 2);
        let primary = report
            .packages
            .iter()
            .find(|package| package.package_id == "mod:primary")
            .unwrap();
        assert_eq!(primary.variant.as_deref(), Some("standard"));
        assert_eq!(primary.component_ids, vec!["pak", "optional"]);
        assert!(
            report
                .packages
                .iter()
                .find(|package| package.package_id == "mod:dependency")
                .unwrap()
                .automatically_selected
        );
    }

    #[test]
    fn reports_ambiguous_missing_incompatible_and_cyclic_dependencies() {
        let mut primary = package("mod:primary", "a");
        primary.requirements = vec![PackageRequirement::Package("mod:dependency".to_owned())];
        let dependency_one = package("mod:dependency", "b");
        let dependency_two = package("mod:dependency", "c");
        let ambiguous = resolve_packages(
            &ResolveRequest {
                build_id: 23_896_268,
                selections: vec![selection("a")],
            },
            &[
                record("a", primary.clone()),
                record("b", dependency_one),
                record("c", dependency_two),
            ],
        )
        .unwrap();
        assert!(
            ambiguous
                .blockers
                .iter()
                .any(|blocker| matches!(blocker, ResolutionBlocker::AmbiguousRequirement { .. }))
        );

        let missing = resolve_packages(
            &ResolveRequest {
                build_id: 23_896_268,
                selections: vec![selection("a")],
            },
            &[record("a", primary.clone())],
        )
        .unwrap();
        assert!(
            missing
                .blockers
                .iter()
                .any(|blocker| matches!(blocker, ResolutionBlocker::MissingRequirement { .. }))
        );

        let mut dependency = package("mod:dependency", "b");
        dependency.requirements = vec![PackageRequirement::Package("mod:primary".to_owned())];
        primary.incompatibilities = vec!["mod:dependency".to_owned()];
        let cyclic = resolve_packages(
            &ResolveRequest {
                build_id: 23_896_268,
                selections: vec![selection("a")],
            },
            &[record("a", primary), record("b", dependency)],
        )
        .unwrap();
        assert!(
            cyclic
                .blockers
                .iter()
                .any(|blocker| matches!(blocker, ResolutionBlocker::DependencyCycle { .. }))
        );
        assert!(
            cyclic
                .blockers
                .iter()
                .any(|blocker| matches!(blocker, ResolutionBlocker::Incompatible { .. }))
        );
    }

    #[test]
    fn blocks_two_artifact_editions_with_the_same_package_id() {
        let first = package("mod:edition", "a");
        let second = package("mod:edition", "b");
        let report = resolve_packages(
            &ResolveRequest {
                build_id: 23_896_268,
                selections: vec![selection("a"), selection("b")],
            },
            &[record("a", first), record("b", second)],
        )
        .unwrap();

        assert!(!report.ready);
        assert!(report.blockers.iter().any(|blocker| matches!(
            blocker,
            ResolutionBlocker::DuplicatePackage { package_id }
                if package_id == "mod:edition"
        )));
    }

    #[test]
    fn blocks_unreviewed_inference_conflicting_variants_and_replacement_cycles() {
        let mut variants = package("mod:variants", "a");
        variants.variants = vec![
            ManifestVariant {
                id: "first".to_owned(),
                name: "First".to_owned(),
                default: false,
                components: Vec::new(),
                requirements: Vec::new(),
                incompatibilities: Vec::new(),
            },
            ManifestVariant {
                id: "second".to_owned(),
                name: "Second".to_owned(),
                default: false,
                components: Vec::new(),
                requirements: Vec::new(),
                incompatibilities: Vec::new(),
            },
        ];
        let mut inferred_record = record("a", variants);
        inferred_record.provenance = ManifestProvenance::Inferred {
            confidence: InferenceConfidence::High,
            reviewed: false,
            issues: Vec::new(),
        };
        let report = resolve_packages(
            &ResolveRequest {
                build_id: 23_896_268,
                selections: vec![
                    ResolveSelection {
                        artifact_sha256: "a".repeat(64),
                        variant: Some("first".to_owned()),
                    },
                    ResolveSelection {
                        artifact_sha256: "a".repeat(64),
                        variant: Some("second".to_owned()),
                    },
                ],
            },
            &[inferred_record],
        )
        .unwrap();
        assert!(
            report
                .blockers
                .iter()
                .any(|blocker| matches!(blocker, ResolutionBlocker::UnreviewedInference { .. }))
        );
        assert!(
            report
                .blockers
                .iter()
                .any(|blocker| matches!(blocker, ResolutionBlocker::ConflictingSelection { .. }))
        );

        let mut primary = package("mod:primary", "b");
        primary.requirements = vec![PackageRequirement::Package("mod:base".to_owned())];
        let mut replacement = package("mod:replacement", "c");
        replacement.replaces = vec!["mod:base".to_owned()];
        replacement.requirements = vec![PackageRequirement::Package("mod:primary".to_owned())];
        let report = resolve_packages(
            &ResolveRequest {
                build_id: 23_896_268,
                selections: vec![selection("b"), selection("c")],
            },
            &[record("b", primary), record("c", replacement)],
        )
        .unwrap();
        assert!(report.blockers.iter().any(|blocker| matches!(
            blocker,
            ResolutionBlocker::DependencyCycle { packages }
                if packages == &vec!["mod:primary".to_owned(), "mod:replacement".to_owned()]
        )));

        let mut one_of = package("mod:one-of", "d");
        one_of.requirements = vec![PackageRequirement::OneOf(OneOfRequirement {
            one_of: vec!["mod:first".to_owned(), "mod:second".to_owned()],
        })];
        let first = package("mod:first", "e");
        let second = package("mod:second", "f");
        let mut trigger = package("mod:trigger", "1");
        trigger.requirements = vec![PackageRequirement::Package("mod:second".to_owned())];
        let report = resolve_packages(
            &ResolveRequest {
                build_id: 23_896_268,
                selections: vec![selection("d"), selection("e"), selection("1")],
            },
            &[
                record("d", one_of),
                record("e", first),
                record("f", second),
                record("1", trigger),
            ],
        )
        .unwrap();
        assert!(report.blockers.iter().any(|blocker| matches!(
            blocker,
            ResolutionBlocker::AmbiguousRequirement { package_id, .. }
                if package_id == "mod:one-of"
        )));
    }

    fn package(id: &str, hash: &str) -> PackageManifest {
        PackageManifest {
            schema_version: 1,
            id: id.to_owned(),
            name: id.to_owned(),
            version: "1.0.0".to_owned(),
            game: ManifestGame {
                steam_app_id: RETRO_REWIND_APP_ID,
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
            runtime_requirements: ManifestRuntimeRequirements::default(),
            incompatibilities: Vec::new(),
            replaces: Vec::new(),
            persistent_effects: Vec::new(),
            install_notes: Vec::new(),
        }
    }

    fn record(hash: &str, manifest: PackageManifest) -> CatalogPackage {
        CatalogPackage {
            artifact_sha256: hash.repeat(64),
            manifest,
            provenance: ManifestProvenance::Declared,
        }
    }

    fn selection(hash: &str) -> ResolveSelection {
        ResolveSelection {
            artifact_sha256: hash.repeat(64),
            variant: None,
        }
    }

    fn extracted(path: &str, hash: &str) -> ExtractedFileReport {
        ExtractedFileReport {
            path: path.to_owned(),
            bytes: 3,
            sha256: hash.repeat(64),
            executable_payload: false,
            native_binary: false,
        }
    }

    fn artifact(
        files: Vec<ExtractedFileReport>,
        layout: PackageLayoutInference,
    ) -> ArtifactManifest {
        ArtifactManifest {
            schema_version: 1,
            sha256: "d".repeat(64),
            format: ArchiveFormat::Zip,
            archive_bytes: 100,
            expanded_bytes: files.iter().map(|file| file.bytes).sum(),
            files,
            layout,
        }
    }
}
