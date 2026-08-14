use anyhow::{Context, Result, bail};
use rrmm_archive::validate_entry_path;
use rrmm_artifacts::{load_artifact_manifest, load_verified_artifact};
use rrmm_deploy::{DeploymentFile, DeploymentRequest};
use rrmm_manifest::{
    CatalogPackage, ComponentType, ManifestProvenance, load_manifest,
    validate_catalog_package_artifact,
};
use rrmm_recipes::RecipeApplicationReport;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const MAX_DEPLOYMENT_DEPTH: usize = 32;

pub struct DeploymentMetadata {
    pub transaction_id: String,
    pub installation_id: String,
    pub profile_id: String,
    pub game_root: PathBuf,
    pub state_root: PathBuf,
    pub allow_unmanaged: bool,
    pub game_running: bool,
}

pub fn materialize_deployment_request(
    artifact_store: &Path,
    package_catalog: &[CatalogPackage],
    report: &RecipeApplicationReport,
    authorized_ue4ss_policies: &BTreeSet<String>,
    metadata: DeploymentMetadata,
) -> Result<DeploymentRequest> {
    materialize_deployment(
        artifact_store,
        package_catalog,
        report,
        authorized_ue4ss_policies,
        metadata,
        true,
    )
}

pub fn materialize_desktop_deployment_request(
    artifact_store: &Path,
    package_catalog: &[CatalogPackage],
    report: &RecipeApplicationReport,
    authorized_ue4ss_policies: &BTreeSet<String>,
    metadata: DeploymentMetadata,
) -> Result<DeploymentRequest> {
    materialize_deployment(
        artifact_store,
        package_catalog,
        report,
        authorized_ue4ss_policies,
        metadata,
        false,
    )
}

fn materialize_deployment(
    artifact_store: &Path,
    package_catalog: &[CatalogPackage],
    report: &RecipeApplicationReport,
    authorized_ue4ss_policies: &BTreeSet<String>,
    metadata: DeploymentMetadata,
    require_embedded_manifest: bool,
) -> Result<DeploymentRequest> {
    if !report.ready
        || !report.resolution.ready
        || !report.blockers.is_empty()
        || !report.resolution.blockers.is_empty()
    {
        bail!("blocked recipe resolution cannot be materialized");
    }
    if !report.winner_decisions.is_empty() {
        bail!("select_winner decisions cannot be materialized until PAK load order is verified");
    }

    let resolved_ids: BTreeSet<_> = report
        .resolution
        .packages
        .iter()
        .map(|package| package.package_id.as_str())
        .collect();
    let mut overrides = BTreeMap::new();
    for install_override in &report.install_name_overrides {
        if !resolved_ids.contains(install_override.package_id.as_str()) {
            bail!(
                "install-name override targets unresolved package '{}'",
                install_override.package_id
            );
        }
        let normalized = validate_entry_path(&install_override.install_name, false, 1)
            .context("invalid recipe install-name override")?;
        if normalized.path != install_override.install_name
            || !install_override
                .install_name
                .to_ascii_lowercase()
                .ends_with(".pak")
        {
            bail!(
                "invalid PAK install-name override '{}'",
                install_override.install_name
            );
        }
        if overrides
            .insert(
                install_override.package_id.as_str(),
                install_override.install_name.as_str(),
            )
            .is_some()
        {
            bail!(
                "multiple install-name overrides target package '{}'",
                install_override.package_id
            );
        }
    }

    let mut files = Vec::new();
    for resolved in &report.resolution.packages {
        let matching: Vec<_> = package_catalog
            .iter()
            .filter(|candidate| {
                candidate.artifact_sha256 == resolved.artifact_sha256
                    && candidate.manifest.id == resolved.package_id
            })
            .collect();
        let [package] = matching.as_slice() else {
            bail!(
                "resolved package '{}' must have exactly one exact catalog entry",
                resolved.package_id
            );
        };
        match &package.provenance {
            ManifestProvenance::Declared => {}
            ManifestProvenance::Inferred { reviewed: true, .. } if !require_embedded_manifest => {}
            _ => bail!(
                "resolved package '{}' does not have reviewed deployment metadata",
                resolved.package_id
            ),
        }

        let artifact_root = artifact_root(artifact_store, &resolved.artifact_sha256)?;
        let artifact = if require_embedded_manifest {
            load_verified_artifact(&artifact_root)
        } else {
            load_artifact_manifest(&artifact_root)
        }
        .with_context(|| format!("failed to revalidate package '{}'", resolved.package_id))?;
        validate_catalog_package_artifact(package, &artifact)
            .with_context(|| format!("artifact binding failed for '{}'", resolved.package_id))?;
        if package.provenance == ManifestProvenance::Declared {
            let embedded_path = artifact_file_path(&artifact_root, "rrmm-manifest.json");
            if embedded_path.is_file() {
                let embedded = load_manifest(&embedded_path)
                    .with_context(|| format!("failed to load {}", embedded_path.display()))?;
                if embedded != package.manifest {
                    bail!(
                        "catalog manifest for '{}' differs from its embedded manifest",
                        resolved.package_id
                    );
                }
            } else if require_embedded_manifest {
                bail!(
                    "package '{}' has no embedded rrmm-manifest.json",
                    resolved.package_id
                );
            }
        }

        let mut selected_ids = BTreeSet::new();
        for component_id in &resolved.component_ids {
            if !selected_ids.insert(component_id.as_str()) {
                bail!(
                    "resolved package '{}' selects component '{}' more than once",
                    resolved.package_id,
                    component_id
                );
            }
        }
        let selected_components: Vec<_> = package
            .manifest
            .components
            .iter()
            .filter(|component| selected_ids.contains(component.id.as_str()))
            .collect();
        if selected_components.len() != selected_ids.len() {
            bail!(
                "resolved package '{}' references an unknown component",
                resolved.package_id
            );
        }

        let package_override = overrides.remove(resolved.package_id.as_str());
        let selected_paks = selected_components
            .iter()
            .filter(|component| component.component_type == ComponentType::Pak)
            .count();
        if package_override.is_some() && selected_paks != 1 {
            bail!(
                "install-name override for '{}' requires exactly one selected PAK",
                resolved.package_id
            );
        }

        let artifact_files: BTreeMap<_, _> = artifact
            .files
            .iter()
            .map(|file| (file.path.as_str(), file))
            .collect();
        for component in selected_components {
            match component.component_type {
                ComponentType::Pak => {
                    let source = artifact_files.get(component.root.as_str()).ok_or_else(|| {
                        anyhow::anyhow!(
                            "selected PAK component '{}' is absent from its artifact",
                            component.id
                        )
                    })?;
                    let install_name = package_override
                        .or(component.install_name.as_deref())
                        .context("selected PAK component has no install name")?;
                    push_file(
                        &mut files,
                        &artifact_root,
                        source,
                        format!("RetroRewind/Content/Paks/{install_name}"),
                        &package.manifest.id,
                        &package.manifest.name,
                    )?;
                    let signature_path = replace_extension(&component.root, "sig");
                    if let Some(signature) = artifact
                        .files
                        .iter()
                        .find(|file| file.path.eq_ignore_ascii_case(&signature_path))
                    {
                        let signature_name = replace_extension(install_name, "sig");
                        push_file(
                            &mut files,
                            &artifact_root,
                            signature,
                            format!("RetroRewind/Content/Paks/{signature_name}"),
                            &package.manifest.id,
                            &package.manifest.name,
                        )?;
                    }
                }
                ComponentType::Ue4ss => {
                    let policy_id = package
                        .manifest
                        .runtime_requirements
                        .ue4ss_loader_policy
                        .as_ref()
                        .with_context(|| {
                            format!(
                                "selected UE4SS package '{}' declares no loader policy",
                                resolved.package_id
                            )
                        })?;
                    if !authorized_ue4ss_policies.contains(policy_id) {
                        bail!(
                            "UE4SS loader policy '{}' was not authorized for this deployment",
                            policy_id
                        );
                    }
                    let install_name = component
                        .install_name
                        .as_deref()
                        .context("selected UE4SS component has no install name")?;
                    let prefix = format!("{}/", component.root);
                    let descendants: Vec<_> = artifact
                        .files
                        .iter()
                        .filter_map(|file| {
                            file.path.strip_prefix(&prefix).map(|suffix| (file, suffix))
                        })
                        .collect();
                    if descendants.is_empty() {
                        bail!(
                            "selected UE4SS component '{}' has no artifact files",
                            component.id
                        );
                    }
                    if !descendants
                        .iter()
                        .any(|(_, suffix)| suffix.eq_ignore_ascii_case("enabled.txt"))
                    {
                        bail!(
                            "selected UE4SS component '{}' has no enabled.txt marker",
                            component.id
                        );
                    }
                    if let Some((unsafe_file, _)) = descendants
                        .iter()
                        .find(|(file, _)| file.executable_payload || file.native_binary)
                    {
                        bail!(
                            "selected UE4SS component '{}' contains unsupported executable or native payload '{}'",
                            component.id,
                            unsafe_file.path
                        );
                    }
                    for (source, suffix) in descendants {
                        push_file(
                            &mut files,
                            &artifact_root,
                            source,
                            format!(
                                "RetroRewind/Binaries/Win64/ue4ss/Mods/{install_name}/{suffix}"
                            ),
                            &package.manifest.id,
                            &package.manifest.name,
                        )?;
                    }
                }
                unsupported => {
                    bail!(
                        "selected component '{}' has unsupported deployment type {:?}",
                        component.id,
                        unsupported
                    );
                }
            }
        }
    }
    if !overrides.is_empty() {
        bail!("one or more install-name overrides were not consumed");
    }
    validate_destinations(&files)?;
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

    Ok(DeploymentRequest {
        transaction_id: metadata.transaction_id,
        installation_id: metadata.installation_id,
        profile_id: metadata.profile_id,
        game_root: metadata.game_root,
        state_root: metadata.state_root,
        files,
        external_files: Vec::new(),
        allow_unmanaged: metadata.allow_unmanaged,
        game_running: metadata.game_running,
    })
}

fn artifact_root(store: &Path, sha256: &str) -> Result<PathBuf> {
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("resolved artifact SHA-256 is invalid");
    }
    Ok(store.join("artifacts").join(&sha256[..2]).join(sha256))
}

fn artifact_file_path(artifact_root: &Path, relative_path: &str) -> PathBuf {
    relative_path
        .split('/')
        .fold(artifact_root.join("files"), |path, part| path.join(part))
}

fn replace_extension(path: &str, extension: &str) -> String {
    path.rsplit_once('.').map_or_else(
        || format!("{path}.{extension}"),
        |(base, _)| format!("{base}.{extension}"),
    )
}

fn push_file(
    files: &mut Vec<DeploymentFile>,
    artifact_root: &Path,
    source: &rrmm_archive::ExtractedFileReport,
    relative_path: String,
    package_id: &str,
    package_name: &str,
) -> Result<()> {
    let normalized = validate_entry_path(&relative_path, false, MAX_DEPLOYMENT_DEPTH)
        .with_context(|| format!("invalid generated deployment path '{relative_path}'"))?;
    if normalized.path != relative_path {
        bail!("generated deployment path is not normalized: '{relative_path}'");
    }
    files.push(DeploymentFile {
        source: artifact_file_path(artifact_root, &source.path),
        relative_path,
        bytes: source.bytes,
        sha256: source.sha256.clone(),
        package_id: Some(package_id.to_owned()),
        package_name: Some(package_name.to_owned()),
    });
    Ok(())
}

fn validate_destinations(files: &[DeploymentFile]) -> Result<()> {
    let mut by_key = BTreeMap::new();
    for file in files {
        let normalized = validate_entry_path(&file.relative_path, false, MAX_DEPLOYMENT_DEPTH)
            .with_context(|| format!("invalid deployment path '{}'", file.relative_path))?;
        if let Some(existing) = by_key.insert(normalized.collision_key, &file.relative_path) {
            bail!(
                "deployment destination collision between '{}' and '{}'",
                existing,
                file.relative_path
            );
        }
    }
    let keys: Vec<_> = by_key.keys().collect();
    for pair in keys.windows(2) {
        if pair[1].starts_with(&format!("{}/", pair[0])) {
            bail!(
                "deployment file/directory collision between '{}' and '{}'",
                by_key[pair[0]],
                by_key[pair[1]]
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrmm_archive::{
        ArchiveFormat, ExtractedFileReport, PackageKind, PackageLayoutInference, sha256_path,
    };
    use rrmm_artifacts::ArtifactManifest;
    use rrmm_manifest::{
        ManifestComponent, ManifestGame, PackageManifest, ResolutionReport, ResolvedPackage,
    };
    use rrmm_recipes::{InstallNameOverride, WinnerDecision};
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn materializes_pak_and_ue4ss_components_with_an_install_name_override() {
        let temporary = TempDir::new().unwrap();
        let pak_hash = hash_bytes(&temporary, "pak-hash", b"pak bytes");
        let manifest = package_manifest(vec![
            ManifestComponent {
                id: "pak".to_owned(),
                component_type: ComponentType::Pak,
                root: "payload/Fast_P.pak".to_owned(),
                required: true,
                install_name: Some("Fast_P.pak".to_owned()),
                sha256: Some(pak_hash),
            },
            ManifestComponent {
                id: "ue4ss".to_owned(),
                component_type: ComponentType::Ue4ss,
                root: "FastTurn".to_owned(),
                required: true,
                install_name: Some("FastTurn".to_owned()),
                sha256: None,
            },
        ]);
        let store = temporary.path().join("store");
        let package = write_artifact(
            &store,
            &manifest,
            &[
                ("payload/Fast_P.pak", b"pak bytes"),
                ("FastTurn/Scripts/main.lua", b"return {}"),
                ("FastTurn/config.lua", b"return { enabled = true }"),
                ("FastTurn/enabled.txt", b""),
            ],
        );
        let report = application_report(
            &package,
            vec!["pak".to_owned(), "ue4ss".to_owned()],
            vec![InstallNameOverride {
                recipe_id: "compat".to_owned(),
                package_id: manifest.id.clone(),
                install_name: "zzzz_Fast_P.pak".to_owned(),
            }],
        );

        let request = materialize_deployment_request(
            &store,
            std::slice::from_ref(&package),
            &report,
            &authorized_policies(&manifest),
            metadata(&temporary),
        )
        .unwrap();

        let destinations: Vec<_> = request
            .files
            .iter()
            .map(|file| file.relative_path.as_str())
            .collect();
        assert_eq!(
            destinations,
            vec![
                "RetroRewind/Binaries/Win64/ue4ss/Mods/FastTurn/Scripts/main.lua",
                "RetroRewind/Binaries/Win64/ue4ss/Mods/FastTurn/config.lua",
                "RetroRewind/Binaries/Win64/ue4ss/Mods/FastTurn/enabled.txt",
                "RetroRewind/Content/Paks/zzzz_Fast_P.pak",
            ]
        );
        assert!(request.files.iter().all(|file| file.source.is_file()));
    }

    #[test]
    fn rejects_artifact_tampering_during_materialization() {
        let temporary = TempDir::new().unwrap();
        let pak_hash = hash_bytes(&temporary, "pak-hash", b"pak bytes");
        let manifest = package_manifest(vec![ManifestComponent {
            id: "pak".to_owned(),
            component_type: ComponentType::Pak,
            root: "Fast_P.pak".to_owned(),
            required: true,
            install_name: Some("Fast_P.pak".to_owned()),
            sha256: Some(pak_hash),
        }]);
        let store = temporary.path().join("store");
        let package = write_artifact(&store, &manifest, &[("Fast_P.pak", b"pak bytes")]);
        let report = application_report(&package, vec!["pak".to_owned()], Vec::new());
        let root = artifact_root(&store, &package.artifact_sha256).unwrap();
        fs::write(root.join("files/Fast_P.pak"), b"tampered").unwrap();

        let error = materialize_deployment_request(
            &store,
            std::slice::from_ref(&package),
            &report,
            &authorized_policies(&manifest),
            metadata(&temporary),
        )
        .unwrap_err();
        assert!(error.to_string().contains("failed to revalidate package"));
    }

    #[test]
    fn rejects_native_payloads_hidden_inside_a_ue4ss_component() {
        let temporary = TempDir::new().unwrap();
        let manifest = package_manifest(vec![ManifestComponent {
            id: "ue4ss".to_owned(),
            component_type: ComponentType::Ue4ss,
            root: "UnsafeMod".to_owned(),
            required: true,
            install_name: Some("UnsafeMod".to_owned()),
            sha256: None,
        }]);
        let store = temporary.path().join("store");
        let package = write_artifact(
            &store,
            &manifest,
            &[
                ("UnsafeMod/Scripts/main.lua", b"return {}"),
                ("UnsafeMod/enabled.txt", b""),
                ("UnsafeMod/dlls/main.dll", b"native"),
            ],
        );
        let report = application_report(&package, vec!["ue4ss".to_owned()], Vec::new());

        let error = materialize_deployment_request(
            &store,
            std::slice::from_ref(&package),
            &report,
            &authorized_policies(&manifest),
            metadata(&temporary),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported executable or native")
        );
    }

    #[test]
    fn rejects_a_ue4ss_component_without_an_enable_marker() {
        let temporary = TempDir::new().unwrap();
        let manifest = package_manifest(vec![ManifestComponent {
            id: "ue4ss".to_owned(),
            component_type: ComponentType::Ue4ss,
            root: "DisabledMod".to_owned(),
            required: true,
            install_name: Some("DisabledMod".to_owned()),
            sha256: None,
        }]);
        let store = temporary.path().join("store");
        let package = write_artifact(
            &store,
            &manifest,
            &[("DisabledMod/Scripts/main.lua", b"return {}")],
        );
        let report = application_report(&package, vec!["ue4ss".to_owned()], Vec::new());

        let error = materialize_deployment_request(
            &store,
            std::slice::from_ref(&package),
            &report,
            &authorized_policies(&manifest),
            metadata(&temporary),
        )
        .unwrap_err();
        assert!(error.to_string().contains("has no enabled.txt marker"));
    }

    #[test]
    fn rejects_a_selected_ue4ss_component_without_an_authorized_loader_policy() {
        let temporary = TempDir::new().unwrap();
        let mut manifest = package_manifest(vec![ManifestComponent {
            id: "ue4ss".to_owned(),
            component_type: ComponentType::Ue4ss,
            root: "PolicyMod".to_owned(),
            required: true,
            install_name: Some("PolicyMod".to_owned()),
            sha256: None,
        }]);
        manifest.runtime_requirements = rrmm_manifest::ManifestRuntimeRequirements::default();
        let store = temporary.path().join("store");
        let package = write_artifact(
            &store,
            &manifest,
            &[
                ("PolicyMod/Scripts/main.lua", b"return {}"),
                ("PolicyMod/enabled.txt", b""),
            ],
        );
        let report = application_report(&package, vec!["ue4ss".to_owned()], Vec::new());

        let error = materialize_deployment_request(
            &store,
            std::slice::from_ref(&package),
            &report,
            &BTreeSet::new(),
            metadata(&temporary),
        )
        .unwrap_err();
        assert!(error.to_string().contains("declares no loader policy"));
    }

    #[test]
    fn rejects_unenforced_winner_decisions_before_reading_artifacts() {
        let temporary = TempDir::new().unwrap();
        let mut report = RecipeApplicationReport {
            ready: true,
            resolution: ResolutionReport {
                build_id: 23_896_268,
                ready: true,
                packages: Vec::new(),
                blockers: Vec::new(),
            },
            applied_recipe_ids: vec!["compat".to_owned()],
            winner_decisions: vec![WinnerDecision {
                recipe_id: "compat".to_owned(),
                winner_package_id: "winner".to_owned(),
                resource: "RetroRewind/Content/Test.uasset".to_owned(),
            }],
            install_name_overrides: Vec::new(),
            disabled_components: Vec::new(),
            blockers: Vec::new(),
        };

        let error = materialize_deployment_request(
            temporary.path(),
            &[],
            &report,
            &BTreeSet::new(),
            metadata(&temporary),
        )
        .unwrap_err();
        assert!(error.to_string().contains("select_winner"));

        report.ready = false;
        let error = materialize_deployment_request(
            temporary.path(),
            &[],
            &report,
            &BTreeSet::new(),
            metadata(&temporary),
        )
        .unwrap_err();
        assert!(error.to_string().contains("blocked recipe resolution"));
    }

    #[test]
    fn desktop_materializes_a_reviewed_archive_without_an_embedded_manifest() {
        let temporary = TempDir::new().unwrap();
        let pak_hash = hash_bytes(&temporary, "pak-hash", b"pak bytes");
        let manifest = package_manifest(vec![ManifestComponent {
            id: "pak".to_owned(),
            component_type: ComponentType::Pak,
            root: "Download/Example_P.pak".to_owned(),
            required: true,
            install_name: Some("Example_P.pak".to_owned()),
            sha256: Some(pak_hash),
        }]);
        let store = temporary.path().join("store");
        let package = write_artifact_internal(
            &store,
            &manifest,
            &[
                ("Download/Example_P.pak", b"pak bytes"),
                ("Download/Example_P.sig", b"signature"),
            ],
            false,
            ManifestProvenance::Inferred {
                confidence: rrmm_manifest::InferenceConfidence::High,
                reviewed: true,
                issues: Vec::new(),
            },
        );
        let report = application_report(&package, vec!["pak".to_owned()], Vec::new());

        let request = materialize_desktop_deployment_request(
            &store,
            std::slice::from_ref(&package),
            &report,
            &BTreeSet::new(),
            metadata(&temporary),
        )
        .unwrap();

        assert_eq!(request.files.len(), 2);
        assert!(
            request
                .files
                .iter()
                .any(|file| { file.relative_path == "RetroRewind/Content/Paks/Example_P.pak" })
        );
        assert!(
            request
                .files
                .iter()
                .any(|file| { file.relative_path == "RetroRewind/Content/Paks/Example_P.sig" })
        );
        assert!(
            materialize_deployment_request(
                &store,
                std::slice::from_ref(&package),
                &report,
                &BTreeSet::new(),
                metadata(&temporary),
            )
            .unwrap_err()
            .to_string()
            .contains("reviewed deployment metadata")
        );

        let mut declared = package;
        declared.provenance = ManifestProvenance::Declared;
        materialize_desktop_deployment_request(
            &store,
            &[declared.clone()],
            &report,
            &BTreeSet::new(),
            metadata(&temporary),
        )
        .unwrap();
        assert!(
            materialize_deployment_request(
                &store,
                &[declared],
                &report,
                &BTreeSet::new(),
                metadata(&temporary),
            )
            .unwrap_err()
            .to_string()
            .contains("no embedded rrmm-manifest.json")
        );
    }

    #[test]
    fn rejects_case_folded_and_file_directory_destination_collisions() {
        let source = PathBuf::from("unused");
        let collision = vec![
            DeploymentFile {
                source: source.clone(),
                relative_path: "RetroRewind/Content/Paks/Example_P.pak".to_owned(),
                bytes: 1,
                sha256: "0".repeat(64),
                package_id: None,
                package_name: None,
            },
            DeploymentFile {
                source: source.clone(),
                relative_path: "retrorewind/content/paks/example_p.PAK".to_owned(),
                bytes: 1,
                sha256: "1".repeat(64),
                package_id: None,
                package_name: None,
            },
        ];
        assert!(
            validate_destinations(&collision)
                .unwrap_err()
                .to_string()
                .contains("destination collision")
        );

        let prefix_collision = vec![
            DeploymentFile {
                source: source.clone(),
                relative_path: "RetroRewind/Binaries/Win64/ue4ss/Mods/FastTurn".to_owned(),
                bytes: 1,
                sha256: "0".repeat(64),
                package_id: None,
                package_name: None,
            },
            DeploymentFile {
                source,
                relative_path: "RetroRewind/Binaries/Win64/ue4ss/Mods/FastTurn/Scripts/main.lua"
                    .to_owned(),
                bytes: 1,
                sha256: "1".repeat(64),
                package_id: None,
                package_name: None,
            },
        ];
        assert!(
            validate_destinations(&prefix_collision)
                .unwrap_err()
                .to_string()
                .contains("file/directory collision")
        );
    }

    fn package_manifest(components: Vec<ManifestComponent>) -> PackageManifest {
        let ue4ss_loader_policy = components
            .iter()
            .any(|component| component.component_type == ComponentType::Ue4ss)
            .then(|| "ue4ss:test-policy".to_owned());
        PackageManifest {
            schema_version: 1,
            id: "fixture-package".to_owned(),
            name: "Fixture Package".to_owned(),
            version: "1.0.0".to_owned(),
            game: ManifestGame {
                steam_app_id: 3_552_140,
                supported_build_ids: vec!["23896268".to_owned()],
                unreal_engine: "5.4.4".to_owned(),
            },
            source: None,
            components,
            variants: Vec::new(),
            requirements: Vec::new(),
            runtime_requirements: rrmm_manifest::ManifestRuntimeRequirements {
                ue4ss_loader_policy,
            },
            incompatibilities: Vec::new(),
            replaces: Vec::new(),
            persistent_effects: Vec::new(),
            install_notes: Vec::new(),
        }
    }

    fn authorized_policies(manifest: &PackageManifest) -> BTreeSet<String> {
        manifest
            .runtime_requirements
            .ue4ss_loader_policy
            .iter()
            .cloned()
            .collect()
    }

    fn write_artifact(
        store: &Path,
        package_manifest: &PackageManifest,
        payloads: &[(&str, &[u8])],
    ) -> CatalogPackage {
        write_artifact_internal(
            store,
            package_manifest,
            payloads,
            true,
            ManifestProvenance::Declared,
        )
    }

    fn write_artifact_internal(
        store: &Path,
        package_manifest: &PackageManifest,
        payloads: &[(&str, &[u8])],
        embed_manifest: bool,
        provenance: ManifestProvenance,
    ) -> CatalogPackage {
        let source_bytes = format!("archive for {}", package_manifest.id);
        let scratch = store.parent().unwrap().join("source-hash");
        fs::write(&scratch, source_bytes.as_bytes()).unwrap();
        let artifact_sha256 = sha256_path(&scratch).unwrap();
        fs::remove_file(&scratch).unwrap();
        let root = artifact_root(store, &artifact_sha256).unwrap();
        let files_root = root.join("files");
        fs::create_dir_all(&files_root).unwrap();
        fs::write(root.join("source.zip"), source_bytes).unwrap();

        let mut files = Vec::new();
        for (path, bytes) in payloads {
            let destination = artifact_file_path(&root, path);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::write(&destination, bytes).unwrap();
            files.push(extracted_file(path, &destination));
        }
        if embed_manifest {
            let embedded_path = artifact_file_path(&root, "rrmm-manifest.json");
            fs::write(
                &embedded_path,
                serde_json::to_vec_pretty(package_manifest).unwrap(),
            )
            .unwrap();
            files.push(extracted_file("rrmm-manifest.json", &embedded_path));
        }
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let expanded_bytes = files.iter().map(|file| file.bytes).sum();
        let artifact_manifest = ArtifactManifest {
            schema_version: 1,
            sha256: artifact_sha256.clone(),
            format: ArchiveFormat::Zip,
            archive_bytes: fs::metadata(root.join("source.zip")).unwrap().len(),
            expanded_bytes,
            files,
            layout: PackageLayoutInference {
                kind: PackageKind::Hybrid,
                pak_files: Vec::new(),
                ue4ss_mod_roots: Vec::new(),
                documentation_files: Vec::new(),
                executable_files: Vec::new(),
                requires_review: false,
                issues: Vec::new(),
            },
        };
        fs::write(
            root.join("manifest.json"),
            serde_json::to_vec_pretty(&artifact_manifest).unwrap(),
        )
        .unwrap();
        CatalogPackage {
            artifact_sha256,
            manifest: package_manifest.clone(),
            provenance,
        }
    }

    fn extracted_file(path: &str, source: &Path) -> ExtractedFileReport {
        let native_binary = path.to_ascii_lowercase().ends_with(".dll");
        ExtractedFileReport {
            path: path.to_owned(),
            bytes: fs::metadata(source).unwrap().len(),
            sha256: sha256_path(source).unwrap(),
            executable_payload: native_binary,
            native_binary,
        }
    }

    fn hash_bytes(temporary: &TempDir, name: &str, bytes: &[u8]) -> String {
        let path = temporary.path().join(name);
        fs::write(&path, bytes).unwrap();
        sha256_path(&path).unwrap()
    }

    fn application_report(
        package: &CatalogPackage,
        component_ids: Vec<String>,
        install_name_overrides: Vec<InstallNameOverride>,
    ) -> RecipeApplicationReport {
        RecipeApplicationReport {
            ready: true,
            resolution: ResolutionReport {
                build_id: 23_896_268,
                ready: true,
                packages: vec![ResolvedPackage {
                    package_id: package.manifest.id.clone(),
                    artifact_sha256: package.artifact_sha256.clone(),
                    variant: None,
                    component_ids,
                    automatically_selected: false,
                }],
                blockers: Vec::new(),
            },
            applied_recipe_ids: vec!["compat".to_owned()],
            winner_decisions: Vec::new(),
            install_name_overrides,
            disabled_components: Vec::new(),
            blockers: Vec::new(),
        }
    }

    fn metadata(temporary: &TempDir) -> DeploymentMetadata {
        DeploymentMetadata {
            transaction_id: "transaction".to_owned(),
            installation_id: "installation".to_owned(),
            profile_id: "profile".to_owned(),
            game_root: temporary.path().join("game"),
            state_root: temporary.path().join("state"),
            allow_unmanaged: false,
            game_running: false,
        }
    }
}
