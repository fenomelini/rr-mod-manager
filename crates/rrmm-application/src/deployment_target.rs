use anyhow::{Context, Result, bail};
use rrmm_deploy::DeploymentPlan;
use rrmm_domain::{
    BuildRecipe, BuildStatus, LayoutStatus, PakLoadOrderPreference, Profile, RETRO_REWIND_APP_ID,
};
use rrmm_manifest::{CatalogPackage, ComponentType, ResolveRequest};
use rrmm_recipes::{CatalogTrustFloor, RecipeApplicationReport};
use rrmm_steam::inspect_manifest;
use rrmm_store::Store;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeDeploymentValidation {
    pub schema_version: u32,
    pub profile_revision: u64,
    #[serde(default)]
    pub pak_load_order: Vec<PakLoadOrderPreference>,
    pub request: ResolveRequest,
    pub catalog: RecipeCatalogValidation,
    pub manifest_path: PathBuf,
    pub game_root: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ue4ss: Option<Ue4ssDeploymentValidation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ue4ssDeploymentValidation {
    pub required_policies: Vec<String>,
    pub loader_identity: rrmm_ue4ss::Ue4ssLoaderIdentityReport,
    pub evaluations: Vec<rrmm_ue4ss::Ue4ssLoaderPolicyEvaluation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeCatalogValidation {
    pub trust_floor: CatalogTrustFloor,
    pub valid_until: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeDeploymentPlan {
    pub schema_version: u32,
    pub plan: DeploymentPlan,
    pub validation: RecipeDeploymentValidation,
}

#[derive(Debug, Clone, Copy)]
pub struct RecipeDeploymentResolution<'a> {
    pub request: &'a ResolveRequest,
    pub package_catalog: &'a [CatalogPackage],
    pub report: &'a RecipeApplicationReport,
}

pub fn validate_recipe_deployment_target(
    store: &Store,
    installation_id: &str,
    profile_id: &str,
    game_root: &Path,
    resolution: RecipeDeploymentResolution<'_>,
    build_recipe: &BuildRecipe,
    catalog: RecipeCatalogValidation,
) -> Result<RecipeDeploymentValidation> {
    validate_recipe_deployment_target_with_profile(
        store,
        installation_id,
        profile_id,
        game_root,
        resolution,
        build_recipe,
        catalog,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn validate_recipe_deployment_target_with_profile(
    store: &Store,
    installation_id: &str,
    profile_id: &str,
    game_root: &Path,
    resolution: RecipeDeploymentResolution<'_>,
    build_recipe: &BuildRecipe,
    catalog: RecipeCatalogValidation,
    profile_override: Option<&Profile>,
) -> Result<RecipeDeploymentValidation> {
    let RecipeDeploymentResolution {
        request,
        package_catalog,
        report,
    } = resolution;
    let stored_profile = store
        .active_profile(installation_id)?
        .with_context(|| format!("installation '{installation_id}' has no active profile"))?;
    if stored_profile.id != profile_id {
        bail!(
            "profile '{}' is not active for installation '{}'",
            profile_id,
            installation_id
        );
    }
    let profile = profile_override.unwrap_or(&stored_profile);
    if profile.id != stored_profile.id || profile.revision < stored_profile.revision {
        bail!("profile override does not match the active stored profile");
    }
    let mut profile_selections: Vec<_> = profile
        .packages
        .iter()
        .filter(|selection| selection.enabled)
        .map(|selection| {
            (
                selection.artifact_sha256.as_str(),
                selection.variant.as_deref(),
            )
        })
        .collect();
    let mut request_selections: Vec<_> = request
        .selections
        .iter()
        .map(|selection| {
            (
                selection.artifact_sha256.as_str(),
                selection.variant.as_deref(),
            )
        })
        .collect();
    profile_selections.sort_unstable();
    request_selections.sort_unstable();
    if profile_selections != request_selections {
        bail!("resolution request does not match the active profile selection");
    }

    let requested_root = fs::canonicalize(game_root)
        .with_context(|| format!("failed to resolve game root {}", game_root.display()))?;
    let matching: Vec<_> = store
        .installations()?
        .into_iter()
        .filter(|inspection| {
            fs::canonicalize(&inspection.installation.game_root)
                .is_ok_and(|stored_root| stored_root == requested_root)
        })
        .collect();
    let [stored] = matching.as_slice() else {
        bail!("game root must match exactly one inventoried Steam installation");
    };

    let live = inspect_manifest(
        &stored.installation.manifest_path,
        &stored.installation.steam_root,
        &stored.installation.library_root,
        stored.installation.source.clone(),
        Some(build_recipe),
        true,
    )
    .context("failed to re-inspect the deployment target")?;
    let live_root = fs::canonicalize(&live.installation.game_root).with_context(|| {
        format!(
            "failed to resolve inspected game root {}",
            live.installation.game_root.display()
        )
    })?;
    if live_root != requested_root {
        bail!("live Steam manifest resolves to a different game root");
    }
    if live.installation.app_id != RETRO_REWIND_APP_ID {
        bail!("deployment target is not Retro Rewind");
    }
    if live.installation.build_id != request.build_id
        || live.installation.build_id != build_recipe.build_id
    {
        bail!(
            "deployment target build {} does not match resolved build {}",
            live.installation.build_id,
            request.build_id
        );
    }
    if live.layout_status != LayoutStatus::Complete
        || live.build_status != BuildStatus::SupportedExact
    {
        bail!(
            "deployment target is not an exact supported installation: layout={:?}, build={:?}",
            live.layout_status,
            live.build_status
        );
    }
    let manifest_path = fs::canonicalize(&live.installation.manifest_path).with_context(|| {
        format!(
            "failed to resolve Steam manifest {}",
            live.installation.manifest_path.display()
        )
    })?;
    let ue4ss = validate_ue4ss_requirements(&live_root, package_catalog, report, build_recipe)?;
    Ok(RecipeDeploymentValidation {
        schema_version: 1,
        profile_revision: profile.revision,
        pak_load_order: profile.pak_load_order.clone(),
        request: request.clone(),
        catalog,
        manifest_path,
        game_root: live_root,
        ue4ss,
    })
}

fn validate_ue4ss_requirements(
    game_root: &Path,
    package_catalog: &[CatalogPackage],
    report: &RecipeApplicationReport,
    build_recipe: &BuildRecipe,
) -> Result<Option<Ue4ssDeploymentValidation>> {
    if !report.ready || !report.resolution.ready {
        bail!("blocked recipe resolution cannot authorize UE4SS deployment");
    }
    let mut required_policies = BTreeSet::new();
    for resolved in &report.resolution.packages {
        let matching: Vec<_> = package_catalog
            .iter()
            .filter(|package| {
                package.artifact_sha256 == resolved.artifact_sha256
                    && package.manifest.id == resolved.package_id
            })
            .collect();
        let [package] = matching.as_slice() else {
            bail!(
                "resolved package '{}' must have exactly one exact catalog entry for UE4SS validation",
                resolved.package_id
            );
        };
        let selected_ids: BTreeSet<_> = resolved.component_ids.iter().map(String::as_str).collect();
        let selects_ue4ss = package.manifest.components.iter().any(|component| {
            selected_ids.contains(component.id.as_str())
                && component.component_type == ComponentType::Ue4ss
        });
        if selects_ue4ss {
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
            required_policies.insert(policy_id.clone());
        }
    }
    if required_policies.is_empty() {
        return Ok(None);
    }

    let loader_identity = rrmm_ue4ss::inspect_ue4ss_loader_identity(
        game_root,
        &rrmm_ue4ss::Ue4ssLoaderIdentityLimits::default(),
    )
    .context("failed to inspect UE4SS loader identity")?;
    let mut evaluations = Vec::new();
    for policy_id in &required_policies {
        let evaluation =
            rrmm_ue4ss::evaluate_ue4ss_loader_policy(build_recipe, policy_id, &loader_identity);
        if evaluation.status != rrmm_ue4ss::Ue4ssLoaderPolicyStatus::AllowedExact {
            bail!(
                "UE4SS loader policy '{}' blocked deployment with status {:?}",
                policy_id,
                evaluation.status
            );
        }
        evaluations.push(evaluation);
    }
    Ok(Some(Ue4ssDeploymentValidation {
        required_policies: required_policies.into_iter().collect(),
        loader_identity,
        evaluations,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrmm_archive::sha256_path;
    use rrmm_domain::{
        CriticalFileRecipe, InstallationSource, Profile, ProfilePackageSelection,
        SUPPORTED_BUILD_ID, Ue4ssLoaderBuildRecipe, Ue4ssLoaderPolicyRecipe,
    };
    use rrmm_manifest::{
        CatalogPackage, ComponentType, ManifestComponent, ManifestGame, ManifestProvenance,
        ManifestRuntimeRequirements, PackageManifest, ResolutionReport, ResolveSelection,
        ResolvedPackage,
    };
    use rrmm_recipes::RecipeApplicationReport;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn binds_the_request_to_an_active_profile_and_live_exact_installation() {
        let temporary = TempDir::new().unwrap();
        let library = temporary.path().join("library");
        let game = library.join("steamapps/common/RetroRewind");
        for relative in [
            "RetroRewind.exe",
            "RetroRewind/Binaries/Win64/RetroRewind-Win64-Shipping.exe",
            "RetroRewind/Content/Paks/RetroRewind-Windows.pak",
        ] {
            let path = game.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"fixture").unwrap();
        }
        let proxy = game.join("RetroRewind/Binaries/Win64/dwmapi.dll");
        let core = game.join("RetroRewind/Binaries/Win64/ue4ss/UE4SS.dll");
        fs::create_dir_all(core.parent().unwrap()).unwrap();
        fs::write(&proxy, b"proxy fixture").unwrap();
        fs::write(&core, b"core fixture").unwrap();
        let manifest = library.join("steamapps/appmanifest_3552140.acf");
        fs::write(
            &manifest,
            format!(
                r#""AppState" {{ "appid" "{RETRO_REWIND_APP_ID}" "StateFlags" "4" "installdir" "RetroRewind" "buildid" "{SUPPORTED_BUILD_ID}" }}"#
            ),
        )
        .unwrap();
        let critical = game.join("RetroRewind.exe");
        let recipe = BuildRecipe {
            app_id: RETRO_REWIND_APP_ID,
            build_id: SUPPORTED_BUILD_ID,
            engine_version: "5.4.4".to_owned(),
            pak_version: 11,
            critical_files: vec![CriticalFileRecipe {
                relative_path: "RetroRewind.exe".into(),
                size: fs::metadata(&critical).unwrap().len(),
                sha256: sha256_path(&critical).unwrap(),
            }],
            ue4ss_loader_builds: vec![Ue4ssLoaderBuildRecipe {
                id: "ue4ss-test-build".to_owned(),
                proxy_sha256: sha256_path(&proxy).unwrap(),
                core_sha256: sha256_path(&core).unwrap(),
            }],
            ue4ss_loader_policies: vec![Ue4ssLoaderPolicyRecipe {
                id: "ue4ss:test-policy".to_owned(),
                allowed_build_ids: vec!["ue4ss-test-build".to_owned()],
                known_unsafe_build_ids: Vec::new(),
            }],
        };
        let inspection = inspect_manifest(
            &manifest,
            &library,
            &library,
            InstallationSource::UserOverride,
            Some(&recipe),
            true,
        )
        .unwrap();
        let store = Store::open(&temporary.path().join("rrmm.sqlite")).unwrap();
        store.upsert_installation(&inspection).unwrap();
        let artifact_sha256 = "a".repeat(64);
        store
            .create_profile(&Profile {
                schema_version: 1,
                id: "profile".to_owned(),
                name: "Profile".to_owned(),
                revision: 0,
                packages: vec![ProfilePackageSelection {
                    artifact_sha256: artifact_sha256.clone(),
                    variant: Some("default".to_owned()),
                    enabled: true,
                }],
                pak_load_order: Vec::new(),
            })
            .unwrap();
        store.set_active_profile("installation", "profile").unwrap();
        let request = ResolveRequest {
            build_id: SUPPORTED_BUILD_ID,
            selections: vec![ResolveSelection {
                artifact_sha256,
                variant: Some("default".to_owned()),
            }],
        };
        let package_catalog = vec![CatalogPackage {
            artifact_sha256: request.selections[0].artifact_sha256.clone(),
            manifest: PackageManifest {
                schema_version: 1,
                id: "fixture-package".to_owned(),
                name: "Fixture Package".to_owned(),
                version: "1.0.0".to_owned(),
                game: ManifestGame {
                    steam_app_id: RETRO_REWIND_APP_ID,
                    supported_build_ids: vec![SUPPORTED_BUILD_ID.to_string()],
                    unreal_engine: "5.4.4".to_owned(),
                },
                source: None,
                components: vec![ManifestComponent {
                    id: "ue4ss".to_owned(),
                    component_type: ComponentType::Ue4ss,
                    root: "FixtureMod".to_owned(),
                    required: true,
                    install_name: Some("FixtureMod".to_owned()),
                    sha256: None,
                }],
                variants: Vec::new(),
                requirements: Vec::new(),
                runtime_requirements: ManifestRuntimeRequirements {
                    ue4ss_loader_policy: Some("ue4ss:test-policy".to_owned()),
                },
                incompatibilities: Vec::new(),
                replaces: Vec::new(),
                persistent_effects: Vec::new(),
                install_notes: Vec::new(),
            },
            provenance: ManifestProvenance::Declared,
        }];
        let report = selected_report(SUPPORTED_BUILD_ID, &request.selections[0].artifact_sha256);

        let validation = validate_recipe_deployment_target(
            &store,
            "installation",
            "profile",
            &game,
            RecipeDeploymentResolution {
                request: &request,
                package_catalog: &package_catalog,
                report: &report,
            },
            &recipe,
            catalog_validation(),
        )
        .unwrap();
        assert_eq!(validation.profile_revision, 0);
        assert_eq!(
            validation
                .ue4ss
                .as_ref()
                .unwrap()
                .evaluations
                .first()
                .unwrap()
                .status,
            rrmm_ue4ss::Ue4ssLoaderPolicyStatus::AllowedExact
        );

        let mut updated = store.active_profile("installation").unwrap().unwrap();
        updated.name = "Updated Profile".to_owned();
        let updated = store.update_profile(&updated, 0).unwrap();
        assert_eq!(updated.revision, 1);
        let current = validate_recipe_deployment_target(
            &store,
            "installation",
            "profile",
            &game,
            RecipeDeploymentResolution {
                request: &request,
                package_catalog: &package_catalog,
                report: &report,
            },
            &recipe,
            catalog_validation(),
        )
        .unwrap();
        assert_ne!(current, validation);

        fs::write(&core, b"changed core").unwrap();
        let error = validate_recipe_deployment_target(
            &store,
            "installation",
            "profile",
            &game,
            RecipeDeploymentResolution {
                request: &request,
                package_catalog: &package_catalog,
                report: &report,
            },
            &recipe,
            catalog_validation(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("UnknownBlocked"));
        fs::write(&core, b"core fixture").unwrap();

        fs::write(&critical, b"changed").unwrap();
        let error = validate_recipe_deployment_target(
            &store,
            "installation",
            "profile",
            &game,
            RecipeDeploymentResolution {
                request: &request,
                package_catalog: &package_catalog,
                report: &report,
            },
            &recipe,
            catalog_validation(),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not an exact supported installation")
        );
    }

    fn catalog_validation() -> RecipeCatalogValidation {
        RecipeCatalogValidation {
            trust_floor: CatalogTrustFloor {
                root_generation: 0,
                root_payload_sha256: None,
                catalog_sequence: 0,
                catalog_payload_sha256: None,
            },
            valid_until: u64::MAX,
        }
    }

    fn empty_report(build_id: u64) -> RecipeApplicationReport {
        RecipeApplicationReport {
            ready: true,
            resolution: ResolutionReport {
                build_id,
                ready: true,
                packages: Vec::new(),
                blockers: Vec::new(),
            },
            applied_recipe_ids: Vec::new(),
            winner_decisions: Vec::new(),
            install_name_overrides: Vec::new(),
            disabled_components: Vec::new(),
            blockers: Vec::new(),
        }
    }

    fn selected_report(build_id: u64, artifact_sha256: &str) -> RecipeApplicationReport {
        let mut report = empty_report(build_id);
        report.resolution.packages.push(ResolvedPackage {
            package_id: "fixture-package".to_owned(),
            artifact_sha256: artifact_sha256.to_owned(),
            variant: None,
            component_ids: vec!["ue4ss".to_owned()],
            automatically_selected: false,
        });
        report
    }
}
