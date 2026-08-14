use rrmm_manifest::{
    CatalogPackage, PackageManifest, ResolutionBlocker, ResolveRequest, ResolveSelection,
    resolve_packages, validate_manifest,
};
use rrmm_recipes::{CompatibilityRecipe, RecipeOperation, validate_recipe};

const PACKAGE_CATALOG: &str = include_str!("../../../catalogs/packages/23896268.json");
const RECIPE: &str = include_str!(
    "../../../recipes/compatibility/23896268/unrewound-tape-fee--employee-fee-policy.json"
);
const UNREWOUND_MANIFEST: &str =
    include_str!("../../../manifests/unrewound-tape-fee/1.0.0/rrmm-manifest.json");
const EMPLOYEE_MANIFEST: &str =
    include_str!("../../../manifests/employee-fee-policy/1.0.0/rrmm-manifest.json");
const COMBINED_MANIFEST: &str = include_str!(
    "../../../manifests/unrewound-tape-fee-employee-fee-policy/1.0.0/rrmm-manifest.json"
);
const SMART_SHELF_MANIFEST: &str =
    include_str!("../../../manifests/smart-shelf-organizer/0.1.0-dev/rrmm-manifest.json");
const FASTER_RETURNS_MANIFEST: &str =
    include_str!("../../../manifests/faster-returns/1.1.0/rrmm-manifest.json");

#[test]
fn authored_manifests_catalog_and_recipe_are_consistent() {
    let manifests: Vec<PackageManifest> = [
        UNREWOUND_MANIFEST,
        EMPLOYEE_MANIFEST,
        COMBINED_MANIFEST,
        SMART_SHELF_MANIFEST,
        FASTER_RETURNS_MANIFEST,
    ]
    .into_iter()
    .map(|input| serde_json::from_str(input).unwrap())
    .collect();
    for manifest in &manifests {
        validate_manifest(manifest).unwrap();
    }

    let catalog: Vec<CatalogPackage> = serde_json::from_str(PACKAGE_CATALOG).unwrap();
    assert_eq!(catalog.len(), manifests.len());
    for manifest in &manifests {
        let entries: Vec<_> = catalog
            .iter()
            .filter(|package| package.manifest.id == manifest.id)
            .collect();
        assert_eq!(entries.len(), 1, "catalog entry for {}", manifest.id);
        assert_eq!(&entries[0].manifest, manifest);
    }
    let smart_shelf = catalog
        .iter()
        .find(|package| package.manifest.id == "local:smart-shelf-organizer")
        .unwrap();
    assert_eq!(
        smart_shelf.artifact_sha256,
        "32be01dd47833f8f61d0bfbe7b831b428bf10f4677f2db62aa4aba2b319d036e"
    );

    let recipe: CompatibilityRecipe = serde_json::from_str(RECIPE).unwrap();
    validate_recipe(&recipe).unwrap();
    for matched in &recipe.matches {
        assert!(catalog.iter().any(|package| {
            package.manifest.id == matched.package_id && package.artifact_sha256 == matched.sha256
        }));
    }
    let [
        RecipeOperation::ReplaceWithCombined {
            remove_package_ids,
            combined_package_id,
            combined_sha256,
        },
    ] = recipe.operations.as_slice()
    else {
        panic!("authored recipe must contain one combined replacement");
    };
    assert!(remove_package_ids.iter().all(|id| {
        recipe
            .matches
            .iter()
            .any(|matched| &matched.package_id == id)
    }));
    assert!(catalog.iter().any(|package| {
        package.manifest.id == *combined_package_id && package.artifact_sha256 == *combined_sha256
    }));

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
        &catalog,
    )
    .unwrap();
    assert!(!resolution.ready);
    assert!(!resolution.blockers.is_empty());
    assert!(
        resolution
            .blockers
            .iter()
            .all(|blocker| matches!(blocker, ResolutionBlocker::Incompatible { .. }))
    );
}
