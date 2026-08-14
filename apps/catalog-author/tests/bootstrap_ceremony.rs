use rrmm_recipes::CatalogTrustFloor;
use serde_json::Value;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

#[test]
fn bootstraps_signs_verifies_and_rejects_tampering() {
    let temporary = TempDir::new().unwrap();
    #[cfg(unix)]
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root_private = temporary.path().join("root.rrmm-private.json");
    let root_public = temporary.path().join("root.public.json");
    let trusted_roots = temporary.path().join("production-roots.json");
    let online_private = temporary.path().join("online.rrmm-private.json");
    let online_public = temporary.path().join("online.public.json");
    let unsigned_root = temporary.path().join("root.json");
    let signed_root = temporary.path().join("root.signed.json");
    let unsigned_catalog = temporary.path().join("catalog.json");
    let signed_catalog = temporary.path().join("catalog.signed.json");
    let replacement_private = temporary.path().join("online-2.rrmm-private.json");
    let replacement_public = temporary.path().join("online-2.public.json");
    let rotated_root = temporary.path().join("root-generation-2.signed.json");
    let updated_catalog = temporary.path().join("catalog-sequence-2.signed.json");
    let next_catalog = temporary
        .path()
        .join("catalog-root-2-sequence-2.signed.json");
    let first_floor = temporary.path().join("trust-floor-1.json");
    let second_floor = temporary.path().join("trust-floor-2.json");
    let third_floor = temporary.path().join("trust-floor-3.json");
    let tampered_catalog = temporary.path().join("catalog.tampered.json");
    let recipe = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../recipes/compatibility/23896268/unrewound-tape-fee--employee-fee-policy.json");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    success(&[
        "key-generate",
        "--role",
        "root",
        "--private-key",
        path(&root_private),
        "--public-key",
        path(&root_public),
    ]);
    success(&[
        "trusted-roots-export",
        "--trusted-root",
        path(&root_public),
        "--output",
        path(&trusted_roots),
    ]);
    let exported: Vec<Value> = serde_json::from_slice(&fs::read(&trusted_roots).unwrap()).unwrap();
    assert_eq!(exported.len(), 1);
    assert_eq!(
        exported[0],
        serde_json::from_slice::<Value>(&fs::read(&root_public).unwrap()).unwrap()
    );
    assert!(
        !command(&[
            "trusted-roots-export",
            "--trusted-root",
            path(&root_public),
            "--trusted-root",
            path(&root_public),
            "--output",
            path(&temporary.path().join("duplicate-roots.json")),
        ])
        .status
        .success()
    );
    success(&[
        "key-generate",
        "--role",
        "online",
        "--private-key",
        path(&online_private),
        "--public-key",
        path(&online_public),
    ]);
    #[cfg(unix)]
    {
        assert_eq!(
            fs::metadata(&root_private).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&online_private).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    success(&[
        "root-bootstrap",
        "--online-public-key",
        path(&online_public),
        "--valid-from",
        &now.saturating_sub(1).to_string(),
        "--valid-until",
        &(now + 3_600).to_string(),
        "--expires-at",
        &(now + 7_200).to_string(),
        "--output",
        path(&unsigned_root),
    ]);
    success(&[
        "root-sign",
        "--private-key",
        path(&root_private),
        "--metadata",
        path(&unsigned_root),
        "--output",
        path(&signed_root),
    ]);
    let mut invalid_root: Value =
        serde_json::from_slice(&fs::read(&unsigned_root).unwrap()).unwrap();
    invalid_root["generation"] = Value::from(2);
    let invalid_root_path = temporary.path().join("root-generation-2.json");
    fs::write(
        &invalid_root_path,
        serde_json::to_vec_pretty(&invalid_root).unwrap(),
    )
    .unwrap();
    assert!(
        !command(&[
            "root-sign",
            "--private-key",
            path(&root_private),
            "--metadata",
            path(&invalid_root_path),
            "--output",
            path(&temporary.path().join("root-generation-2.signed.json")),
        ])
        .status
        .success()
    );
    success(&[
        "catalog-bootstrap",
        "--recipe",
        path(&recipe),
        "--issued-at",
        &now.saturating_sub(1).to_string(),
        "--expires-at",
        &(now + 1_800).to_string(),
        "--output",
        path(&unsigned_catalog),
    ]);
    success(&[
        "catalog-sign",
        "--private-key",
        path(&online_private),
        "--trusted-root",
        path(&root_public),
        "--root-metadata",
        path(&signed_root),
        "--catalog",
        path(&unsigned_catalog),
        "--output",
        path(&signed_catalog),
    ]);
    let mut invalid_sequence: Value =
        serde_json::from_slice(&fs::read(&unsigned_catalog).unwrap()).unwrap();
    invalid_sequence["sequence"] = Value::from(2);
    let invalid_sequence_path = temporary.path().join("catalog-sequence-2.json");
    fs::write(
        &invalid_sequence_path,
        serde_json::to_vec_pretty(&invalid_sequence).unwrap(),
    )
    .unwrap();
    assert!(
        !command(&[
            "catalog-sign",
            "--private-key",
            path(&online_private),
            "--trusted-root",
            path(&root_public),
            "--root-metadata",
            path(&signed_root),
            "--catalog",
            path(&invalid_sequence_path),
            "--output",
            path(&temporary.path().join("catalog-sequence-2.signed.json")),
        ])
        .status
        .success()
    );
    let verified = success(&[
        "verify",
        "--trusted-root",
        path(&root_public),
        "--root-metadata",
        path(&signed_root),
        "--recipe-catalog",
        path(&signed_catalog),
    ]);
    let floor: CatalogTrustFloor = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(floor.root_generation, 1);
    assert_eq!(floor.catalog_sequence, 1);
    fs::write(&first_floor, &verified.stdout).unwrap();

    success(&[
        "key-generate",
        "--role",
        "online",
        "--private-key",
        path(&replacement_private),
        "--public-key",
        path(&replacement_public),
    ]);
    success(&[
        "root-update",
        "--private-key",
        path(&root_private),
        "--trusted-root",
        path(&root_public),
        "--floor",
        path(&first_floor),
        "--previous-root-metadata",
        path(&signed_root),
        "--online-public-key",
        path(&replacement_public),
        "--valid-from",
        &now.saturating_sub(1).to_string(),
        "--valid-until",
        &(now + 7_200).to_string(),
        "--expires-at",
        &(now + 10_800).to_string(),
        "--output",
        path(&rotated_root),
    ]);
    let same_key_rotation = command(&[
        "root-update",
        "--private-key",
        path(&root_private),
        "--trusted-root",
        path(&root_public),
        "--floor",
        path(&first_floor),
        "--previous-root-metadata",
        path(&signed_root),
        "--online-public-key",
        path(&online_public),
        "--valid-from",
        &now.saturating_sub(1).to_string(),
        "--valid-until",
        &(now + 7_200).to_string(),
        "--expires-at",
        &(now + 10_800).to_string(),
        "--output",
        path(&temporary.path().join("same-key-root.json")),
    ]);
    assert!(!same_key_rotation.status.success());
    success(&[
        "catalog-update",
        "--private-key",
        path(&replacement_private),
        "--trusted-root",
        path(&root_public),
        "--floor",
        path(&first_floor),
        "--previous-root-metadata",
        path(&signed_root),
        "--root-metadata",
        path(&rotated_root),
        "--recipe",
        path(&recipe),
        "--issued-at",
        &now.to_string(),
        "--expires-at",
        &(now + 1_800).to_string(),
        "--output",
        path(&updated_catalog),
    ]);
    let updated = success(&[
        "verify",
        "--trusted-root",
        path(&root_public),
        "--root-metadata",
        path(&rotated_root),
        "--recipe-catalog",
        path(&updated_catalog),
        "--floor",
        path(&first_floor),
    ]);
    let updated_floor: CatalogTrustFloor = serde_json::from_slice(&updated.stdout).unwrap();
    assert_eq!(updated_floor.root_generation, 2);
    assert_eq!(updated_floor.catalog_sequence, 1);
    fs::write(&second_floor, &updated.stdout).unwrap();

    success(&[
        "catalog-update",
        "--private-key",
        path(&replacement_private),
        "--trusted-root",
        path(&root_public),
        "--floor",
        path(&second_floor),
        "--previous-root-metadata",
        path(&rotated_root),
        "--previous-catalog",
        path(&updated_catalog),
        "--root-metadata",
        path(&rotated_root),
        "--recipe",
        path(&recipe),
        "--issued-at",
        &now.to_string(),
        "--expires-at",
        &(now + 1_800).to_string(),
        "--output",
        path(&next_catalog),
    ]);
    let next = success(&[
        "verify",
        "--trusted-root",
        path(&root_public),
        "--root-metadata",
        path(&rotated_root),
        "--recipe-catalog",
        path(&next_catalog),
        "--floor",
        path(&second_floor),
    ]);
    let next_floor: CatalogTrustFloor = serde_json::from_slice(&next.stdout).unwrap();
    assert_eq!(next_floor.root_generation, 2);
    assert_eq!(next_floor.catalog_sequence, 2);
    fs::write(&third_floor, &next.stdout).unwrap();

    let stale_root = command(&[
        "root-update",
        "--private-key",
        path(&root_private),
        "--trusted-root",
        path(&root_public),
        "--floor",
        path(&third_floor),
        "--previous-root-metadata",
        path(&signed_root),
        "--online-public-key",
        path(&replacement_public),
        "--valid-from",
        &now.saturating_sub(1).to_string(),
        "--valid-until",
        &(now + 7_200).to_string(),
        "--expires-at",
        &(now + 10_800).to_string(),
        "--output",
        path(&temporary.path().join("stale-root.json")),
    ]);
    assert!(!stale_root.status.success());

    let stale_catalog = command(&[
        "catalog-update",
        "--private-key",
        path(&replacement_private),
        "--trusted-root",
        path(&root_public),
        "--floor",
        path(&third_floor),
        "--previous-root-metadata",
        path(&rotated_root),
        "--previous-catalog",
        path(&updated_catalog),
        "--root-metadata",
        path(&rotated_root),
        "--recipe",
        path(&recipe),
        "--issued-at",
        &now.to_string(),
        "--expires-at",
        &(now + 1_800).to_string(),
        "--output",
        path(&temporary.path().join("stale-catalog.json")),
    ]);
    assert!(!stale_catalog.status.success());

    let reintroduced_key = command(&[
        "root-update",
        "--private-key",
        path(&root_private),
        "--trusted-root",
        path(&root_public),
        "--floor",
        path(&third_floor),
        "--previous-root-metadata",
        path(&rotated_root),
        "--online-public-key",
        path(&online_public),
        "--valid-from",
        &now.saturating_sub(1).to_string(),
        "--valid-until",
        &(now + 7_200).to_string(),
        "--expires-at",
        &(now + 10_800).to_string(),
        "--output",
        path(&temporary.path().join("reintroduced-key-root.json")),
    ]);
    assert!(!reintroduced_key.status.success());

    let revoked = command(&[
        "catalog-update",
        "--private-key",
        path(&online_private),
        "--trusted-root",
        path(&root_public),
        "--floor",
        path(&first_floor),
        "--previous-root-metadata",
        path(&signed_root),
        "--previous-catalog",
        path(&signed_catalog),
        "--root-metadata",
        path(&rotated_root),
        "--recipe",
        path(&recipe),
        "--issued-at",
        &now.to_string(),
        "--expires-at",
        &(now + 1_800).to_string(),
        "--output",
        path(&temporary.path().join("revoked-key-catalog.json")),
    ]);
    assert!(!revoked.status.success());

    let rollback = command(&[
        "verify",
        "--trusted-root",
        path(&root_public),
        "--root-metadata",
        path(&signed_root),
        "--recipe-catalog",
        path(&signed_catalog),
        "--floor",
        path(&third_floor),
    ]);
    assert!(!rollback.status.success());

    let original_private = fs::read(&root_private).unwrap();
    let repeated = command(&[
        "key-generate",
        "--role",
        "root",
        "--private-key",
        path(&root_private),
        "--public-key",
        path(&root_public),
    ]);
    assert!(!repeated.status.success());
    assert_eq!(fs::read(&root_private).unwrap(), original_private);

    #[cfg(unix)]
    {
        fs::set_permissions(&online_private, fs::Permissions::from_mode(0o644)).unwrap();
        let rejected_permissions = command(&[
            "catalog-sign",
            "--private-key",
            path(&online_private),
            "--trusted-root",
            path(&root_public),
            "--root-metadata",
            path(&signed_root),
            "--catalog",
            path(&unsigned_catalog),
            "--output",
            path(&temporary.path().join("permissions-rejected.json")),
        ]);
        assert!(!rejected_permissions.status.success());
        fs::set_permissions(&online_private, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut tampered: Value = serde_json::from_slice(&fs::read(&signed_catalog).unwrap()).unwrap();
    tampered["signed"]["issued_at"] = Value::from(now);
    fs::write(
        &tampered_catalog,
        serde_json::to_vec_pretty(&tampered).unwrap(),
    )
    .unwrap();
    let rejected = command(&[
        "verify",
        "--trusted-root",
        path(&root_public),
        "--root-metadata",
        path(&signed_root),
        "--recipe-catalog",
        path(&tampered_catalog),
    ]);
    assert!(!rejected.status.success());
}

#[test]
fn refuses_private_keys_inside_a_source_checkout() {
    let inside = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    #[cfg(unix)]
    fs::set_permissions(inside.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let private = inside.path().join("root.rrmm-private.json");
    let public = inside.path().join("root.public.json");

    let output = command(&[
        "key-generate",
        "--role",
        "root",
        "--private-key",
        path(&private),
        "--public-key",
        path(&public),
    ]);

    assert!(!output.status.success());
    assert!(!private.exists());
    assert!(!public.exists());
}

fn success(arguments: &[&str]) -> Output {
    let output = command(arguments);
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn command(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rrmm-catalog-author"))
        .args(arguments)
        .output()
        .unwrap()
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}
