#![cfg(unix)]

use rrmm_conflicts::{CrossLayerMatchConfidence, PakLuaCorrelationReport};
use rrmm_pak::{
    CookedPackage, CookedSidecar, PakIntegrityReport, PakInventory, PakMember,
    PakPriorityConfidence, PakPriorityHint, PakWorkerResponse,
};
use rrmm_ue4ss::Ue4ssDeclaredActivation;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn correlates_a_sandboxed_pak_inventory_with_installed_literal_hooks() {
    let temporary = TempDir::new().unwrap();
    let game = temporary.path().join("game");
    let module = game.join("RetroRewind/Binaries/Win64/ue4ss/Mods/Example");
    fs::create_dir_all(module.join("Scripts")).unwrap();
    fs::write(
        module.join("Scripts/main.lua"),
        b"RegisterHook(\"/Game/Foo/Bar.Bar_C:Run\", function() error('must not run') end)",
    )
    .unwrap();
    fs::write(module.join("enabled.txt"), b"").unwrap();

    let pak = temporary.path().join("Example_P.pak");
    fs::write(&pak, b"worker fixture only").unwrap();
    let pak = fs::canonicalize(pak).unwrap();
    let response_path = temporary.path().join("response.json");
    fs::write(
        &response_path,
        serde_json::to_vec(&worker_response(&pak)).unwrap(),
    )
    .unwrap();
    let worker = temporary.path().join("pak-worker.sh");
    fs::write(
        &worker,
        format!("#!/bin/sh\n/bin/cat \"{}\"\n", response_path.display()),
    )
    .unwrap();
    let mut permissions = fs::metadata(&worker).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&worker, permissions).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rrmm-cli"))
        .args(["pak-ue4ss-correlate", "--pak"])
        .arg(&pak)
        .args(["--game-root"])
        .arg(&game)
        .args(["--build-id", "23896268", "--worker"])
        .arg(&worker)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: PakLuaCorrelationReport = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report.complete);
    assert_eq!(report.matches.len(), 1);
    assert_eq!(
        report.matches[0].confidence,
        CrossLayerMatchConfidence::ExactConfiguredPolicyPackageKey
    );
    assert_eq!(
        report.matches[0].declared_activation,
        Some(Ue4ssDeclaredActivation::EnabledByMarker)
    );
    assert!(report.matches[0].warning.contains("not runtime-verified"));
    assert_eq!(
        fs::read(module.join("Scripts/main.lua")).unwrap(),
        b"RegisterHook(\"/Game/Foo/Bar.Bar_C:Run\", function() error('must not run') end)"
    );
}

#[test]
fn rejects_builds_without_a_mount_policy_before_starting_a_worker() {
    let temporary = TempDir::new().unwrap();
    let pak = temporary.path().join("Example_P.pak");
    fs::write(&pak, b"not inspected").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rrmm-cli"))
        .args(["pak-ue4ss-correlate", "--pak"])
        .arg(&pak)
        .args([
            "--game-root",
            "unused",
            "--build-id",
            "1",
            "--worker",
            "missing-worker",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no mount policy for build 1"));
}

#[test]
fn rejects_incoherent_worker_inventory_before_lua_analysis() {
    let temporary = TempDir::new().unwrap();
    let pak = temporary.path().join("Example_P.pak");
    fs::write(&pak, b"worker fixture only").unwrap();
    let pak = fs::canonicalize(pak).unwrap();
    let mut response = worker_response(&pak);
    response.inventory.as_mut().unwrap().packages[0].package_key =
        "retrorewind/content/forged".to_owned();
    let response_path = temporary.path().join("response.json");
    fs::write(&response_path, serde_json::to_vec(&response).unwrap()).unwrap();
    let worker = temporary.path().join("pak-worker.sh");
    fs::write(
        &worker,
        format!("#!/bin/sh\n/bin/cat \"{}\"\n", response_path.display()),
    )
    .unwrap();
    let mut permissions = fs::metadata(&worker).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&worker, permissions).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rrmm-cli"))
        .args(["pak-ue4ss-correlate", "--pak"])
        .arg(&pak)
        .args([
            "--game-root",
            "unused",
            "--build-id",
            "23896268",
            "--worker",
        ])
        .arg(&worker)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("incoherent inventory"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rejects_pak_count_limits_before_resolving_paths_or_starting_workers() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rrmm-cli"));
    command.arg("pak-ue4ss-correlate");
    for index in 0..129 {
        command.args(["--pak", &format!("missing-{index}.pak")]);
    }
    let output = command
        .args([
            "--game-root",
            "unused",
            "--build-id",
            "23896268",
            "--worker",
            "missing-worker",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("accepts at most 128 PAKs"));
}

fn worker_response(pak: &Path) -> PakWorkerResponse {
    PakWorkerResponse {
        ok: true,
        sandboxed: true,
        inventory: Some(PakInventory {
            archive_path: pak.to_path_buf(),
            archive_name: "Example_P.pak".to_owned(),
            archive_bytes: fs::metadata(pak).unwrap().len(),
            version: "V11".to_owned(),
            mount_point: "../../../".to_owned(),
            encrypted_index: false,
            compression: Vec::new(),
            path_hash_seed: Some(0),
            priority: PakPriorityHint {
                patch_generation: 1,
                patch_increment: 100,
                explicit_number: None,
                confidence: PakPriorityConfidence::ObservedBuildRule,
            },
            integrity: PakIntegrityReport {
                structural_parse_succeeded: true,
                index_hashes_verified: false,
                index_metadata_sha256: "00".repeat(32),
                detail: "synthetic worker response".to_owned(),
            },
            members: vec![
                PakMember {
                    stored_path: "RetroRewind/Content/Foo/Bar.uasset".to_owned(),
                    virtual_path: "RetroRewind/Content/Foo/Bar.uasset".to_owned(),
                    collision_key: "retrorewind/content/foo/bar.uasset".to_owned(),
                    package_key: Some("retrorewind/content/foo/bar".to_owned()),
                    sidecar: Some(CookedSidecar::Asset),
                },
                PakMember {
                    stored_path: "RetroRewind/Content/Foo/Bar.uexp".to_owned(),
                    virtual_path: "RetroRewind/Content/Foo/Bar.uexp".to_owned(),
                    collision_key: "retrorewind/content/foo/bar.uexp".to_owned(),
                    package_key: Some("retrorewind/content/foo/bar".to_owned()),
                    sidecar: Some(CookedSidecar::Export),
                },
            ],
            packages: vec![CookedPackage {
                package_key: "retrorewind/content/foo/bar".to_owned(),
                members: vec![
                    "RetroRewind/Content/Foo/Bar.uasset".to_owned(),
                    "RetroRewind/Content/Foo/Bar.uexp".to_owned(),
                ],
                sidecars: vec![CookedSidecar::Asset, CookedSidecar::Export],
                warnings: Vec::new(),
            }],
        }),
        member_digests: Vec::new(),
        index_metadata_sha256: None,
        error: None,
    }
}
