use rrmm_archive::sha256_path;
use rrmm_deploy::{DeploymentFile, DeploymentPlan, DeploymentRequest};
use std::fs;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn preview_requires_a_separate_confirmed_apply() {
    let temporary = TempDir::new().unwrap();
    let game = temporary.path().join("game");
    let state = temporary.path().join("state");
    let source = temporary.path().join("Example_P.pak");
    let request_path = temporary.path().join("request.json");
    let plan_path = temporary.path().join("plan.json");
    fs::create_dir(&game).unwrap();
    fs::write(&source, b"pak fixture").unwrap();
    let request = DeploymentRequest {
        transaction_id: "cli_transaction".to_owned(),
        installation_id: "test_installation".to_owned(),
        profile_id: "test_profile".to_owned(),
        game_root: game.clone(),
        state_root: state,
        files: vec![DeploymentFile {
            source: source.clone(),
            relative_path: "RetroRewind/Content/Paks/Example_P.pak".to_owned(),
            bytes: fs::metadata(&source).unwrap().len(),
            sha256: sha256_path(&source).unwrap(),
            package_id: None,
            package_name: None,
        }],
        external_files: Vec::new(),
        allow_unmanaged: false,
        game_running: false,
    };
    fs::write(&request_path, serde_json::to_vec_pretty(&request).unwrap()).unwrap();

    let preview = Command::new(env!("CARGO_BIN_EXE_rrmm-cli"))
        .args(["deploy-preview", "--request"])
        .arg(&request_path)
        .output()
        .unwrap();
    assert!(preview.status.success());
    let plan: DeploymentPlan = serde_json::from_slice(&preview.stdout).unwrap();
    assert!(plan.ready(), "preview blockers: {:?}", plan.blockers);
    assert!(!game.join("RetroRewind").exists());
    fs::write(&plan_path, &preview.stdout).unwrap();

    let rejected = Command::new(env!("CARGO_BIN_EXE_rrmm-cli"))
        .args(["deploy-apply", "--plan"])
        .arg(&plan_path)
        .status()
        .unwrap();
    assert!(!rejected.success());
    assert!(!game.join("RetroRewind").exists());

    let applied = Command::new(env!("CARGO_BIN_EXE_rrmm-cli"))
        .args(["deploy-apply", "--plan"])
        .arg(&plan_path)
        .arg("--confirm")
        .status()
        .unwrap();
    assert!(applied.success());
    assert_eq!(
        fs::read(game.join("RetroRewind/Content/Paks/Example_P.pak")).unwrap(),
        b"pak fixture"
    );
}

#[cfg(unix)]
#[test]
fn write_limit_failure_leaves_the_game_unchanged_and_cleans_staging() {
    let temporary = TempDir::new().unwrap();
    let game = temporary.path().join("game");
    let state = temporary.path().join("state");
    let source = temporary.path().join("large.pak");
    let request_path = temporary.path().join("request.json");
    let plan_path = temporary.path().join("plan.json");
    fs::create_dir(&game).unwrap();
    fs::write(&source, vec![b'p'; 4096]).unwrap();
    let request = DeploymentRequest {
        transaction_id: "write_limit_transaction".to_owned(),
        installation_id: "test_installation".to_owned(),
        profile_id: "test_profile".to_owned(),
        game_root: game.clone(),
        state_root: state.clone(),
        files: vec![DeploymentFile {
            source: source.clone(),
            relative_path: "RetroRewind/Content/Paks/Large_P.pak".to_owned(),
            bytes: fs::metadata(&source).unwrap().len(),
            sha256: sha256_path(&source).unwrap(),
            package_id: None,
            package_name: None,
        }],
        external_files: Vec::new(),
        allow_unmanaged: false,
        game_running: false,
    };
    fs::write(&request_path, serde_json::to_vec_pretty(&request).unwrap()).unwrap();
    let preview = Command::new(env!("CARGO_BIN_EXE_rrmm-cli"))
        .args(["deploy-preview", "--request"])
        .arg(&request_path)
        .output()
        .unwrap();
    assert!(preview.status.success());
    let plan: DeploymentPlan = serde_json::from_slice(&preview.stdout).unwrap();
    assert!(plan.ready(), "preview blockers: {:?}", plan.blockers);
    fs::write(&plan_path, preview.stdout).unwrap();

    let status = Command::new("/bin/sh")
        .args([
            "-c",
            "trap '' XFSZ; ulimit -f 1; exec \"$1\" deploy-apply --plan \"$2\" --confirm",
            "rrmm-deploy-write-limit-test",
            env!("CARGO_BIN_EXE_rrmm-cli"),
            plan_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();

    assert!(!status.success());
    assert!(!game.join("RetroRewind").exists());
    assert_eq!(fs::read_dir(state.join("staging")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(state.join("journals")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(state.join("receipts")).unwrap().count(), 0);
}
