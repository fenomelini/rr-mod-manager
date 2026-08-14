#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[test]
fn timed_out_worker_is_killed_and_partial_staging_is_removed() {
    let temporary = TempDir::new().unwrap();
    let staging = temporary.path().join("partial-staging");
    let worker = temporary.path().join("hanging-worker.sh");
    fs::write(
        &worker,
        format!(
            "#!/bin/sh\n/bin/mkdir -p \"{}\"\nprintf partial > \"{}/partial.txt\"\nexec /bin/sleep 30\n",
            staging.display(),
            staging.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&worker, fs::Permissions::from_mode(0o700)).unwrap();

    let started = Instant::now();
    let status = Command::new(env!("CARGO_BIN_EXE_rrmm-cli"))
        .args([
            "archive-extract",
            "--archive",
            "/does/not/matter.zip",
            "--staging",
            staging.to_str().unwrap(),
            "--worker",
            worker.to_str().unwrap(),
            "--timeout-seconds",
            "1",
        ])
        .status()
        .unwrap();

    assert!(!status.success());
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(!staging.exists());
}

#[test]
fn timed_out_pak_worker_is_killed() {
    let temporary = TempDir::new().unwrap();
    let worker = temporary.path().join("hanging-pak-worker.sh");
    fs::write(&worker, "#!/bin/sh\nexec /bin/sleep 30\n").unwrap();
    fs::set_permissions(&worker, fs::Permissions::from_mode(0o700)).unwrap();

    let started = Instant::now();
    let status = Command::new(env!("CARGO_BIN_EXE_rrmm-cli"))
        .args([
            "pak-inspect",
            "--pak",
            "/does/not/matter.pak",
            "--worker",
            worker.to_str().unwrap(),
            "--timeout-seconds",
            "1",
        ])
        .status()
        .unwrap();

    assert!(!status.success());
    assert!(started.elapsed() < Duration::from_secs(5));
}
