use rrmm_pak::{PakLimits, PakWorkerRequest, PakWorkerResponse};
#[cfg(any(target_os = "linux", windows))]
use std::fs::File;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use tempfile::TempDir;

#[test]
#[cfg(any(target_os = "linux", windows))]
fn sandboxed_worker_inventories_and_hashes_a_pak() {
    let temporary = TempDir::new().unwrap();
    let pak = temporary.path().join("Example_P.pak");
    write_pak(&pak);
    let request = PakWorkerRequest::Inspect {
        pak,
        limits: PakLimits::default(),
        hash_members: vec![
            "RetroRewind/Content/Foo.uasset".to_owned(),
            "RetroRewind/Content/Foo.uexp".to_owned(),
        ],
    };

    let (status, response) = run_worker(&request);

    assert!(status.success());
    assert!(response.ok);
    assert!(response.sandboxed);
    assert_eq!(response.inventory.unwrap().members.len(), 2);
    assert_eq!(response.member_digests.len(), 2);
    assert_eq!(response.member_digests[1].bytes, 6);
}

#[test]
#[cfg(any(target_os = "linux", windows))]
fn sandboxed_worker_fingerprints_pak_indexes_without_inventory() {
    let temporary = TempDir::new().unwrap();
    let pak = temporary.path().join("Example_P.pak");
    write_pak(&pak);
    let request = PakWorkerRequest::Fingerprint {
        pak,
        limits: PakLimits::default(),
    };

    let (status, response) = run_worker(&request);

    assert!(status.success());
    assert!(response.ok);
    assert!(response.sandboxed);
    assert!(response.inventory.is_none());
    assert_eq!(response.index_metadata_sha256.unwrap().len(), 64);
}

#[test]
fn malformed_requests_return_json_without_panicking() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rrmm-pak-worker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"not json").unwrap();
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut output)
        .unwrap();
    let status = child.wait().unwrap();
    let response: PakWorkerResponse = serde_json::from_slice(&output).unwrap();

    assert!(!status.success());
    assert!(!response.ok);
    assert!(response.error.is_some());
}

#[test]
#[cfg(not(any(target_os = "linux", windows)))]
fn valid_requests_fail_before_pak_parsing_without_a_sandbox() {
    let temporary = TempDir::new().unwrap();
    let pak = temporary.path().join("not-a-pak.pak");
    std::fs::write(&pak, b"hostile parser input must remain unread").unwrap();
    let request = PakWorkerRequest::Fingerprint {
        pak,
        limits: PakLimits::default(),
    };

    let (status, response) = run_worker(&request);

    assert!(!status.success());
    assert!(!response.ok);
    assert!(!response.sandboxed);
    assert!(response.inventory.is_none());
    assert!(
        response
            .error
            .as_deref()
            .is_some_and(|error| error.contains("sandbox is unavailable"))
    );
}

#[test]
#[cfg(windows)]
fn forged_child_marker_fails_closed_before_reading_a_request() {
    let output = Command::new(env!("CARGO_BIN_EXE_rrmm-pak-worker"))
        .arg("--rrmm-windows-sandbox-child=0")
        .output()
        .unwrap();
    let response: PakWorkerResponse = serde_json::from_slice(&output.stdout).unwrap();

    assert!(!output.status.success());
    assert!(!response.ok);
    assert!(!response.sandboxed);
    assert!(response.inventory.is_none());
}

fn run_worker(request: &PakWorkerRequest) -> (std::process::ExitStatus, PakWorkerResponse) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rrmm-pak-worker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(child.stdin.take().unwrap(), request).unwrap();
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut output)
        .unwrap();
    let status = child.wait().unwrap();
    (status, serde_json::from_slice(&output).unwrap())
}

#[cfg(any(target_os = "linux", windows))]
fn write_pak(path: &std::path::Path) {
    let output = File::create(path).unwrap();
    let mut writer = repak_trumank::PakBuilder::new().writer(
        output,
        repak_trumank::Version::V11,
        "../../../".to_owned(),
        Some(0),
    );
    writer
        .write_file("RetroRewind/Content/Foo.uasset", false, b"asset")
        .unwrap();
    writer
        .write_file("RetroRewind/Content/Foo.uexp", false, b"export")
        .unwrap();
    writer.write_index().unwrap().sync_all().unwrap();
}
