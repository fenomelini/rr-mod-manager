use rrmm_archive::{ArchiveLimits, ArchiveWorkerRequest, ArchiveWorkerResponse};
use std::fs;
#[cfg(any(target_os = "linux", windows))]
use std::fs::File;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use tempfile::TempDir;
#[cfg(any(target_os = "linux", windows))]
use zip::write::SimpleFileOptions;

#[test]
#[cfg(any(target_os = "linux", windows))]
fn worker_returns_a_structured_preflight_response() {
    let temporary = TempDir::new().unwrap();
    let archive = temporary.path().join("mod.zip");
    let file = File::create(&archive).unwrap();
    let mut writer = zip::ZipWriter::new(file);
    writer
        .start_file("Example_P.pak", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"pak").unwrap();
    writer.finish().unwrap();

    let request = ArchiveWorkerRequest::Preflight {
        archive,
        limits: ArchiveLimits::default(),
    };
    let mut child = Command::new(env!("CARGO_BIN_EXE_rrmm-archive-worker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(child.stdin.take().unwrap(), &request).unwrap();
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut output)
        .unwrap();
    let status = child.wait().unwrap();
    let response: ArchiveWorkerResponse = serde_json::from_slice(&output).unwrap();

    assert!(status.success());
    assert!(response.ok);
    assert!(response.sandboxed);
    assert!(response.preflight.unwrap().accepted);
}

#[test]
#[cfg(any(target_os = "linux", windows))]
fn policy_rejection_returns_the_structured_preflight_report() {
    let temporary = TempDir::new().unwrap();
    let archive = temporary.path().join("unsafe.zip");
    let file = File::create(&archive).unwrap();
    let mut writer = zip::ZipWriter::new(file);
    writer
        .start_file("../escape.pak", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"pak").unwrap();
    writer.finish().unwrap();

    let request = ArchiveWorkerRequest::Preflight {
        archive,
        limits: ArchiveLimits::default(),
    };
    let mut child = Command::new(env!("CARGO_BIN_EXE_rrmm-archive-worker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(child.stdin.take().unwrap(), &request).unwrap();
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut output)
        .unwrap();
    let status = child.wait().unwrap();
    let response: ArchiveWorkerResponse = serde_json::from_slice(&output).unwrap();

    assert!(status.success());
    assert!(response.ok);
    assert!(response.error.is_none());
    let preflight = response.preflight.unwrap();
    assert!(!preflight.accepted);
    assert!(
        preflight
            .rejections
            .iter()
            .any(|rejection| rejection.code == "unsafe_path")
    );
}

#[test]
fn malformed_requests_return_json_without_panicking() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rrmm-archive-worker"))
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
    let response: ArchiveWorkerResponse = serde_json::from_slice(&output).unwrap();

    assert!(!status.success());
    assert!(!response.ok);
    assert!(response.error.is_some());
}

#[test]
#[cfg(any(target_os = "linux", windows))]
fn sandboxed_worker_extracts_into_staging() {
    let temporary = TempDir::new().unwrap();
    let archive = temporary.path().join("mod.zip");
    let staging = temporary.path().join("staging");
    let file = File::create(&archive).unwrap();
    let mut writer = zip::ZipWriter::new(file);
    writer
        .start_file("Example_P.pak", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"pak").unwrap();
    writer.finish().unwrap();

    let request = ArchiveWorkerRequest::Extract {
        archive,
        staging: staging.clone(),
        limits: ArchiveLimits::default(),
    };
    let mut child = Command::new(env!("CARGO_BIN_EXE_rrmm-archive-worker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(child.stdin.take().unwrap(), &request).unwrap();
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut output)
        .unwrap();
    let status = child.wait().unwrap();
    let response: ArchiveWorkerResponse = serde_json::from_slice(&output).unwrap();

    assert!(status.success());
    assert!(response.ok);
    assert!(response.sandboxed);
    assert_eq!(fs::read(staging.join("Example_P.pak")).unwrap(), b"pak");
}

#[test]
#[cfg(not(any(target_os = "linux", windows)))]
fn valid_requests_fail_before_archive_parsing_without_a_sandbox() {
    let temporary = TempDir::new().unwrap();
    let archive = temporary.path().join("not-an-archive.zip");
    fs::write(&archive, b"hostile parser input must remain unread").unwrap();
    let request = ArchiveWorkerRequest::Preflight {
        archive,
        limits: ArchiveLimits::default(),
    };
    let mut child = Command::new(env!("CARGO_BIN_EXE_rrmm-archive-worker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(child.stdin.take().unwrap(), &request).unwrap();
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut output)
        .unwrap();
    let status = child.wait().unwrap();
    let response: ArchiveWorkerResponse = serde_json::from_slice(&output).unwrap();

    assert!(!status.success());
    assert!(!response.ok);
    assert!(!response.sandboxed);
    assert!(response.preflight.is_none());
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
    let output = Command::new(env!("CARGO_BIN_EXE_rrmm-archive-worker"))
        .arg("--rrmm-windows-sandbox-child=0")
        .output()
        .unwrap();
    let response: ArchiveWorkerResponse = serde_json::from_slice(&output.stdout).unwrap();

    assert!(!output.status.success());
    assert!(!response.ok);
    assert!(!response.sandboxed);
    assert!(response.preflight.is_none());
}
