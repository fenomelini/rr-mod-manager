#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn cli_rejects_a_successful_unsandboxed_pak_worker() {
    let temporary = TempDir::new().unwrap();
    let worker = temporary.path().join("unsandboxed-worker.sh");
    fs::write(
        &worker,
        "#!/bin/sh\n/bin/cat >/dev/null\nprintf '%s' '{\"ok\":true,\"sandboxed\":false,\"inventory\":null,\"member_digests\":[],\"index_metadata_sha256\":null,\"error\":null}'\n",
    )
    .unwrap();
    fs::set_permissions(&worker, fs::Permissions::from_mode(0o700)).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_rrmm-cli"))
        .args([
            "pak-inspect",
            "--pak",
            "/does/not/matter.pak",
            "--worker",
            worker.to_str().unwrap(),
        ])
        .status()
        .unwrap();

    assert!(!status.success());
}
