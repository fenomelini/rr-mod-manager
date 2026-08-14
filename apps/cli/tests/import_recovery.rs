#![cfg(unix)]

use rrmm_archive::sha256_path;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn storage_failure_cleans_import_staging_without_publishing_an_artifact() {
    let temporary = TempDir::new().unwrap();
    let archive = temporary.path().join("mod.zip");
    let store = temporary.path().join("store");
    let worker = temporary.path().join("successful-worker.sh");
    fs::write(&archive, b"source archive fixture").unwrap();
    fs::create_dir_all(&store).unwrap();
    fs::write(store.join("artifacts"), b"blocks artifact directory").unwrap();

    write_successful_worker(&worker, &archive, temporary.path());

    let status = Command::new(env!("CARGO_BIN_EXE_rrmm-cli"))
        .args([
            "archive-import",
            "--archive",
            archive.to_str().unwrap(),
            "--store",
            store.to_str().unwrap(),
            "--worker",
            worker.to_str().unwrap(),
        ])
        .status()
        .unwrap();

    assert!(!status.success());
    assert_eq!(
        fs::read(store.join("artifacts")).unwrap(),
        b"blocks artifact directory"
    );
    assert_eq!(fs::read_dir(store.join(".work")).unwrap().count(), 0);
}

#[test]
fn write_limit_failure_removes_incoming_artifact_and_import_staging() {
    let temporary = TempDir::new().unwrap();
    let archive = temporary.path().join("large-mod.zip");
    let store = temporary.path().join("store");
    let worker = temporary.path().join("successful-worker.sh");
    fs::write(&archive, vec![b'a'; 4096]).unwrap();
    fs::create_dir_all(&store).unwrap();
    write_successful_worker(&worker, &archive, temporary.path());

    let status = Command::new("/bin/sh")
        .args([
            "-c",
            "trap '' XFSZ; ulimit -f 1; exec \"$1\" archive-import --archive \"$2\" --store \"$3\" --worker \"$4\"",
            "rrmm-write-limit-test",
            env!("CARGO_BIN_EXE_rrmm-cli"),
            archive.to_str().unwrap(),
            store.to_str().unwrap(),
            worker.to_str().unwrap(),
        ])
        .status()
        .unwrap();

    assert!(!status.success());
    assert_eq!(fs::read_dir(store.join(".work")).unwrap().count(), 0);
    let artifact_shards = fs::read_dir(store.join("artifacts")).unwrap().count();
    assert_eq!(artifact_shards, 1);
    let shard = fs::read_dir(store.join("artifacts"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(fs::read_dir(shard).unwrap().count(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn enospc_removes_incoming_artifact_and_import_staging() {
    let namespace_probe = Command::new("unshare")
        .args(["--user", "--map-root-user", "true"])
        .status();
    if !namespace_probe.is_ok_and(|status| status.success()) {
        eprintln!("skipping ENOSPC test: unprivileged user namespaces are unavailable");
        return;
    }

    let temporary = TempDir::new().unwrap();
    let archive = temporary.path().join("larger-than-store.zip");
    let store = temporary.path().join("tiny-store");
    let worker = temporary.path().join("successful-worker.sh");
    let error_log = temporary.path().join("enospc-error.log");
    fs::write(&archive, vec![b'a'; 2 * 1024 * 1024]).unwrap();
    fs::create_dir(&store).unwrap();
    write_large_successful_worker(&worker, &archive);

    let script = r#"
/usr/bin/mount -t tmpfs -o size=3m,nr_inodes=128 tmpfs "$1" || exit 77
if "$2" archive-import --archive "$3" --store "$1" --worker "$4" >/dev/null 2>"$5"; then
    exit 1
fi
/usr/bin/grep -q 'os error 28' "$5" || { echo 'missing ENOSPC error' >>"$5"; exit 1; }
test -d "$1/.work" || { echo 'missing work directory' >>"$5"; exit 1; }
test -d "$1/artifacts" || { echo 'missing artifacts directory' >>"$5"; exit 1; }
test -z "$(/usr/bin/find "$1/.work" -mindepth 1 -print -quit)" || { echo 'work directory was not cleaned' >>"$5"; exit 1; }
test -z "$(/usr/bin/find "$1/artifacts" -mindepth 2 -print -quit)" || { echo 'incoming artifact was not cleaned' >>"$5"; exit 1; }
"#;
    let status = Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "/bin/sh",
            "-c",
            script,
            "rrmm-enospc-test",
            store.to_str().unwrap(),
            env!("CARGO_BIN_EXE_rrmm-cli"),
            archive.to_str().unwrap(),
            worker.to_str().unwrap(),
            error_log.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    if status.code() == Some(77) {
        eprintln!("skipping ENOSPC test: tmpfs mounts are unavailable in the user namespace");
        return;
    }

    assert!(
        status.success(),
        "ENOSPC recovery check failed with status {:?}:\n{}",
        status.code(),
        fs::read_to_string(&error_log).unwrap_or_else(|error| error.to_string())
    );
}

fn write_successful_worker(
    worker: &std::path::Path,
    archive: &std::path::Path,
    root: &std::path::Path,
) {
    let archive_hash = sha256_path(archive).unwrap();
    let file_contents = b"pak";
    let hash_fixture = root.join("file-hash-fixture");
    fs::write(&hash_fixture, file_contents).unwrap();
    let file_hash = sha256_path(&hash_fixture).unwrap();
    fs::write(
        worker,
        format!(
            "#!/bin/sh\nrequest=$(/bin/cat)\nstaging=${{request#*\\\"staging\\\":\\\"}}\nstaging=${{staging%%\\\"*}}\n/bin/mkdir -p \"$staging\"\nprintf pak > \"$staging/Example_P.pak\"\nprintf '%s' '{{\"ok\":true,\"sandboxed\":true,\"preflight\":null,\"extraction\":{{\"archive_sha256\":\"{archive_hash}\",\"format\":\"zip\",\"staging_root\":\"'\nprintf '%s' \"$staging\"\nprintf '%s' '\",\"expanded_bytes\":{},\"files\":[{{\"path\":\"Example_P.pak\",\"bytes\":{},\"sha256\":\"{file_hash}\",\"executable_payload\":false,\"native_binary\":false}}],\"layout\":{{\"kind\":\"pak_only\",\"pak_files\":[\"Example_P.pak\"],\"ue4ss_mod_roots\":[],\"documentation_files\":[],\"executable_files\":[],\"requires_review\":false,\"issues\":[]}}}},\"error\":null}}'\n",
            file_contents.len(),
            file_contents.len()
        ),
    )
    .unwrap();
    fs::set_permissions(worker, fs::Permissions::from_mode(0o700)).unwrap();
}

fn write_large_successful_worker(worker: &std::path::Path, archive: &std::path::Path) {
    let archive_hash = sha256_path(archive).unwrap();
    let file_bytes = fs::metadata(archive).unwrap().len();
    fs::write(
        worker,
        format!(
            "#!/bin/sh\nrequest=$(/bin/cat)\nstaging=${{request#*\\\"staging\\\":\\\"}}\nstaging=${{staging%%\\\"*}}\n/bin/mkdir -p \"$staging\"\n/bin/cp \"{}\" \"$staging/Example_P.pak\"\nprintf '%s' '{{\"ok\":true,\"sandboxed\":true,\"preflight\":null,\"extraction\":{{\"archive_sha256\":\"{archive_hash}\",\"format\":\"zip\",\"staging_root\":\"'\nprintf '%s' \"$staging\"\nprintf '%s' '\",\"expanded_bytes\":{file_bytes},\"files\":[{{\"path\":\"Example_P.pak\",\"bytes\":{file_bytes},\"sha256\":\"{archive_hash}\",\"executable_payload\":false,\"native_binary\":false}}],\"layout\":{{\"kind\":\"pak_only\",\"pak_files\":[\"Example_P.pak\"],\"ue4ss_mod_roots\":[],\"documentation_files\":[],\"executable_files\":[],\"requires_review\":false,\"issues\":[]}}}},\"error\":null}}'\n",
            archive.display()
        ),
    )
    .unwrap();
    fs::set_permissions(worker, fs::Permissions::from_mode(0o700)).unwrap();
}
