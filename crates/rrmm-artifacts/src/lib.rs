use rrmm_archive::{
    ArchiveExtractionReport, ArchiveFormat, ArchiveLimits, ExtractedFileReport,
    PackageLayoutInference, sha256_path, validate_entry_path, verify_extraction_report,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::Builder;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactManifest {
    pub schema_version: u32,
    pub sha256: String,
    pub format: ArchiveFormat,
    pub archive_bytes: u64,
    pub expanded_bytes: u64,
    pub files: Vec<ExtractedFileReport>,
    pub layout: PackageLayoutInference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedArtifact {
    pub root: PathBuf,
    pub duplicate: bool,
    pub manifest: ArtifactManifest,
}

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("archive verification failed: {0}")]
    Archive(#[from] rrmm_archive::ArchiveError),
    #[error("artifact I/O failed at {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("artifact JSON failed at {path}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("artifact verification failed: {0}")]
    Verification(String),
}

pub fn accept_artifact(
    source_archive: &Path,
    extraction: &ArchiveExtractionReport,
    store_root: &Path,
    limits: &ArchiveLimits,
) -> Result<AcceptedArtifact, ArtifactError> {
    let manifest = preview_artifact_manifest(source_archive, extraction, limits)?;
    let shard = store_root
        .join("artifacts")
        .join(&extraction.archive_sha256[..2]);
    create_directory(&shard)?;
    let destination = shard.join(&extraction.archive_sha256);
    if destination.exists() {
        let existing = read_manifest(&destination.join("manifest.json"))?;
        if existing != manifest {
            return Err(ArtifactError::Verification(format!(
                "existing artifact {} has different metadata",
                extraction.archive_sha256
            )));
        }
        verify_existing_artifact(&destination, &existing)?;
        remove_staging(&extraction.staging_root)?;
        return Ok(AcceptedArtifact {
            root: destination,
            duplicate: true,
            manifest,
        });
    }

    let temporary = Builder::new()
        .prefix(".incoming-")
        .tempdir_in(&shard)
        .map_err(|source| ArtifactError::Io {
            path: shard.clone(),
            source,
        })?;
    let files_root = temporary.path().join("files");
    create_directory(&files_root)?;
    for file in &extraction.files {
        let source = extraction
            .staging_root
            .join(path_from_archive_name(&file.path));
        let destination_file = files_root.join(path_from_archive_name(&file.path));
        if let Some(parent) = destination_file.parent() {
            create_directory(parent)?;
        }
        copy_verified(&source, &destination_file, file.bytes, &file.sha256)?;
    }

    let manifest_path = temporary.path().join("manifest.json");
    let manifest_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&manifest_path)
        .map_err(|source| ArtifactError::Io {
            path: manifest_path.clone(),
            source,
        })?;
    serde_json::to_writer_pretty(&manifest_file, &manifest).map_err(|source| {
        ArtifactError::Json {
            path: manifest_path.clone(),
            source,
        }
    })?;
    manifest_file
        .sync_all()
        .map_err(|source| ArtifactError::Io {
            path: manifest_path,
            source,
        })?;
    drop(manifest_file);

    set_files_readonly(temporary.path())?;
    remove_staging(&extraction.staging_root)?;
    match fs::rename(temporary.path(), &destination) {
        Ok(()) => std::mem::forget(temporary),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let existing = read_manifest(&destination.join("manifest.json"))?;
            if existing != manifest {
                return Err(ArtifactError::Verification(format!(
                    "artifact {} raced with different metadata",
                    extraction.archive_sha256
                )));
            }
            verify_existing_artifact(&destination, &existing)?;
            return Ok(AcceptedArtifact {
                root: destination,
                duplicate: true,
                manifest,
            });
        }
        Err(source) => {
            return Err(ArtifactError::Io {
                path: destination,
                source,
            });
        }
    }

    Ok(AcceptedArtifact {
        root: destination,
        duplicate: false,
        manifest,
    })
}

pub fn preview_artifact_manifest(
    source_archive: &Path,
    extraction: &ArchiveExtractionReport,
    limits: &ArchiveLimits,
) -> Result<ArtifactManifest, ArtifactError> {
    validate_sha256(&extraction.archive_sha256)?;
    let source_hash = sha256_path(source_archive)?;
    if source_hash != extraction.archive_sha256 {
        return Err(ArtifactError::Verification(
            "source archive hash differs from the worker report".to_owned(),
        ));
    }
    verify_extraction_report(extraction, limits)?;

    let archive_bytes = fs::metadata(source_archive)
        .map_err(|source| ArtifactError::Io {
            path: source_archive.to_path_buf(),
            source,
        })?
        .len();
    Ok(ArtifactManifest {
        schema_version: 1,
        sha256: extraction.archive_sha256.clone(),
        format: extraction.format,
        archive_bytes,
        expanded_bytes: extraction.expanded_bytes,
        files: extraction.files.clone(),
        layout: extraction.layout.clone(),
    })
}

pub fn load_verified_artifact(artifact_root: &Path) -> Result<ArtifactManifest, ArtifactError> {
    let manifest = load_artifact_manifest(artifact_root)?;
    verify_existing_artifact(artifact_root, &manifest)?;
    Ok(manifest)
}

/// Validates immutable-store metadata, paths, file types, and sizes without
/// rehashing payloads. The caller must verify hashes separately.
pub fn load_artifact_manifest(artifact_root: &Path) -> Result<ArtifactManifest, ArtifactError> {
    let metadata = fs::symlink_metadata(artifact_root).map_err(|source| ArtifactError::Io {
        path: artifact_root.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ArtifactError::Verification(format!(
            "artifact root is not a real directory: {}",
            artifact_root.display()
        )));
    }
    let manifest_path = artifact_root.join("manifest.json");
    let manifest_metadata =
        fs::symlink_metadata(&manifest_path).map_err(|source| ArtifactError::Io {
            path: manifest_path.clone(),
            source,
        })?;
    if !manifest_metadata.file_type().is_file() {
        return Err(ArtifactError::Verification(format!(
            "artifact manifest is not a regular file: {}",
            manifest_path.display()
        )));
    }
    let manifest = read_manifest(&manifest_path)?;
    validate_artifact_manifest(&manifest)?;
    for file in &manifest.files {
        let path = artifact_root
            .join("files")
            .join(path_from_archive_name(&file.path));
        let metadata = fs::symlink_metadata(&path).map_err(|source| ArtifactError::Io {
            path: path.clone(),
            source,
        })?;
        if !metadata.file_type().is_file() || metadata.len() != file.bytes {
            return Err(ArtifactError::Verification(format!(
                "artifact file '{}' has unexpected type or size",
                path.display()
            )));
        }
    }
    let source_present = ["source.zip", "source.7z"]
        .iter()
        .any(|name| artifact_root.join(name).exists());
    let actual_file_count = walk_files(artifact_root)?.len();
    let expected_file_count = manifest.files.len() + 1 + usize::from(source_present);
    if actual_file_count != expected_file_count {
        return Err(ArtifactError::Verification(format!(
            "artifact contains {actual_file_count} files; expected {expected_file_count}"
        )));
    }
    Ok(manifest)
}

fn verify_existing_artifact(
    artifact_root: &Path,
    manifest: &ArtifactManifest,
) -> Result<(), ArtifactError> {
    validate_artifact_manifest(manifest)?;
    let source_name = match manifest.format {
        ArchiveFormat::Zip => "source.zip",
        ArchiveFormat::SevenZip => "source.7z",
    };
    let source_path = artifact_root.join(source_name);
    let source_present = source_path.exists();
    if source_present {
        verify_file(&source_path, manifest.archive_bytes, &manifest.sha256)?;
    }
    for file in &manifest.files {
        verify_file(
            &artifact_root
                .join("files")
                .join(path_from_archive_name(&file.path)),
            file.bytes,
            &file.sha256,
        )?;
    }
    let actual_file_count = walk_files(artifact_root)?.len();
    let expected_file_count = manifest.files.len() + 1 + usize::from(source_present);
    if actual_file_count != expected_file_count {
        return Err(ArtifactError::Verification(format!(
            "artifact contains {actual_file_count} files; expected {expected_file_count}"
        )));
    }
    Ok(())
}

fn validate_artifact_manifest(manifest: &ArtifactManifest) -> Result<(), ArtifactError> {
    if manifest.schema_version != 1 {
        return Err(ArtifactError::Verification(format!(
            "unsupported artifact schema version {}",
            manifest.schema_version
        )));
    }
    validate_sha256(&manifest.sha256)?;
    let mut collision_keys = std::collections::BTreeSet::new();
    let mut expanded_bytes = 0_u64;
    for file in &manifest.files {
        validate_sha256(&file.sha256)?;
        let normalized = validate_entry_path(&file.path, false, 32).map_err(|error| {
            ArtifactError::Verification(format!("invalid artifact path '{}': {error}", file.path))
        })?;
        if normalized.path != file.path || !collision_keys.insert(normalized.collision_key) {
            return Err(ArtifactError::Verification(format!(
                "duplicate or non-normalized artifact path '{}'",
                file.path
            )));
        }
        expanded_bytes = expanded_bytes.checked_add(file.bytes).ok_or_else(|| {
            ArtifactError::Verification("artifact expanded byte count overflowed".to_owned())
        })?;
    }
    if expanded_bytes != manifest.expanded_bytes {
        return Err(ArtifactError::Verification(
            "artifact expanded byte count does not match its files".to_owned(),
        ));
    }
    Ok(())
}

fn verify_file(path: &Path, expected_bytes: u64, expected_hash: &str) -> Result<(), ArtifactError> {
    let metadata = fs::metadata(path).map_err(|source| ArtifactError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() || metadata.len() != expected_bytes {
        return Err(ArtifactError::Verification(format!(
            "artifact file '{}' has unexpected type or size",
            path.display()
        )));
    }
    let hash = sha256_path(path)?;
    if hash != expected_hash {
        return Err(ArtifactError::Verification(format!(
            "artifact file '{}' has an unexpected hash",
            path.display()
        )));
    }
    Ok(())
}

fn copy_verified(
    source: &Path,
    destination: &Path,
    expected_bytes: u64,
    expected_hash: &str,
) -> Result<(), ArtifactError> {
    let mut input = BufReader::new(File::open(source).map_err(|error| ArtifactError::Io {
        path: source.to_path_buf(),
        source: error,
    })?);
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|error| ArtifactError::Io {
            path: destination.to_path_buf(),
            source: error,
        })?;
    let mut bytes = 0_u64;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = input.read(&mut buffer).map_err(|error| ArtifactError::Io {
            path: source.to_path_buf(),
            source: error,
        })?;
        if read == 0 {
            break;
        }
        bytes = bytes.saturating_add(read as u64);
        hasher.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .map_err(|error| ArtifactError::Io {
                path: destination.to_path_buf(),
                source: error,
            })?;
    }
    output.sync_all().map_err(|error| ArtifactError::Io {
        path: destination.to_path_buf(),
        source: error,
    })?;
    let hash = format!("{:x}", hasher.finalize());
    if bytes != expected_bytes || hash != expected_hash {
        return Err(ArtifactError::Verification(format!(
            "'{}' changed while being accepted",
            source.display()
        )));
    }
    Ok(())
}

fn read_manifest(path: &Path) -> Result<ArtifactManifest, ArtifactError> {
    let input = fs::read(path).map_err(|source| ArtifactError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&input).map_err(|source| ArtifactError::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn set_files_readonly(root: &Path) -> Result<(), ArtifactError> {
    for item in walk_files(root)? {
        let mut permissions = fs::metadata(&item)
            .map_err(|source| ArtifactError::Io {
                path: item.clone(),
                source,
            })?
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&item, permissions)
            .map_err(|source| ArtifactError::Io { path: item, source })?;
    }
    Ok(())
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>, ArtifactError> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for item in fs::read_dir(&directory).map_err(|source| ArtifactError::Io {
            path: directory.clone(),
            source,
        })? {
            let item = item.map_err(|source| ArtifactError::Io {
                path: directory.clone(),
                source,
            })?;
            let file_type = item.file_type().map_err(|source| ArtifactError::Io {
                path: item.path(),
                source,
            })?;
            if file_type.is_symlink() {
                return Err(ArtifactError::Verification(format!(
                    "artifact staging contains a link: {}",
                    item.path().display()
                )));
            }
            if file_type.is_dir() {
                pending.push(item.path());
            } else if file_type.is_file() {
                files.push(item.path());
            } else {
                return Err(ArtifactError::Verification(format!(
                    "artifact staging contains a special file: {}",
                    item.path().display()
                )));
            }
        }
    }
    Ok(files)
}

fn create_directory(path: &Path) -> Result<(), ArtifactError> {
    fs::create_dir_all(path).map_err(|source| ArtifactError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn remove_staging(path: &Path) -> Result<(), ArtifactError> {
    fs::remove_dir_all(path).map_err(|source| ArtifactError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn validate_sha256(value: &str) -> Result<(), ArtifactError> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ArtifactError::Verification(
            "artifact SHA-256 is invalid".to_owned(),
        ))
    }
}

fn path_from_archive_name(name: &str) -> PathBuf {
    name.split('/').collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrmm_archive::{ArchiveLimits, extract_zip_to_staging};
    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;

    #[test]
    fn accepts_and_deduplicates_a_verified_artifact() {
        let temporary = TempDir::new().unwrap();
        let archive = temporary.path().join("mod.zip");
        write_zip(&archive);
        let limits = ArchiveLimits::default();

        let first_staging = temporary.path().join("staging-one");
        let first_extraction = extract_zip_to_staging(&archive, &first_staging, &limits).unwrap();
        let preview = preview_artifact_manifest(&archive, &first_extraction, &limits).unwrap();
        let first = accept_artifact(
            &archive,
            &first_extraction,
            &temporary.path().join("store"),
            &limits,
        )
        .unwrap();
        assert_eq!(preview, first.manifest);
        assert!(!first.duplicate);
        assert!(!first_staging.exists());
        assert!(!first.root.join("source.zip").exists());
        assert!(first.root.join("files/Example_P.pak").is_file());
        assert_eq!(load_verified_artifact(&first.root).unwrap(), first.manifest);

        let second_staging = temporary.path().join("staging-two");
        let second_extraction = extract_zip_to_staging(&archive, &second_staging, &limits).unwrap();
        let second = accept_artifact(
            &archive,
            &second_extraction,
            &temporary.path().join("store"),
            &limits,
        )
        .unwrap();
        assert!(second.duplicate);
        assert_eq!(first.root, second.root);
        assert!(!second_staging.exists());
    }

    #[test]
    fn rejects_staging_tampering_before_publication() {
        let temporary = TempDir::new().unwrap();
        let archive = temporary.path().join("mod.zip");
        let staging = temporary.path().join("staging");
        write_zip(&archive);
        let limits = ArchiveLimits::default();
        let extraction = extract_zip_to_staging(&archive, &staging, &limits).unwrap();
        fs::write(staging.join("Example_P.pak"), b"tampered").unwrap();

        let result = accept_artifact(
            &archive,
            &extraction,
            &temporary.path().join("store"),
            &limits,
        );
        assert!(result.is_err());
        assert!(!temporary.path().join("store/artifacts").exists());
    }

    #[test]
    fn rejects_a_tampered_existing_artifact_instead_of_deduplicating_it() {
        let temporary = TempDir::new().unwrap();
        let archive = temporary.path().join("mod.zip");
        let store = temporary.path().join("store");
        let limits = ArchiveLimits::default();
        write_zip(&archive);

        let first_staging = temporary.path().join("staging-one");
        let first_extraction = extract_zip_to_staging(&archive, &first_staging, &limits).unwrap();
        let first = accept_artifact(&archive, &first_extraction, &store, &limits).unwrap();
        let stored_file = first.root.join("files/Example_P.pak");
        make_writable(&stored_file);
        fs::write(&stored_file, b"tampered").unwrap();

        let second_staging = temporary.path().join("staging-two");
        let second_extraction = extract_zip_to_staging(&archive, &second_staging, &limits).unwrap();
        let result = accept_artifact(&archive, &second_extraction, &store, &limits);
        assert!(result.is_err());
        assert!(second_staging.exists());
    }

    fn write_zip(path: &Path) {
        let file = File::create(path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file("Example_P.pak", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"pak").unwrap();
        writer.finish().unwrap();
    }

    #[cfg(unix)]
    fn make_writable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(not(unix))]
    fn make_writable(path: &Path) {
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions).unwrap();
    }
}
