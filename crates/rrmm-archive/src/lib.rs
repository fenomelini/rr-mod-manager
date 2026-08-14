use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;

const MAX_ARCHIVE_PATH_BYTES: usize = 4_096;
const MAX_ARCHIVE_COMPONENT_BYTES: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveLimits {
    pub max_archive_bytes: u64,
    pub max_expanded_bytes: u64,
    pub max_file_bytes: u64,
    pub max_entries: usize,
    pub max_depth: usize,
    pub max_compression_ratio: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: u64::MAX,
            max_expanded_bytes: u64::MAX,
            max_file_bytes: u64::MAX,
            max_entries: usize::MAX,
            max_depth: 32,
            max_compression_ratio: u64::MAX,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedArchivePath {
    /// Separator-normalized path retained for staging.
    pub path: String,
    /// NFKD, full-case-folded, NFC key used only for collision detection.
    pub collision_key: String,
    pub depth: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivePreflightReport {
    pub accepted: bool,
    pub format: ArchiveFormat,
    pub archive_path: PathBuf,
    pub archive_sha256: Option<String>,
    pub archive_bytes: u64,
    pub expanded_bytes: u64,
    pub entry_count: usize,
    pub entries: Vec<ArchiveEntryReport>,
    pub rejections: Vec<ArchiveRejection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveFormat {
    Zip,
    SevenZip,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveEntryReport {
    pub path: String,
    pub expanded_bytes: u64,
    pub compressed_bytes: u64,
    pub directory: bool,
    pub executable_payload: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveRejection {
    pub code: String,
    pub path: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveExtractionReport {
    pub archive_sha256: String,
    pub format: ArchiveFormat,
    pub staging_root: PathBuf,
    pub expanded_bytes: u64,
    pub files: Vec<ExtractedFileReport>,
    pub layout: PackageLayoutInference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedFileReport {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub executable_payload: bool,
    pub native_binary: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageKind {
    PakOnly,
    Ue4ssOnly,
    Hybrid,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageLayoutInference {
    pub kind: PackageKind,
    pub pak_files: Vec<String>,
    pub ue4ss_mod_roots: Vec<String>,
    pub documentation_files: Vec<String>,
    pub executable_files: Vec<String>,
    pub requires_review: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum ArchiveWorkerRequest {
    Preflight {
        archive: PathBuf,
        limits: ArchiveLimits,
    },
    Extract {
        archive: PathBuf,
        staging: PathBuf,
        limits: ArchiveLimits,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveWorkerResponse {
    pub ok: bool,
    pub sandboxed: bool,
    pub preflight: Option<ArchivePreflightReport>,
    pub extraction: Option<ArchiveExtractionReport>,
    pub error: Option<String>,
}

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("failed to access archive {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("failed to parse ZIP archive {path}: {source}")]
    Zip {
        path: PathBuf,
        source: zip::result::ZipError,
    },
    #[error("failed to parse 7z archive {path}: {source}")]
    SevenZip {
        path: PathBuf,
        source: sevenz_rust2::Error,
    },
    #[error("unsupported archive format: {0}")]
    UnsupportedFormat(PathBuf),
    #[error("archive preflight rejected {count} item(s)")]
    PreflightRejected { count: usize },
    #[error("invalid staging directory {path}: {detail}")]
    InvalidStaging { path: PathBuf, detail: String },
    #[error("archive changed after preflight: {0}")]
    ArchiveChanged(PathBuf),
    #[error("extraction limit exceeded for {path}: {detail}")]
    ExtractionLimit { path: String, detail: String },
    #[error("post-extraction verification failed: {0}")]
    Verification(String),
}

#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", content = "detail", rename_all = "snake_case")]
pub enum PathPolicyError {
    #[error("archive entry path is empty")]
    Empty,
    #[error("archive entry path contains a NUL byte")]
    NullByte,
    #[error("archive entry path is absolute or drive-qualified: {0}")]
    Absolute(String),
    #[error("archive entry path contains an empty component: {0}")]
    EmptyComponent(String),
    #[error("archive entry path contains traversal: {0}")]
    Traversal(String),
    #[error("archive entry path exceeds maximum depth {max}: {actual}")]
    TooDeep { actual: usize, max: usize },
    #[error("archive entry path exceeds {max} bytes: {actual}")]
    TooLong { actual: usize, max: usize },
    #[error("archive entry component exceeds {max} bytes: {actual}")]
    ComponentTooLong { actual: usize, max: usize },
    #[error("archive entry component is invalid on Windows: {0}")]
    InvalidWindowsComponent(String),
    #[error("archive entry uses a reserved Windows device name: {0}")]
    ReservedWindowsName(String),
    #[error("file entry path ends with a directory separator: {0}")]
    FileWithDirectorySuffix(String),
}

pub fn validate_entry_path(
    raw: &str,
    is_directory: bool,
    max_depth: usize,
) -> Result<NormalizedArchivePath, PathPolicyError> {
    if raw.is_empty() {
        return Err(PathPolicyError::Empty);
    }
    if raw.contains('\0') {
        return Err(PathPolicyError::NullByte);
    }

    let normalized_separators = raw.replace('\\', "/");
    if normalized_separators.starts_with('/')
        || normalized_separators
            .as_bytes()
            .get(1)
            .is_some_and(|byte| *byte == b':')
    {
        return Err(PathPolicyError::Absolute(raw.to_owned()));
    }
    if !is_directory && normalized_separators.ends_with('/') {
        return Err(PathPolicyError::FileWithDirectorySuffix(raw.to_owned()));
    }

    let path = normalized_separators.trim_end_matches('/');
    if path.is_empty() {
        return Err(PathPolicyError::Empty);
    }
    if path.len() > MAX_ARCHIVE_PATH_BYTES {
        return Err(PathPolicyError::TooLong {
            actual: path.len(),
            max: MAX_ARCHIVE_PATH_BYTES,
        });
    }
    let components: Vec<_> = path.split('/').collect();
    if components.len() > max_depth {
        return Err(PathPolicyError::TooDeep {
            actual: components.len(),
            max: max_depth,
        });
    }

    for component in &components {
        validate_component(component)?;
    }

    let path = components.join("/");
    let collision_key = path.nfkd().case_fold().nfc().collect::<String>();
    Ok(NormalizedArchivePath {
        path,
        collision_key,
        depth: components.len(),
    })
}

pub fn is_executable_payload(path: &str) -> bool {
    let extension = path
        .rsplit_once('.')
        .map(|(_, extension)| extension)
        .unwrap_or_default();
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "bat" | "cmd" | "com" | "cpl" | "dll" | "exe" | "msi" | "ps1" | "scr"
    )
}

pub fn infer_package_layout(files: &[ExtractedFileReport]) -> PackageLayoutInference {
    let mut pak_files = Vec::new();
    let mut ue4ss_mod_roots = Vec::new();
    let mut documentation_files = Vec::new();
    let mut executable_files = Vec::new();
    let mut issues = Vec::new();

    for file in files {
        let folded = file.path.to_ascii_lowercase();
        if folded.ends_with(".pak") {
            pak_files.push(file.path.clone());
        }
        if let Some(root) = ue4ss_root_for_path(&file.path)
            && !ue4ss_mod_roots.contains(&root)
        {
            ue4ss_mod_roots.push(root);
        }
        if is_documentation_file(&folded) {
            documentation_files.push(file.path.clone());
        }
        if file.executable_payload || file.native_binary {
            executable_files.push(file.path.clone());
        }
    }
    pak_files.sort();
    ue4ss_mod_roots.sort();
    documentation_files.sort();
    executable_files.sort();

    let kind = match (pak_files.is_empty(), ue4ss_mod_roots.is_empty()) {
        (false, true) => PackageKind::PakOnly,
        (true, false) => PackageKind::Ue4ssOnly,
        (false, false) => PackageKind::Hybrid,
        (true, true) => PackageKind::Unknown,
    };
    if kind == PackageKind::Unknown {
        issues.push("no PAK or UE4SS Scripts/main.lua payload was recognized".to_owned());
    }
    if ue4ss_mod_roots.len() > 1 {
        issues.push(format!(
            "archive contains {} UE4SS mod roots",
            ue4ss_mod_roots.len()
        ));
    }
    if !executable_files.is_empty() {
        issues.push("archive contains executable or native-binary payloads".to_owned());
    }

    PackageLayoutInference {
        kind,
        pak_files,
        ue4ss_mod_roots,
        documentation_files,
        executable_files,
        requires_review: !issues.is_empty(),
        issues,
    }
}

pub fn verify_extraction_report(
    report: &ArchiveExtractionReport,
    limits: &ArchiveLimits,
) -> Result<(), ArchiveError> {
    verify_staging(
        &report.staging_root,
        &report.files,
        report.expanded_bytes,
        limits,
    )
}

pub fn sha256_path(path: &Path) -> Result<String, ArchiveError> {
    sha256_file(path).map_err(|source| ArchiveError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn ue4ss_root_for_path(path: &str) -> Option<String> {
    let components: Vec<_> = path.split('/').collect();
    for index in 0..components.len().saturating_sub(1) {
        if components[index].eq_ignore_ascii_case("scripts")
            && components[index + 1].eq_ignore_ascii_case("main.lua")
            && index > 0
        {
            return Some(components[..index].join("/"));
        }
    }
    None
}

fn is_documentation_file(folded_path: &str) -> bool {
    let name = folded_path.rsplit('/').next().unwrap_or(folded_path);
    name.starts_with("readme")
        || name.starts_with("changelog")
        || name.starts_with("license")
        || matches!(name, "install.txt" | "installation.txt")
}

pub fn preflight_zip(
    archive_path: &Path,
    limits: &ArchiveLimits,
) -> Result<ArchivePreflightReport, ArchiveError> {
    let mut report = initial_report(archive_path, ArchiveFormat::Zip, limits)?;
    if !report.rejections.is_empty() {
        return Ok(report);
    }

    let file = File::open(archive_path).map_err(|source| ArchiveError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let mut archive =
        zip::ZipArchive::new(BufReader::new(file)).map_err(|source| ArchiveError::Zip {
            path: archive_path.to_path_buf(),
            source,
        })?;
    report.entry_count = archive.len();
    if report.entry_count > limits.max_entries {
        let detail = format!(
            "archive has {} entries; limit is {}",
            report.entry_count, limits.max_entries
        );
        reject(&mut report, "too_many_entries", None, detail);
    }
    if archive
        .has_overlapping_files()
        .map_err(|source| ArchiveError::Zip {
            path: archive_path.to_path_buf(),
            source,
        })?
    {
        reject(
            &mut report,
            "overlapping_entries",
            None,
            "multiple ZIP entries share compressed data".to_owned(),
        );
    }

    let mut collision_keys = BTreeMap::<String, (String, bool)>::new();
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|source| ArchiveError::Zip {
                path: archive_path.to_path_buf(),
                source,
            })?;
        let raw_path = entry.name().to_owned();
        let is_directory = entry.is_dir();

        if entry.encrypted() {
            reject(
                &mut report,
                "encrypted_entry",
                Some(raw_path.clone()),
                "encrypted archives are not supported".to_owned(),
            );
        }
        if entry.is_symlink() {
            reject(
                &mut report,
                "link_entry",
                Some(raw_path.clone()),
                "symbolic links are not supported".to_owned(),
            );
        } else if !is_directory && !entry.is_file() {
            reject(
                &mut report,
                "special_entry",
                Some(raw_path.clone()),
                "only regular files and directories are supported".to_owned(),
            );
        }

        let normalized = match validate_entry_path(&raw_path, is_directory, limits.max_depth) {
            Ok(normalized) => normalized,
            Err(error) => {
                reject(
                    &mut report,
                    "unsafe_path",
                    Some(raw_path),
                    error.to_string(),
                );
                continue;
            }
        };
        record_archive_path(&mut report, &mut collision_keys, &normalized, is_directory);

        let expanded_bytes = entry.size();
        let compressed_bytes = entry.compressed_size();
        if expanded_bytes > limits.max_file_bytes {
            reject(
                &mut report,
                "file_too_large",
                Some(normalized.path.clone()),
                format!(
                    "entry expands to {expanded_bytes} bytes; limit is {}",
                    limits.max_file_bytes
                ),
            );
        }
        report.expanded_bytes = report.expanded_bytes.saturating_add(expanded_bytes);
        if expanded_bytes
            > compressed_bytes
                .max(1)
                .saturating_mul(limits.max_compression_ratio)
        {
            reject(
                &mut report,
                "compression_ratio_exceeded",
                Some(normalized.path.clone()),
                format!(
                    "entry compression ratio exceeds {}:1",
                    limits.max_compression_ratio
                ),
            );
        }
        report.entries.push(ArchiveEntryReport {
            executable_payload: !is_directory && is_executable_payload(&normalized.path),
            path: normalized.path,
            expanded_bytes,
            compressed_bytes,
            directory: is_directory,
        });
    }

    if report.expanded_bytes > limits.max_expanded_bytes {
        let detail = format!(
            "archive expands to {} bytes; limit is {}",
            report.expanded_bytes, limits.max_expanded_bytes
        );
        reject(&mut report, "expanded_size_exceeded", None, detail);
    }
    report.accepted = report.rejections.is_empty();
    Ok(report)
}

pub fn preflight_seven_zip(
    archive_path: &Path,
    limits: &ArchiveLimits,
) -> Result<ArchivePreflightReport, ArchiveError> {
    let mut report = initial_report(archive_path, ArchiveFormat::SevenZip, limits)?;
    if is_multipart_name(archive_path) {
        reject(
            &mut report,
            "multipart_archive",
            None,
            "multipart archives are not supported".to_owned(),
        );
        return Ok(report);
    }
    if !report.rejections.is_empty() {
        return Ok(report);
    }

    let archive = match sevenz_rust2::Archive::open(archive_path) {
        Ok(archive) => archive,
        Err(source) if is_seven_zip_encryption_error(&source) => {
            reject(
                &mut report,
                "encrypted_archive",
                None,
                "encrypted archives are not supported".to_owned(),
            );
            return Ok(report);
        }
        Err(source) => {
            return Err(ArchiveError::SevenZip {
                path: archive_path.to_path_buf(),
                source,
            });
        }
    };

    report.entry_count = archive.files.len();
    if report.entry_count > limits.max_entries {
        let detail = format!(
            "archive has {} entries; limit is {}",
            report.entry_count, limits.max_entries
        );
        reject(&mut report, "too_many_entries", None, detail);
    }
    if archive.blocks.iter().any(|block| {
        block
            .coders
            .iter()
            .any(|coder| coder.encoder_method_id() == [0x06, 0xf1, 0x07, 0x01])
    }) {
        reject(
            &mut report,
            "encrypted_archive",
            None,
            "encrypted archives are not supported".to_owned(),
        );
    }
    let unsupported_methods: BTreeSet<_> = archive
        .blocks
        .iter()
        .flat_map(|block| &block.coders)
        .map(|coder| coder.encoder_method_id())
        .filter(|method| {
            *method != sevenz_rust2::EncoderMethod::ID_AES256_SHA256
                && !is_supported_seven_zip_method(method)
        })
        .map(seven_zip_method_label)
        .collect();
    for method in unsupported_methods {
        reject(
            &mut report,
            "unsupported_codec",
            None,
            format!("7z codec or filter is not supported: {method}"),
        );
    }

    let mut collision_keys = BTreeMap::<String, (String, bool)>::new();
    for entry in &archive.files {
        let raw_path = entry.name.clone();
        let is_directory = entry.is_directory;
        if entry.is_anti_item {
            reject(
                &mut report,
                "anti_item",
                Some(raw_path.clone()),
                "7z anti-items are not supported".to_owned(),
            );
        }
        if is_link_like_7z(entry.windows_attributes) {
            reject(
                &mut report,
                "link_entry",
                Some(raw_path.clone()),
                "links and reparse points are not supported".to_owned(),
            );
        }

        let normalized = match validate_entry_path(&raw_path, is_directory, limits.max_depth) {
            Ok(normalized) => normalized,
            Err(error) => {
                reject(
                    &mut report,
                    "unsafe_path",
                    Some(raw_path),
                    error.to_string(),
                );
                continue;
            }
        };
        record_archive_path(&mut report, &mut collision_keys, &normalized, is_directory);

        let expanded_bytes = entry.size;
        if expanded_bytes > limits.max_file_bytes {
            reject(
                &mut report,
                "file_too_large",
                Some(normalized.path.clone()),
                format!(
                    "entry expands to {expanded_bytes} bytes; limit is {}",
                    limits.max_file_bytes
                ),
            );
        }
        report.expanded_bytes = report.expanded_bytes.saturating_add(expanded_bytes);
        report.entries.push(ArchiveEntryReport {
            executable_payload: !is_directory && is_executable_payload(&normalized.path),
            path: normalized.path,
            expanded_bytes,
            compressed_bytes: entry.compressed_size,
            directory: is_directory,
        });
    }
    finish_size_checks(&mut report, limits);
    if report.expanded_bytes
        > report
            .archive_bytes
            .max(1)
            .saturating_mul(limits.max_compression_ratio)
    {
        reject(
            &mut report,
            "compression_ratio_exceeded",
            None,
            format!(
                "archive compression ratio exceeds {}:1",
                limits.max_compression_ratio
            ),
        );
    }
    report.accepted = report.rejections.is_empty();
    Ok(report)
}

pub fn preflight_archive(
    archive_path: &Path,
    limits: &ArchiveLimits,
) -> Result<ArchivePreflightReport, ArchiveError> {
    let mut file = File::open(archive_path).map_err(|source| ArchiveError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let mut magic = [0_u8; 6];
    let read = file.read(&mut magic).map_err(|source| ArchiveError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    if read >= 4 && matches!(&magic[..4], b"PK\x03\x04" | b"PK\x05\x06" | b"PK\x07\x08") {
        preflight_zip(archive_path, limits)
    } else if read == 6 && magic == [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] {
        preflight_seven_zip(archive_path, limits)
    } else {
        Err(ArchiveError::UnsupportedFormat(archive_path.to_path_buf()))
    }
}

pub fn extract_archive_to_staging(
    archive_path: &Path,
    staging_root: &Path,
    limits: &ArchiveLimits,
) -> Result<ArchiveExtractionReport, ArchiveError> {
    let preflight = preflight_archive(archive_path, limits)?;
    if !preflight.accepted {
        return Err(ArchiveError::PreflightRejected {
            count: preflight.rejections.len(),
        });
    }
    match preflight.format {
        ArchiveFormat::Zip => extract_zip_to_staging(archive_path, staging_root, limits),
        ArchiveFormat::SevenZip => extract_seven_zip_to_staging(archive_path, staging_root, limits),
    }
}

pub fn extract_zip_to_staging(
    archive_path: &Path,
    staging_root: &Path,
    limits: &ArchiveLimits,
) -> Result<ArchiveExtractionReport, ArchiveError> {
    let preflight = preflight_zip(archive_path, limits)?;
    if !preflight.accepted {
        return Err(ArchiveError::PreflightRejected {
            count: preflight.rejections.len(),
        });
    }
    prepare_staging(staging_root)?;

    match extract_preflighted_zip(archive_path, staging_root, limits, &preflight) {
        Ok(report) => Ok(report),
        Err(error) => {
            if let Err(cleanup) = fs::remove_dir_all(staging_root) {
                return Err(ArchiveError::InvalidStaging {
                    path: staging_root.to_path_buf(),
                    detail: format!("extraction failed ({error}); cleanup also failed: {cleanup}"),
                });
            }
            Err(error)
        }
    }
}

pub fn extract_seven_zip_to_staging(
    archive_path: &Path,
    staging_root: &Path,
    limits: &ArchiveLimits,
) -> Result<ArchiveExtractionReport, ArchiveError> {
    let preflight = preflight_seven_zip(archive_path, limits)?;
    if !preflight.accepted {
        return Err(ArchiveError::PreflightRejected {
            count: preflight.rejections.len(),
        });
    }
    prepare_staging(staging_root)?;

    match extract_preflighted_seven_zip(archive_path, staging_root, limits, &preflight) {
        Ok(report) => Ok(report),
        Err(error) => {
            if let Err(cleanup) = fs::remove_dir_all(staging_root) {
                return Err(ArchiveError::InvalidStaging {
                    path: staging_root.to_path_buf(),
                    detail: format!("extraction failed ({error}); cleanup also failed: {cleanup}"),
                });
            }
            Err(error)
        }
    }
}

pub fn execute_worker_request(request: ArchiveWorkerRequest) -> ArchiveWorkerResponse {
    match request {
        ArchiveWorkerRequest::Preflight { archive, limits } => {
            match preflight_archive(&archive, &limits) {
                Ok(preflight) => ArchiveWorkerResponse {
                    ok: true,
                    sandboxed: false,
                    preflight: Some(preflight),
                    extraction: None,
                    error: None,
                },
                Err(error) => ArchiveWorkerResponse {
                    ok: false,
                    sandboxed: false,
                    preflight: None,
                    extraction: None,
                    error: Some(error.to_string()),
                },
            }
        }
        ArchiveWorkerRequest::Extract {
            archive,
            staging,
            limits,
        } => match extract_archive_to_staging(&archive, &staging, &limits) {
            Ok(extraction) => ArchiveWorkerResponse {
                ok: true,
                sandboxed: false,
                preflight: None,
                extraction: Some(extraction),
                error: None,
            },
            Err(error) => ArchiveWorkerResponse {
                ok: false,
                sandboxed: false,
                preflight: None,
                extraction: None,
                error: Some(error.to_string()),
            },
        },
    }
}

fn extract_preflighted_zip(
    archive_path: &Path,
    staging_root: &Path,
    limits: &ArchiveLimits,
    preflight: &ArchivePreflightReport,
) -> Result<ArchiveExtractionReport, ArchiveError> {
    let file = File::open(archive_path).map_err(|source| ArchiveError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let current_hash = sha256_reader(&mut reader).map_err(|source| ArchiveError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    if preflight.archive_sha256.as_deref() != Some(current_hash.as_str()) {
        return Err(ArchiveError::ArchiveChanged(archive_path.to_path_buf()));
    }
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|source| ArchiveError::Io {
            path: archive_path.to_path_buf(),
            source,
        })?;
    let mut archive = zip::ZipArchive::new(reader).map_err(|source| ArchiveError::Zip {
        path: archive_path.to_path_buf(),
        source,
    })?;

    let mut expanded_bytes = 0_u64;
    let mut files = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|source| ArchiveError::Zip {
                path: archive_path.to_path_buf(),
                source,
            })?;
        let normalized = validate_entry_path(entry.name(), entry.is_dir(), limits.max_depth)
            .map_err(|error| ArchiveError::Verification(error.to_string()))?;
        let destination = staging_root.join(path_from_archive_name(&normalized.path));
        if entry.is_dir() {
            create_private_directory(&destination)?;
            continue;
        }
        if let Some(parent) = destination.parent() {
            create_private_directory(parent)?;
        }

        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&destination)
            .map_err(|source| ArchiveError::Io {
                path: destination.clone(),
                source,
            })?;
        set_private_file_permissions(&destination)?;

        let mut file_bytes = 0_u64;
        let mut file_hasher = Sha256::new();
        let mut signature = Vec::with_capacity(8);
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = entry.read(&mut buffer).map_err(|source| ArchiveError::Io {
                path: archive_path.to_path_buf(),
                source,
            })?;
            if read == 0 {
                break;
            }
            file_bytes = file_bytes.saturating_add(read as u64);
            expanded_bytes = expanded_bytes.saturating_add(read as u64);
            if file_bytes > limits.max_file_bytes {
                return Err(ArchiveError::ExtractionLimit {
                    path: normalized.path,
                    detail: format!("file exceeds {} bytes", limits.max_file_bytes),
                });
            }
            if expanded_bytes > limits.max_expanded_bytes {
                return Err(ArchiveError::ExtractionLimit {
                    path: normalized.path,
                    detail: format!(
                        "archive exceeds {} expanded bytes",
                        limits.max_expanded_bytes
                    ),
                });
            }
            if signature.len() < 8 {
                let remaining = 8 - signature.len();
                signature.extend_from_slice(&buffer[..read.min(remaining)]);
            }
            output
                .write_all(&buffer[..read])
                .map_err(|source| ArchiveError::Io {
                    path: destination.clone(),
                    source,
                })?;
            file_hasher.update(&buffer[..read]);
        }
        output.flush().map_err(|source| ArchiveError::Io {
            path: destination,
            source,
        })?;
        if file_bytes != entry.size() {
            return Err(ArchiveError::Verification(format!(
                "'{}' produced {file_bytes} bytes; metadata declared {}",
                normalized.path,
                entry.size()
            )));
        }
        files.push(ExtractedFileReport {
            executable_payload: is_executable_payload(&normalized.path),
            native_binary: has_native_binary_magic(&signature),
            path: normalized.path,
            bytes: file_bytes,
            sha256: format!("{:x}", file_hasher.finalize()),
        });
    }

    verify_staging(staging_root, &files, expanded_bytes, limits)?;
    let layout = infer_package_layout(&files);
    Ok(ArchiveExtractionReport {
        archive_sha256: current_hash,
        format: ArchiveFormat::Zip,
        staging_root: staging_root.to_path_buf(),
        expanded_bytes,
        files,
        layout,
    })
}

fn extract_preflighted_seven_zip(
    archive_path: &Path,
    staging_root: &Path,
    limits: &ArchiveLimits,
    preflight: &ArchivePreflightReport,
) -> Result<ArchiveExtractionReport, ArchiveError> {
    let file = File::open(archive_path).map_err(|source| ArchiveError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let current_hash = sha256_reader(&mut reader).map_err(|source| ArchiveError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    if preflight.archive_sha256.as_deref() != Some(current_hash.as_str()) {
        return Err(ArchiveError::ArchiveChanged(archive_path.to_path_buf()));
    }
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|source| ArchiveError::Io {
            path: archive_path.to_path_buf(),
            source,
        })?;

    let mut expanded_bytes = 0_u64;
    let mut files = Vec::new();
    let mut extraction_error = None;
    let decode_result = sevenz_rust2::decompress_with_extract_fn(
        reader,
        staging_root,
        |entry, input, _suggested_destination| match extract_seven_zip_entry(
            entry,
            input,
            staging_root,
            limits,
            &mut expanded_bytes,
            &mut files,
        ) {
            Ok(()) => Ok(true),
            Err(error) => {
                extraction_error = Some(error);
                Err(sevenz_rust2::Error::Other(
                    "RRMM rejected a 7z entry".into(),
                ))
            }
        },
    );
    if let Some(error) = extraction_error {
        return Err(error);
    }
    decode_result.map_err(|source| ArchiveError::SevenZip {
        path: archive_path.to_path_buf(),
        source,
    })?;

    verify_staging(staging_root, &files, expanded_bytes, limits)?;
    let layout = infer_package_layout(&files);
    Ok(ArchiveExtractionReport {
        archive_sha256: current_hash,
        format: ArchiveFormat::SevenZip,
        staging_root: staging_root.to_path_buf(),
        expanded_bytes,
        files,
        layout,
    })
}

fn extract_seven_zip_entry(
    entry: &sevenz_rust2::ArchiveEntry,
    input: &mut dyn Read,
    staging_root: &Path,
    limits: &ArchiveLimits,
    expanded_bytes: &mut u64,
    files: &mut Vec<ExtractedFileReport>,
) -> Result<(), ArchiveError> {
    let normalized = validate_entry_path(&entry.name, entry.is_directory, limits.max_depth)
        .map_err(|error| ArchiveError::Verification(error.to_string()))?;
    let destination = staging_root.join(path_from_archive_name(&normalized.path));
    if entry.is_directory {
        create_private_directory(&destination)?;
        return Ok(());
    }
    if let Some(parent) = destination.parent() {
        create_private_directory(parent)?;
    }
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&destination)
        .map_err(|source| ArchiveError::Io {
            path: destination.clone(),
            source,
        })?;
    set_private_file_permissions(&destination)?;

    let mut file_bytes = 0_u64;
    let mut file_hasher = Sha256::new();
    let mut signature = Vec::with_capacity(8);
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer).map_err(|source| ArchiveError::Io {
            path: destination.clone(),
            source,
        })?;
        if read == 0 {
            break;
        }
        file_bytes = file_bytes.saturating_add(read as u64);
        *expanded_bytes = expanded_bytes.saturating_add(read as u64);
        if file_bytes > limits.max_file_bytes {
            return Err(ArchiveError::ExtractionLimit {
                path: normalized.path,
                detail: format!("file exceeds {} bytes", limits.max_file_bytes),
            });
        }
        if *expanded_bytes > limits.max_expanded_bytes {
            return Err(ArchiveError::ExtractionLimit {
                path: normalized.path,
                detail: format!(
                    "archive exceeds {} expanded bytes",
                    limits.max_expanded_bytes
                ),
            });
        }
        if signature.len() < 8 {
            let remaining = 8 - signature.len();
            signature.extend_from_slice(&buffer[..read.min(remaining)]);
        }
        output
            .write_all(&buffer[..read])
            .map_err(|source| ArchiveError::Io {
                path: destination.clone(),
                source,
            })?;
        file_hasher.update(&buffer[..read]);
    }
    output.flush().map_err(|source| ArchiveError::Io {
        path: destination,
        source,
    })?;
    if file_bytes != entry.size {
        return Err(ArchiveError::Verification(format!(
            "'{}' produced {file_bytes} bytes; metadata declared {}",
            normalized.path, entry.size
        )));
    }
    files.push(ExtractedFileReport {
        executable_payload: is_executable_payload(&normalized.path),
        native_binary: has_native_binary_magic(&signature),
        path: normalized.path,
        bytes: file_bytes,
        sha256: format!("{:x}", file_hasher.finalize()),
    });
    Ok(())
}

fn prepare_staging(staging_root: &Path) -> Result<(), ArchiveError> {
    match fs::symlink_metadata(staging_root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(ArchiveError::InvalidStaging {
                    path: staging_root.to_path_buf(),
                    detail: "path must be a real directory".to_owned(),
                });
            }
            let mut entries = fs::read_dir(staging_root).map_err(|source| ArchiveError::Io {
                path: staging_root.to_path_buf(),
                source,
            })?;
            if entries.next().is_some() {
                return Err(ArchiveError::InvalidStaging {
                    path: staging_root.to_path_buf(),
                    detail: "directory must be empty".to_owned(),
                });
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(staging_root).map_err(|source| ArchiveError::Io {
                path: staging_root.to_path_buf(),
                source,
            })?;
        }
        Err(source) => {
            return Err(ArchiveError::Io {
                path: staging_root.to_path_buf(),
                source,
            });
        }
    }
    set_private_directory_permissions(staging_root)
}

fn create_private_directory(path: &Path) -> Result<(), ArchiveError> {
    fs::create_dir_all(path).map_err(|source| ArchiveError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    set_private_directory_permissions(path)
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), ArchiveError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
        ArchiveError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), ArchiveError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<(), ArchiveError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        ArchiveError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<(), ArchiveError> {
    Ok(())
}

fn verify_staging(
    staging_root: &Path,
    files: &[ExtractedFileReport],
    expanded_bytes: u64,
    limits: &ArchiveLimits,
) -> Result<(), ArchiveError> {
    let expected: BTreeMap<_, _> = files
        .iter()
        .map(|file| (file.path.as_str(), (file.bytes, file.sha256.as_str())))
        .collect();
    let mut actual_files = 0_usize;
    let mut actual_bytes = 0_u64;
    for item in walkdir::WalkDir::new(staging_root)
        .follow_links(false)
        .min_depth(1)
    {
        let item = item.map_err(|error| ArchiveError::Verification(error.to_string()))?;
        let file_type = item.file_type();
        if file_type.is_symlink() || (!file_type.is_dir() && !file_type.is_file()) {
            return Err(ArchiveError::Verification(format!(
                "staging contains unsupported filesystem object: {}",
                item.path().display()
            )));
        }
        if file_type.is_dir() {
            continue;
        }
        let relative = item
            .path()
            .strip_prefix(staging_root)
            .map_err(|_| ArchiveError::Verification("staging entry escaped its root".to_owned()))?;
        let normalized = filesystem_relative_name(relative)?;
        let bytes = item
            .metadata()
            .map_err(|error| ArchiveError::Verification(error.to_string()))?
            .len();
        let Some((expected_bytes, expected_sha256)) = expected.get(normalized.as_str()) else {
            return Err(ArchiveError::Verification(format!(
                "unexpected staging file '{normalized}'"
            )));
        };
        if bytes != *expected_bytes {
            return Err(ArchiveError::Verification(format!(
                "staging file '{normalized}' has {bytes} bytes; expected {expected_bytes}"
            )));
        }
        let actual_sha256 = sha256_file(item.path()).map_err(|error| ArchiveError::Io {
            path: item.path().to_path_buf(),
            source: error,
        })?;
        if actual_sha256 != *expected_sha256 {
            return Err(ArchiveError::Verification(format!(
                "staging file '{normalized}' hash differs from its extraction report"
            )));
        }
        actual_files += 1;
        actual_bytes = actual_bytes.saturating_add(bytes);
    }
    if actual_files != files.len() || actual_bytes != expanded_bytes {
        return Err(ArchiveError::Verification(format!(
            "staging totals differ: {actual_files} files/{actual_bytes} bytes, expected {} files/{expanded_bytes} bytes",
            files.len()
        )));
    }
    if actual_files > limits.max_entries || actual_bytes > limits.max_expanded_bytes {
        return Err(ArchiveError::Verification(
            "staging exceeds configured limits".to_owned(),
        ));
    }
    Ok(())
}

fn filesystem_relative_name(path: &Path) -> Result<String, ArchiveError> {
    let mut components = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(value) = component else {
            return Err(ArchiveError::Verification(format!(
                "invalid staging path '{}'",
                path.display()
            )));
        };
        let value = value.to_str().ok_or_else(|| {
            ArchiveError::Verification("staging path is not valid Unicode".to_owned())
        })?;
        components.push(value);
    }
    Ok(components.join("/"))
}

fn path_from_archive_name(name: &str) -> PathBuf {
    name.split('/').collect()
}

fn has_native_binary_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MZ")
        || bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
}

fn initial_report(
    archive_path: &Path,
    format: ArchiveFormat,
    limits: &ArchiveLimits,
) -> Result<ArchivePreflightReport, ArchiveError> {
    let metadata = fs::metadata(archive_path).map_err(|source| ArchiveError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let archive_bytes = metadata.len();
    let mut report = ArchivePreflightReport {
        accepted: false,
        format,
        archive_path: archive_path.to_path_buf(),
        archive_sha256: None,
        archive_bytes,
        expanded_bytes: 0,
        entry_count: 0,
        entries: Vec::new(),
        rejections: Vec::new(),
    };
    if archive_bytes > limits.max_archive_bytes {
        reject(
            &mut report,
            "archive_too_large",
            None,
            format!(
                "archive has {archive_bytes} bytes; limit is {}",
                limits.max_archive_bytes
            ),
        );
        return Ok(report);
    }
    report.archive_sha256 = Some(
        sha256_file(archive_path).map_err(|source| ArchiveError::Io {
            path: archive_path.to_path_buf(),
            source,
        })?,
    );
    Ok(report)
}

fn finish_size_checks(report: &mut ArchivePreflightReport, limits: &ArchiveLimits) {
    if report.expanded_bytes > limits.max_expanded_bytes {
        let detail = format!(
            "archive expands to {} bytes; limit is {}",
            report.expanded_bytes, limits.max_expanded_bytes
        );
        reject(report, "expanded_size_exceeded", None, detail);
    }
}

fn record_archive_path(
    report: &mut ArchivePreflightReport,
    collision_keys: &mut BTreeMap<String, (String, bool)>,
    normalized: &NormalizedArchivePath,
    is_directory: bool,
) {
    if let Some((previous, _)) = collision_keys.get(&normalized.collision_key) {
        reject(
            report,
            "path_collision",
            Some(normalized.path.clone()),
            format!("collides with '{previous}' after case folding and Unicode normalization"),
        );
        return;
    }

    let mut parent = normalized.collision_key.as_str();
    while let Some((next_parent, _)) = parent.rsplit_once('/') {
        if let Some((previous, false)) = collision_keys.get(next_parent) {
            reject(
                report,
                "path_type_conflict",
                Some(normalized.path.clone()),
                format!("parent '{previous}' is a file"),
            );
            break;
        }
        parent = next_parent;
    }
    if !is_directory {
        let prefix = format!("{}/", normalized.collision_key);
        if let Some((key, (descendant, _))) = collision_keys.range(prefix.clone()..).next()
            && key.starts_with(&prefix)
        {
            reject(
                report,
                "path_type_conflict",
                Some(normalized.path.clone()),
                format!("file path is already a directory ancestor of '{descendant}'"),
            );
        }
    }
    collision_keys.insert(
        normalized.collision_key.clone(),
        (normalized.path.clone(), is_directory),
    );
}

fn is_link_like_7z(attributes: u32) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const UNIX_FILE_TYPE_MASK: u32 = 0o170000;
    const UNIX_SYMLINK: u32 = 0o120000;
    attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (attributes >> 16) & UNIX_FILE_TYPE_MASK == UNIX_SYMLINK
}

fn is_seven_zip_encryption_error(error: &sevenz_rust2::Error) -> bool {
    match error {
        sevenz_rust2::Error::PasswordRequired | sevenz_rust2::Error::MaybeBadPassword(_) => true,
        sevenz_rust2::Error::UnsupportedCompressionMethod(method) => {
            method.to_ascii_lowercase().contains("aes")
        }
        _ => false,
    }
}

fn is_supported_seven_zip_method(method: &[u8]) -> bool {
    use sevenz_rust2::EncoderMethod;

    [
        EncoderMethod::ID_COPY,
        EncoderMethod::ID_LZMA,
        EncoderMethod::ID_LZMA2,
        EncoderMethod::ID_PPMD,
        EncoderMethod::ID_BZIP2,
        EncoderMethod::ID_DEFLATE,
        EncoderMethod::ID_BCJ_X86,
        EncoderMethod::ID_BCJ2,
        EncoderMethod::ID_BCJ_PPC,
        EncoderMethod::ID_BCJ_IA64,
        EncoderMethod::ID_BCJ_ARM,
        EncoderMethod::ID_BCJ_ARM64,
        EncoderMethod::ID_BCJ_ARM_THUMB,
        EncoderMethod::ID_BCJ_SPARC,
        EncoderMethod::ID_BCJ_RISCV,
        EncoderMethod::ID_DELTA,
    ]
    .contains(&method)
}

fn seven_zip_method_label(method: &[u8]) -> String {
    let id = method
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    match sevenz_rust2::EncoderMethod::by_id(method) {
        Some(method) => format!("{} (0x{id})", method.name()),
        None => format!("0x{id}"),
    }
}

fn is_multipart_name(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.ends_with(".7z.001")
        || name.ends_with(".zip.001")
        || name.rsplit_once('.').is_some_and(|(_, extension)| {
            extension.len() == 3
                && extension.starts_with('z')
                && extension[1..].chars().all(|value| value.is_ascii_digit())
        })
}

fn reject(report: &mut ArchivePreflightReport, code: &str, path: Option<String>, detail: String) {
    report.rejections.push(ArchiveRejection {
        code: code.to_owned(),
        path,
        detail,
    });
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut reader = BufReader::new(File::open(path)?);
    sha256_reader(&mut reader)
}

fn sha256_reader(reader: &mut impl Read) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_component(component: &str) -> Result<(), PathPolicyError> {
    if component.is_empty() {
        return Err(PathPolicyError::EmptyComponent(component.to_owned()));
    }
    if matches!(component, "." | "..") {
        return Err(PathPolicyError::Traversal(component.to_owned()));
    }
    if component.len() > MAX_ARCHIVE_COMPONENT_BYTES {
        return Err(PathPolicyError::ComponentTooLong {
            actual: component.len(),
            max: MAX_ARCHIVE_COMPONENT_BYTES,
        });
    }
    if component.ends_with([' ', '.'])
        || component.chars().any(|character| {
            character < ' ' || matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*')
        })
    {
        return Err(PathPolicyError::InvalidWindowsComponent(
            component.to_owned(),
        ));
    }

    let device_stem = component
        .split_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(component)
        .to_ascii_uppercase();
    if matches!(
        device_stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$"
    ) || is_numbered_device(&device_stem, "COM")
        || is_numbered_device(&device_stem, "LPT")
    {
        return Err(PathPolicyError::ReservedWindowsName(component.to_owned()));
    }
    Ok(())
}

fn is_numbered_device(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|suffix| matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;

    #[test]
    fn default_policy_has_no_fixed_resource_ceilings() {
        let limits = ArchiveLimits::default();
        assert_eq!(limits.max_archive_bytes, u64::MAX);
        assert_eq!(limits.max_expanded_bytes, u64::MAX);
        assert_eq!(limits.max_file_bytes, u64::MAX);
        assert_eq!(limits.max_entries, usize::MAX);
        assert_eq!(limits.max_compression_ratio, u64::MAX);
    }

    #[test]
    fn accepts_and_normalizes_a_mod_path() {
        let path =
            validate_entry_path("RetroRewind\\Content\\Paks\\Example_P.pak", false, 32).unwrap();
        assert_eq!(path.path, "RetroRewind/Content/Paks/Example_P.pak");
        assert_eq!(path.depth, 4);
    }

    #[test]
    fn rejects_cross_platform_escape_and_ads_paths() {
        for path in [
            "../outside",
            "/absolute",
            "C:\\absolute",
            "folder/../../outside",
            "file.txt:stream",
        ] {
            assert!(validate_entry_path(path, false, 32).is_err(), "{path}");
        }
    }

    #[test]
    fn rejects_windows_device_names_and_collapsing_suffixes() {
        for path in ["CON", "aux.txt", "mods/LPT9.ini", "folder./file"] {
            assert!(validate_entry_path(path, false, 32).is_err(), "{path}");
        }
    }

    #[test]
    fn creates_equal_keys_for_case_and_unicode_normalization_collisions() {
        let composed = validate_entry_path("Mods/Café.PAK", false, 32).unwrap();
        let decomposed = validate_entry_path("mods/Cafe\u{301}.pak", false, 32).unwrap();
        assert_eq!(composed.collision_key, decomposed.collision_key);
    }

    #[test]
    fn enforces_depth_and_file_suffix_rules() {
        assert!(matches!(
            validate_entry_path("a/b/c", false, 2),
            Err(PathPolicyError::TooDeep { .. })
        ));
        assert!(matches!(
            validate_entry_path("file/", false, 2),
            Err(PathPolicyError::FileWithDirectorySuffix(_))
        ));
        assert!(validate_entry_path("folder/", true, 2).is_ok());
    }

    #[test]
    fn identifies_native_and_script_payloads() {
        assert!(is_executable_payload("UE4SS/mods/example/main.DLL"));
        assert!(is_executable_payload("setup.exe"));
        assert!(!is_executable_payload("Example_P.pak"));
    }

    #[test]
    fn infers_hybrid_and_unknown_package_layouts_conservatively() {
        let hybrid = infer_package_layout(&[
            extracted("Example_P.pak", false, false),
            extracted("Example/Scripts/main.lua", false, false),
            extracted("README.md", false, false),
        ]);
        assert_eq!(hybrid.kind, PackageKind::Hybrid);
        assert_eq!(hybrid.ue4ss_mod_roots, ["Example"]);
        assert!(!hybrid.requires_review);

        let unknown = infer_package_layout(&[extracted("tools/helper", false, true)]);
        assert_eq!(unknown.kind, PackageKind::Unknown);
        assert!(unknown.requires_review);
        assert_eq!(unknown.executable_files, ["tools/helper"]);
    }

    #[test]
    fn accepts_a_small_zip_and_reports_executables() {
        let temporary = TempDir::new().unwrap();
        let archive_path = temporary.path().join("mod.zip");
        write_zip(
            &archive_path,
            &[
                ("RetroRewind/Content/Paks/Example_P.pak", b"pak"),
                ("ue4ss/mods/example.dll", b"dll"),
            ],
        );

        let report = preflight_zip(&archive_path, &ArchiveLimits::default()).unwrap();
        assert!(report.accepted);
        assert_eq!(report.entry_count, 2);
        assert!(report.archive_sha256.is_some());
        assert_eq!(
            report
                .entries
                .iter()
                .filter(|entry| entry.executable_payload)
                .count(),
            1
        );
    }

    #[test]
    fn rejects_zip_slip_and_normalized_collisions() {
        let temporary = TempDir::new().unwrap();
        let archive_path = temporary.path().join("hostile.zip");
        write_zip(
            &archive_path,
            &[
                ("../outside", b"escape"),
                ("Mods/Café.pak", b"one"),
                ("mods/Cafe\u{301}.PAK", b"two"),
            ],
        );

        let report = preflight_zip(&archive_path, &ArchiveLimits::default()).unwrap();
        assert!(!report.accepted);
        assert!(
            report
                .rejections
                .iter()
                .any(|item| item.code == "unsafe_path")
        );
        assert!(
            report
                .rejections
                .iter()
                .any(|item| item.code == "path_collision")
        );
    }

    #[test]
    fn rejects_declared_size_limits_before_extraction() {
        let temporary = TempDir::new().unwrap();
        let archive_path = temporary.path().join("large.zip");
        write_zip(&archive_path, &[("large.pak", b"12345")]);
        let limits = ArchiveLimits {
            max_file_bytes: 4,
            max_expanded_bytes: 4,
            ..ArchiveLimits::default()
        };

        let report = preflight_zip(&archive_path, &limits).unwrap();
        assert!(!report.accepted);
        assert!(
            report
                .rejections
                .iter()
                .any(|item| item.code == "file_too_large")
        );
        assert!(
            report
                .rejections
                .iter()
                .any(|item| item.code == "expanded_size_exceeded")
        );
    }

    #[test]
    fn rejects_file_directory_prefix_conflicts() {
        let temporary = TempDir::new().unwrap();
        let archive_path = temporary.path().join("conflict.zip");
        write_zip(
            &archive_path,
            &[("mods", b"file"), ("mods/main.lua", b"lua")],
        );

        let report = preflight_zip(&archive_path, &ArchiveLimits::default()).unwrap();
        assert!(!report.accepted);
        assert!(
            report
                .rejections
                .iter()
                .any(|item| item.code == "path_type_conflict")
        );
    }

    #[test]
    fn extracts_to_empty_staging_and_detects_extensionless_native_files() {
        let temporary = TempDir::new().unwrap();
        let archive_path = temporary.path().join("mod.zip");
        let staging = temporary.path().join("staging");
        write_zip(
            &archive_path,
            &[
                ("Example_P.pak", b"pak"),
                ("tools/native-helper", b"\x7fELFfixture"),
            ],
        );

        let report =
            extract_zip_to_staging(&archive_path, &staging, &ArchiveLimits::default()).unwrap();
        assert_eq!(report.files.len(), 2);
        assert!(
            report
                .files
                .iter()
                .any(|file| file.path == "tools/native-helper" && file.native_binary)
        );
        assert_eq!(fs::read(staging.join("Example_P.pak")).unwrap(), b"pak");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(staging.join("tools/native-helper"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o111, 0);
        }
    }

    #[test]
    fn refuses_nonempty_staging_without_modifying_it() {
        let temporary = TempDir::new().unwrap();
        let archive_path = temporary.path().join("mod.zip");
        let staging = temporary.path().join("staging");
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("keep.txt"), b"keep").unwrap();
        write_zip(&archive_path, &[("Example_P.pak", b"pak")]);

        let error =
            extract_zip_to_staging(&archive_path, &staging, &ArchiveLimits::default()).unwrap_err();
        assert!(matches!(error, ArchiveError::InvalidStaging { .. }));
        assert_eq!(fs::read(staging.join("keep.txt")).unwrap(), b"keep");
    }

    #[test]
    fn rejected_archive_never_creates_staging_or_writes_outside() {
        let temporary = TempDir::new().unwrap();
        let archive_path = temporary.path().join("hostile.zip");
        let staging = temporary.path().join("staging");
        let outside = temporary.path().join("outside.txt");
        write_zip(&archive_path, &[("../outside.txt", b"escape")]);

        let error =
            extract_zip_to_staging(&archive_path, &staging, &ArchiveLimits::default()).unwrap_err();
        assert!(matches!(error, ArchiveError::PreflightRejected { .. }));
        assert!(!staging.exists());
        assert!(!outside.exists());
    }

    #[test]
    fn rejects_multipart_7z_before_parsing() {
        let temporary = TempDir::new().unwrap();
        let archive_path = temporary.path().join("mod.7z.001");
        fs::write(&archive_path, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]).unwrap();

        let report = preflight_seven_zip(&archive_path, &ArchiveLimits::default()).unwrap();
        assert!(!report.accepted);
        assert!(
            report
                .rejections
                .iter()
                .any(|item| item.code == "multipart_archive")
        );
    }

    #[test]
    fn preflights_and_extracts_a_seven_zip_archive() {
        let temporary = TempDir::new().unwrap();
        let source = temporary.path().join("Example_P.pak");
        let archive = temporary.path().join("mod.7z");
        let staging = temporary.path().join("staging-7z");
        fs::write(&source, b"pak fixture").unwrap();
        sevenz_rust2::compress_to_path(&source, &archive).unwrap();

        let preflight = preflight_archive(&archive, &ArchiveLimits::default()).unwrap();
        assert!(preflight.accepted);
        assert_eq!(preflight.format, ArchiveFormat::SevenZip);

        let extraction =
            extract_archive_to_staging(&archive, &staging, &ArchiveLimits::default()).unwrap();
        assert_eq!(extraction.format, ArchiveFormat::SevenZip);
        assert_eq!(extraction.files.len(), 1);
        assert_eq!(
            fs::read(staging.join("Example_P.pak")).unwrap(),
            b"pak fixture"
        );
    }

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        for (name, contents) in entries {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(contents).unwrap();
        }
        writer.finish().unwrap();
    }

    fn extracted(path: &str, executable_payload: bool, native_binary: bool) -> ExtractedFileReport {
        ExtractedFileReport {
            path: path.to_owned(),
            bytes: 1,
            sha256: "0".repeat(64),
            executable_payload,
            native_binary,
        }
    }
}
