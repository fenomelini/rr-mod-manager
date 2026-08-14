use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;

const COOKED_EXTENSIONS: &[(&str, CookedSidecar)] = &[
    ("uasset", CookedSidecar::Asset),
    ("umap", CookedSidecar::Map),
    ("uexp", CookedSidecar::Export),
    ("ubulk", CookedSidecar::Bulk),
    ("uptnl", CookedSidecar::Optional),
];
const MAX_PAK_STRING_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakLimits {
    pub max_archive_bytes: u64,
    pub max_index_bytes: u64,
    pub max_entries: usize,
    pub max_member_bytes: u64,
}

impl Default for PakLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: u64::MAX,
            max_index_bytes: u64::MAX,
            max_entries: usize::MAX,
            max_member_bytes: u64::MAX,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakInventory {
    pub archive_path: PathBuf,
    pub archive_name: String,
    pub archive_bytes: u64,
    pub version: String,
    pub mount_point: String,
    pub encrypted_index: bool,
    pub compression: Vec<String>,
    pub path_hash_seed: Option<u64>,
    pub priority: PakPriorityHint,
    pub integrity: PakIntegrityReport,
    pub members: Vec<PakMember>,
    pub packages: Vec<CookedPackage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakIntegrityReport {
    pub structural_parse_succeeded: bool,
    pub index_hashes_verified: bool,
    pub index_metadata_sha256: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakMember {
    pub stored_path: String,
    pub virtual_path: String,
    pub collision_key: String,
    pub package_key: Option<String>,
    pub sidecar: Option<CookedSidecar>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CookedPackage {
    pub package_key: String,
    pub members: Vec<String>,
    pub sidecars: Vec<CookedSidecar>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CookedSidecar {
    Asset,
    Map,
    Export,
    Bulk,
    Optional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakPriorityHint {
    pub patch_generation: u64,
    pub patch_increment: u64,
    pub explicit_number: Option<u64>,
    pub confidence: PakPriorityConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakLoadOrderNode {
    pub pak_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakLoadOrderConstraint {
    pub loser_pak_sha256: String,
    pub winner_pak_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakLoadOrderResolution {
    pub order: Vec<String>,
    pub slots: BTreeMap<String, u64>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PakLoadOrderError {
    #[error("invalid lowercase PAK SHA-256: {0}")]
    InvalidSha256(String),
    #[error("duplicate PAK load-order node: {0}")]
    DuplicateNode(String),
    #[error("PAK load-order constraint references an absent node: {0}")]
    MissingNode(String),
    #[error("PAK load-order constraint contains a self-edge: {0}")]
    SelfEdge(String),
    #[error("PAK load-order constraints contain a cycle involving {0:?}")]
    Cycle(Vec<String>),
    #[error("PAK load-order slot must be greater than zero")]
    InvalidSlot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakOrderDecision {
    pub winner: Option<PathBuf>,
    pub confidence: PakOrderConfidence,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PakOrderConfidence {
    ObservedPatchGeneration,
    UnverifiedLexicalTie,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakDiscoveryReport {
    pub root: PathBuf,
    pub pak_count: usize,
    pub disabled_looking_count: usize,
    pub paks: Vec<DiscoveredPak>,
    pub skipped_links: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredPak {
    pub path: PathBuf,
    pub relative_path: PathBuf,
    pub priority: PakPriorityHint,
    pub disabled_looking_ancestor: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PakPriorityConfidence {
    NoPatchSuffix,
    ObservedBuildRule,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedVirtualPath {
    pub virtual_path: String,
    pub collision_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberDigest {
    pub stored_path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberHashRequest {
    pub archive_path: PathBuf,
    pub stored_path: String,
    pub virtual_path: String,
    pub collision_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberHashEvidence {
    pub archive_path: PathBuf,
    pub collision_key: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakConflictGraph {
    pub archive_count: usize,
    pub edges: Vec<PakConflictEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakConflictEdge {
    pub first_archive: PathBuf,
    pub second_archive: PathBuf,
    pub outcome: PakConflictOutcome,
    pub winner: Option<PathBuf>,
    pub order_confidence: PakOrderConfidence,
    pub winner_reason: String,
    pub domains: Vec<PakConflictDomain>,
    pub members: Vec<MemberConflict>,
    pub packages: Vec<PackageConflict>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PakConflictOutcome {
    BenignDuplicate,
    OrderedWithLoss,
    UnknownOrder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PakConflictDomain {
    CookedPackage,
    Localization,
    LooseFile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberConflict {
    pub virtual_path: String,
    pub first_stored_path: String,
    pub second_stored_path: String,
    pub identical: Option<bool>,
    pub localization: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageConflict {
    pub package_key: String,
    pub first_members: Vec<String>,
    pub second_members: Vec<String>,
    pub split_package: bool,
    pub localization: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum PakWorkerRequest {
    Fingerprint {
        pak: PathBuf,
        limits: PakLimits,
    },
    Inspect {
        pak: PathBuf,
        limits: PakLimits,
        hash_members: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakWorkerResponse {
    pub ok: bool,
    pub sandboxed: bool,
    pub inventory: Option<PakInventory>,
    pub member_digests: Vec<MemberDigest>,
    pub index_metadata_sha256: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Error)]
pub enum PakError {
    #[error("failed to access PAK {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("failed to parse PAK {path}: {source}")]
    Parse {
        path: PathBuf,
        source: repak_trumank::Error,
    },
    #[error("PAK exceeds the configured archive limit: {actual} > {limit}")]
    ArchiveTooLarge { actual: u64, limit: u64 },
    #[error("PAK has too many entries: {actual} > {limit}")]
    TooManyEntries { actual: usize, limit: usize },
    #[error("PAK discovery root is not a directory: {0}")]
    InvalidDiscoveryRoot(PathBuf),
    #[error("invalid PAK container: {0}")]
    InvalidContainer(String),
    #[error("invalid PAK worker inventory: {0}")]
    InvalidInventory(String),
    #[error("invalid PAK virtual path: {0}")]
    Path(#[from] PakPathError),
    #[error("case-insensitive PAK virtual-path collision: {first} and {second}")]
    VirtualPathCollision { first: String, second: String },
    #[error("PAK member exceeds the configured output limit: {actual} > {limit}")]
    MemberTooLarge { actual: u64, limit: u64 },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PakPathError {
    #[error("mount point must begin with exactly '../../../': {0}")]
    InvalidMount(String),
    #[error("path is empty, absolute, drive-qualified, or contains traversal: {0}")]
    UnsafePath(String),
}

pub fn resolve_pak_load_order(
    nodes: &[PakLoadOrderNode],
    constraints: &[PakLoadOrderConstraint],
) -> Result<PakLoadOrderResolution, PakLoadOrderError> {
    let mut outgoing = BTreeMap::<String, BTreeSet<String>>::new();
    let mut indegree = BTreeMap::<String, usize>::new();
    for node in nodes {
        validate_lowercase_pak_sha256(&node.pak_sha256)?;
        if outgoing
            .insert(node.pak_sha256.clone(), BTreeSet::new())
            .is_some()
        {
            return Err(PakLoadOrderError::DuplicateNode(node.pak_sha256.clone()));
        }
        indegree.insert(node.pak_sha256.clone(), 0);
    }

    for constraint in constraints {
        validate_lowercase_pak_sha256(&constraint.loser_pak_sha256)?;
        validate_lowercase_pak_sha256(&constraint.winner_pak_sha256)?;
        if !outgoing.contains_key(&constraint.loser_pak_sha256) {
            return Err(PakLoadOrderError::MissingNode(
                constraint.loser_pak_sha256.clone(),
            ));
        }
        if !outgoing.contains_key(&constraint.winner_pak_sha256) {
            return Err(PakLoadOrderError::MissingNode(
                constraint.winner_pak_sha256.clone(),
            ));
        }
        if constraint.loser_pak_sha256 == constraint.winner_pak_sha256 {
            return Err(PakLoadOrderError::SelfEdge(
                constraint.loser_pak_sha256.clone(),
            ));
        }
        if outgoing
            .get_mut(&constraint.loser_pak_sha256)
            .expect("constraint loser was checked")
            .insert(constraint.winner_pak_sha256.clone())
        {
            *indegree
                .get_mut(&constraint.winner_pak_sha256)
                .expect("constraint winner was checked") += 1;
        }
    }

    let mut ready: BTreeSet<_> = indegree
        .iter()
        .filter_map(|(pak_sha256, degree)| (*degree == 0).then_some(pak_sha256.clone()))
        .collect();
    let mut order = Vec::with_capacity(nodes.len());
    while let Some(pak_sha256) = ready.pop_first() {
        for winner in &outgoing[&pak_sha256] {
            let degree = indegree
                .get_mut(winner)
                .expect("outgoing edge targets a known node");
            *degree -= 1;
            if *degree == 0 {
                ready.insert(winner.clone());
            }
        }
        order.push(pak_sha256);
    }

    if order.len() != nodes.len() {
        let cycle = indegree
            .into_iter()
            .filter_map(|(pak_sha256, degree)| (degree > 0).then_some(pak_sha256))
            .collect();
        return Err(PakLoadOrderError::Cycle(cycle));
    }
    let slots = order
        .iter()
        .enumerate()
        .map(|(index, pak_sha256)| (pak_sha256.clone(), index as u64 + 1))
        .collect();
    Ok(PakLoadOrderResolution { order, slots })
}

pub fn rrmm_ordered_pak_name(sha256: &str, slot: u64) -> Result<String, PakLoadOrderError> {
    validate_lowercase_pak_sha256(sha256)?;
    if slot == 0 {
        return Err(PakLoadOrderError::InvalidSlot);
    }
    Ok(format!("RRMM_{}_{slot}_P.pak", &sha256[..16]))
}

fn validate_lowercase_pak_sha256(sha256: &str) -> Result<(), PakLoadOrderError> {
    if sha256.len() == 64
        && sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(PakLoadOrderError::InvalidSha256(sha256.to_owned()))
    }
}

pub fn inspect_pak(path: &Path, limits: &PakLimits) -> Result<PakInventory, PakError> {
    let archive_bytes = fs::metadata(path)
        .map_err(|source| PakError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    if archive_bytes > limits.max_archive_bytes {
        return Err(PakError::ArchiveTooLarge {
            actual: archive_bytes,
            limit: limits.max_archive_bytes,
        });
    }
    let index_metadata_sha256 = validate_pak_container(path, archive_bytes, limits)?
        .ok_or_else(|| invalid_container("no recognized PAK footer was found"))?;

    let mut file = File::open(path).map_err(|source| PakError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let reader = repak_trumank::PakBuilder::new()
        .reader(&mut file)
        .map_err(|source| PakError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
    let stored_paths = reader.files();
    if stored_paths.len() > limits.max_entries {
        return Err(PakError::TooManyEntries {
            actual: stored_paths.len(),
            limit: limits.max_entries,
        });
    }

    let mount_point = reader.mount_point().to_owned();
    let mut collision_paths = BTreeMap::<String, String>::new();
    let mut members = Vec::with_capacity(stored_paths.len());
    for stored_path in stored_paths {
        let normalized = normalize_virtual_path(&mount_point, &stored_path)?;
        if let Some(first) = collision_paths.insert(
            normalized.collision_key.clone(),
            normalized.virtual_path.clone(),
        ) {
            return Err(PakError::VirtualPathCollision {
                first,
                second: normalized.virtual_path,
            });
        }
        let cooked = cooked_package_member(&normalized.virtual_path);
        members.push(PakMember {
            stored_path,
            virtual_path: normalized.virtual_path,
            collision_key: normalized.collision_key,
            package_key: cooked.as_ref().map(|(key, _)| key.clone()),
            sidecar: cooked.map(|(_, sidecar)| sidecar),
        });
    }
    members.sort_by(|left, right| left.collision_key.cmp(&right.collision_key));

    let archive_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(PakInventory {
        archive_path: path.to_path_buf(),
        archive_name: archive_name.clone(),
        archive_bytes,
        version: reader.version().to_string(),
        mount_point,
        encrypted_index: reader.encrypted_index(),
        compression: reader
            .used_compression()
            .into_iter()
            .map(|method| method.to_string().to_ascii_lowercase())
            .collect(),
        path_hash_seed: reader.path_hash_seed(),
        priority: parse_priority_hint(&archive_name),
        integrity: PakIntegrityReport {
            structural_parse_succeeded: true,
            index_hashes_verified: false,
            index_metadata_sha256,
            detail: "repak 0.2.3 parses structure but does not verify all index hashes".to_owned(),
        },
        packages: group_cooked_packages(&members),
        members,
    })
}

pub fn validate_inventory_contract(
    inventory: &PakInventory,
    expected_path: &Path,
    expected_bytes: u64,
    limits: &PakLimits,
) -> Result<(), PakError> {
    if inventory.archive_path != expected_path {
        return Err(PakError::InvalidInventory(format!(
            "archive path {} does not match requested {}",
            inventory.archive_path.display(),
            expected_path.display()
        )));
    }
    if inventory.archive_bytes != expected_bytes {
        return Err(PakError::InvalidInventory(format!(
            "archive size {} does not match observed {expected_bytes}",
            inventory.archive_bytes
        )));
    }
    if inventory.archive_bytes > limits.max_archive_bytes {
        return Err(PakError::InvalidInventory(format!(
            "archive size {} exceeds limit {}",
            inventory.archive_bytes, limits.max_archive_bytes
        )));
    }
    let expected_name = expected_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    if inventory.archive_name != expected_name {
        return Err(PakError::InvalidInventory(format!(
            "archive name {:?} does not match requested filename {:?}",
            inventory.archive_name, expected_name
        )));
    }
    if inventory.priority != parse_priority_hint(&inventory.archive_name) {
        return Err(PakError::InvalidInventory(
            "priority hint does not match the archive filename".to_owned(),
        ));
    }
    if !inventory.integrity.structural_parse_succeeded {
        return Err(PakError::InvalidInventory(
            "worker did not report a successful structural parse".to_owned(),
        ));
    }
    if inventory.integrity.index_hashes_verified {
        return Err(PakError::InvalidInventory(
            "worker claimed index-hash verification that the pinned parser does not perform"
                .to_owned(),
        ));
    }
    if inventory.integrity.index_metadata_sha256.len() != 64
        || !inventory
            .integrity
            .index_metadata_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(PakError::InvalidInventory(
            "index metadata digest is not a 64-character hexadecimal SHA-256".to_owned(),
        ));
    }
    if inventory.members.len() > limits.max_entries {
        return Err(PakError::InvalidInventory(format!(
            "member count {} exceeds limit {}",
            inventory.members.len(),
            limits.max_entries
        )));
    }
    normalize_virtual_path(&inventory.mount_point, "__rrmm_mount_probe__")
        .map_err(|error| PakError::InvalidInventory(format!("invalid mount point: {error}")))?;
    let mut previous_key: Option<&str> = None;
    for member in &inventory.members {
        let normalized = normalize_virtual_path(&inventory.mount_point, &member.stored_path)
            .map_err(|error| {
                PakError::InvalidInventory(format!(
                    "member {:?} cannot be normalized: {error}",
                    member.stored_path
                ))
            })?;
        if normalized.virtual_path != member.virtual_path
            || normalized.collision_key != member.collision_key
        {
            return Err(PakError::InvalidInventory(format!(
                "member {:?} has inconsistent normalized paths",
                member.stored_path
            )));
        }
        let cooked = cooked_package_member(&member.virtual_path);
        if member.package_key != cooked.as_ref().map(|(key, _)| key.clone())
            || member.sidecar != cooked.map(|(_, sidecar)| sidecar)
        {
            return Err(PakError::InvalidInventory(format!(
                "member {:?} has inconsistent cooked-package metadata",
                member.stored_path
            )));
        }
        if previous_key.is_some_and(|previous| previous >= member.collision_key.as_str()) {
            return Err(PakError::InvalidInventory(
                "members are not strictly sorted by unique collision key".to_owned(),
            ));
        }
        previous_key = Some(&member.collision_key);
    }
    let expected_packages = group_cooked_packages(&inventory.members);
    if inventory.packages != expected_packages {
        return Err(PakError::InvalidInventory(
            "cooked package groups do not match member metadata".to_owned(),
        ));
    }
    Ok(())
}

pub fn execute_worker_request(request: PakWorkerRequest) -> PakWorkerResponse {
    match request {
        PakWorkerRequest::Fingerprint { pak, limits } => {
            match pak_index_metadata_sha256(&pak, &limits) {
                Ok(index_metadata_sha256) => PakWorkerResponse {
                    ok: true,
                    sandboxed: false,
                    inventory: None,
                    member_digests: Vec::new(),
                    index_metadata_sha256: Some(index_metadata_sha256),
                    error: None,
                },
                Err(error) => PakWorkerResponse {
                    ok: false,
                    sandboxed: false,
                    inventory: None,
                    member_digests: Vec::new(),
                    index_metadata_sha256: None,
                    error: Some(error.to_string()),
                },
            }
        }
        PakWorkerRequest::Inspect {
            pak,
            limits,
            hash_members: requested_members,
        } => match inspect_pak(&pak, &limits) {
            Ok(inventory) => {
                if requested_members.is_empty() {
                    PakWorkerResponse {
                        ok: true,
                        sandboxed: false,
                        inventory: Some(inventory),
                        member_digests: Vec::new(),
                        index_metadata_sha256: None,
                        error: None,
                    }
                } else {
                    match hash_members(&pak, &requested_members, &limits) {
                        Ok(member_digests) => PakWorkerResponse {
                            ok: true,
                            sandboxed: false,
                            inventory: Some(inventory),
                            member_digests,
                            index_metadata_sha256: None,
                            error: None,
                        },
                        Err(error) => PakWorkerResponse {
                            ok: false,
                            sandboxed: false,
                            inventory: Some(inventory),
                            member_digests: Vec::new(),
                            index_metadata_sha256: None,
                            error: Some(error.to_string()),
                        },
                    }
                }
            }
            Err(error) => PakWorkerResponse {
                ok: false,
                sandboxed: false,
                inventory: None,
                member_digests: Vec::new(),
                index_metadata_sha256: None,
                error: Some(error.to_string()),
            },
        },
    }
}

pub fn hash_members(
    path: &Path,
    stored_paths: &[String],
    limits: &PakLimits,
) -> Result<Vec<MemberDigest>, PakError> {
    let archive_bytes = fs::metadata(path)
        .map_err(|source| PakError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    if archive_bytes > limits.max_archive_bytes {
        return Err(PakError::ArchiveTooLarge {
            actual: archive_bytes,
            limit: limits.max_archive_bytes,
        });
    }
    validate_pak_container(path, archive_bytes, limits)?;
    let mut file = File::open(path).map_err(|source| PakError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let reader = repak_trumank::PakBuilder::new()
        .reader(&mut file)
        .map_err(|source| PakError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
    let mut digests = Vec::with_capacity(stored_paths.len());
    for stored_path in stored_paths {
        let mut output = HashingWriter::new(limits.max_member_bytes);
        if let Err(source) = reader.read_file(stored_path, &mut file, &mut output) {
            if matches!(&source, repak_trumank::Error::Io(error) if error.kind() == io::ErrorKind::FileTooLarge)
                && let Some(actual) = output.exceeded_at
            {
                return Err(PakError::MemberTooLarge {
                    actual,
                    limit: limits.max_member_bytes,
                });
            }
            return Err(PakError::Parse {
                path: path.to_path_buf(),
                source,
            });
        }
        digests.push(output.finish(stored_path));
    }
    Ok(digests)
}

pub fn hash_member(
    path: &Path,
    stored_path: &str,
    limits: &PakLimits,
) -> Result<MemberDigest, PakError> {
    let mut digests = hash_members(path, &[stored_path.to_owned()], limits)?;
    Ok(digests.remove(0))
}

pub fn overlapping_member_hash_requests(inventories: &[PakInventory]) -> Vec<MemberHashRequest> {
    let mut sources = BTreeMap::<String, Vec<(&PakInventory, &PakMember)>>::new();
    for inventory in inventories {
        for member in &inventory.members {
            sources
                .entry(member.collision_key.clone())
                .or_default()
                .push((inventory, member));
        }
    }
    let mut requests = Vec::new();
    for sources in sources.into_values().filter(|sources| sources.len() > 1) {
        for (inventory, member) in sources {
            requests.push(MemberHashRequest {
                archive_path: inventory.archive_path.clone(),
                stored_path: member.stored_path.clone(),
                virtual_path: member.virtual_path.clone(),
                collision_key: member.collision_key.clone(),
            });
        }
    }
    requests.sort_by(|left, right| {
        left.archive_path
            .cmp(&right.archive_path)
            .then_with(|| left.collision_key.cmp(&right.collision_key))
    });
    requests.dedup_by(|left, right| {
        left.archive_path == right.archive_path && left.collision_key == right.collision_key
    });
    requests
}

pub fn discover_paks(root: &Path) -> Result<PakDiscoveryReport, PakError> {
    let root = fs::canonicalize(root).map_err(|source| PakError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    if !fs::metadata(&root)
        .map_err(|source| PakError::Io {
            path: root.clone(),
            source,
        })?
        .is_dir()
    {
        return Err(PakError::InvalidDiscoveryRoot(root));
    }

    let mut pending = vec![root.clone()];
    let mut paks = Vec::new();
    let mut skipped_links = Vec::new();
    while let Some(directory) = pending.pop() {
        let mut entries: Vec<_> = fs::read_dir(&directory)
            .map_err(|source| PakError::Io {
                path: directory.clone(),
                source,
            })?
            .collect::<Result<_, _>>()
            .map_err(|source| PakError::Io {
                path: directory.clone(),
                source,
            })?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries.into_iter().rev() {
            let path = entry.path();
            let file_type = entry.file_type().map_err(|source| PakError::Io {
                path: path.clone(),
                source,
            })?;
            if file_type.is_symlink() {
                skipped_links.push(path);
            } else if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file()
                && path.extension().is_some_and(|extension| {
                    extension.to_string_lossy().eq_ignore_ascii_case("pak")
                })
            {
                let relative_path = path
                    .strip_prefix(&root)
                    .expect("discovered path remains beneath root")
                    .to_path_buf();
                let disabled_looking_ancestor = relative_path.components().any(|component| {
                    component
                        .as_os_str()
                        .to_string_lossy()
                        .eq_ignore_ascii_case("disabled")
                });
                let filename = path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default();
                paks.push(DiscoveredPak {
                    path,
                    relative_path,
                    priority: parse_priority_hint(&filename),
                    disabled_looking_ancestor,
                });
            }
        }
    }
    paks.sort_by(|left, right| {
        left.relative_path
            .to_string_lossy()
            .cmp(&right.relative_path.to_string_lossy())
    });
    skipped_links.sort();
    let disabled_looking_count = paks
        .iter()
        .filter(|pak| pak.disabled_looking_ancestor)
        .count();
    Ok(PakDiscoveryReport {
        root,
        pak_count: paks.len(),
        disabled_looking_count,
        paks,
        skipped_links,
    })
}

pub fn analyze_conflicts(
    inventories: &[PakInventory],
    evidence: &[MemberHashEvidence],
) -> PakConflictGraph {
    let hashes: BTreeMap<_, _> = evidence
        .iter()
        .map(|item| {
            (
                (item.archive_path.clone(), item.collision_key.clone()),
                item.sha256.as_str(),
            )
        })
        .collect();
    let mut ordered: Vec<_> = inventories.iter().collect();
    ordered.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    let mut edges = Vec::new();

    for first_index in 0..ordered.len() {
        for second_index in first_index + 1..ordered.len() {
            let first = ordered[first_index];
            let second = ordered[second_index];
            let first_members: BTreeMap<_, _> = first
                .members
                .iter()
                .map(|member| (member.collision_key.as_str(), member))
                .collect();
            let second_members: BTreeMap<_, _> = second
                .members
                .iter()
                .map(|member| (member.collision_key.as_str(), member))
                .collect();
            let member_keys: Vec<_> = first_members
                .keys()
                .filter(|key| second_members.contains_key(**key))
                .copied()
                .collect();
            let first_packages: BTreeMap<_, _> = first
                .packages
                .iter()
                .map(|package| (package.package_key.as_str(), package))
                .collect();
            let second_packages: BTreeMap<_, _> = second
                .packages
                .iter()
                .map(|package| (package.package_key.as_str(), package))
                .collect();
            let package_keys: Vec<_> = first_packages
                .keys()
                .filter(|key| second_packages.contains_key(**key))
                .copied()
                .collect();
            if member_keys.is_empty() && package_keys.is_empty() {
                continue;
            }

            let members: Vec<_> = member_keys
                .iter()
                .map(|key| {
                    let first_member = first_members[key];
                    let second_member = second_members[key];
                    let first_hash = hashes.get(&(
                        first.archive_path.clone(),
                        first_member.collision_key.clone(),
                    ));
                    let second_hash = hashes.get(&(
                        second.archive_path.clone(),
                        second_member.collision_key.clone(),
                    ));
                    MemberConflict {
                        virtual_path: first_member.virtual_path.clone(),
                        first_stored_path: first_member.stored_path.clone(),
                        second_stored_path: second_member.stored_path.clone(),
                        identical: first_hash
                            .zip(second_hash)
                            .map(|(left, right)| left == right),
                        localization: is_localization_path(&first_member.virtual_path),
                    }
                })
                .collect();
            let packages: Vec<_> = package_keys
                .iter()
                .map(|key| {
                    let first_package = first_packages[key];
                    let second_package = second_packages[key];
                    let first_members = package_collision_keys(first, key);
                    let second_members = package_collision_keys(second, key);
                    PackageConflict {
                        package_key: (*key).to_owned(),
                        first_members: first_package.members.clone(),
                        second_members: second_package.members.clone(),
                        split_package: first_members != second_members,
                        localization: first_package
                            .members
                            .iter()
                            .chain(&second_package.members)
                            .any(|member| is_localization_path(member)),
                    }
                })
                .collect();
            let all_members_identical =
                !members.is_empty() && members.iter().all(|member| member.identical == Some(true));
            let complete_packages = packages.iter().all(|package| !package.split_package)
                && package_keys.iter().all(|key| {
                    first_packages[key].warnings.is_empty()
                        && second_packages[key].warnings.is_empty()
                        && package_collision_keys(first, key)
                            .iter()
                            .all(|member| member_keys.contains(&member.as_str()))
                });
            let benign_duplicate = all_members_identical && complete_packages;
            let order = decide_priority(first, second);
            let outcome = if benign_duplicate {
                PakConflictOutcome::BenignDuplicate
            } else if order.winner.is_some() {
                PakConflictOutcome::OrderedWithLoss
            } else {
                PakConflictOutcome::UnknownOrder
            };
            let mut domains = BTreeSet::new();
            if !packages.is_empty() {
                domains.insert(PakConflictDomain::CookedPackage);
            }
            if members
                .iter()
                .any(|member| cooked_package_member(&member.virtual_path).is_none())
            {
                domains.insert(PakConflictDomain::LooseFile);
            }
            if members.iter().any(|member| member.localization)
                || packages.iter().any(|package| package.localization)
            {
                domains.insert(PakConflictDomain::Localization);
            }
            edges.push(PakConflictEdge {
                first_archive: first.archive_path.clone(),
                second_archive: second.archive_path.clone(),
                outcome,
                winner: order.winner,
                order_confidence: order.confidence,
                winner_reason: order.reason,
                domains: domains.into_iter().collect(),
                members,
                packages,
            });
        }
    }
    PakConflictGraph {
        archive_count: inventories.len(),
        edges,
    }
}

pub fn is_localization_path(path: &str) -> bool {
    let folded = path.replace('\\', "/").to_ascii_lowercase();
    let extension = folded.rsplit_once('.').map(|(_, extension)| extension);
    matches!(extension, Some("locres" | "locmeta"))
        || folded
            .split('/')
            .any(|component| matches!(component, "localization" | "l10n"))
}

fn package_collision_keys(inventory: &PakInventory, package_key: &str) -> BTreeSet<String> {
    inventory
        .members
        .iter()
        .filter(|member| member.package_key.as_deref() == Some(package_key))
        .map(|member| member.collision_key.clone())
        .collect()
}

pub fn decide_priority(first: &PakInventory, second: &PakInventory) -> PakOrderDecision {
    match first
        .priority
        .patch_generation
        .cmp(&second.priority.patch_generation)
    {
        std::cmp::Ordering::Greater => PakOrderDecision {
            winner: Some(first.archive_path.clone()),
            confidence: PakOrderConfidence::ObservedPatchGeneration,
            reason: format!(
                "patch generation {} is greater than {}",
                first.priority.patch_generation, second.priority.patch_generation
            ),
        },
        std::cmp::Ordering::Less => PakOrderDecision {
            winner: Some(second.archive_path.clone()),
            confidence: PakOrderConfidence::ObservedPatchGeneration,
            reason: format!(
                "patch generation {} is greater than {}",
                second.priority.patch_generation, first.priority.patch_generation
            ),
        },
        std::cmp::Ordering::Equal => PakOrderDecision {
            winner: None,
            confidence: PakOrderConfidence::UnverifiedLexicalTie,
            reason: "patch generations are equal; lexical runtime order is not yet verified"
                .to_owned(),
        },
    }
}

pub fn normalize_virtual_path(
    mount_point: &str,
    stored_path: &str,
) -> Result<NormalizedVirtualPath, PakPathError> {
    let mount = mount_point.replace('\\', "/");
    let Some(mount) = mount.strip_prefix("../../../") else {
        return Err(PakPathError::InvalidMount(mount_point.to_owned()));
    };
    if mount.starts_with("../") || mount == ".." {
        return Err(PakPathError::InvalidMount(mount_point.to_owned()));
    }
    let mount = normalize_relative_path(mount.trim_end_matches('/'))?;
    let stored = normalize_relative_path(&stored_path.replace('\\', "/"))?;
    if stored.is_empty() {
        return Err(PakPathError::UnsafePath(stored_path.to_owned()));
    }
    let virtual_path = if mount.is_empty() {
        stored
    } else {
        format!("{mount}/{stored}")
    };
    Ok(NormalizedVirtualPath {
        collision_key: virtual_path.nfkd().case_fold().nfc().collect(),
        virtual_path,
    })
}

pub fn cooked_package_member(path: &str) -> Option<(String, CookedSidecar)> {
    let (stem, extension) = path.rsplit_once('.')?;
    let sidecar = COOKED_EXTENSIONS.iter().find_map(|(candidate, sidecar)| {
        extension
            .eq_ignore_ascii_case(candidate)
            .then_some(*sidecar)
    })?;
    Some((stem.to_lowercase(), sidecar))
}

pub fn parse_priority_hint(filename: &str) -> PakPriorityHint {
    let folded = filename.to_ascii_lowercase();
    if !folded.ends_with("_p.pak") {
        return PakPriorityHint {
            patch_generation: 0,
            patch_increment: 0,
            explicit_number: None,
            confidence: PakPriorityConfidence::NoPatchSuffix,
        };
    }
    let prefix = &folded[..folded.len() - "_p.pak".len()];
    let explicit_number = prefix
        .rsplit_once('_')
        .map(|(_, suffix)| suffix)
        .filter(|suffix| !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|suffix| suffix.parse::<u64>().ok());
    let patch_generation = explicit_number
        .filter(|number| *number > 0)
        .map_or(1, |number| number.saturating_add(1));
    PakPriorityHint {
        patch_generation,
        patch_increment: patch_generation.saturating_mul(100),
        explicit_number,
        confidence: PakPriorityConfidence::ObservedBuildRule,
    }
}

fn normalize_relative_path(path: &str) -> Result<String, PakPathError> {
    if path.is_empty() {
        return Ok(String::new());
    }
    if path.starts_with('/')
        || path.as_bytes().get(1).is_some_and(|byte| *byte == b':')
        || path.contains('\0')
    {
        return Err(PakPathError::UnsafePath(path.to_owned()));
    }
    let components: Vec<_> = path.split('/').collect();
    if components
        .iter()
        .any(|component| component.is_empty() || matches!(*component, "." | ".."))
    {
        return Err(PakPathError::UnsafePath(path.to_owned()));
    }
    Ok(components.join("/"))
}

pub fn pak_index_metadata_sha256(path: &Path, limits: &PakLimits) -> Result<String, PakError> {
    let archive_bytes = fs::metadata(path)
        .map_err(|source| PakError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    if archive_bytes > limits.max_archive_bytes {
        return Err(PakError::ArchiveTooLarge {
            actual: archive_bytes,
            limit: limits.max_archive_bytes,
        });
    }
    validate_pak_container(path, archive_bytes, limits)?
        .ok_or_else(|| invalid_container("no recognized PAK footer was found"))
}

fn validate_pak_container(
    path: &Path,
    archive_bytes: u64,
    limits: &PakLimits,
) -> Result<Option<String>, PakError> {
    let mut file = File::open(path).map_err(|source| PakError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    for version in repak_trumank::Version::iter() {
        let footer_bytes = version.size() as u64;
        if archive_bytes < footer_bytes {
            continue;
        }
        let footer_start = archive_bytes - footer_bytes;
        file.seek(SeekFrom::Start(footer_start))
            .map_err(|source| PakError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if version.version_major() >= repak_trumank::VersionMajor::EncryptionKeyGuid {
            read_exact_discard(&mut file, 16, path)?;
        }
        if version.version_major() >= repak_trumank::VersionMajor::IndexEncryption {
            read_exact_discard(&mut file, 1, path)?;
        }
        let magic = read_u32(&mut file, path)?;
        let version_major = read_u32(&mut file, path)?;
        if magic != repak_trumank::MAGIC || version_major != version.version_major() as u32 {
            continue;
        }
        let index_offset = read_u64(&mut file, path)?;
        let index_size = read_u64(&mut file, path)?;
        if index_size > limits.max_index_bytes {
            return Err(PakError::InvalidContainer(format!(
                "index has {index_size} bytes; limit is {}",
                limits.max_index_bytes
            )));
        }
        let Some(index_end) = index_offset.checked_add(index_size) else {
            return Err(PakError::InvalidContainer(
                "index offset and size overflow u64".to_owned(),
            ));
        };
        if index_offset > footer_start || index_end > footer_start {
            return Err(PakError::InvalidContainer(format!(
                "index range {index_offset}..{index_end} exceeds footer start {footer_start}"
            )));
        }
        let secondary_ranges = validate_pak_indexes(
            &mut file,
            version,
            index_offset,
            index_size,
            footer_start,
            limits,
            path,
        )?;
        let mut hasher = Sha256::new();
        for range in std::iter::once(IndexRange {
            offset: index_offset,
            size: index_size,
        })
        .chain(secondary_ranges)
        .chain(std::iter::once(IndexRange {
            offset: footer_start,
            size: footer_bytes,
        })) {
            hasher.update(read_index_range(&mut file, range, path)?);
        }
        return Ok(Some(format!("{:x}", hasher.finalize())));
    }
    Ok(None)
}

#[derive(Debug, Clone, Copy)]
struct IndexRange {
    offset: u64,
    size: u64,
}

fn validate_pak_indexes(
    file: &mut File,
    version: repak_trumank::Version,
    index_offset: u64,
    index_size: u64,
    footer_start: u64,
    limits: &PakLimits,
    path: &Path,
) -> Result<Vec<IndexRange>, PakError> {
    let main_index = read_index_range(
        file,
        IndexRange {
            offset: index_offset,
            size: index_size,
        },
        path,
    )?;
    let mut index = IndexCursor::new(&main_index);
    index.skip_string("mount point")?;
    let record_count = index.read_u32("record count")? as usize;
    validate_count("record count", record_count, limits.max_entries)?;

    if version.version_major() < repak_trumank::VersionMajor::PathHashIndex {
        for _ in 0..record_count {
            index.skip_string("entry path")?;
            skip_legacy_entry(&mut index, version, limits)?;
        }
        return Ok(Vec::new());
    }

    index.skip(8, "path hash seed")?;
    let path_hash_range = read_optional_index_range(&mut index, "path hash index")?;
    let full_directory_range = read_optional_index_range(&mut index, "full directory index")?;
    let encoded_entries_size = index.read_u32("encoded entries size")? as usize;
    index.skip(encoded_entries_size, "encoded entries")?;
    let non_encoded_count = index.read_u32("non-encoded entry count")? as usize;
    validate_count(
        "non-encoded entry count",
        non_encoded_count,
        limits.max_entries,
    )?;
    for _ in 0..non_encoded_count {
        skip_legacy_entry(&mut index, version, limits)?;
    }

    if let Some(range) = path_hash_range {
        validate_index_range(range, footer_start, limits, "path hash index")?;
        let bytes = read_index_range(file, range, path)?;
        let mut path_hash = IndexCursor::new(&bytes);
        let count = path_hash.read_u32("path hash entry count")? as usize;
        validate_count("path hash entry count", count, limits.max_entries)?;
        path_hash.skip(
            count
                .checked_mul(12)
                .ok_or_else(|| invalid_container("path hash entry bytes overflow"))?,
            "path hash entries",
        )?;
        path_hash.skip(4, "path hash terminator")?;
    }

    if let Some(range) = full_directory_range {
        validate_index_range(range, footer_start, limits, "full directory index")?;
        let bytes = read_index_range(file, range, path)?;
        let mut directory = IndexCursor::new(&bytes);
        let directory_count = directory.read_u32("directory count")? as usize;
        validate_count("directory count", directory_count, limits.max_entries)?;
        let mut file_count_total = 0_usize;
        let mut encoded_offsets = Vec::new();
        for _ in 0..directory_count {
            directory.skip_string("directory name")?;
            let file_count = directory.read_u32("directory file count")? as usize;
            file_count_total = file_count_total
                .checked_add(file_count)
                .ok_or_else(|| invalid_container("directory file count overflow"))?;
            validate_count("directory file count", file_count_total, limits.max_entries)?;
            for _ in 0..file_count {
                directory.skip_string("file name")?;
                encoded_offsets.push(directory.read_i32("encoded entry offset")?);
            }
        }
        if file_count_total > record_count {
            return Err(invalid_container(format!(
                "full directory index references {file_count_total} files; record count is {record_count}"
            )));
        }
        for offset in encoded_offsets {
            if offset >= 0 {
                if offset as usize >= encoded_entries_size {
                    return Err(invalid_container(format!(
                        "encoded entry offset {offset} exceeds {encoded_entries_size} bytes"
                    )));
                }
            } else {
                let decoded = i64::from(offset).unsigned_abs() as usize;
                if decoded == 0 || decoded > non_encoded_count {
                    return Err(invalid_container(format!(
                        "non-encoded entry reference {offset} exceeds count {non_encoded_count}"
                    )));
                }
            }
        }
    }
    Ok(path_hash_range
        .into_iter()
        .chain(full_directory_range)
        .collect())
}

fn read_optional_index_range(
    index: &mut IndexCursor<'_>,
    label: &str,
) -> Result<Option<IndexRange>, PakError> {
    if index.read_u32(&format!("has {label}"))? == 0 {
        return Ok(None);
    }
    let range = IndexRange {
        offset: index.read_u64(&format!("{label} offset"))?,
        size: index.read_u64(&format!("{label} size"))?,
    };
    index.skip(20, &format!("{label} hash"))?;
    Ok(Some(range))
}

fn validate_index_range(
    range: IndexRange,
    footer_start: u64,
    limits: &PakLimits,
    label: &str,
) -> Result<(), PakError> {
    if range.size > limits.max_index_bytes {
        return Err(invalid_container(format!(
            "{label} has {} bytes; limit is {}",
            range.size, limits.max_index_bytes
        )));
    }
    let end = range
        .offset
        .checked_add(range.size)
        .ok_or_else(|| invalid_container(format!("{label} range overflows u64")))?;
    if range.offset > footer_start || end > footer_start {
        return Err(invalid_container(format!(
            "{label} range {}..{end} exceeds footer start {footer_start}",
            range.offset
        )));
    }
    Ok(())
}

fn read_index_range(file: &mut File, range: IndexRange, path: &Path) -> Result<Vec<u8>, PakError> {
    let size = usize::try_from(range.size)
        .map_err(|_| invalid_container("index size does not fit usize"))?;
    let mut bytes = vec![0_u8; size];
    file.seek(SeekFrom::Start(range.offset))
        .and_then(|_| file.read_exact(&mut bytes))
        .map_err(|source| PakError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(bytes)
}

fn skip_legacy_entry(
    index: &mut IndexCursor<'_>,
    version: repak_trumank::Version,
    limits: &PakLimits,
) -> Result<(), PakError> {
    index.skip(24, "entry offset and sizes")?;
    let compression = if version == repak_trumank::Version::V8A {
        u32::from(index.read_u8("compression slot")?)
    } else {
        index.read_u32("compression slot")?
    };
    if version.version_major() == repak_trumank::VersionMajor::Initial {
        index.skip(8, "entry timestamp")?;
    }
    index.skip(20, "entry hash")?;
    if version.version_major() >= repak_trumank::VersionMajor::CompressionEncryption {
        if compression != 0 {
            let block_count = index.read_u32("compression block count")? as usize;
            let max_blocks = limits.max_entries.saturating_mul(64).max(1024);
            validate_count("compression block count", block_count, max_blocks)?;
            index.skip(
                block_count
                    .checked_mul(16)
                    .ok_or_else(|| invalid_container("compression block bytes overflow"))?,
                "compression blocks",
            )?;
        }
        index.skip(5, "entry flags and block size")?;
    }
    Ok(())
}

fn validate_count(label: &str, actual: usize, limit: usize) -> Result<(), PakError> {
    if actual > limit {
        Err(invalid_container(format!(
            "{label} is {actual}; limit is {limit}"
        )))
    } else {
        Ok(())
    }
}

fn invalid_container(detail: impl Into<String>) -> PakError {
    PakError::InvalidContainer(detail.into())
}

struct IndexCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> IndexCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn skip(&mut self, bytes: usize, label: &str) -> Result<(), PakError> {
        let end = self
            .position
            .checked_add(bytes)
            .ok_or_else(|| invalid_container(format!("{label} position overflow")))?;
        if end > self.bytes.len() {
            return Err(invalid_container(format!(
                "{label} exceeds index bounds at {}..{end} of {}",
                self.position,
                self.bytes.len()
            )));
        }
        self.position = end;
        Ok(())
    }

    fn read_u8(&mut self, label: &str) -> Result<u8, PakError> {
        let value = *self
            .bytes
            .get(self.position)
            .ok_or_else(|| invalid_container(format!("{label} exceeds index bounds")))?;
        self.position += 1;
        Ok(value)
    }

    fn read_u32(&mut self, label: &str) -> Result<u32, PakError> {
        let bytes: [u8; 4] = self.read_array(label)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_i32(&mut self, label: &str) -> Result<i32, PakError> {
        let bytes: [u8; 4] = self.read_array(label)?;
        Ok(i32::from_le_bytes(bytes))
    }

    fn read_u64(&mut self, label: &str) -> Result<u64, PakError> {
        let bytes: [u8; 8] = self.read_array(label)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_array<const N: usize>(&mut self, label: &str) -> Result<[u8; N], PakError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or_else(|| invalid_container(format!("{label} position overflow")))?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| invalid_container(format!("{label} exceeds index bounds")))?;
        self.position = end;
        Ok(bytes.try_into().expect("slice length matches array"))
    }

    fn skip_string(&mut self, label: &str) -> Result<(), PakError> {
        let length = self.read_i32(&format!("{label} length"))?;
        let units = length.unsigned_abs() as usize;
        let bytes = if length < 0 {
            units
                .checked_mul(2)
                .ok_or_else(|| invalid_container(format!("{label} byte length overflow")))?
        } else {
            units
        };
        if bytes > MAX_PAK_STRING_BYTES {
            return Err(invalid_container(format!(
                "{label} has {bytes} bytes; limit is {MAX_PAK_STRING_BYTES}"
            )));
        }
        self.skip(bytes, label)
    }
}

fn read_exact_discard(file: &mut File, bytes: usize, path: &Path) -> Result<(), PakError> {
    let mut buffer = [0_u8; 16];
    file.read_exact(&mut buffer[..bytes])
        .map_err(|source| PakError::Io {
            path: path.to_path_buf(),
            source,
        })
}

fn read_u32(file: &mut File, path: &Path) -> Result<u32, PakError> {
    let mut bytes = [0_u8; 4];
    file.read_exact(&mut bytes).map_err(|source| PakError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(file: &mut File, path: &Path) -> Result<u64, PakError> {
    let mut bytes = [0_u8; 8];
    file.read_exact(&mut bytes).map_err(|source| PakError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(u64::from_le_bytes(bytes))
}

fn group_cooked_packages(members: &[PakMember]) -> Vec<CookedPackage> {
    let mut grouped = BTreeMap::<String, Vec<&PakMember>>::new();
    for member in members {
        if let Some(package_key) = &member.package_key {
            grouped.entry(package_key.clone()).or_default().push(member);
        }
    }
    grouped
        .into_iter()
        .map(|(package_key, package_members)| {
            let mut sidecars: Vec<_> = package_members
                .iter()
                .filter_map(|member| member.sidecar)
                .collect();
            sidecars.sort();
            sidecars.dedup();
            let sidecar_set: BTreeSet<_> = sidecars.iter().copied().collect();
            let primary_count = usize::from(sidecar_set.contains(&CookedSidecar::Asset))
                + usize::from(sidecar_set.contains(&CookedSidecar::Map));
            let mut warnings = Vec::new();
            if primary_count == 0 {
                warnings.push("orphan sidecar group has no .uasset or .umap".to_owned());
            } else if primary_count > 1 {
                warnings.push("package contains both .uasset and .umap primaries".to_owned());
            }
            if primary_count == 1 && !sidecar_set.contains(&CookedSidecar::Export) {
                warnings.push(
                    "primary asset has no .uexp sidecar; verify package completeness".to_owned(),
                );
            }
            CookedPackage {
                package_key,
                members: package_members
                    .into_iter()
                    .map(|member| member.virtual_path.clone())
                    .collect(),
                sidecars,
                warnings,
            }
        })
        .collect()
}

struct HashingWriter {
    hasher: Sha256,
    bytes: u64,
    limit: u64,
    exceeded_at: Option<u64>,
}

impl HashingWriter {
    fn new(limit: u64) -> Self {
        Self {
            hasher: Sha256::new(),
            bytes: 0,
            limit,
            exceeded_at: None,
        }
    }

    fn finish(self, stored_path: &str) -> MemberDigest {
        MemberDigest {
            stored_path: stored_path.to_owned(),
            bytes: self.bytes,
            sha256: format!("{:x}", self.hasher.finalize()),
        }
    }
}

impl Write for HashingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next = self.bytes.saturating_add(buffer.len() as u64);
        if next > self.limit {
            self.exceeded_at = Some(next);
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                format!("member exceeds {} bytes", self.limit),
            ));
        }
        self.hasher.update(buffer);
        self.bytes = next;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn default_policy_has_no_fixed_resource_ceilings() {
        let limits = PakLimits::default();
        assert_eq!(limits.max_archive_bytes, u64::MAX);
        assert_eq!(limits.max_index_bytes, u64::MAX);
        assert_eq!(limits.max_entries, usize::MAX);
        assert_eq!(limits.max_member_bytes, u64::MAX);
    }

    #[test]
    fn parses_observed_priority_suffixes() {
        assert_eq!(parse_priority_hint("Example_P.pak").patch_generation, 1);
        assert_eq!(
            parse_priority_hint("Example_2301_P.pak"),
            PakPriorityHint {
                patch_generation: 2302,
                patch_increment: 230_200,
                explicit_number: Some(2301),
                confidence: PakPriorityConfidence::ObservedBuildRule,
            }
        );
        assert_eq!(
            parse_priority_hint("Example_9999_P.pak").patch_generation,
            10_000
        );
        assert_eq!(parse_priority_hint("Example.pak").patch_generation, 0);
    }

    #[test]
    fn resolves_pak_load_order_chains_and_assigns_slots() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let c = "c".repeat(64);
        let resolution = resolve_pak_load_order(
            &nodes([&c, &a, &b]),
            &[constraint(&a, &b), constraint(&b, &c), constraint(&a, &b)],
        )
        .unwrap();

        assert_eq!(resolution.order, [a.clone(), b.clone(), c.clone()]);
        assert_eq!(resolution.slots[&a], 1);
        assert_eq!(resolution.slots[&b], 2);
        assert_eq!(resolution.slots[&c], 3);
    }

    #[test]
    fn resolves_unconstrained_nodes_deterministically_by_sha256() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let c = "c".repeat(64);
        let first = resolve_pak_load_order(&nodes([&c, &a, &b]), &[]).unwrap();
        let second = resolve_pak_load_order(&nodes([&b, &c, &a]), &[]).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.order, [a, b, c]);
    }

    #[test]
    fn rejects_cycles_self_edges_and_absent_nodes() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let c = "c".repeat(64);
        assert!(matches!(
            resolve_pak_load_order(&nodes([&a, &b]), &[constraint(&a, &b), constraint(&b, &a)]),
            Err(PakLoadOrderError::Cycle(_))
        ));
        assert!(matches!(
            resolve_pak_load_order(&nodes([&a]), &[constraint(&a, &a)]),
            Err(PakLoadOrderError::SelfEdge(_))
        ));
        assert!(matches!(
            resolve_pak_load_order(&nodes([&a, &b]), &[constraint(&a, &c)]),
            Err(PakLoadOrderError::MissingNode(value)) if value == c
        ));
    }

    #[test]
    fn ordered_names_produce_increasing_observed_generations() {
        let sha256 = "0123456789abcdef".repeat(4);
        let first = rrmm_ordered_pak_name(&sha256, 1).unwrap();
        let second = rrmm_ordered_pak_name(&sha256, 2).unwrap();

        assert_eq!(first, "RRMM_0123456789abcdef_1_P.pak");
        assert!(
            parse_priority_hint(&first).patch_generation
                < parse_priority_hint(&second).patch_generation
        );
        assert!(matches!(
            rrmm_ordered_pak_name(&sha256, 0),
            Err(PakLoadOrderError::InvalidSlot)
        ));
        assert!(matches!(
            rrmm_ordered_pak_name(&"A".repeat(64), 1),
            Err(PakLoadOrderError::InvalidSha256(_))
        ));
    }

    #[test]
    fn normalizes_mounts_and_rejects_traversal() {
        let path = normalize_virtual_path(
            "../../../RetroRewind/Content/VideoStore/",
            "core\\Example.uasset",
        )
        .unwrap();
        assert_eq!(
            path.virtual_path,
            "RetroRewind/Content/VideoStore/core/Example.uasset"
        );
        assert!(normalize_virtual_path("../../../../", "Example.uasset").is_err());
        assert!(normalize_virtual_path("../../../", "../Example.uasset").is_err());
        assert!(normalize_virtual_path("../../../", "C:/Example.uasset").is_err());
    }

    #[test]
    fn inventories_v11_sidecars_and_hashes_members_lazily() {
        let temporary = TempDir::new().unwrap();
        let pak = temporary.path().join("Example_2301_P.pak");
        write_pak(
            &pak,
            "../../../RetroRewind/Content/VideoStore/",
            &[
                ("core/Foo.uasset", b"asset"),
                ("core/Foo.uexp", b"export"),
                ("core/Orphan.ubulk", b"bulk"),
            ],
            true,
        );

        let inventory = inspect_pak(&pak, &PakLimits::default()).unwrap();
        assert_eq!(inventory.version, "V11");
        assert_eq!(inventory.members.len(), 3);
        assert_eq!(inventory.packages.len(), 2);
        assert_eq!(inventory.priority.explicit_number, Some(2301));
        assert!(inventory.packages[1].warnings[0].contains("orphan"));
        assert!(!inventory.integrity.index_hashes_verified);

        let digest = hash_member(&pak, "core/Foo.uexp", &PakLimits::default()).unwrap();
        assert_eq!(digest.bytes, 6);
        assert_eq!(
            digest.sha256,
            "d46aee08cc49f6d1eb41800c1d6bab4506c960c700cff0efffe490d7cb1de5e3"
        );
        let small_limit = PakLimits {
            max_member_bytes: 5,
            ..PakLimits::default()
        };
        assert!(matches!(
            hash_member(&pak, "core/Foo.uexp", &small_limit),
            Err(PakError::MemberTooLarge {
                actual: 6,
                limit: 5
            })
        ));
    }

    #[test]
    fn rejects_case_collisions_and_unsafe_mounts() {
        let temporary = TempDir::new().unwrap();
        let collision = temporary.path().join("collision.pak");
        write_pak(
            &collision,
            "../../../",
            &[("Mods/Foo.uasset", b"one"), ("mods/foo.UASSET", b"two")],
            false,
        );
        assert!(matches!(
            inspect_pak(&collision, &PakLimits::default()),
            Err(PakError::VirtualPathCollision { .. })
        ));

        let traversal = temporary.path().join("traversal.pak");
        write_pak(&traversal, "../../../../", &[("Foo.uasset", b"one")], false);
        assert!(matches!(
            inspect_pak(&traversal, &PakLimits::default()),
            Err(PakError::Path(PakPathError::InvalidMount(_)))
        ));
    }

    #[test]
    fn rejects_truncated_paks() {
        let temporary = TempDir::new().unwrap();
        let pak = temporary.path().join("truncated.pak");
        fs::write(&pak, [0_u8; 16]).unwrap();
        assert!(matches!(
            inspect_pak(&pak, &PakLimits::default()),
            Err(PakError::InvalidContainer(_))
        ));
    }

    #[test]
    fn rejects_oversized_internal_entry_count_before_upstream_parsing() {
        let temporary = TempDir::new().unwrap();
        let pak = temporary.path().join("oversized-entry-count.pak");
        write_pak(
            &pak,
            "../../../",
            &[("RetroRewind/Content/Fuzz.uasset", b"")],
            false,
        );
        let mut bytes = fs::read(&pak).unwrap();
        let offset = 0x2a0a % bytes.len();
        bytes[offset] ^= 0xff;
        fs::write(&pak, bytes).unwrap();

        assert!(matches!(
            inspect_pak(&pak, &PakLimits::default()),
            Err(PakError::InvalidContainer(_))
        ));
    }

    #[test]
    fn inventories_and_hashes_a_zlib_compressed_member() {
        let temporary = TempDir::new().unwrap();
        let pak = temporary.path().join("compressed.pak");
        let contents = vec![b'a'; 64 * 1024];
        write_pak(
            &pak,
            "../../../",
            &[("RetroRewind/Content/Compressed.uasset", &contents)],
            true,
        );

        let inventory = inspect_pak(&pak, &PakLimits::default()).unwrap();
        assert_eq!(inventory.compression, ["zlib"]);
        let digest = hash_member(
            &pak,
            "RetroRewind/Content/Compressed.uasset",
            &PakLimits::default(),
        )
        .unwrap();
        assert_eq!(digest.bytes, contents.len() as u64);
        assert_eq!(digest.sha256, format!("{:x}", Sha256::digest(&contents)));
    }

    #[test]
    fn classifies_duplicates_ordered_loss_and_split_packages() {
        let temporary = TempDir::new().unwrap();
        let first_path = temporary.path().join("A_P.pak");
        let duplicate_path = temporary.path().join("B_P.pak");
        let changed_path = temporary.path().join("C_2301_P.pak");
        let split_path = temporary.path().join("D_9999_P.pak");
        let incomplete_path = temporary.path().join("E_9999_P.pak");
        let original = [("Foo.uasset", b"asset".as_slice()), ("Foo.uexp", b"one")];
        write_pak(&first_path, "../../../", &original, false);
        write_pak(&duplicate_path, "../../../", &original, false);
        write_pak(
            &changed_path,
            "../../../",
            &[("Foo.uasset", b"asset"), ("Foo.uexp", b"two")],
            false,
        );
        write_pak(&split_path, "../../../", &[("Foo.uasset", b"asset")], false);
        write_pak(
            &incomplete_path,
            "../../../",
            &[("Foo.uasset", b"asset")],
            false,
        );
        let inventories = [
            inspect_pak(&first_path, &PakLimits::default()).unwrap(),
            inspect_pak(&duplicate_path, &PakLimits::default()).unwrap(),
            inspect_pak(&changed_path, &PakLimits::default()).unwrap(),
            inspect_pak(&split_path, &PakLimits::default()).unwrap(),
            inspect_pak(&incomplete_path, &PakLimits::default()).unwrap(),
        ];
        let requests = overlapping_member_hash_requests(&inventories);
        let evidence: Vec<_> = requests
            .iter()
            .map(|request| {
                let digest = hash_member(
                    &request.archive_path,
                    &request.stored_path,
                    &PakLimits::default(),
                )
                .unwrap();
                MemberHashEvidence {
                    archive_path: request.archive_path.clone(),
                    collision_key: request.collision_key.clone(),
                    sha256: digest.sha256,
                }
            })
            .collect();

        let graph = analyze_conflicts(&inventories, &evidence);
        let duplicate = edge_for(&graph, "A_P.pak", "B_P.pak");
        assert_eq!(duplicate.outcome, PakConflictOutcome::BenignDuplicate);
        assert!(duplicate.winner.is_none());
        let changed = edge_for(&graph, "A_P.pak", "C_2301_P.pak");
        assert_eq!(changed.outcome, PakConflictOutcome::OrderedWithLoss);
        assert_eq!(
            changed.order_confidence,
            PakOrderConfidence::ObservedPatchGeneration
        );
        assert_eq!(
            changed.winner.as_ref().unwrap().file_name().unwrap(),
            "C_2301_P.pak"
        );
        assert!(
            changed
                .members
                .iter()
                .any(|member| member.identical == Some(false))
        );
        let split = edge_for(&graph, "A_P.pak", "D_9999_P.pak");
        assert!(split.packages[0].split_package);
        assert_eq!(split.outcome, PakConflictOutcome::OrderedWithLoss);
        let incomplete = edge_for(&graph, "D_9999_P.pak", "E_9999_P.pak");
        assert_eq!(incomplete.outcome, PakConflictOutcome::UnknownOrder);
        assert_eq!(
            incomplete.order_confidence,
            PakOrderConfidence::UnverifiedLexicalTie
        );

        let graph_without_hashes = analyze_conflicts(&inventories[..2], &[]);
        assert_eq!(
            graph_without_hashes.edges[0].outcome,
            PakConflictOutcome::UnknownOrder
        );
    }

    #[test]
    fn identifies_loose_and_cooked_localization_conflicts() {
        assert!(is_localization_path("Game/Content/en/Game.locres"));
        assert!(is_localization_path(
            "RetroRewind/Content/VideoStore/localization/interface/Quest.uasset"
        ));
        assert!(!is_localization_path("RetroRewind/Content/UI/Quest.uasset"));

        let temporary = TempDir::new().unwrap();
        let first_path = temporary.path().join("LocalizationA_P.pak");
        let second_path = temporary.path().join("LocalizationB_P.pak");
        let quest_asset = "RetroRewind/Content/VideoStore/localization/interface/Quest.uasset";
        let quest_export = "RetroRewind/Content/VideoStore/localization/interface/Quest.uexp";
        let locres = "RetroRewind/Content/Localization/en/Game.locres";
        write_pak(
            &first_path,
            "../../../",
            &[
                (locres, b"locale-one"),
                (quest_asset, b"asset"),
                (quest_export, b"export-one"),
            ],
            false,
        );
        write_pak(
            &second_path,
            "../../../",
            &[
                (locres, b"locale-two"),
                (quest_asset, b"asset"),
                (quest_export, b"export-two"),
            ],
            false,
        );
        let inventories = [
            inspect_pak(&first_path, &PakLimits::default()).unwrap(),
            inspect_pak(&second_path, &PakLimits::default()).unwrap(),
        ];
        let evidence: Vec<_> = overlapping_member_hash_requests(&inventories)
            .into_iter()
            .map(|request| {
                let digest = hash_member(
                    &request.archive_path,
                    &request.stored_path,
                    &PakLimits::default(),
                )
                .unwrap();
                MemberHashEvidence {
                    archive_path: request.archive_path,
                    collision_key: request.collision_key,
                    sha256: digest.sha256,
                }
            })
            .collect();

        let graph = analyze_conflicts(&inventories, &evidence);
        let edge = &graph.edges[0];
        assert_eq!(
            edge.domains,
            [
                PakConflictDomain::CookedPackage,
                PakConflictDomain::Localization,
                PakConflictDomain::LooseFile,
            ]
        );
        assert!(edge.members.iter().any(|member| member.localization));
        assert!(edge.packages[0].localization);
        assert_eq!(edge.outcome, PakConflictOutcome::UnknownOrder);
    }

    #[test]
    fn recursively_discovers_paks_and_keeps_disabled_directories_visible() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("Paks");
        fs::create_dir_all(root.join("~mods")).unwrap();
        fs::create_dir_all(root.join("disabled")).unwrap();
        fs::write(root.join("RetroRewind-Windows.pak"), b"base").unwrap();
        fs::write(root.join("~mods/Example_2301_P.PAK"), b"mod").unwrap();
        fs::write(root.join("disabled/StillActive_P.pak"), b"mod").unwrap();
        fs::write(root.join("ignore.txt"), b"not a pak").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let outside = temporary.path().join("outside");
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("Linked_P.pak"), b"linked").unwrap();
            symlink(&outside, root.join("linked")).unwrap();
        }

        let report = discover_paks(&root).unwrap();

        assert_eq!(report.paks.len(), 3);
        assert_eq!(report.pak_count, 3);
        assert_eq!(report.disabled_looking_count, 1);
        let explicit = report
            .paks
            .iter()
            .find(|pak| pak.relative_path.ends_with("Example_2301_P.PAK"))
            .unwrap();
        assert_eq!(explicit.priority.patch_generation, 2302);
        assert!(
            report
                .paks
                .iter()
                .find(|pak| pak.relative_path.ends_with("StillActive_P.pak"))
                .unwrap()
                .disabled_looking_ancestor
        );
        #[cfg(unix)]
        assert_eq!(report.skipped_links.len(), 1);
    }

    #[test]
    fn validates_worker_inventory_coherence_without_reparsing_payloads() {
        let temporary = TempDir::new().unwrap();
        let pak = temporary.path().join("Example_P.pak");
        write_pak(
            &pak,
            "../../../",
            &[
                ("RetroRewind/Content/Foo.uasset", b"asset"),
                ("RetroRewind/Content/Foo.uexp", b"export"),
            ],
            false,
        );
        let inventory = inspect_pak(&pak, &PakLimits::default()).unwrap();

        validate_inventory_contract(
            &inventory,
            &pak,
            fs::metadata(&pak).unwrap().len(),
            &PakLimits::default(),
        )
        .unwrap();

        let mut forged = inventory.clone();
        forged.packages[0].package_key = "retrorewind/content/other".to_owned();
        assert!(matches!(
            validate_inventory_contract(
                &forged,
                &pak,
                fs::metadata(&pak).unwrap().len(),
                &PakLimits::default(),
            ),
            Err(PakError::InvalidInventory(_))
        ));

        let mut forged = inventory;
        forged.members[0].collision_key = "forged".to_owned();
        assert!(matches!(
            validate_inventory_contract(
                &forged,
                &pak,
                fs::metadata(&pak).unwrap().len(),
                &PakLimits::default(),
            ),
            Err(PakError::InvalidInventory(_))
        ));

        let mut forged = inspect_pak(&pak, &PakLimits::default()).unwrap();
        forged.integrity.index_hashes_verified = true;
        assert!(matches!(
            validate_inventory_contract(
                &forged,
                &pak,
                fs::metadata(&pak).unwrap().len(),
                &PakLimits::default(),
            ),
            Err(PakError::InvalidInventory(_))
        ));
    }

    fn write_pak(path: &Path, mount: &str, entries: &[(&str, &[u8])], compress: bool) {
        let output = File::create(path).unwrap();
        let mut writer = repak_trumank::PakBuilder::new()
            .compression([repak_trumank::Compression::Zlib])
            .writer(
                output,
                repak_trumank::Version::V11,
                mount.to_owned(),
                Some(0x6493_4de7),
            );
        for (name, bytes) in entries {
            writer.write_file(name, compress, bytes).unwrap();
        }
        let output = writer.write_index().unwrap();
        output.sync_all().unwrap();
    }

    fn edge_for<'a>(graph: &'a PakConflictGraph, first: &str, second: &str) -> &'a PakConflictEdge {
        graph
            .edges
            .iter()
            .find(|edge| {
                edge.first_archive
                    .file_name()
                    .is_some_and(|name| name == first)
                    && edge
                        .second_archive
                        .file_name()
                        .is_some_and(|name| name == second)
            })
            .unwrap()
    }

    fn nodes<const N: usize>(sha256: [&str; N]) -> Vec<PakLoadOrderNode> {
        sha256
            .into_iter()
            .map(|pak_sha256| PakLoadOrderNode {
                pak_sha256: pak_sha256.to_owned(),
            })
            .collect()
    }

    fn constraint(loser: &str, winner: &str) -> PakLoadOrderConstraint {
        PakLoadOrderConstraint {
            loser_pak_sha256: loser.to_owned(),
            winner_pak_sha256: winner.to_owned(),
        }
    }
}
