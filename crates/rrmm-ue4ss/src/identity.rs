use crate::{
    EntryStatus, FLAT_CORE_RELATIVE_PATH, FLAT_MODS_RELATIVE_ROOT, FLAT_SETTINGS_RELATIVE_PATH,
    LEGACY_XINPUT_RELATIVE_PATH, LoaderClassificationInput, NESTED_CORE_RELATIVE_PATH,
    NESTED_SETTINGS_RELATIVE_PATH, OVERRIDE_RELATIVE_PATH, PROXY_RELATIVE_PATH,
    UE4SS_RELATIVE_ROOT, Ue4ssInventoryError, Ue4ssLoaderRisk, Ue4ssLoaderStatus, classify_loader,
    metadata, observation_present, observe_beneath,
};
use rrmm_domain::BuildRecipe;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssLoaderIdentityLimits {
    pub max_binary_bytes: u64,
}

impl Default for Ue4ssLoaderIdentityLimits {
    fn default() -> Self {
        Self {
            max_binary_bytes: 256 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ue4ssLoaderIdentityStatus {
    Exact,
    Absent,
    Incomplete,
    Ambiguous,
    Unsafe,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ue4ssLoaderLayout {
    Nested,
    Flat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssBinaryHashObservation {
    pub relative_path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssLoaderBinaryIdentity {
    pub layout: Ue4ssLoaderLayout,
    pub proxy: Ue4ssBinaryHashObservation,
    pub core: Ue4ssBinaryHashObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssLoaderIdentityReport {
    pub schema_version: u32,
    pub game_root: PathBuf,
    pub status: Ue4ssLoaderIdentityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Ue4ssLoaderBinaryIdentity>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ue4ssLoaderPolicyStatus {
    AllowedExact,
    KnownUnsafe,
    RequirementUnsatisfied,
    UnknownBlocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssLoaderPolicyEvaluation {
    pub policy_id: String,
    pub status: Ue4ssLoaderPolicyStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recognized_build_id: Option<String>,
}

pub fn inspect_ue4ss_loader_identity(
    game_root: &Path,
    limits: &Ue4ssLoaderIdentityLimits,
) -> Result<Ue4ssLoaderIdentityReport, Ue4ssInventoryError> {
    let game_root = fs::canonicalize(game_root).map_err(|source| Ue4ssInventoryError::Io {
        path: game_root.to_path_buf(),
        source,
    })?;
    if !metadata(&game_root)?.is_dir() {
        return Err(Ue4ssInventoryError::InvalidGameRoot(game_root));
    }

    let nested_root = observe_beneath(&game_root, UE4SS_RELATIVE_ROOT, UE4SS_RELATIVE_ROOT);
    let nested_mods = observe_beneath(
        &game_root,
        "RetroRewind/Binaries/Win64/ue4ss/Mods",
        "RetroRewind/Binaries/Win64/ue4ss/Mods",
    );
    let flat_mods = observe_beneath(&game_root, FLAT_MODS_RELATIVE_ROOT, FLAT_MODS_RELATIVE_ROOT);
    let canonical_proxy_candidate =
        observe_beneath(&game_root, PROXY_RELATIVE_PATH, PROXY_RELATIVE_PATH);
    let override_txt = observe_beneath(&game_root, OVERRIDE_RELATIVE_PATH, OVERRIDE_RELATIVE_PATH);
    let nested_core_candidate = observe_beneath(
        &game_root,
        NESTED_CORE_RELATIVE_PATH,
        NESTED_CORE_RELATIVE_PATH,
    );
    let flat_core_candidate =
        observe_beneath(&game_root, FLAT_CORE_RELATIVE_PATH, FLAT_CORE_RELATIVE_PATH);
    let nested_settings_candidate = observe_beneath(
        &game_root,
        NESTED_SETTINGS_RELATIVE_PATH,
        NESTED_SETTINGS_RELATIVE_PATH,
    );
    let flat_settings_candidate = observe_beneath(
        &game_root,
        FLAT_SETTINGS_RELATIVE_PATH,
        FLAT_SETTINGS_RELATIVE_PATH,
    );
    let legacy_xinput_candidate = observe_beneath(
        &game_root,
        LEGACY_XINPUT_RELATIVE_PATH,
        LEGACY_XINPUT_RELATIVE_PATH,
    );
    let nested_root_present = observation_present(&nested_root);
    let nested_layout_detected = observation_present(&nested_core_candidate)
        || observation_present(&nested_settings_candidate)
        || observation_present(&nested_mods);
    let flat_layout_detected = observation_present(&flat_core_candidate)
        || observation_present(&flat_settings_candidate)
        || observation_present(&flat_mods);
    let support_path_unsafe = required_directory_unsafe(&nested_root)
        || required_directory_unsafe(&nested_mods)
        || required_directory_unsafe(&flat_mods);
    let loader = classify_loader(LoaderClassificationInput {
        canonical_proxy_candidate,
        override_txt,
        nested_core_candidate,
        flat_core_candidate,
        nested_settings_candidate,
        flat_settings_candidate,
        legacy_xinput_candidate,
        nested_root_present,
        nested_layout_detected,
        flat_layout_detected,
        support_path_unsafe,
    });

    let (layout, core_path) = match loader.status {
        Ue4ssLoaderStatus::NestedAutomaticCandidate => {
            (Ue4ssLoaderLayout::Nested, NESTED_CORE_RELATIVE_PATH)
        }
        Ue4ssLoaderStatus::FlatAutomaticCandidate => {
            (Ue4ssLoaderLayout::Flat, FLAT_CORE_RELATIVE_PATH)
        }
        Ue4ssLoaderStatus::Absent => {
            return Ok(report(game_root, Ue4ssLoaderIdentityStatus::Absent, vec![]));
        }
        Ue4ssLoaderStatus::Ambiguous => {
            return Ok(report(
                game_root,
                Ue4ssLoaderIdentityStatus::Ambiguous,
                vec!["multiple UE4SS loader layouts prevent exact binary identity".to_owned()],
            ));
        }
        Ue4ssLoaderStatus::Unsafe | Ue4ssLoaderStatus::OverrideTargetUnverified => {
            return Ok(report(
                game_root,
                Ue4ssLoaderIdentityStatus::Unsafe,
                vec!["unsafe or redirected loader paths prevent exact binary identity".to_owned()],
            ));
        }
        _ => {
            return Ok(report(
                game_root,
                Ue4ssLoaderIdentityStatus::Incomplete,
                vec!["both the canonical proxy and exactly one UE4SS core are required".to_owned()],
            ));
        }
    };
    if loader
        .risks
        .contains(&Ue4ssLoaderRisk::ObsoleteXinputCandidateCoLocated)
    {
        return Ok(report(
            game_root,
            Ue4ssLoaderIdentityStatus::Unsafe,
            vec!["obsolete xinput1_3.dll is co-located with the UE4SS loader".to_owned()],
        ));
    }

    let proxy = match hash_binary(&game_root, PROXY_RELATIVE_PATH, limits.max_binary_bytes) {
        Ok(observation) => observation,
        Err(error) => return Ok(hash_failure_report(game_root, PROXY_RELATIVE_PATH, error)),
    };
    let core = match hash_binary(&game_root, core_path, limits.max_binary_bytes) {
        Ok(observation) => observation,
        Err(error) => return Ok(hash_failure_report(game_root, core_path, error)),
    };
    Ok(Ue4ssLoaderIdentityReport {
        schema_version: 1,
        game_root,
        status: Ue4ssLoaderIdentityStatus::Exact,
        identity: Some(Ue4ssLoaderBinaryIdentity {
            layout,
            proxy,
            core,
        }),
        issues: Vec::new(),
    })
}

pub fn evaluate_ue4ss_loader_policy(
    recipe: &BuildRecipe,
    policy_id: &str,
    identity_report: &Ue4ssLoaderIdentityReport,
) -> Ue4ssLoaderPolicyEvaluation {
    let Some(policy) = recipe
        .ue4ss_loader_policies
        .iter()
        .find(|policy| policy.id == policy_id)
    else {
        return policy_evaluation(policy_id, Ue4ssLoaderPolicyStatus::UnknownBlocked, None);
    };
    let Some(identity) = identity_report
        .identity
        .as_ref()
        .filter(|_| identity_report.status == Ue4ssLoaderIdentityStatus::Exact)
    else {
        return policy_evaluation(policy_id, Ue4ssLoaderPolicyStatus::UnknownBlocked, None);
    };
    let Some(build) = recipe.ue4ss_loader_builds.iter().find(|build| {
        build.proxy_sha256 == identity.proxy.sha256 && build.core_sha256 == identity.core.sha256
    }) else {
        return policy_evaluation(policy_id, Ue4ssLoaderPolicyStatus::UnknownBlocked, None);
    };
    let status = if policy.known_unsafe_build_ids.contains(&build.id) {
        Ue4ssLoaderPolicyStatus::KnownUnsafe
    } else if policy.allowed_build_ids.contains(&build.id) {
        Ue4ssLoaderPolicyStatus::AllowedExact
    } else {
        Ue4ssLoaderPolicyStatus::RequirementUnsatisfied
    };
    policy_evaluation(policy_id, status, Some(build.id.clone()))
}

fn hash_binary(
    game_root: &Path,
    relative_path: &str,
    max_bytes: u64,
) -> io::Result<Ue4ssBinaryHashObservation> {
    let mut file = crate::safe_file::open_file_beneath(game_root, relative_path)?;
    let before = regular_file_metadata(&file)?;
    if before.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("binary exceeds the {max_bytes} byte limit"),
        ));
    }
    let mut hasher = Sha256::new();
    let bytes = io::copy(
        &mut file.by_ref().take(max_bytes.saturating_add(1)),
        &mut hasher,
    )?;
    if bytes > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("binary exceeded the {max_bytes} byte limit while reading"),
        ));
    }
    let after = regular_file_metadata(&file)?;
    if before.len() != bytes || after.len() != bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "binary size changed or did not match the bytes read",
        ));
    }
    Ok(Ue4ssBinaryHashObservation {
        relative_path: relative_path.to_owned(),
        bytes,
        sha256: format!("{:x}", hasher.finalize()),
    })
}

fn regular_file_metadata(file: &File) -> io::Result<fs::Metadata> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "opened loader entry is not a regular file",
        ));
    }
    Ok(metadata)
}

fn required_directory_unsafe(observation: &crate::EntryObservation) -> bool {
    !matches!(
        observation.status,
        EntryStatus::Missing | EntryStatus::Directory
    )
}

fn report(
    game_root: PathBuf,
    status: Ue4ssLoaderIdentityStatus,
    issues: Vec<String>,
) -> Ue4ssLoaderIdentityReport {
    Ue4ssLoaderIdentityReport {
        schema_version: 1,
        game_root,
        status,
        identity: None,
        issues,
    }
}

fn hash_failure_report(
    game_root: PathBuf,
    relative_path: &str,
    error: io::Error,
) -> Ue4ssLoaderIdentityReport {
    let status = if error.kind() == io::ErrorKind::Unsupported {
        Ue4ssLoaderIdentityStatus::Unsupported
    } else {
        Ue4ssLoaderIdentityStatus::Incomplete
    };
    report(
        game_root,
        status,
        vec![format!("failed to hash '{relative_path}' safely: {error}")],
    )
}

fn policy_evaluation(
    policy_id: &str,
    status: Ue4ssLoaderPolicyStatus,
    recognized_build_id: Option<String>,
) -> Ue4ssLoaderPolicyEvaluation {
    Ue4ssLoaderPolicyEvaluation {
        policy_id: policy_id.to_owned(),
        status,
        recognized_build_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrmm_domain::{Ue4ssLoaderBuildRecipe, Ue4ssLoaderPolicyRecipe};
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn hashes_an_unambiguous_nested_loader_and_evaluates_exact_policy() {
        let temporary = TempDir::new().unwrap();
        write(temporary.path(), PROXY_RELATIVE_PATH, b"proxy");
        write(temporary.path(), NESTED_CORE_RELATIVE_PATH, b"core");
        let report =
            inspect_ue4ss_loader_identity(temporary.path(), &Ue4ssLoaderIdentityLimits::default())
                .unwrap();

        assert_eq!(report.status, Ue4ssLoaderIdentityStatus::Exact);
        let identity = report.identity.as_ref().unwrap();
        assert_eq!(identity.layout, Ue4ssLoaderLayout::Nested);
        let recipe = recipe(identity, "allowed");
        let evaluation = evaluate_ue4ss_loader_policy(&recipe, "policy", &report);
        assert_eq!(evaluation.status, Ue4ssLoaderPolicyStatus::AllowedExact);
        assert_eq!(evaluation.recognized_build_id.as_deref(), Some("allowed"));
    }

    #[test]
    fn blocks_ambiguous_redirected_legacy_and_oversized_loaders() {
        let ambiguous = TempDir::new().unwrap();
        write(ambiguous.path(), PROXY_RELATIVE_PATH, b"proxy");
        write(ambiguous.path(), NESTED_CORE_RELATIVE_PATH, b"nested");
        write(ambiguous.path(), FLAT_CORE_RELATIVE_PATH, b"flat");
        assert_eq!(
            inspect_ue4ss_loader_identity(ambiguous.path(), &Ue4ssLoaderIdentityLimits::default())
                .unwrap()
                .status,
            Ue4ssLoaderIdentityStatus::Ambiguous
        );

        let redirected = TempDir::new().unwrap();
        write(redirected.path(), PROXY_RELATIVE_PATH, b"proxy");
        write(redirected.path(), NESTED_CORE_RELATIVE_PATH, b"core");
        write(redirected.path(), OVERRIDE_RELATIVE_PATH, b"target.dll");
        assert_eq!(
            inspect_ue4ss_loader_identity(redirected.path(), &Ue4ssLoaderIdentityLimits::default())
                .unwrap()
                .status,
            Ue4ssLoaderIdentityStatus::Unsafe
        );

        let legacy = TempDir::new().unwrap();
        write(legacy.path(), PROXY_RELATIVE_PATH, b"proxy");
        write(legacy.path(), NESTED_CORE_RELATIVE_PATH, b"core");
        write(legacy.path(), LEGACY_XINPUT_RELATIVE_PATH, b"legacy");
        assert_eq!(
            inspect_ue4ss_loader_identity(legacy.path(), &Ue4ssLoaderIdentityLimits::default())
                .unwrap()
                .status,
            Ue4ssLoaderIdentityStatus::Unsafe
        );

        let oversized = TempDir::new().unwrap();
        write(oversized.path(), PROXY_RELATIVE_PATH, b"proxy");
        write(oversized.path(), NESTED_CORE_RELATIVE_PATH, b"core");
        assert_eq!(
            inspect_ue4ss_loader_identity(
                oversized.path(),
                &Ue4ssLoaderIdentityLimits {
                    max_binary_bytes: 4
                }
            )
            .unwrap()
            .status,
            Ue4ssLoaderIdentityStatus::Incomplete
        );
    }

    #[cfg(unix)]
    #[test]
    fn never_hashes_a_linked_proxy() {
        use std::os::unix::fs::symlink;

        let temporary = TempDir::new().unwrap();
        let outside = temporary.path().join("outside.dll");
        fs::write(&outside, b"proxy").unwrap();
        let proxy = temporary.path().join(PROXY_RELATIVE_PATH);
        fs::create_dir_all(proxy.parent().unwrap()).unwrap();
        symlink(&outside, proxy).unwrap();
        write(temporary.path(), NESTED_CORE_RELATIVE_PATH, b"core");

        let report =
            inspect_ue4ss_loader_identity(temporary.path(), &Ue4ssLoaderIdentityLimits::default())
                .unwrap();
        assert_eq!(report.status, Ue4ssLoaderIdentityStatus::Unsafe);
        assert!(report.identity.is_none());
    }

    #[test]
    fn distinguishes_unsafe_unsatisfied_and_unknown_policy_results() {
        let report = exact_report("proxy", "core");
        let mut recipe = recipe(report.identity.as_ref().unwrap(), "recognized");
        recipe.ue4ss_loader_policies[0].allowed_build_ids.clear();
        assert_eq!(
            evaluate_ue4ss_loader_policy(&recipe, "policy", &report).status,
            Ue4ssLoaderPolicyStatus::RequirementUnsatisfied
        );
        recipe.ue4ss_loader_policies[0]
            .known_unsafe_build_ids
            .push("recognized".to_owned());
        assert_eq!(
            evaluate_ue4ss_loader_policy(&recipe, "policy", &report).status,
            Ue4ssLoaderPolicyStatus::KnownUnsafe
        );
        assert_eq!(
            evaluate_ue4ss_loader_policy(&recipe, "missing", &report).status,
            Ue4ssLoaderPolicyStatus::UnknownBlocked
        );
        let unknown = exact_report("different", "bytes");
        assert_eq!(
            evaluate_ue4ss_loader_policy(&recipe, "policy", &unknown).status,
            Ue4ssLoaderPolicyStatus::UnknownBlocked
        );
    }

    fn write(root: &Path, relative: &str, bytes: &[u8]) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn exact_report(proxy: &str, core: &str) -> Ue4ssLoaderIdentityReport {
        Ue4ssLoaderIdentityReport {
            schema_version: 1,
            game_root: PathBuf::from("game"),
            status: Ue4ssLoaderIdentityStatus::Exact,
            identity: Some(Ue4ssLoaderBinaryIdentity {
                layout: Ue4ssLoaderLayout::Nested,
                proxy: Ue4ssBinaryHashObservation {
                    relative_path: PROXY_RELATIVE_PATH.to_owned(),
                    bytes: 1,
                    sha256: proxy.to_owned(),
                },
                core: Ue4ssBinaryHashObservation {
                    relative_path: NESTED_CORE_RELATIVE_PATH.to_owned(),
                    bytes: 1,
                    sha256: core.to_owned(),
                },
            }),
            issues: Vec::new(),
        }
    }

    fn recipe(identity: &Ue4ssLoaderBinaryIdentity, build_id: &str) -> BuildRecipe {
        BuildRecipe {
            app_id: 3_552_140,
            build_id: 23_896_268,
            engine_version: "5.4.4".to_owned(),
            pak_version: 11,
            critical_files: Vec::new(),
            ue4ss_loader_builds: vec![Ue4ssLoaderBuildRecipe {
                id: build_id.to_owned(),
                proxy_sha256: identity.proxy.sha256.clone(),
                core_sha256: identity.core.sha256.clone(),
            }],
            ue4ss_loader_policies: vec![Ue4ssLoaderPolicyRecipe {
                id: "policy".to_owned(),
                allowed_build_ids: vec![build_id.to_owned()],
                known_unsafe_build_ids: Vec::new(),
            }],
        }
    }
}
