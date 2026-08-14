use rrmm_archive::validate_entry_path;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::path::Component;
use std::path::{Path, PathBuf};
use thiserror::Error;

mod activation;
mod identity;
mod lua_advisory;
mod runtime_log;
mod safe_file;

pub use activation::{
    ModsTxtAnalysis, ModsTxtAnalysisStatus, ModsTxtDirective, ModsTxtEntry, Ue4ssActivationLimits,
    Ue4ssActivationReport, Ue4ssActivationScope, Ue4ssDeclaredActivation, Ue4ssModuleActivation,
    analyze_ue4ss_activation,
};
pub use identity::{
    Ue4ssBinaryHashObservation, Ue4ssLoaderBinaryIdentity, Ue4ssLoaderIdentityLimits,
    Ue4ssLoaderIdentityReport, Ue4ssLoaderIdentityStatus, Ue4ssLoaderLayout,
    Ue4ssLoaderPolicyEvaluation, Ue4ssLoaderPolicyStatus, evaluate_ue4ss_loader_policy,
    inspect_ue4ss_loader_identity,
};
pub use lua_advisory::{
    LuaAdvisoryArgument, LuaAdvisoryFinding, LuaAdvisoryLimits, LuaAdvisoryModule,
    LuaAdvisoryReport, LuaAdvisoryScript, LuaPropertyWriteFinding, LuaPropertyWriteKind,
    Ue4ssLuaApi, analyze_ue4ss_lua,
};
pub use runtime_log::{
    Ue4ssRuntimeBeta, Ue4ssRuntimeBuildConfiguration, Ue4ssRuntimeCompiler, Ue4ssRuntimeExecutable,
    Ue4ssRuntimeGitSha, Ue4ssRuntimeLogFile, Ue4ssRuntimeLogFreshness, Ue4ssRuntimeLogLimits,
    Ue4ssRuntimeLogReport, Ue4ssRuntimeLogStatus, Ue4ssRuntimeLogText, Ue4ssRuntimeModEvent,
    Ue4ssRuntimeModEventKind, Ue4ssRuntimeModPhase, Ue4ssRuntimeModuleKind, Ue4ssRuntimeSession,
    Ue4ssRuntimeVersion, analyze_ue4ss_runtime_logs, read_ue4ss_runtime_log_tail_text,
    read_ue4ss_runtime_log_text,
};
pub use safe_file::{read_game_relative_file, replace_game_relative_file};

const WIN64_RELATIVE_ROOT: &str = "RetroRewind/Binaries/Win64";
const UE4SS_RELATIVE_ROOT: &str = "RetroRewind/Binaries/Win64/ue4ss";
const MODS_RELATIVE_ROOT: &str = "RetroRewind/Binaries/Win64/ue4ss/Mods";
const FLAT_MODS_RELATIVE_ROOT: &str = "RetroRewind/Binaries/Win64/Mods";
const PROXY_RELATIVE_PATH: &str = "RetroRewind/Binaries/Win64/dwmapi.dll";
const OVERRIDE_RELATIVE_PATH: &str = "RetroRewind/Binaries/Win64/override.txt";
const NESTED_CORE_RELATIVE_PATH: &str = "RetroRewind/Binaries/Win64/ue4ss/UE4SS.dll";
const FLAT_CORE_RELATIVE_PATH: &str = "RetroRewind/Binaries/Win64/UE4SS.dll";
const NESTED_SETTINGS_RELATIVE_PATH: &str = "RetroRewind/Binaries/Win64/ue4ss/UE4SS-settings.ini";
const FLAT_SETTINGS_RELATIVE_PATH: &str = "RetroRewind/Binaries/Win64/UE4SS-settings.ini";
const LEGACY_XINPUT_RELATIVE_PATH: &str = "RetroRewind/Binaries/Win64/xinput1_3.dll";
const NESTED_LOG_RELATIVE_PATH: &str = "RetroRewind/Binaries/Win64/ue4ss/UE4SS.log";
const FLAT_LOG_RELATIVE_PATH: &str = "RetroRewind/Binaries/Win64/UE4SS.log";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssInventoryLimits {
    pub max_entries: usize,
    pub max_depth: usize,
}

impl Default for Ue4ssInventoryLimits {
    fn default() -> Self {
        Self {
            max_entries: 20_000,
            max_depth: 32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssInventoryReport {
    pub schema_version: u32,
    pub game_root: PathBuf,
    pub complete: bool,
    pub installation_status: Ue4ssInstallationStatus,
    pub version_evidence: Ue4ssVersionEvidence,
    pub loader: Ue4ssLoaderInventory,
    pub ue4ss_root: EntryObservation,
    pub mods_root: EntryObservation,
    pub mods_txt: ModsTxtObservation,
    pub installation_files: Vec<Ue4ssFileObservation>,
    pub modules: Vec<Ue4ssModuleInventory>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ue4ssInstallationStatus {
    Absent,
    Partial,
    ModuleTreeDetected,
    Unsafe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ue4ssVersionEvidence {
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssLoaderInventory {
    pub status: Ue4ssLoaderStatus,
    pub canonical_proxy_candidate: EntryObservation,
    pub override_txt: EntryObservation,
    pub nested_core_candidate: EntryObservation,
    pub flat_core_candidate: EntryObservation,
    pub nested_settings_candidate: EntryObservation,
    pub flat_settings_candidate: EntryObservation,
    pub legacy_xinput_candidate: EntryObservation,
    pub risks: Vec<Ue4ssLoaderRisk>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ue4ssLoaderStatus {
    Absent,
    SupportingFilesOnly,
    NestedAutomaticCandidate,
    FlatAutomaticCandidate,
    OverrideTargetUnverified,
    CorePresentWithoutCanonicalProxy,
    CanonicalProxyWithoutCore,
    Ambiguous,
    Unsafe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ue4ssLoaderRisk {
    CanonicalProxyIdentityUnverified,
    CoreIdentityUnverified,
    OverrideTargetUnverified,
    MultipleLayoutsDetected,
    ObsoleteXinputCandidateCoLocated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryObservation {
    pub relative_path: String,
    pub status: EntryStatus,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryStatus {
    Missing,
    Incomplete,
    RegularFile,
    Directory,
    UnsafeLink,
    Special,
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModsTxtObservation {
    pub entry: EntryObservation,
    pub semantics: ModsTxtSemantics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModsTxtSemantics {
    Missing,
    PresentUnparsed,
    Unsafe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssModuleInventory {
    pub name: String,
    pub relative_path: String,
    pub kind: Ue4ssModuleKind,
    pub declared_state: DeclaredModuleState,
    pub main_lua: EntryObservation,
    pub enabled_txt: EntryObservation,
    pub files: Vec<Ue4ssFileObservation>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ue4ssModuleKind {
    Lua,
    Native,
    Hybrid,
    Unknown,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredModuleState {
    EnabledMarkerPresent,
    MarkerAbsent,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssFileObservation {
    pub relative_path: String,
    pub bytes: Option<u64>,
    pub kind: Ue4ssFileKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ue4ssFileKind {
    Lua,
    ConfigurationCandidate,
    StateMarker,
    NativeUnverified,
    ExecutableUnverified,
    Other,
    UnsafeLink,
    Special,
}

#[derive(Debug, Error)]
pub enum Ue4ssInventoryError {
    #[error("failed to access UE4SS inventory path {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("UE4SS game root is not a directory: {0}")]
    InvalidGameRoot(PathBuf),
}

pub fn inventory_ue4ss(
    game_root: &Path,
    limits: &Ue4ssInventoryLimits,
) -> Result<Ue4ssInventoryReport, Ue4ssInventoryError> {
    let game_root = fs::canonicalize(game_root).map_err(|source| Ue4ssInventoryError::Io {
        path: game_root.to_path_buf(),
        source,
    })?;
    if !metadata(&game_root)?.is_dir() {
        return Err(Ue4ssInventoryError::InvalidGameRoot(game_root));
    }

    let nested_root = observe_beneath(&game_root, UE4SS_RELATIVE_ROOT, UE4SS_RELATIVE_ROOT);
    let nested_mods = observe_beneath(&game_root, MODS_RELATIVE_ROOT, MODS_RELATIVE_ROOT);
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
    let support_path_unsafe = observation_unsafe_directory(&nested_root)
        || observation_unsafe_directory(&nested_mods)
        || observation_unsafe_directory(&flat_mods);
    let use_flat_layout = match (
        nested_core_candidate.status == EntryStatus::RegularFile,
        flat_core_candidate.status == EntryStatus::RegularFile,
    ) {
        (false, true) => true,
        (true, _) => false,
        (false, false) if flat_mods.status == EntryStatus::Directory => {
            nested_mods.status != EntryStatus::Directory
        }
        (false, false) if nested_mods.status == EntryStatus::Directory => false,
        (false, false) => flat_layout_detected && !nested_layout_detected,
    };
    let (ue4ss_root, mods_root, ue4ss_relative_root, mods_relative_root) = if use_flat_layout {
        (
            observe_beneath(&game_root, WIN64_RELATIVE_ROOT, WIN64_RELATIVE_ROOT),
            flat_mods,
            WIN64_RELATIVE_ROOT,
            FLAT_MODS_RELATIVE_ROOT,
        )
    } else {
        (
            nested_root,
            nested_mods,
            UE4SS_RELATIVE_ROOT,
            MODS_RELATIVE_ROOT,
        )
    };
    let ue4ss_path = game_root.join(path_from_relative(ue4ss_relative_root));
    let mods_path = game_root.join(path_from_relative(mods_relative_root));
    let mods_txt_relative = format!("{mods_relative_root}/mods.txt");
    let mods_txt_entry = observe_beneath(&game_root, &mods_txt_relative, &mods_txt_relative);
    let mods_txt = ModsTxtObservation {
        semantics: match mods_txt_entry.status {
            EntryStatus::Missing => ModsTxtSemantics::Missing,
            EntryStatus::RegularFile => ModsTxtSemantics::PresentUnparsed,
            _ => ModsTxtSemantics::Unsafe,
        },
        entry: mods_txt_entry,
    };

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

    let has_installation_evidence = nested_root_present
        || nested_layout_detected
        || flat_layout_detected
        || observation_present(&loader.canonical_proxy_candidate)
        || observation_present(&loader.override_txt);
    let installation_status = if loader.status == Ue4ssLoaderStatus::Unsafe
        || observation_unsafe_directory(&ue4ss_root)
        || observation_unsafe_directory(&mods_root)
    {
        Ue4ssInstallationStatus::Unsafe
    } else if mods_root.status == EntryStatus::Directory {
        Ue4ssInstallationStatus::ModuleTreeDetected
    } else if has_installation_evidence {
        Ue4ssInstallationStatus::Partial
    } else {
        Ue4ssInstallationStatus::Absent
    };

    let mut scan = ScanState::new(limits);
    if installation_status == Ue4ssInstallationStatus::Unsafe {
        scan.incomplete("required UE4SS paths are unsafe or unreadable".to_owned());
    }
    if mods_txt.semantics == ModsTxtSemantics::Unsafe
        && mods_txt.entry.status != EntryStatus::Missing
    {
        scan.incomplete("mods.txt is not a safe regular file".to_owned());
    }
    if loader.status == Ue4ssLoaderStatus::Unsafe {
        scan.incomplete("loader candidate paths are unsafe or unreadable".to_owned());
    }
    let installation_files = if !use_flat_layout && ue4ss_root.status == EntryStatus::Directory {
        scan_tree(
            &ue4ss_path,
            &game_root,
            Some(&mods_path),
            mods_root.status == EntryStatus::Directory,
            &mut scan,
        )?
    } else {
        Vec::new()
    };
    let modules = if mods_root.status == EntryStatus::Directory {
        scan_modules(&mods_path, &game_root, &mut scan)?
    } else {
        Vec::new()
    };

    let mut issues = scan.issues;
    if mods_txt.semantics == ModsTxtSemantics::PresentUnparsed {
        issues.push(
            "mods.txt is present, but its grammar and precedence are not verified; content was not read"
                .to_owned(),
        );
    }
    if installation_status != Ue4ssInstallationStatus::Absent {
        issues.push(
            "no stable installed-file contract proves the UE4SS version or commit".to_owned(),
        );
    }
    if loader
        .risks
        .contains(&Ue4ssLoaderRisk::CanonicalProxyIdentityUnverified)
    {
        issues.push(
            "dwmapi.dll matches the canonical UE4SS proxy filename, but its binary identity and activation are unverified"
                .to_owned(),
        );
    }
    if loader
        .risks
        .contains(&Ue4ssLoaderRisk::CoreIdentityUnverified)
    {
        issues.push(
            "UE4SS.dll filename candidates were not loaded or accepted as binary identity evidence"
                .to_owned(),
        );
    }
    if loader
        .risks
        .contains(&Ue4ssLoaderRisk::OverrideTargetUnverified)
    {
        issues.push(
            "override.txt may redirect the canonical proxy, but its mutable target was not read or resolved"
                .to_owned(),
        );
    }
    if loader
        .risks
        .contains(&Ue4ssLoaderRisk::MultipleLayoutsDetected)
    {
        issues.push(
            "both nested and flat UE4SS layout evidence exists; one module tree was inventoried from core and fallback evidence, but effective loading remains ambiguous"
                .to_owned(),
        );
    }
    if loader
        .risks
        .contains(&Ue4ssLoaderRisk::ObsoleteXinputCandidateCoLocated)
    {
        issues.push(
            "xinput1_3.dll is co-located with canonical UE4SS 3.x loader candidates; official 3.0 release notes require removing the obsolete proxy"
                .to_owned(),
        );
    }
    issues.sort();
    issues.dedup();

    Ok(Ue4ssInventoryReport {
        schema_version: 2,
        game_root,
        complete: scan.complete,
        installation_status,
        version_evidence: Ue4ssVersionEvidence::Unknown,
        loader,
        ue4ss_root,
        mods_root,
        mods_txt,
        installation_files,
        modules,
        issues,
    })
}

struct LoaderClassificationInput {
    canonical_proxy_candidate: EntryObservation,
    override_txt: EntryObservation,
    nested_core_candidate: EntryObservation,
    flat_core_candidate: EntryObservation,
    nested_settings_candidate: EntryObservation,
    flat_settings_candidate: EntryObservation,
    legacy_xinput_candidate: EntryObservation,
    nested_root_present: bool,
    nested_layout_detected: bool,
    flat_layout_detected: bool,
    support_path_unsafe: bool,
}

fn classify_loader(input: LoaderClassificationInput) -> Ue4ssLoaderInventory {
    let LoaderClassificationInput {
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
    } = input;
    let proxy_present = canonical_proxy_candidate.status == EntryStatus::RegularFile;
    let override_present = override_txt.status == EntryStatus::RegularFile;
    let nested_core_present = nested_core_candidate.status == EntryStatus::RegularFile;
    let flat_core_present = flat_core_candidate.status == EntryStatus::RegularFile;
    let core_present = nested_core_present || flat_core_present;
    let current_candidate_present = observation_present(&canonical_proxy_candidate)
        || nested_root_present
        || nested_layout_detected
        || flat_layout_detected
        || observation_present(&override_txt);
    let loader_path_unsafe = support_path_unsafe
        || observation_unsafe_file(&canonical_proxy_candidate)
        || observation_unsafe_file(&override_txt)
        || observation_unsafe_file(&nested_core_candidate)
        || observation_unsafe_file(&flat_core_candidate)
        || observation_unsafe_file(&nested_settings_candidate)
        || observation_unsafe_file(&flat_settings_candidate)
        || (current_candidate_present && observation_unsafe_file(&legacy_xinput_candidate));

    let status = if loader_path_unsafe {
        Ue4ssLoaderStatus::Unsafe
    } else if proxy_present && override_present {
        Ue4ssLoaderStatus::OverrideTargetUnverified
    } else if nested_layout_detected && flat_layout_detected {
        Ue4ssLoaderStatus::Ambiguous
    } else if proxy_present && nested_core_present {
        Ue4ssLoaderStatus::NestedAutomaticCandidate
    } else if proxy_present && flat_core_present {
        Ue4ssLoaderStatus::FlatAutomaticCandidate
    } else if core_present {
        Ue4ssLoaderStatus::CorePresentWithoutCanonicalProxy
    } else if proxy_present {
        Ue4ssLoaderStatus::CanonicalProxyWithoutCore
    } else if nested_root_present
        || nested_layout_detected
        || flat_layout_detected
        || override_present
    {
        Ue4ssLoaderStatus::SupportingFilesOnly
    } else {
        Ue4ssLoaderStatus::Absent
    };

    let mut risks = Vec::new();
    if proxy_present {
        risks.push(Ue4ssLoaderRisk::CanonicalProxyIdentityUnverified);
    }
    if core_present {
        risks.push(Ue4ssLoaderRisk::CoreIdentityUnverified);
    }
    if override_present {
        risks.push(Ue4ssLoaderRisk::OverrideTargetUnverified);
    }
    if nested_layout_detected && flat_layout_detected {
        risks.push(Ue4ssLoaderRisk::MultipleLayoutsDetected);
    }
    if proxy_present && core_present && legacy_xinput_candidate.status == EntryStatus::RegularFile {
        risks.push(Ue4ssLoaderRisk::ObsoleteXinputCandidateCoLocated);
    }

    Ue4ssLoaderInventory {
        status,
        canonical_proxy_candidate,
        override_txt,
        nested_core_candidate,
        flat_core_candidate,
        nested_settings_candidate,
        flat_settings_candidate,
        legacy_xinput_candidate,
        risks,
    }
}

fn observation_present(observation: &EntryObservation) -> bool {
    observation.status != EntryStatus::Missing
}

fn observation_unsafe_file(observation: &EntryObservation) -> bool {
    !matches!(
        observation.status,
        EntryStatus::Missing | EntryStatus::RegularFile
    )
}

fn observation_unsafe_directory(observation: &EntryObservation) -> bool {
    !matches!(
        observation.status,
        EntryStatus::Missing | EntryStatus::Directory
    )
}

fn scan_modules(
    mods_root: &Path,
    game_root: &Path,
    scan: &mut ScanState<'_>,
) -> Result<Vec<Ue4ssModuleInventory>, Ue4ssInventoryError> {
    let mut entries = read_directory_bounded(mods_root, game_root, scan)?;
    entries.sort_by(|left, right| left.file_name.cmp(&right.file_name));
    let mut modules = Vec::new();
    let mut names = BTreeMap::new();

    for entry in entries {
        let path = mods_root.join(&entry.file_name);
        let file_type = entry.file_type;
        let Some(name) = entry.file_name.to_str().map(str::to_owned) else {
            scan.incomplete(format!(
                "module-root entry name is not valid Unicode: {}",
                path.to_string_lossy()
            ));
            continue;
        };
        if name.eq_ignore_ascii_case("mods.txt") && !file_type.is_dir() {
            if name != "mods.txt" {
                scan.incomplete(format!(
                    "case-equivalent mods.txt entry does not match the required path spelling: {}",
                    path.to_string_lossy()
                ));
            }
            if file_type.is_symlink() {
                scan.incomplete(format!(
                    "mods.txt link was not followed: {}",
                    path.to_string_lossy()
                ));
            }
            continue;
        }
        if file_type.is_symlink() {
            scan.incomplete(format!(
                "module link was not followed: {}",
                path.to_string_lossy()
            ));
            continue;
        }
        if !file_type.is_dir() {
            scan.incomplete(format!(
                "non-module entry at Mods root was not inventoried as a module: {}",
                path.to_string_lossy()
            ));
            continue;
        }
        let relative = relative_string(&path, game_root);
        if relative.contains('\\') {
            scan.incomplete(format!(
                "module path contains an ambiguous backslash component: {relative}"
            ));
            continue;
        }
        let normalized = match validate_entry_path(&relative, true, scan.limits.max_depth) {
            Ok(normalized) => normalized,
            Err(error) => {
                scan.incomplete(format!("unsafe module path '{relative}': {error}"));
                continue;
            }
        };
        if let Some(previous) = names.insert(normalized.collision_key, normalized.path.clone()) {
            scan.incomplete(format!(
                "module path collision between '{previous}' and '{}'",
                normalized.path
            ));
        }
        modules.push(scan_module(&name, &path, game_root, scan)?);
    }
    modules.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(modules)
}

fn scan_module(
    name: &str,
    module_root: &Path,
    game_root: &Path,
    scan: &mut ScanState<'_>,
) -> Result<Ue4ssModuleInventory, Ue4ssInventoryError> {
    let relative_path = relative_string(module_root, game_root);
    let main_path = format!("{relative_path}/Scripts/main.lua");
    let enabled_path = format!("{relative_path}/enabled.txt");
    let mut main_lua = observe_beneath(module_root, "Scripts/main.lua", &main_path);
    let mut enabled_txt = observe_beneath(module_root, "enabled.txt", &enabled_path);
    let mut issues = Vec::new();
    let issues_before = scan.issues.len();
    let truncations_before = scan.truncations;
    let files = scan_tree(module_root, game_root, None, false, scan)?;
    let module_scan_complete =
        scan.issues.len() == issues_before && scan.truncations == truncations_before;

    for file in &files {
        let suffix = file
            .relative_path
            .strip_prefix(&format!("{relative_path}/"))
            .unwrap_or(&file.relative_path);
        if suffix.eq_ignore_ascii_case("Scripts/main.lua") {
            merge_special_observation(&mut main_lua, file, &mut issues, "Scripts/main.lua");
        }
        if suffix.eq_ignore_ascii_case("enabled.txt") {
            merge_special_observation(&mut enabled_txt, file, &mut issues, "enabled.txt");
        }
    }
    if !module_scan_complete {
        mark_missing_incomplete(&mut main_lua, "module scan was incomplete");
        mark_missing_incomplete(&mut enabled_txt, "module scan was incomplete");
    }

    let has_lua = files
        .iter()
        .any(|file| matches!(file.kind, Ue4ssFileKind::Lua));
    let has_native = files.iter().any(|file| {
        matches!(
            file.kind,
            Ue4ssFileKind::NativeUnverified | Ue4ssFileKind::ExecutableUnverified
        )
    });
    let kind = if !module_scan_complete {
        Ue4ssModuleKind::Indeterminate
    } else {
        match (has_lua, has_native) {
            (true, false) => Ue4ssModuleKind::Lua,
            (false, true) => Ue4ssModuleKind::Native,
            (true, true) => Ue4ssModuleKind::Hybrid,
            (false, false) => Ue4ssModuleKind::Unknown,
        }
    };
    let declared_state = match enabled_txt.status {
        EntryStatus::RegularFile => DeclaredModuleState::EnabledMarkerPresent,
        EntryStatus::Missing => DeclaredModuleState::MarkerAbsent,
        _ => DeclaredModuleState::Indeterminate,
    };
    if main_lua.status != EntryStatus::RegularFile && kind != Ue4ssModuleKind::Native {
        issues.push("module has no regular Scripts/main.lua entry".to_owned());
    }
    if has_native {
        issues
            .push("module contains native or executable content; safety is unverified".to_owned());
    }
    issues.sort();
    issues.dedup();

    Ok(Ue4ssModuleInventory {
        name: name.to_owned(),
        relative_path,
        kind,
        declared_state,
        main_lua,
        enabled_txt,
        files,
        issues,
    })
}

fn scan_tree(
    root: &Path,
    game_root: &Path,
    excluded_root: Option<&Path>,
    exclude_matched_root: bool,
    scan: &mut ScanState<'_>,
) -> Result<Vec<Ue4ssFileObservation>, Ue4ssInventoryError> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    let mut collisions = BTreeMap::new();
    let excluded_collision_key = excluded_root.and_then(|excluded| {
        validate_entry_path(
            &relative_string(excluded, game_root),
            true,
            scan.limits.max_depth,
        )
        .ok()
        .map(|normalized| normalized.collision_key)
    });
    let mut excluded_matches = 0_usize;

    while let Some(directory) = pending.pop() {
        let mut entries = read_directory_bounded(&directory, game_root, scan)?;
        entries.sort_by(|left, right| left.file_name.cmp(&right.file_name));
        for entry in entries.into_iter().rev() {
            let path = directory.join(&entry.file_name);
            let file_type = entry.file_type;
            let relative = relative_string(&path, game_root);
            let Some(_) = path.file_name().and_then(|name| name.to_str()) else {
                scan.incomplete(format!(
                    "filesystem entry name is not valid Unicode: {}",
                    path.to_string_lossy()
                ));
                continue;
            };
            if relative.contains('\\') {
                scan.incomplete(format!(
                    "UE4SS path contains an ambiguous backslash component: {relative}"
                ));
                continue;
            }
            let normalized =
                match validate_entry_path(&relative, file_type.is_dir(), scan.limits.max_depth) {
                    Ok(normalized) => normalized,
                    Err(error) => {
                        scan.incomplete(format!("unsafe UE4SS path '{relative}': {error}"));
                        continue;
                    }
                };
            if excluded_collision_key
                .as_ref()
                .is_some_and(|excluded| excluded == &normalized.collision_key)
            {
                if exclude_matched_root {
                    excluded_matches += 1;
                    if excluded_matches > 1 {
                        scan.incomplete(format!(
                            "multiple case-equivalent module roots match {MODS_RELATIVE_ROOT}"
                        ));
                    }
                    continue;
                } else {
                    scan.incomplete(format!(
                        "case-equivalent module root does not match the required path spelling: {}",
                        normalized.path
                    ));
                }
            }
            if let Some(previous) =
                collisions.insert(normalized.collision_key, normalized.path.clone())
                && previous != normalized.path
            {
                scan.incomplete(format!(
                    "UE4SS path collision between '{previous}' and '{}'",
                    normalized.path
                ));
            }
            if file_type.is_symlink() {
                files.push(Ue4ssFileObservation {
                    relative_path: normalized.path,
                    bytes: None,
                    kind: Ue4ssFileKind::UnsafeLink,
                });
                scan.incomplete(format!(
                    "filesystem link was not followed: {}",
                    path.to_string_lossy()
                ));
            } else if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() {
                files.push(Ue4ssFileObservation {
                    kind: classify_file(&normalized.path),
                    relative_path: normalized.path,
                    bytes: entry.bytes,
                });
            } else {
                files.push(Ue4ssFileObservation {
                    relative_path: normalized.path,
                    bytes: None,
                    kind: Ue4ssFileKind::Special,
                });
                scan.incomplete(format!(
                    "special filesystem entry was not opened: {}",
                    path.to_string_lossy()
                ));
            }
        }
    }
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(files)
}

fn classify_file(path: &str) -> Ue4ssFileKind {
    let name = path.rsplit('/').next().unwrap_or(path);
    let folded = name.to_ascii_lowercase();
    let extension = folded.rsplit_once('.').map(|(_, extension)| extension);
    if folded == "enabled.txt" {
        Ue4ssFileKind::StateMarker
    } else if folded == "config.lua" {
        Ue4ssFileKind::ConfigurationCandidate
    } else {
        match extension {
            Some("lua") => Ue4ssFileKind::Lua,
            Some("ini" | "cfg" | "json" | "toml" | "tsv") => Ue4ssFileKind::ConfigurationCandidate,
            Some("dll") => Ue4ssFileKind::NativeUnverified,
            Some("exe" | "bat" | "cmd" | "com" | "cpl" | "msi" | "ps1" | "scr") => {
                Ue4ssFileKind::ExecutableUnverified
            }
            _ => Ue4ssFileKind::Other,
        }
    }
}

fn merge_special_observation(
    observation: &mut EntryObservation,
    file: &Ue4ssFileObservation,
    issues: &mut Vec<String>,
    role: &str,
) {
    let file_status = match file.kind {
        Ue4ssFileKind::UnsafeLink => EntryStatus::UnsafeLink,
        Ue4ssFileKind::Special => EntryStatus::Special,
        _ => EntryStatus::RegularFile,
    };
    if observation.relative_path == file.relative_path && observation.status == file_status {
        return;
    }
    if observation.status != EntryStatus::Missing {
        observation.status = EntryStatus::Special;
        observation.detail = Some(format!("multiple case-equivalent {role} entries"));
        issues.push(format!("multiple case-equivalent {role} entries"));
        return;
    }
    observation.relative_path = file.relative_path.clone();
    observation.status = file_status;
    if observation.status != EntryStatus::RegularFile {
        observation.detail = Some(format!("{role} is not a regular file"));
    }
}

fn observe_beneath(root: &Path, traversal_path: &str, reported_path: &str) -> EntryObservation {
    let components: Vec<_> = traversal_path.split('/').collect();
    let mut current = root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                let file_type = metadata.file_type();
                if file_type.is_symlink() {
                    return EntryObservation {
                        relative_path: reported_path.to_owned(),
                        status: EntryStatus::UnsafeLink,
                        detail: Some(format!(
                            "filesystem link in required path was not followed: {}",
                            components[..=index].join("/")
                        )),
                    };
                }
                if index + 1 < components.len() && !file_type.is_dir() {
                    return EntryObservation {
                        relative_path: reported_path.to_owned(),
                        status: EntryStatus::Special,
                        detail: Some(format!(
                            "required parent is not a directory: {}",
                            components[..=index].join("/")
                        )),
                    };
                }
                if index + 1 == components.len() {
                    let status = if file_type.is_file() {
                        EntryStatus::RegularFile
                    } else if file_type.is_dir() {
                        EntryStatus::Directory
                    } else {
                        EntryStatus::Special
                    };
                    return EntryObservation {
                        relative_path: reported_path.to_owned(),
                        status,
                        detail: None,
                    };
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return missing_observation(reported_path.to_owned());
            }
            Err(error) => {
                return EntryObservation {
                    relative_path: reported_path.to_owned(),
                    status: EntryStatus::Unreadable,
                    detail: Some(error.to_string()),
                };
            }
        }
    }
    missing_observation(reported_path.to_owned())
}

fn mark_missing_incomplete(observation: &mut EntryObservation, detail: &str) {
    if observation.status == EntryStatus::Missing {
        observation.status = EntryStatus::Incomplete;
        observation.detail = Some(detail.to_owned());
    }
}

fn missing_observation(relative_path: String) -> EntryObservation {
    EntryObservation {
        relative_path,
        status: EntryStatus::Missing,
        detail: None,
    }
}

struct ScanState<'a> {
    limits: &'a Ue4ssInventoryLimits,
    entries: usize,
    complete: bool,
    issues: Vec<String>,
    limit_reported: bool,
    truncations: usize,
}

impl<'a> ScanState<'a> {
    fn new(limits: &'a Ue4ssInventoryLimits) -> Self {
        Self {
            limits,
            entries: 0,
            complete: true,
            issues: Vec::new(),
            limit_reported: false,
            truncations: 0,
        }
    }

    fn record_limit(&mut self) {
        self.truncations += 1;
        if !self.limit_reported {
            self.incomplete(format!(
                "UE4SS inventory exceeded the {} entry limit",
                self.limits.max_entries
            ));
            self.limit_reported = true;
        }
    }

    fn incomplete(&mut self, issue: String) {
        self.complete = false;
        self.issues.push(issue);
    }
}

fn metadata(path: &Path) -> Result<fs::Metadata, Ue4ssInventoryError> {
    fs::metadata(path).map_err(|source| Ue4ssInventoryError::Io {
        path: path.to_path_buf(),
        source,
    })
}

struct BoundedDirEntry {
    file_name: OsString,
    file_type: fs::FileType,
    bytes: Option<u64>,
}

fn read_directory_bounded(
    path: &Path,
    game_root: &Path,
    scan: &mut ScanState<'_>,
) -> Result<Vec<BoundedDirEntry>, Ue4ssInventoryError> {
    let directory_source = match directory_enumeration_source(path, game_root) {
        Ok(source) => source,
        Err(error) => {
            scan.incomplete(format!(
                "failed to open UE4SS directory without following links {}: {error}",
                path.to_string_lossy()
            ));
            return Ok(Vec::new());
        }
    };
    let directory = match fs::read_dir(&directory_source.path) {
        Ok(directory) => directory,
        Err(error) => {
            scan.incomplete(format!(
                "failed to enumerate UE4SS directory {}: {error}",
                path.to_string_lossy()
            ));
            return Ok(Vec::new());
        }
    };
    let remaining = scan.limits.max_entries.saturating_sub(scan.entries);
    let mut entries = Vec::new();
    let mut observed = 0_usize;
    for entry in directory {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                scan.incomplete(format!(
                    "failed to enumerate an entry in {}: {error}",
                    path.to_string_lossy()
                ));
                continue;
            }
        };
        if observed == remaining {
            scan.entries = scan.limits.max_entries;
            scan.record_limit();
            return Ok(Vec::new());
        }
        observed += 1;
        let entry_path = entry.path();
        let metadata = match fs::symlink_metadata(&entry_path) {
            Ok(metadata) => metadata,
            Err(error) => {
                scan.incomplete(format!(
                    "failed to inspect an entry in {}: {error}",
                    path.to_string_lossy()
                ));
                continue;
            }
        };
        entries.push(BoundedDirEntry {
            file_name: entry.file_name(),
            file_type: metadata.file_type(),
            bytes: metadata.is_file().then_some(metadata.len()),
        });
    }
    scan.entries += observed;
    Ok(entries)
}

struct DirectoryEnumerationSource {
    path: PathBuf,
    _handle: Option<File>,
}

#[cfg(target_os = "linux")]
fn directory_enumeration_source(
    path: &Path,
    game_root: &Path,
) -> io::Result<DirectoryEnumerationSource> {
    let filesystem_root = c"/";
    // SAFETY: filesystem_root is NUL-terminated and flags require no variadic mode argument.
    let descriptor = unsafe {
        libc::open(
            filesystem_root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor is newly owned after a successful open.
    let mut directory = unsafe { File::from_raw_fd(descriptor) };
    for component in game_root.components().chain(
        path.strip_prefix(game_root)
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "directory escaped game root")
            })?
            .components(),
    ) {
        let Component::Normal(component) = component else {
            continue;
        };
        let component = CString::new(component.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory component contains NUL",
            )
        })?;
        // SAFETY: component is NUL-terminated, dirfd is live, and no mode argument is required.
        let child = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if child < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: child is newly owned after a successful openat.
        directory = unsafe { File::from_raw_fd(child) };
    }
    let path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    Ok(DirectoryEnumerationSource {
        path,
        _handle: Some(directory),
    })
}

#[cfg(not(target_os = "linux"))]
fn directory_enumeration_source(
    path: &Path,
    _game_root: &Path,
) -> io::Result<DirectoryEnumerationSource> {
    Ok(DirectoryEnumerationSource {
        path: path.to_path_buf(),
        _handle: None,
    })
}

fn relative_string(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .expect("inventoried path remains beneath game root")
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

fn path_from_relative(path: &str) -> PathBuf {
    path.split('/').collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn reports_an_absent_installation_without_creating_files() {
        let temporary = TempDir::new().unwrap();
        let report = inventory_ue4ss(temporary.path(), &Ue4ssInventoryLimits::default()).unwrap();

        assert_eq!(report.installation_status, Ue4ssInstallationStatus::Absent);
        assert!(report.complete);
        assert!(report.modules.is_empty());
        assert!(!temporary.path().join("RetroRewind").exists());
    }

    #[test]
    fn inventories_lua_native_and_activation_evidence_without_reading_content() {
        let temporary = TempDir::new().unwrap();
        let mods = ue4ss_root(temporary.path()).join("Mods");
        fs::create_dir_all(mods.join("LuaMod/Scripts")).unwrap();
        fs::create_dir_all(mods.join("NativeMod/bin")).unwrap();
        fs::write(
            mods.join("LuaMod/Scripts/main.lua"),
            b"error('must not run')",
        )
        .unwrap();
        fs::write(mods.join("LuaMod/Scripts/config.lua"), b"Enabled = false").unwrap();
        fs::write(mods.join("LuaMod/enabled.txt"), b"").unwrap();
        fs::write(mods.join("NativeMod/bin/main.dll"), b"not loaded").unwrap();
        fs::write(mods.join("mods.txt"), b"unknown syntax must not be parsed").unwrap();

        let report = inventory_ue4ss(temporary.path(), &Ue4ssInventoryLimits::default()).unwrap();

        assert_eq!(
            report.installation_status,
            Ue4ssInstallationStatus::ModuleTreeDetected
        );
        assert_eq!(report.mods_txt.semantics, ModsTxtSemantics::PresentUnparsed);
        assert_eq!(report.modules.len(), 2);
        assert_eq!(report.modules[0].kind, Ue4ssModuleKind::Lua);
        assert_eq!(
            report.modules[0].declared_state,
            DeclaredModuleState::EnabledMarkerPresent
        );
        assert_eq!(report.modules[1].kind, Ue4ssModuleKind::Native);
        assert!(
            report.modules[1]
                .issues
                .iter()
                .any(|issue| issue.contains("unverified"))
        );
        assert_eq!(
            fs::read(mods.join("LuaMod/Scripts/main.lua")).unwrap(),
            b"error('must not run')"
        );
    }

    #[test]
    fn distinguishes_partial_and_unsafe_module_trees() {
        let partial = TempDir::new().unwrap();
        fs::create_dir_all(ue4ss_root(partial.path())).unwrap();
        let report = inventory_ue4ss(partial.path(), &Ue4ssInventoryLimits::default()).unwrap();
        assert_eq!(report.installation_status, Ue4ssInstallationStatus::Partial);

        #[cfg(unix)]
        {
            let unsafe_root = TempDir::new().unwrap();
            let ue4ss = ue4ss_root(unsafe_root.path());
            fs::create_dir_all(ue4ss.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(partial.path(), &ue4ss).unwrap();
            let report =
                inventory_ue4ss(unsafe_root.path(), &Ue4ssInventoryLimits::default()).unwrap();
            assert_eq!(report.installation_status, Ue4ssInstallationStatus::Unsafe);
        }
    }

    #[test]
    #[cfg(unix)]
    fn never_follows_links_inside_a_module() {
        let temporary = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        fs::write(outside.path().join("outside.lua"), b"outside").unwrap();
        let module = ue4ss_root(temporary.path()).join("Mods/LinkedMod");
        fs::create_dir_all(&module).unwrap();
        std::os::unix::fs::symlink(outside.path(), module.join("Scripts")).unwrap();

        let report = inventory_ue4ss(temporary.path(), &Ue4ssInventoryLimits::default()).unwrap();
        let module = &report.modules[0];
        assert!(!report.complete);
        assert_eq!(module.files.len(), 1);
        assert_eq!(module.files[0].kind, Ue4ssFileKind::UnsafeLink);
        assert!(
            !module
                .files
                .iter()
                .any(|file| file.relative_path.ends_with("outside.lua"))
        );
    }

    #[test]
    #[cfg(unix)]
    fn rejects_links_in_intermediate_required_paths() {
        let temporary = TempDir::new().unwrap();
        let game = temporary.path().join("game");
        let outside = temporary.path().join("outside/RetroRewind");
        fs::create_dir_all(outside.join("Binaries/Win64/ue4ss/Mods/OutsideMod")).unwrap();
        fs::create_dir(&game).unwrap();
        std::os::unix::fs::symlink(&outside, game.join("RetroRewind")).unwrap();

        let report = inventory_ue4ss(&game, &Ue4ssInventoryLimits::default()).unwrap();

        assert_eq!(report.installation_status, Ue4ssInstallationStatus::Unsafe);
        assert!(!report.complete);
        assert!(report.modules.is_empty());
        assert_eq!(report.ue4ss_root.status, EntryStatus::UnsafeLink);
    }

    #[test]
    fn wrong_marker_types_are_indeterminate() {
        let temporary = TempDir::new().unwrap();
        let module = ue4ss_root(temporary.path()).join("Mods/Example");
        fs::create_dir_all(module.join("Scripts")).unwrap();
        fs::create_dir(module.join("enabled.txt")).unwrap();
        fs::write(module.join("Scripts/main.lua"), b"").unwrap();

        let report = inventory_ue4ss(temporary.path(), &Ue4ssInventoryLimits::default()).unwrap();

        assert_eq!(report.modules[0].enabled_txt.status, EntryStatus::Directory);
        assert_eq!(
            report.modules[0].declared_state,
            DeclaredModuleState::Indeterminate
        );
    }

    #[test]
    fn reports_entry_limits_without_collecting_the_whole_directory() {
        let temporary = TempDir::new().unwrap();
        let mods = ue4ss_root(temporary.path()).join("Mods");
        fs::create_dir_all(mods.join("Example")).unwrap();
        fs::create_dir_all(mods.join("example")).unwrap();
        fs::write(mods.join("Example/one.lua"), b"").unwrap();
        fs::write(mods.join("example/two.lua"), b"").unwrap();

        let report = inventory_ue4ss(
            temporary.path(),
            &Ue4ssInventoryLimits {
                max_entries: 2,
                max_depth: 32,
            },
        )
        .unwrap();

        assert!(!report.complete);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.contains("entry limit"))
        );
    }

    #[test]
    fn truncated_module_kinds_are_indeterminate() {
        let temporary = TempDir::new().unwrap();
        let module = ue4ss_root(temporary.path()).join("Mods/Example/Scripts");
        fs::create_dir_all(&module).unwrap();
        fs::write(module.join("main.lua"), b"").unwrap();

        let report = inventory_ue4ss(
            temporary.path(),
            &Ue4ssInventoryLimits {
                max_entries: 2,
                max_depth: 32,
            },
        )
        .unwrap();

        assert_eq!(report.modules.len(), 1);
        assert_eq!(report.modules[0].main_lua.status, EntryStatus::RegularFile);
        assert_eq!(report.modules[0].kind, Ue4ssModuleKind::Indeterminate);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn reports_case_folded_module_collisions() {
        let temporary = TempDir::new().unwrap();
        let mods = ue4ss_root(temporary.path()).join("Mods");
        fs::create_dir_all(mods.join("Example")).unwrap();
        fs::create_dir_all(mods.join("example")).unwrap();

        let report = inventory_ue4ss(temporary.path(), &Ue4ssInventoryLimits::default()).unwrap();
        assert!(!report.complete);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.contains("module path collision"))
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn reports_a_case_equivalent_but_noncanonical_mods_root() {
        let temporary = TempDir::new().unwrap();
        fs::create_dir_all(ue4ss_root(temporary.path()).join("mods")).unwrap();

        let report = inventory_ue4ss(temporary.path(), &Ue4ssInventoryLimits::default()).unwrap();

        assert_eq!(report.installation_status, Ue4ssInstallationStatus::Partial);
        assert!(!report.complete);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.contains("required path spelling"))
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn reports_case_equivalent_mods_txt_links() {
        let temporary = TempDir::new().unwrap();
        let mods = ue4ss_root(temporary.path()).join("Mods");
        fs::create_dir_all(&mods).unwrap();
        std::os::unix::fs::symlink(temporary.path(), mods.join("MODS.TXT")).unwrap();

        let report = inventory_ue4ss(temporary.path(), &Ue4ssInventoryLimits::default()).unwrap();

        assert_eq!(report.mods_txt.semantics, ModsTxtSemantics::Missing);
        assert!(!report.complete);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.contains("mods.txt link was not followed"))
        );
    }

    #[test]
    #[cfg(unix)]
    fn does_not_reinterpret_backslashes_as_filesystem_separators() {
        let temporary = TempDir::new().unwrap();
        let module = ue4ss_root(temporary.path()).join("Mods/Example");
        fs::create_dir_all(&module).unwrap();
        fs::write(module.join("Scripts\\main.lua"), b"").unwrap();

        let report = inventory_ue4ss(temporary.path(), &Ue4ssInventoryLimits::default()).unwrap();

        assert!(!report.complete);
        assert_ne!(report.modules[0].main_lua.status, EntryStatus::RegularFile);
        assert!(report.modules[0].files.is_empty());
    }

    #[test]
    fn detects_a_nested_automatic_loader_candidate_without_claiming_identity() {
        let temporary = TempDir::new().unwrap();
        let win64 = temporary
            .path()
            .join(path_from_relative(WIN64_RELATIVE_ROOT));
        fs::create_dir_all(win64.join("ue4ss/Mods")).unwrap();
        fs::write(win64.join("dwmapi.dll"), b"unverified proxy").unwrap();
        fs::write(win64.join("ue4ss/UE4SS.dll"), b"unverified core").unwrap();

        let report = inventory_ue4ss(temporary.path(), &Ue4ssInventoryLimits::default()).unwrap();

        assert_eq!(
            report.loader.status,
            Ue4ssLoaderStatus::NestedAutomaticCandidate
        );
        assert_eq!(report.version_evidence, Ue4ssVersionEvidence::Unknown);
        assert!(
            report
                .loader
                .risks
                .contains(&Ue4ssLoaderRisk::CanonicalProxyIdentityUnverified)
        );
        assert!(
            report
                .loader
                .risks
                .contains(&Ue4ssLoaderRisk::CoreIdentityUnverified)
        );
    }

    #[test]
    fn inventories_flat_modules_without_scanning_the_game_binary_directory() {
        let temporary = TempDir::new().unwrap();
        let win64 = temporary
            .path()
            .join(path_from_relative(WIN64_RELATIVE_ROOT));
        fs::create_dir_all(win64.join("Mods/FlatMod/Scripts")).unwrap();
        fs::write(win64.join("dwmapi.dll"), b"unverified proxy").unwrap();
        fs::write(win64.join("UE4SS.dll"), b"unverified core").unwrap();
        fs::write(win64.join("game.dll"), b"unrelated game binary").unwrap();
        fs::write(win64.join("Mods/FlatMod/Scripts/main.lua"), b"").unwrap();

        let report = inventory_ue4ss(temporary.path(), &Ue4ssInventoryLimits::default()).unwrap();

        assert_eq!(
            report.loader.status,
            Ue4ssLoaderStatus::FlatAutomaticCandidate
        );
        assert_eq!(
            report.installation_status,
            Ue4ssInstallationStatus::ModuleTreeDetected
        );
        assert_eq!(report.ue4ss_root.relative_path, WIN64_RELATIVE_ROOT);
        assert_eq!(report.modules.len(), 1);
        assert_eq!(report.modules[0].name, "FlatMod");
        assert!(report.installation_files.is_empty());
    }

    #[test]
    fn an_empty_nested_directory_does_not_hide_a_complete_flat_layout() {
        let temporary = TempDir::new().unwrap();
        let win64 = temporary
            .path()
            .join(path_from_relative(WIN64_RELATIVE_ROOT));
        fs::create_dir_all(win64.join("ue4ss")).unwrap();
        fs::create_dir_all(win64.join("Mods/FlatMod")).unwrap();
        fs::write(win64.join("dwmapi.dll"), b"unverified proxy").unwrap();
        fs::write(win64.join("UE4SS.dll"), b"unverified core").unwrap();

        let report = inventory_ue4ss(temporary.path(), &Ue4ssInventoryLimits::default()).unwrap();

        assert_eq!(
            report.loader.status,
            Ue4ssLoaderStatus::FlatAutomaticCandidate
        );
        assert_eq!(report.mods_root.relative_path, FLAT_MODS_RELATIVE_ROOT);
        assert_eq!(report.modules[0].name, "FlatMod");
    }

    #[test]
    fn reports_multiple_layouts_without_guessing_the_effective_tree() {
        let temporary = TempDir::new().unwrap();
        let win64 = temporary
            .path()
            .join(path_from_relative(WIN64_RELATIVE_ROOT));
        fs::create_dir_all(win64.join("ue4ss/Mods/NestedMod")).unwrap();
        fs::create_dir_all(win64.join("Mods/FlatMod")).unwrap();
        fs::write(win64.join("ue4ss/UE4SS.dll"), b"nested").unwrap();
        fs::write(win64.join("UE4SS.dll"), b"flat").unwrap();

        let report = inventory_ue4ss(temporary.path(), &Ue4ssInventoryLimits::default()).unwrap();

        assert_eq!(report.loader.status, Ue4ssLoaderStatus::Ambiguous);
        assert!(
            report
                .loader
                .risks
                .contains(&Ue4ssLoaderRisk::MultipleLayoutsDetected)
        );
        assert_eq!(report.mods_root.relative_path, MODS_RELATIVE_ROOT);
        assert_eq!(report.modules[0].name, "NestedMod");
    }

    #[test]
    fn leaves_override_targets_unresolved() {
        let temporary = TempDir::new().unwrap();
        let win64 = temporary
            .path()
            .join(path_from_relative(WIN64_RELATIVE_ROOT));
        fs::create_dir_all(win64.join("ue4ss")).unwrap();
        fs::write(win64.join("dwmapi.dll"), b"unverified proxy").unwrap();
        fs::write(win64.join("ue4ss/UE4SS.dll"), b"unverified core").unwrap();
        fs::write(win64.join("override.txt"), b"C:\\external\\ue4ss").unwrap();

        let report = inventory_ue4ss(temporary.path(), &Ue4ssInventoryLimits::default()).unwrap();

        assert_eq!(
            report.loader.status,
            Ue4ssLoaderStatus::OverrideTargetUnverified
        );
        assert!(
            report
                .loader
                .risks
                .contains(&Ue4ssLoaderRisk::OverrideTargetUnverified)
        );
        assert_eq!(
            fs::read(win64.join("override.txt")).unwrap(),
            b"C:\\external\\ue4ss"
        );
    }

    #[test]
    fn warns_about_an_obsolete_xinput_candidate_only_with_three_x_candidates() {
        let temporary = TempDir::new().unwrap();
        let win64 = temporary
            .path()
            .join(path_from_relative(WIN64_RELATIVE_ROOT));
        fs::create_dir_all(win64.join("ue4ss")).unwrap();
        fs::write(win64.join("dwmapi.dll"), b"unverified proxy").unwrap();
        fs::write(win64.join("ue4ss/UE4SS.dll"), b"unverified core").unwrap();
        fs::write(win64.join("xinput1_3.dll"), b"possibly obsolete").unwrap();

        let report = inventory_ue4ss(temporary.path(), &Ue4ssInventoryLimits::default()).unwrap();

        assert!(
            report
                .loader
                .risks
                .contains(&Ue4ssLoaderRisk::ObsoleteXinputCandidateCoLocated)
        );
    }

    #[test]
    fn treats_a_canonical_proxy_without_a_core_as_partial() {
        let temporary = TempDir::new().unwrap();
        let win64 = temporary
            .path()
            .join(path_from_relative(WIN64_RELATIVE_ROOT));
        fs::create_dir_all(&win64).unwrap();
        fs::write(win64.join("dwmapi.dll"), b"unverified proxy").unwrap();

        let report = inventory_ue4ss(temporary.path(), &Ue4ssInventoryLimits::default()).unwrap();

        assert_eq!(
            report.loader.status,
            Ue4ssLoaderStatus::CanonicalProxyWithoutCore
        );
        assert_eq!(report.installation_status, Ue4ssInstallationStatus::Partial);
    }

    #[test]
    fn reports_settings_evidence_that_influences_layout_selection() {
        let temporary = TempDir::new().unwrap();
        let win64 = temporary
            .path()
            .join(path_from_relative(WIN64_RELATIVE_ROOT));
        fs::create_dir_all(&win64).unwrap();
        fs::write(win64.join("UE4SS-settings.ini"), b"[General]").unwrap();

        let report = inventory_ue4ss(temporary.path(), &Ue4ssInventoryLimits::default()).unwrap();

        assert_eq!(report.loader.status, Ue4ssLoaderStatus::SupportingFilesOnly);
        assert_eq!(
            report.loader.flat_settings_candidate.status,
            EntryStatus::RegularFile
        );
        assert_eq!(report.ue4ss_root.relative_path, WIN64_RELATIVE_ROOT);
    }

    #[test]
    #[cfg(unix)]
    fn rejects_links_at_loader_candidate_paths() {
        let temporary = TempDir::new().unwrap();
        let win64 = temporary
            .path()
            .join(path_from_relative(WIN64_RELATIVE_ROOT));
        fs::create_dir_all(&win64).unwrap();
        std::os::unix::fs::symlink(temporary.path(), win64.join("dwmapi.dll")).unwrap();

        let report = inventory_ue4ss(temporary.path(), &Ue4ssInventoryLimits::default()).unwrap();

        assert_eq!(report.loader.status, Ue4ssLoaderStatus::Unsafe);
        assert_eq!(report.installation_status, Ue4ssInstallationStatus::Unsafe);
        assert!(!report.complete);
    }

    #[test]
    #[cfg(unix)]
    fn ignores_an_isolated_unsafe_xinput_candidate_as_ue4ss_evidence() {
        let temporary = TempDir::new().unwrap();
        let win64 = temporary
            .path()
            .join(path_from_relative(WIN64_RELATIVE_ROOT));
        fs::create_dir_all(&win64).unwrap();
        std::os::unix::fs::symlink(temporary.path(), win64.join("xinput1_3.dll")).unwrap();

        let report = inventory_ue4ss(temporary.path(), &Ue4ssInventoryLimits::default()).unwrap();

        assert_eq!(report.loader.status, Ue4ssLoaderStatus::Absent);
        assert_eq!(report.installation_status, Ue4ssInstallationStatus::Absent);
        assert!(report.complete);
    }

    #[test]
    fn classifies_configuration_and_native_files_conservatively() {
        assert_eq!(classify_file("Module/Scripts/main.lua"), Ue4ssFileKind::Lua);
        assert_eq!(
            classify_file("Module/Scripts/config.lua"),
            Ue4ssFileKind::ConfigurationCandidate
        );
        assert_eq!(
            classify_file("Module/state.tsv"),
            Ue4ssFileKind::ConfigurationCandidate
        );
        assert_eq!(
            classify_file("Module/main.DLL"),
            Ue4ssFileKind::NativeUnverified
        );
    }

    fn ue4ss_root(game_root: &Path) -> PathBuf {
        game_root.join(path_from_relative(UE4SS_RELATIVE_ROOT))
    }
}
