pub mod vdf;

use rrmm_domain::{
    BuildRecipe, BuildStatus, CriticalFileInspection, DiscoveryReport, GameInstallation,
    HashStatus, InstallationInspection, InstallationSource, LayoutStatus, RETRO_REWIND_APP_ID,
    SUPPORTED_BUILD_ID,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
#[cfg(not(target_os = "windows"))]
use sysinfo::UpdateKind;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
use thiserror::Error;
use vdf::Value;
#[cfg(target_os = "windows")]
use winreg::{
    RegKey,
    enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY},
};

const REQUIRED_GAME_PATHS: &[&str] = &[
    "RetroRewind.exe",
    "RetroRewind/Binaries/Win64/RetroRewind-Win64-Shipping.exe",
    "RetroRewind/Content/Paks/RetroRewind-Windows.pak",
];
const GAME_START_TIMEOUT: Duration = Duration::from_secs(30);
const GAME_START_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Error)]
pub enum SteamError {
    #[error("failed to read {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("failed to parse VDF {path}: {source}")]
    Vdf {
        path: PathBuf,
        source: vdf::VdfError,
    },
    #[error("failed to parse build recipe {path}: {source}")]
    Recipe {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("missing or invalid field '{field}' in {path}")]
    InvalidField { path: PathBuf, field: &'static str },
    #[error("manifest {path} belongs to app {actual}, expected {expected}")]
    WrongApp {
        path: PathBuf,
        actual: u32,
        expected: u32,
    },
    #[error("invalid install directory '{value}' in {path}")]
    InvalidInstallDirectory { path: PathBuf, value: String },
    #[error("invalid build recipe: {0}")]
    InvalidRecipe(String),
    #[error("invalid Steam executable: {0}")]
    InvalidSteamExecutable(PathBuf),
    #[error("Retro Rewind is already running")]
    GameAlreadyRunning,
    #[error("failed to launch Retro Rewind through {path}: {source}")]
    Launch { path: PathBuf, source: io::Error },
    #[error(
        "Steam accepted the launch request but Retro Rewind did not start within {seconds} seconds"
    )]
    LaunchTimeout { seconds: u64 },
}

#[derive(Debug, Clone)]
pub struct DiscoveryOptions<'a> {
    pub steam_root_override: Option<&'a Path>,
    pub recipe: Option<&'a BuildRecipe>,
    pub deep: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchReport {
    pub app_id: u32,
    pub steam_executable: PathBuf,
    pub process_id: u32,
    pub game_detected: bool,
}

pub fn launch_game_via_steam(steam_executable: &Path) -> Result<LaunchReport, SteamError> {
    let mut detector = GameProcessDetector::new();
    launch_game_with_guard(steam_executable, || detector.refresh_and_check())
}

fn launch_game_with_guard<F>(
    steam_executable: &Path,
    mut game_running: F,
) -> Result<LaunchReport, SteamError>
where
    F: FnMut() -> bool,
{
    if game_running() {
        return Err(SteamError::GameAlreadyRunning);
    }
    let valid_name = steam_executable
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            ["steam", "steam.exe", "steam_osx", "steam.sh"]
                .iter()
                .any(|expected| name.eq_ignore_ascii_case(expected))
        });
    if !valid_name {
        return Err(SteamError::InvalidSteamExecutable(
            steam_executable.to_path_buf(),
        ));
    }
    let canonical = fs::canonicalize(steam_executable).map_err(|source| SteamError::Launch {
        path: steam_executable.to_path_buf(),
        source,
    })?;
    let metadata = fs::metadata(&canonical).map_err(|source| SteamError::Launch {
        path: canonical.clone(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(SteamError::InvalidSteamExecutable(canonical));
    }
    let mut child = Command::new(steam_executable)
        .arg("-applaunch")
        .arg(RETRO_REWIND_APP_ID.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|source| SteamError::Launch {
            path: canonical.clone(),
            source,
        })?;
    let process_id = child.id();
    thread::spawn(move || {
        let _ = child.wait();
    });
    if !wait_for_game_start(
        &mut game_running,
        GAME_START_TIMEOUT,
        GAME_START_POLL_INTERVAL,
    ) {
        return Err(SteamError::LaunchTimeout {
            seconds: GAME_START_TIMEOUT.as_secs(),
        });
    }
    Ok(LaunchReport {
        app_id: RETRO_REWIND_APP_ID,
        steam_executable: canonical,
        process_id,
        game_detected: true,
    })
}

fn wait_for_game_start<F>(game_running: &mut F, timeout: Duration, poll_interval: Duration) -> bool
where
    F: FnMut() -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        if game_running() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(poll_interval.min(deadline.saturating_duration_since(Instant::now())));
    }
}

pub fn load_build_recipe(path: &Path) -> Result<BuildRecipe, SteamError> {
    let input = read_string(path)?;
    let recipe = serde_json::from_str(&input).map_err(|source| SteamError::Recipe {
        path: path.to_path_buf(),
        source,
    })?;
    validate_build_recipe(&recipe)?;
    Ok(recipe)
}

pub fn validate_build_recipe(recipe: &BuildRecipe) -> Result<(), SteamError> {
    if recipe.app_id != RETRO_REWIND_APP_ID {
        return Err(SteamError::InvalidRecipe(format!(
            "app_id {} is not Retro Rewind",
            recipe.app_id
        )));
    }
    if recipe.build_id == 0 {
        return Err(SteamError::InvalidRecipe(
            "build_id must be non-zero".to_owned(),
        ));
    }

    let mut seen_paths = BTreeSet::new();
    for file in &recipe.critical_files {
        if !is_safe_relative_path(&file.relative_path) {
            return Err(SteamError::InvalidRecipe(format!(
                "critical path '{}' must stay below the game root",
                file.relative_path.display()
            )));
        }
        if !seen_paths.insert(file.relative_path.clone()) {
            return Err(SteamError::InvalidRecipe(format!(
                "duplicate critical path '{}'",
                file.relative_path.display()
            )));
        }
        if file.sha256.len() != 64
            || !file
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(SteamError::InvalidRecipe(format!(
                "invalid lowercase SHA-256 for '{}'",
                file.relative_path.display()
            )));
        }
    }

    let mut build_ids = BTreeSet::new();
    let mut binary_pairs = BTreeSet::new();
    for build in &recipe.ue4ss_loader_builds {
        validate_policy_id("UE4SS loader build", &build.id)?;
        validate_lowercase_sha256("UE4SS proxy", &build.proxy_sha256)?;
        validate_lowercase_sha256("UE4SS core", &build.core_sha256)?;
        if !build_ids.insert(build.id.clone()) {
            return Err(SteamError::InvalidRecipe(format!(
                "duplicate UE4SS loader build ID '{}'",
                build.id
            )));
        }
        if !binary_pairs.insert((&build.proxy_sha256, &build.core_sha256)) {
            return Err(SteamError::InvalidRecipe(format!(
                "duplicate UE4SS loader binary pair for build '{}'",
                build.id
            )));
        }
    }
    let mut policy_ids = BTreeSet::new();
    for policy in &recipe.ue4ss_loader_policies {
        validate_policy_id("UE4SS loader policy", &policy.id)?;
        if !policy_ids.insert(policy.id.clone()) {
            return Err(SteamError::InvalidRecipe(format!(
                "duplicate UE4SS loader policy ID '{}'",
                policy.id
            )));
        }
        if policy.allowed_build_ids.is_empty() {
            return Err(SteamError::InvalidRecipe(format!(
                "UE4SS loader policy '{}' has no allowed builds",
                policy.id
            )));
        }
        let mut references = BTreeSet::new();
        for build_id in &policy.allowed_build_ids {
            if !build_ids.contains(build_id) || !references.insert(build_id) {
                return Err(SteamError::InvalidRecipe(format!(
                    "UE4SS loader policy '{}' has an unknown or duplicate allowed build '{}'",
                    policy.id, build_id
                )));
            }
        }
        for build_id in &policy.known_unsafe_build_ids {
            if !build_ids.contains(build_id) || !references.insert(build_id) {
                return Err(SteamError::InvalidRecipe(format!(
                    "UE4SS loader policy '{}' has an unknown, duplicate, or conflicting unsafe build '{}'",
                    policy.id, build_id
                )));
            }
        }
    }
    Ok(())
}

fn validate_policy_id(role: &str, id: &str) -> Result<(), SteamError> {
    let valid = (3..=127).contains(&id.len())
        && id
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && id.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        });
    if !valid {
        return Err(SteamError::InvalidRecipe(format!(
            "invalid {role} ID '{id}'"
        )));
    }
    Ok(())
}

fn validate_lowercase_sha256(role: &str, sha256: &str) -> Result<(), SteamError> {
    if sha256.len() != 64
        || !sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SteamError::InvalidRecipe(format!(
            "invalid lowercase SHA-256 for {role}"
        )));
    }
    Ok(())
}

pub fn candidate_steam_roots(override_path: Option<&Path>) -> Vec<(PathBuf, InstallationSource)> {
    let mut candidates = Vec::new();
    if let Some(path) = override_path {
        candidates.push((path.to_path_buf(), InstallationSource::UserOverride));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if let Some(home) = dirs::home_dir() {
        #[cfg(target_os = "linux")]
        {
            candidates.push((
                home.join(".local/share/Steam"),
                InstallationSource::SteamLibrary,
            ));
            candidates.push((home.join(".steam/steam"), InstallationSource::SteamLibrary));
            candidates.push((
                home.join(".var/app/com.valvesoftware.Steam/.local/share/Steam"),
                InstallationSource::SteamLibrary,
            ));
        }
        #[cfg(target_os = "macos")]
        candidates.push((
            home.join("Library/Application Support/Steam"),
            InstallationSource::SteamLibrary,
        ));
    }

    #[cfg(target_os = "windows")]
    candidates.extend(
        windows_registry_roots()
            .into_iter()
            .map(|path| (path, InstallationSource::SteamLibrary)),
    );

    #[cfg(target_os = "windows")]
    for variable in ["PROGRAMFILES(X86)", "PROGRAMFILES"] {
        if let Some(value) = std::env::var_os(variable) {
            candidates.push((
                PathBuf::from(value).join("Steam"),
                InstallationSource::SteamLibrary,
            ));
        }
    }

    let mut seen = BTreeSet::new();
    candidates
        .into_iter()
        .filter(|(path, _)| seen.insert(normalized_key(path)))
        .collect()
}

#[cfg(target_os = "windows")]
fn windows_registry_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let current_user = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(steam) = current_user.open_subkey_with_flags("Software\\Valve\\Steam", KEY_READ) {
        if let Ok(path) = steam.get_value::<String, _>("SteamPath") {
            roots.push(PathBuf::from(path));
        }
    }

    let local_machine = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(steam) =
        local_machine.open_subkey_with_flags("Software\\Valve\\Steam", KEY_READ | KEY_WOW64_32KEY)
    {
        if let Ok(path) = steam.get_value::<String, _>("InstallPath") {
            roots.push(PathBuf::from(path));
        }
    }
    roots
}

pub fn discover_installations(options: DiscoveryOptions<'_>) -> DiscoveryReport {
    discover_from_roots(
        candidate_steam_roots(options.steam_root_override),
        options.recipe,
        options.deep,
    )
}

fn discover_from_roots(
    roots: Vec<(PathBuf, InstallationSource)>,
    recipe: Option<&BuildRecipe>,
    deep: bool,
) -> DiscoveryReport {
    let mut report = DiscoveryReport {
        installations: Vec::new(),
        warnings: Vec::new(),
    };
    let mut seen_manifests = BTreeSet::new();

    for (steam_root, source) in roots {
        if !steam_root.is_dir() {
            continue;
        }

        let mut libraries = vec![steam_root.clone()];
        let library_file = steam_root.join("steamapps/libraryfolders.vdf");
        if library_file.is_file() {
            match parse_library_folders(&library_file) {
                Ok(extra) => libraries.extend(extra),
                Err(error) => report.warnings.push(error.to_string()),
            }
        }

        let mut seen_libraries = BTreeSet::new();
        for library_root in libraries {
            if !seen_libraries.insert(normalized_key(&library_root)) {
                continue;
            }
            let manifest_path = library_root
                .join("steamapps")
                .join(format!("appmanifest_{RETRO_REWIND_APP_ID}.acf"));
            if !manifest_path.is_file() || !seen_manifests.insert(normalized_key(&manifest_path)) {
                continue;
            }

            match inspect_manifest(
                &manifest_path,
                &steam_root,
                &library_root,
                source.clone(),
                recipe,
                deep,
            ) {
                Ok(inspection) => report.installations.push(inspection),
                Err(error) => report.warnings.push(error.to_string()),
            }
        }
    }

    report
}

pub fn parse_library_folders(path: &Path) -> Result<Vec<PathBuf>, SteamError> {
    let document = read_vdf(path)?;
    let folders = object_field(&document, "libraryfolders", path)?;
    let mut result = Vec::new();
    for value in folders.values() {
        let Some(folder) = value.as_object() else {
            continue;
        };
        let Some(library_path) = folder.get("path").and_then(Value::as_str) else {
            continue;
        };
        result.push(PathBuf::from(library_path));
    }
    Ok(result)
}

pub fn inspect_manifest(
    manifest_path: &Path,
    steam_root: &Path,
    library_root: &Path,
    source: InstallationSource,
    recipe: Option<&BuildRecipe>,
    deep: bool,
) -> Result<InstallationInspection, SteamError> {
    if let Some(recipe) = recipe {
        validate_build_recipe(recipe)?;
    }
    let document = read_vdf(manifest_path)?;
    let app_state = object_field(&document, "AppState", manifest_path)?;
    let app_id = integer_field::<u32>(app_state, "appid", manifest_path)?;
    if app_id != RETRO_REWIND_APP_ID {
        return Err(SteamError::WrongApp {
            path: manifest_path.to_path_buf(),
            actual: app_id,
            expected: RETRO_REWIND_APP_ID,
        });
    }

    let build_id = integer_field::<u64>(app_state, "buildid", manifest_path)?;
    let state_flags = integer_field::<u64>(app_state, "StateFlags", manifest_path)?;
    let install_dir_name = string_field(app_state, "installdir", manifest_path)?.to_owned();
    if !is_safe_install_directory(&install_dir_name) {
        return Err(SteamError::InvalidInstallDirectory {
            path: manifest_path.to_path_buf(),
            value: install_dir_name,
        });
    }
    let game_root = library_root
        .join("steamapps/common")
        .join(&install_dir_name);
    let layout_status = inspect_layout(&game_root);

    let installation = GameInstallation {
        app_id,
        build_id,
        state_flags,
        install_dir_name,
        steam_root: steam_root.to_path_buf(),
        library_root: library_root.to_path_buf(),
        manifest_path: manifest_path.to_path_buf(),
        game_root: game_root.clone(),
        source,
    };

    let mut warnings = Vec::new();
    let matching_recipe =
        recipe.filter(|candidate| candidate.app_id == app_id && candidate.build_id == build_id);
    if recipe.is_some() && matching_recipe.is_none() {
        warnings.push("the supplied build recipe does not match this installation".to_owned());
    }
    let critical_files = matching_recipe
        .map(|candidate| inspect_critical_files(&game_root, candidate, deep))
        .unwrap_or_default();
    let build_status = classify_build(
        build_id,
        state_flags,
        &layout_status,
        matching_recipe,
        deep,
        &critical_files,
    );
    if !deep && matching_recipe.is_some() {
        warnings.push("critical-file hashes were not calculated; run a deep inspection".to_owned());
    }

    Ok(InstallationInspection {
        installation,
        layout_status,
        build_status,
        game_running: is_game_running(),
        writable_hint: is_writable_hint(&game_root),
        critical_files,
        warnings,
    })
}

fn classify_build(
    build_id: u64,
    state_flags: u64,
    layout_status: &LayoutStatus,
    recipe: Option<&BuildRecipe>,
    deep: bool,
    critical_files: &[CriticalFileInspection],
) -> BuildStatus {
    if state_flags & 4 == 0 || *layout_status != LayoutStatus::Complete {
        return BuildStatus::PartialInstall;
    }
    if build_id != SUPPORTED_BUILD_ID {
        return if recipe.is_some() {
            BuildStatus::KnownUnsupported
        } else {
            BuildStatus::Unknown
        };
    }
    if recipe.is_none() || !deep {
        return BuildStatus::SupportedUnfingerprinted;
    }
    if critical_files
        .iter()
        .all(|file| file.hash_status == HashStatus::Match)
    {
        BuildStatus::SupportedExact
    } else {
        BuildStatus::SupportedModified
    }
}

fn inspect_layout(game_root: &Path) -> LayoutStatus {
    if !game_root.is_dir() {
        return LayoutStatus::Missing;
    }
    if REQUIRED_GAME_PATHS
        .iter()
        .all(|relative| game_root.join(relative).is_file())
    {
        LayoutStatus::Complete
    } else {
        LayoutStatus::Partial
    }
}

fn inspect_critical_files(
    game_root: &Path,
    recipe: &BuildRecipe,
    deep: bool,
) -> Vec<CriticalFileInspection> {
    recipe
        .critical_files
        .iter()
        .map(|expected| {
            let path = game_root.join(&expected.relative_path);
            let metadata = fs::metadata(&path).ok();
            let size = metadata.as_ref().map(fs::Metadata::len);
            let actual_hash = if deep && size == Some(expected.size) {
                sha256_file(&path).ok()
            } else {
                None
            };
            let hash_status = if metadata.is_none() {
                HashStatus::Missing
            } else if size != Some(expected.size) {
                HashStatus::Mismatch
            } else if !deep {
                HashStatus::NotChecked
            } else if actual_hash.as_deref() == Some(expected.sha256.as_str()) {
                HashStatus::Match
            } else {
                HashStatus::Mismatch
            };

            CriticalFileInspection {
                relative_path: expected.relative_path.clone(),
                exists: metadata.is_some(),
                size,
                expected_size: Some(expected.size),
                sha256: actual_hash,
                expected_sha256: Some(expected.sha256.clone()),
                hash_status,
            }
        })
        .collect()
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    // Windows GUI executables reserve a 1 MiB main-thread stack by default.
    // Keep the large streaming buffer on the heap so a deep inspection cannot
    // exhaust that entire stack before the first read.
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

struct GameProcessDetector {
    system: System,
}

impl GameProcessDetector {
    fn new() -> Self {
        Self {
            system: System::new(),
        }
    }

    fn refresh_and_check(&mut self) -> bool {
        #[cfg(target_os = "windows")]
        let refresh_kind = ProcessRefreshKind::nothing().without_tasks();
        #[cfg(not(target_os = "windows"))]
        let refresh_kind = ProcessRefreshKind::nothing()
            .with_exe(UpdateKind::Always)
            .with_cmd(UpdateKind::Always)
            .without_tasks();
        self.system
            .refresh_processes_specifics(ProcessesToUpdate::All, true, refresh_kind);
        self.system.processes().values().any(|process| {
            process_identity_matches(
                process.name(),
                process.exe().and_then(Path::file_name),
                process.cmd().iter().map(AsRef::as_ref),
            )
        })
    }
}

pub fn is_game_running() -> bool {
    GameProcessDetector::new().refresh_and_check()
}

fn process_identity_matches<'a, I>(name: &OsStr, executable: Option<&OsStr>, command: I) -> bool
where
    I: IntoIterator<Item = &'a OsStr>,
{
    const EXECUTABLES: &[&str] = &["RetroRewind.exe", "RetroRewind-Win64-Shipping.exe"];
    let matches = |value: &OsStr| {
        let value = value.to_string_lossy();
        let basename = value.rsplit(['/', '\\']).next().unwrap_or(&value);
        EXECUTABLES
            .iter()
            .any(|expected| basename.eq_ignore_ascii_case(expected))
            || (cfg!(target_os = "linux") && basename == "RetroRewind-Win")
    };
    matches(name) || executable.is_some_and(matches) || command.into_iter().any(matches)
}

fn is_writable_hint(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| !metadata.permissions().readonly())
        .unwrap_or(false)
}

fn read_vdf(path: &Path) -> Result<BTreeMap<String, Value>, SteamError> {
    let input = read_string(path)?;
    vdf::parse(&input).map_err(|source| SteamError::Vdf {
        path: path.to_path_buf(),
        source,
    })
}

fn read_string(path: &Path) -> Result<String, SteamError> {
    fs::read_to_string(path).map_err(|source| SteamError::Read {
        path: path.to_path_buf(),
        source,
    })
}

fn object_field<'a>(
    object: &'a BTreeMap<String, Value>,
    field: &'static str,
    path: &Path,
) -> Result<&'a BTreeMap<String, Value>, SteamError> {
    object
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| SteamError::InvalidField {
            path: path.to_path_buf(),
            field,
        })
}

fn string_field<'a>(
    object: &'a BTreeMap<String, Value>,
    field: &'static str,
    path: &Path,
) -> Result<&'a str, SteamError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| SteamError::InvalidField {
            path: path.to_path_buf(),
            field,
        })
}

fn integer_field<T>(
    object: &BTreeMap<String, Value>,
    field: &'static str,
    path: &Path,
) -> Result<T, SteamError>
where
    T: std::str::FromStr,
{
    string_field(object, field, path)?
        .parse()
        .map_err(|_| SteamError::InvalidField {
            path: path.to_path_buf(),
            field,
        })
}

fn normalized_key(path: &Path) -> String {
    let key = fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned();
    #[cfg(target_os = "windows")]
    return key.to_lowercase();
    #[cfg(not(target_os = "windows"))]
    key
}

fn is_safe_install_directory(value: &str) -> bool {
    let mut components = Path::new(value).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn is_safe_relative_path(path: &Path) -> bool {
    let mut found_component = false;
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return false;
        }
        found_component = true;
    }
    found_component
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrmm_domain::CriticalFileRecipe;
    use std::io::Write;
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    fn parses_library_folders() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("libraryfolders.vdf");
        fs::write(
            &path,
            r#""libraryfolders" { "0" { "path" "/games/Steam" } "contentstatsid" "1" }"#,
        )
        .unwrap();
        assert_eq!(
            parse_library_folders(&path).unwrap(),
            vec![PathBuf::from("/games/Steam")]
        );
    }

    #[test]
    fn discovers_a_unicode_secondary_library() {
        let temporary = TempDir::new().unwrap();
        let steam_root = temporary.path().join("Steam");
        let library = temporary.path().join("Biblioteca Vídeo");
        fs::create_dir_all(steam_root.join("steamapps")).unwrap();
        fs::create_dir_all(library.join("steamapps")).unwrap();
        fs::write(
            steam_root.join("steamapps/libraryfolders.vdf"),
            format!(
                "\"libraryfolders\" {{ \"0\" {{ \"path\" \"{}\" }} }}",
                library.display()
            ),
        )
        .unwrap();
        fs::write(
            library.join(format!("steamapps/appmanifest_{RETRO_REWIND_APP_ID}.acf")),
            format!(
                r#""AppState" {{ "appid" "{RETRO_REWIND_APP_ID}" "StateFlags" "4" "installdir" "RetroRewind" "buildid" "{SUPPORTED_BUILD_ID}" }}"#
            ),
        )
        .unwrap();

        let report = discover_from_roots(
            vec![(steam_root, InstallationSource::UserOverride)],
            None,
            false,
        );
        assert!(report.warnings.is_empty());
        assert_eq!(report.installations.len(), 1);
        assert_eq!(report.installations[0].installation.library_root, library);
    }

    #[test]
    fn inspects_an_exact_supported_installation() {
        let temporary = TempDir::new().unwrap();
        let library = temporary.path();
        let game = library.join("steamapps/common/RetroRewind");
        for relative in REQUIRED_GAME_PATHS {
            let path = game.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            File::create(path).unwrap().write_all(b"fixture").unwrap();
        }
        let manifest = library.join(format!("steamapps/appmanifest_{RETRO_REWIND_APP_ID}.acf"));
        fs::write(
            &manifest,
            format!(
                r#""AppState" {{ "appid" "{RETRO_REWIND_APP_ID}" "StateFlags" "4" "installdir" "RetroRewind" "buildid" "{SUPPORTED_BUILD_ID}" }}"#
            ),
        )
        .unwrap();
        let hash = sha256_file(&game.join(REQUIRED_GAME_PATHS[0])).unwrap();
        let recipe = BuildRecipe {
            app_id: RETRO_REWIND_APP_ID,
            build_id: SUPPORTED_BUILD_ID,
            engine_version: "5.4.4".to_owned(),
            pak_version: 11,
            critical_files: vec![CriticalFileRecipe {
                relative_path: PathBuf::from(REQUIRED_GAME_PATHS[0]),
                size: 7,
                sha256: hash,
            }],
            ue4ss_loader_builds: Vec::new(),
            ue4ss_loader_policies: Vec::new(),
        };

        let inspection = inspect_manifest(
            &manifest,
            library,
            library,
            InstallationSource::UserOverride,
            Some(&recipe),
            true,
        )
        .unwrap();

        assert_eq!(inspection.layout_status, LayoutStatus::Complete);
        assert_eq!(inspection.build_status, BuildStatus::SupportedExact);
    }

    #[test]
    fn hashes_a_file_on_a_windows_sized_stack() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("critical-file.bin");
        fs::write(&path, b"Retro Rewind critical file").unwrap();

        let hash = std::thread::Builder::new()
            .stack_size(1024 * 1024)
            .spawn(move || sha256_file(&path))
            .unwrap()
            .join()
            .unwrap()
            .unwrap();

        assert_eq!(
            hash,
            "d5a059ae136b1d89d77c2bc10fdb7be3bc3bdd96c3138994fd71ea045c6cc92d"
        );
    }

    #[test]
    fn marks_incomplete_layout_as_partial_install() {
        let temporary = TempDir::new().unwrap();
        let manifest = temporary
            .path()
            .join(format!("appmanifest_{RETRO_REWIND_APP_ID}.acf"));
        fs::write(
            &manifest,
            format!(
                r#""AppState" {{ "appid" "{RETRO_REWIND_APP_ID}" "StateFlags" "4" "installdir" "RetroRewind" "buildid" "{SUPPORTED_BUILD_ID}" }}"#
            ),
        )
        .unwrap();

        let inspection = inspect_manifest(
            &manifest,
            temporary.path(),
            temporary.path(),
            InstallationSource::UserOverride,
            None,
            false,
        )
        .unwrap();
        assert_eq!(inspection.build_status, BuildStatus::PartialInstall);
        assert_eq!(inspection.layout_status, LayoutStatus::Missing);
    }

    #[test]
    fn rejects_install_directory_traversal() {
        let temporary = TempDir::new().unwrap();
        let manifest = temporary.path().join("appmanifest_3552140.acf");
        fs::write(
            &manifest,
            format!(
                r#""AppState" {{ "appid" "{RETRO_REWIND_APP_ID}" "StateFlags" "4" "installdir" "../outside" "buildid" "{SUPPORTED_BUILD_ID}" }}"#
            ),
        )
        .unwrap();

        let error = inspect_manifest(
            &manifest,
            temporary.path(),
            temporary.path(),
            InstallationSource::UserOverride,
            None,
            false,
        )
        .unwrap_err();
        assert!(matches!(error, SteamError::InvalidInstallDirectory { .. }));
    }

    #[test]
    fn rejects_recipe_path_traversal() {
        let recipe = BuildRecipe {
            app_id: RETRO_REWIND_APP_ID,
            build_id: SUPPORTED_BUILD_ID,
            engine_version: "5.4.4".to_owned(),
            pak_version: 11,
            critical_files: vec![CriticalFileRecipe {
                relative_path: PathBuf::from("../outside.exe"),
                size: 1,
                sha256: "a".repeat(64),
            }],
            ue4ss_loader_builds: Vec::new(),
            ue4ss_loader_policies: Vec::new(),
        };
        assert!(matches!(
            validate_build_recipe(&recipe),
            Err(SteamError::InvalidRecipe(_))
        ));
    }

    #[test]
    fn validates_exact_ue4ss_build_and_policy_references() {
        let mut recipe = BuildRecipe {
            app_id: RETRO_REWIND_APP_ID,
            build_id: SUPPORTED_BUILD_ID,
            engine_version: "5.4.4".to_owned(),
            pak_version: 11,
            critical_files: Vec::new(),
            ue4ss_loader_builds: vec![rrmm_domain::Ue4ssLoaderBuildRecipe {
                id: "ue4ss-test-build".to_owned(),
                proxy_sha256: "a".repeat(64),
                core_sha256: "b".repeat(64),
            }],
            ue4ss_loader_policies: vec![rrmm_domain::Ue4ssLoaderPolicyRecipe {
                id: "ue4ss:test-policy".to_owned(),
                allowed_build_ids: vec!["ue4ss-test-build".to_owned()],
                known_unsafe_build_ids: Vec::new(),
            }],
        };
        validate_build_recipe(&recipe).unwrap();

        recipe.ue4ss_loader_policies[0].allowed_build_ids = vec!["662df915".to_owned()];
        assert!(matches!(
            validate_build_recipe(&recipe),
            Err(SteamError::InvalidRecipe(_))
        ));

        recipe.ue4ss_loader_policies[0].allowed_build_ids = vec!["ue4ss-test-build".to_owned()];
        recipe.ue4ss_loader_policies[0]
            .known_unsafe_build_ids
            .push("ue4ss-test-build".to_owned());
        assert!(matches!(
            validate_build_recipe(&recipe),
            Err(SteamError::InvalidRecipe(_))
        ));
    }

    #[test]
    fn distinguishes_known_unsupported_and_unknown_builds() {
        let recipe = BuildRecipe {
            app_id: RETRO_REWIND_APP_ID,
            build_id: 1,
            engine_version: "unknown".to_owned(),
            pak_version: 11,
            critical_files: Vec::new(),
            ue4ss_loader_builds: Vec::new(),
            ue4ss_loader_policies: Vec::new(),
        };
        assert_eq!(
            classify_build(1, 4, &LayoutStatus::Complete, Some(&recipe), false, &[]),
            BuildStatus::KnownUnsupported
        );
        assert_eq!(
            classify_build(2, 4, &LayoutStatus::Complete, None, false, &[]),
            BuildStatus::Unknown
        );
    }

    #[cfg(unix)]
    #[test]
    fn launches_only_the_fixed_retro_rewind_steam_command() {
        use std::cell::Cell;
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temporary = TempDir::new().unwrap();
        let steam = temporary.path().join("steam");
        let wrapper = temporary.path().join("bin_steam.sh");
        let capture = temporary.path().join("arguments.txt");
        fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"{}\"\n",
                capture.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&wrapper, &steam).unwrap();

        let checks = Cell::new(0);
        let report = launch_game_with_guard(&steam, || {
            let current = checks.get();
            checks.set(current + 1);
            current > 0
        })
        .unwrap();

        assert_eq!(report.app_id, RETRO_REWIND_APP_ID);
        assert!(report.process_id > 0);
        assert!(report.game_detected);
        for _ in 0..50 {
            if capture.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            fs::read_to_string(capture).unwrap(),
            format!("-applaunch\n{RETRO_REWIND_APP_ID}\n")
        );
    }

    #[test]
    fn recognizes_full_paths_and_linux_truncated_game_process_names() {
        assert!(process_identity_matches(
            OsStr::new("wine64"),
            Some(OsStr::new("RetroRewind-Win64-Shipping.exe")),
            std::iter::empty::<&OsStr>(),
        ));
        assert!(process_identity_matches(
            OsStr::new("wine64"),
            None,
            [OsStr::new("Z:\\games\\RetroRewind-Win64-Shipping.exe")],
        ));
        #[cfg(target_os = "linux")]
        assert!(process_identity_matches(
            OsStr::new("RetroRewind-Win"),
            None,
            std::iter::empty::<&OsStr>(),
        ));
    }

    #[test]
    fn rejects_launch_when_running_or_the_executable_name_is_untrusted() {
        let temporary = TempDir::new().unwrap();
        let executable = temporary.path().join("not-steam");
        fs::write(&executable, b"fixture").unwrap();

        assert!(matches!(
            launch_game_with_guard(&executable, || true),
            Err(SteamError::GameAlreadyRunning)
        ));
        assert!(matches!(
            launch_game_with_guard(&executable, || false),
            Err(SteamError::InvalidSteamExecutable(_))
        ));
    }

    #[test]
    fn launch_wait_detects_start_and_reports_timeout() {
        let mut checks = 0;
        assert!(wait_for_game_start(
            &mut || {
                checks += 1;
                checks == 2
            },
            Duration::from_secs(1),
            Duration::ZERO,
        ));
        assert_eq!(checks, 2);

        assert!(!wait_for_game_start(
            &mut || false,
            Duration::ZERO,
            Duration::ZERO,
        ));
    }
}
