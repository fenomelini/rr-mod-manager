use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const RETRO_REWIND_APP_ID: u32 = 3_552_140;
pub const SUPPORTED_BUILD_ID: u64 = 23_896_268;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationSource {
    SteamLibrary,
    UserOverride,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayoutStatus {
    Complete,
    Partial,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildStatus {
    SupportedExact,
    SupportedModified,
    SupportedUnfingerprinted,
    KnownUnsupported,
    Unknown,
    PartialInstall,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashStatus {
    Match,
    Mismatch,
    Missing,
    NotChecked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CriticalFileRecipe {
    pub relative_path: PathBuf,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildRecipe {
    pub app_id: u32,
    pub build_id: u64,
    pub engine_version: String,
    pub pak_version: u32,
    pub critical_files: Vec<CriticalFileRecipe>,
    #[serde(default)]
    pub ue4ss_loader_builds: Vec<Ue4ssLoaderBuildRecipe>,
    #[serde(default)]
    pub ue4ss_loader_policies: Vec<Ue4ssLoaderPolicyRecipe>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ue4ssLoaderBuildRecipe {
    pub id: String,
    pub proxy_sha256: String,
    pub core_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ue4ssLoaderPolicyRecipe {
    pub id: String,
    pub allowed_build_ids: Vec<String>,
    #[serde(default)]
    pub known_unsafe_build_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CriticalFileInspection {
    pub relative_path: PathBuf,
    pub exists: bool,
    pub size: Option<u64>,
    pub expected_size: Option<u64>,
    pub sha256: Option<String>,
    pub expected_sha256: Option<String>,
    pub hash_status: HashStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameInstallation {
    pub app_id: u32,
    pub build_id: u64,
    pub state_flags: u64,
    pub install_dir_name: String,
    pub steam_root: PathBuf,
    pub library_root: PathBuf,
    pub manifest_path: PathBuf,
    pub game_root: PathBuf,
    pub source: InstallationSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallationInspection {
    pub installation: GameInstallation,
    pub layout_status: LayoutStatus,
    pub build_status: BuildStatus,
    pub game_running: bool,
    pub writable_hint: bool,
    pub critical_files: Vec<CriticalFileInspection>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryReport {
    pub installations: Vec<InstallationInspection>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilePackageSelection {
    pub artifact_sha256: String,
    pub variant: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakLoadOrderPreference {
    pub build_id: u64,
    pub first_pak_sha256: String,
    pub second_pak_sha256: String,
    pub winner_pak_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub revision: u64,
    pub packages: Vec<ProfilePackageSelection>,
    #[serde(default)]
    pub pak_load_order: Vec<PakLoadOrderPreference>,
}
