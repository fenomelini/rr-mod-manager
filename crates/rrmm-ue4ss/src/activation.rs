use super::{
    EntryObservation, EntryStatus, Ue4ssInventoryError, Ue4ssInventoryLimits, inventory_ue4ss,
};
use crate::safe_file::open_file_beneath;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssActivationLimits {
    pub max_bytes: u64,
    pub max_line_bytes: usize,
    pub max_lines: usize,
    pub max_entries: usize,
}

impl Default for Ue4ssActivationLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
            max_line_bytes: 16 * 1024,
            max_lines: 20_000,
            max_entries: 10_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssActivationReport {
    pub schema_version: u32,
    pub game_root: PathBuf,
    pub complete: bool,
    pub scope: Ue4ssActivationScope,
    pub mods_root: EntryObservation,
    pub mods_txt: ModsTxtAnalysis,
    pub modules: Vec<Ue4ssModuleActivation>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ue4ssActivationScope {
    SelectedTreeOnly,
    SelectedTreeFromAmbiguousLayouts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModsTxtAnalysis {
    pub entry: EntryObservation,
    pub status: ModsTxtAnalysisStatus,
    pub complete: bool,
    pub bytes: u64,
    pub entries: Vec<ModsTxtEntry>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModsTxtAnalysisStatus {
    Missing,
    Parsed,
    Invalid,
    Unsafe,
    UnsupportedPlatform,
    Unreadable,
    LimitExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModsTxtEntry {
    pub line: usize,
    pub name: String,
    pub directive: ModsTxtDirective,
    pub matched_module: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModsTxtDirective {
    Enable,
    Disable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssModuleActivation {
    pub name: String,
    pub relative_path: String,
    pub declared_state: Ue4ssDeclaredActivation,
    pub enabled_txt: EntryObservation,
    pub mods_txt_lines: Vec<usize>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ue4ssDeclaredActivation {
    EnabledByMarker,
    EnabledByModsTxt,
    EnabledByBoth,
    DisabledByModsTxt,
    Unlisted,
    Indeterminate,
}

pub fn analyze_ue4ss_activation(
    game_root: &Path,
    inventory_limits: &Ue4ssInventoryLimits,
    activation_limits: &Ue4ssActivationLimits,
) -> Result<Ue4ssActivationReport, Ue4ssInventoryError> {
    let inventory = inventory_ue4ss(game_root, inventory_limits)?;
    let module_names: BTreeSet<_> = inventory
        .modules
        .iter()
        .map(|module| module.name.clone())
        .collect();
    let mods_txt = analyze_mods_txt(
        &inventory.game_root,
        inventory.mods_txt.entry.clone(),
        &module_names,
        activation_limits,
    );
    let mut directives: BTreeMap<&str, Vec<&ModsTxtEntry>> = BTreeMap::new();
    for entry in &mods_txt.entries {
        if entry.matched_module {
            directives.entry(&entry.name).or_default().push(entry);
        }
    }

    let mut modules = Vec::with_capacity(inventory.modules.len());
    for module in inventory.modules {
        let module_directives = directives
            .get(module.name.as_str())
            .cloned()
            .unwrap_or_default();
        let has_enable = module_directives
            .iter()
            .any(|entry| entry.directive == ModsTxtDirective::Enable);
        let has_disable = module_directives
            .iter()
            .any(|entry| entry.directive == ModsTxtDirective::Disable);
        let marker_present = matches!(
            module.enabled_txt.status,
            EntryStatus::RegularFile | EntryStatus::Directory
        );
        let marker_known = matches!(
            module.enabled_txt.status,
            EntryStatus::RegularFile | EntryStatus::Directory | EntryStatus::Missing
        );
        let declared_state = if marker_present && has_enable {
            Ue4ssDeclaredActivation::EnabledByBoth
        } else if has_enable {
            Ue4ssDeclaredActivation::EnabledByModsTxt
        } else if marker_present {
            Ue4ssDeclaredActivation::EnabledByMarker
        } else if !marker_known || !mods_txt.complete {
            Ue4ssDeclaredActivation::Indeterminate
        } else if has_disable {
            Ue4ssDeclaredActivation::DisabledByModsTxt
        } else {
            Ue4ssDeclaredActivation::Unlisted
        };
        let mut issues = module.issues;
        if module_directives.len() > 1 {
            issues.push(
                "module has duplicate mods.txt directives; repeated-start behavior is UE4SS-version-specific"
                    .to_owned(),
            );
        }
        if marker_present && has_disable {
            issues.push(
                "mods.txt disables this module, but enabled.txt independently enables it"
                    .to_owned(),
            );
        }
        if module.enabled_txt.status == EntryStatus::Directory {
            issues.push(
                "enabled.txt exists as a directory; UE4SS treats existence as enabling, but the marker is non-canonical"
                    .to_owned(),
            );
        }
        issues.sort();
        issues.dedup();
        modules.push(Ue4ssModuleActivation {
            name: module.name,
            relative_path: module.relative_path,
            declared_state,
            enabled_txt: module.enabled_txt,
            mods_txt_lines: module_directives.iter().map(|entry| entry.line).collect(),
            issues,
        });
    }

    let scope = if inventory
        .loader
        .risks
        .contains(&super::Ue4ssLoaderRisk::MultipleLayoutsDetected)
    {
        Ue4ssActivationScope::SelectedTreeFromAmbiguousLayouts
    } else {
        Ue4ssActivationScope::SelectedTreeOnly
    };
    let mut issues = mods_txt.issues.clone();
    if !inventory.complete {
        issues.push("the underlying UE4SS inventory was incomplete".to_owned());
    }
    issues.push(
        "UE4SS settings or environment may select other module roots or a controlling mods.txt; selectors were not evaluated"
            .to_owned(),
    );
    issues.push(
        "declared evidence is limited to the selected tree and is not effective runtime-load evidence"
            .to_owned(),
    );
    issues.sort();
    issues.dedup();

    Ok(Ue4ssActivationReport {
        schema_version: 1,
        game_root: inventory.game_root,
        complete: inventory.complete && mods_txt.complete,
        scope,
        mods_root: inventory.mods_root,
        mods_txt,
        modules,
        issues,
    })
}

fn analyze_mods_txt(
    game_root: &Path,
    entry: EntryObservation,
    module_names: &BTreeSet<String>,
    limits: &Ue4ssActivationLimits,
) -> ModsTxtAnalysis {
    if entry.status == EntryStatus::Missing {
        return mods_txt_result(entry, ModsTxtAnalysisStatus::Missing, true, 0, Vec::new());
    }
    if entry.status != EntryStatus::RegularFile {
        return mods_txt_result(
            entry,
            ModsTxtAnalysisStatus::Unsafe,
            false,
            0,
            vec!["mods.txt is not a safe regular file".to_owned()],
        );
    }
    let mut file = match open_file_beneath(game_root, &entry.relative_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::Unsupported => {
            return mods_txt_result(
                entry,
                ModsTxtAnalysisStatus::UnsupportedPlatform,
                false,
                0,
                vec![format!("safe mods.txt opening is unsupported: {error}")],
            );
        }
        Err(error) => {
            return mods_txt_result(
                entry,
                ModsTxtAnalysisStatus::Unreadable,
                false,
                0,
                vec![format!("failed to open mods.txt safely: {error}")],
            );
        }
    };
    let metadata = match file.metadata() {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => {
            return mods_txt_result(
                entry,
                ModsTxtAnalysisStatus::Unsafe,
                false,
                0,
                vec!["opened mods.txt is not a regular file".to_owned()],
            );
        }
        Err(error) => {
            return mods_txt_result(
                entry,
                ModsTxtAnalysisStatus::Unreadable,
                false,
                0,
                vec![format!("failed to inspect opened mods.txt: {error}")],
            );
        }
    };
    if metadata.len() > limits.max_bytes {
        return mods_txt_result(
            entry,
            ModsTxtAnalysisStatus::LimitExceeded,
            false,
            metadata.len(),
            vec![format!(
                "mods.txt exceeds the {} byte limit",
                limits.max_bytes
            )],
        );
    }
    let mut input = Vec::new();
    if let Err(error) = file
        .by_ref()
        .take(limits.max_bytes.saturating_add(1))
        .read_to_end(&mut input)
    {
        return mods_txt_result(
            entry,
            ModsTxtAnalysisStatus::Unreadable,
            false,
            input.len() as u64,
            vec![format!("failed to read mods.txt: {error}")],
        );
    }
    if input.len() as u64 > limits.max_bytes {
        return mods_txt_result(
            entry,
            ModsTxtAnalysisStatus::LimitExceeded,
            false,
            input.len() as u64,
            vec![format!(
                "mods.txt exceeded the {} byte limit",
                limits.max_bytes
            )],
        );
    }
    let source = match std::str::from_utf8(&input) {
        Ok(source) => source.strip_prefix('\u{feff}').unwrap_or(source),
        Err(error) => {
            return mods_txt_result(
                entry,
                ModsTxtAnalysisStatus::Invalid,
                false,
                input.len() as u64,
                vec![format!("mods.txt is not valid UTF-8: {error}")],
            );
        }
    };

    let mut entries = Vec::new();
    let mut issues = Vec::new();
    let mut syntax_complete = true;
    for (index, line) in source.lines().enumerate() {
        let line_number = index + 1;
        if line_number > limits.max_lines {
            return mods_txt_result(
                entry,
                ModsTxtAnalysisStatus::LimitExceeded,
                false,
                input.len() as u64,
                vec![format!(
                    "mods.txt exceeds the {} line limit",
                    limits.max_lines
                )],
            );
        }
        if line.len() > limits.max_line_bytes {
            return mods_txt_result(
                entry,
                ModsTxtAnalysisStatus::LimitExceeded,
                false,
                input.len() as u64,
                vec![format!(
                    "mods.txt line {line_number} exceeds the {} byte limit",
                    limits.max_line_bytes
                )],
            );
        }
        let trimmed = line.trim_matches(' ');
        if trimmed.is_empty() || trimmed.starts_with(';') {
            continue;
        }
        let parsed = parse_canonical_line(trimmed);
        let (name, directive) = match parsed {
            Ok(parsed) => parsed,
            Err(reason) => {
                syntax_complete = false;
                issues.push(format!(
                    "non-canonical mods.txt line {line_number}: {reason}"
                ));
                continue;
            }
        };
        if entries.len() == limits.max_entries {
            return mods_txt_result(
                entry,
                ModsTxtAnalysisStatus::LimitExceeded,
                false,
                input.len() as u64,
                vec![format!(
                    "mods.txt exceeds the {} directive limit",
                    limits.max_entries
                )],
            );
        }
        let matched_module = module_names.contains(name);
        if !matched_module {
            let case_match = module_names
                .iter()
                .find(|module| module.eq_ignore_ascii_case(name));
            if let Some(case_match) = case_match {
                issues.push(format!(
                    "mods.txt line {line_number} names '{name}', but module matching is case-sensitive; observed '{case_match}'"
                ));
            } else {
                issues.push(format!(
                    "mods.txt line {line_number} names an unobserved module '{name}'"
                ));
            }
        }
        entries.push(ModsTxtEntry {
            line: line_number,
            name: name.to_owned(),
            directive,
            matched_module,
        });
    }
    issues.sort();
    issues.dedup();
    ModsTxtAnalysis {
        entry,
        status: if syntax_complete {
            ModsTxtAnalysisStatus::Parsed
        } else {
            ModsTxtAnalysisStatus::Invalid
        },
        complete: syntax_complete,
        bytes: input.len() as u64,
        entries,
        issues,
    }
}

fn parse_canonical_line(line: &str) -> Result<(&str, ModsTxtDirective), &'static str> {
    if line.contains(';') {
        return Err("semicolon comments must occupy the full line");
    }
    if line.contains('\t') || line.chars().any(|character| character.is_control()) {
        return Err("tabs and control characters are not accepted");
    }
    if line.matches(':').count() != 1 {
        return Err("expected exactly one ':' separator");
    }
    let (name, value) = line.split_once(':').expect("separator count was checked");
    let name = name.trim_matches(' ');
    let value = value.trim_matches(' ');
    if name.is_empty() {
        return Err("module name is empty");
    }
    if name.contains(' ') {
        return Err("module names containing spaces are not faithfully representable");
    }
    let directive = match value {
        "1" => ModsTxtDirective::Enable,
        "0" => ModsTxtDirective::Disable,
        _ => return Err("directive must be exactly 0 or 1"),
    };
    Ok((name, directive))
}

fn mods_txt_result(
    entry: EntryObservation,
    status: ModsTxtAnalysisStatus,
    complete: bool,
    bytes: u64,
    issues: Vec<String>,
) -> ModsTxtAnalysis {
    ModsTxtAnalysis {
        entry,
        status,
        complete,
        bytes,
        entries: Vec::new(),
        issues,
    }
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;
    use crate::{MODS_RELATIVE_ROOT, path_from_relative};
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn reconciles_canonical_list_directives_and_markers() {
        let temporary = TempDir::new().unwrap();
        let mods = temporary
            .path()
            .join(path_from_relative(MODS_RELATIVE_ROOT));
        create_module(&mods, "ListEnabled", false);
        create_module(&mods, "ListDisabled", false);
        create_module(&mods, "MarkerOverridesZero", true);
        create_module(&mods, "Both", true);
        create_module(&mods, "Unlisted", false);
        fs::write(
            mods.join("mods.txt"),
            b"\xEF\xBB\xBF; official comment\r\nListEnabled : 1\r\nListDisabled : 0\r\nMarkerOverridesZero : 0\r\nBoth : 1\r\n",
        )
        .unwrap();

        let report = analyze(temporary.path(), Ue4ssActivationLimits::default());

        assert!(report.complete);
        assert_eq!(report.mods_txt.status, ModsTxtAnalysisStatus::Parsed);
        assert_eq!(
            state(&report, "ListEnabled"),
            Ue4ssDeclaredActivation::EnabledByModsTxt
        );
        assert_eq!(
            state(&report, "ListDisabled"),
            Ue4ssDeclaredActivation::DisabledByModsTxt
        );
        assert_eq!(
            state(&report, "MarkerOverridesZero"),
            Ue4ssDeclaredActivation::EnabledByMarker
        );
        assert_eq!(
            state(&report, "Both"),
            Ue4ssDeclaredActivation::EnabledByBoth
        );
        assert_eq!(
            state(&report, "Unlisted"),
            Ue4ssDeclaredActivation::Unlisted
        );
        assert!(
            module(&report, "MarkerOverridesZero")
                .issues
                .iter()
                .any(|issue| issue.contains("independently enables"))
        );
    }

    #[test]
    fn missing_list_preserves_marker_and_unlisted_evidence() {
        let temporary = TempDir::new().unwrap();
        let mods = temporary
            .path()
            .join(path_from_relative(MODS_RELATIVE_ROOT));
        create_module(&mods, "Marker", true);
        create_module(&mods, "NoMarker", false);

        let report = analyze(temporary.path(), Ue4ssActivationLimits::default());

        assert!(report.complete);
        assert_eq!(report.mods_txt.status, ModsTxtAnalysisStatus::Missing);
        assert_eq!(
            state(&report, "Marker"),
            Ue4ssDeclaredActivation::EnabledByMarker
        );
        assert_eq!(
            state(&report, "NoMarker"),
            Ue4ssDeclaredActivation::Unlisted
        );
    }

    #[test]
    fn malformed_lines_only_suppress_unproven_negative_states() {
        let temporary = TempDir::new().unwrap();
        let mods = temporary
            .path()
            .join(path_from_relative(MODS_RELATIVE_ROOT));
        create_module(&mods, "Disabled", false);
        create_module(&mods, "Enabled", false);
        create_module(&mods, "Marker", true);
        fs::write(
            mods.join("mods.txt"),
            b"Disabled : 0\nnot canonical\nEnabled : 1\n",
        )
        .unwrap();

        let report = analyze(temporary.path(), Ue4ssActivationLimits::default());

        assert!(!report.complete);
        assert_eq!(report.mods_txt.status, ModsTxtAnalysisStatus::Invalid);
        assert_eq!(
            state(&report, "Disabled"),
            Ue4ssDeclaredActivation::Indeterminate
        );
        assert_eq!(
            state(&report, "Enabled"),
            Ue4ssDeclaredActivation::EnabledByModsTxt
        );
        assert_eq!(
            state(&report, "Marker"),
            Ue4ssDeclaredActivation::EnabledByMarker
        );
    }

    #[test]
    fn positive_list_evidence_survives_a_noncanonical_marker_type() {
        let temporary = TempDir::new().unwrap();
        let mods = temporary
            .path()
            .join(path_from_relative(MODS_RELATIVE_ROOT));
        create_module(&mods, "Example", false);
        fs::create_dir(mods.join("Example/enabled.txt")).unwrap();
        fs::write(mods.join("mods.txt"), b"Example : 1\n").unwrap();

        let report = analyze(temporary.path(), Ue4ssActivationLimits::default());

        assert_eq!(
            state(&report, "Example"),
            Ue4ssDeclaredActivation::EnabledByBoth
        );
        assert!(
            module(&report, "Example")
                .issues
                .iter()
                .any(|issue| issue.contains("non-canonical"))
        );
    }

    #[test]
    fn reports_duplicate_and_case_sensitive_entries_without_last_value_wins() {
        let temporary = TempDir::new().unwrap();
        let mods = temporary
            .path()
            .join(path_from_relative(MODS_RELATIVE_ROOT));
        create_module(&mods, "Example", false);
        fs::write(
            mods.join("mods.txt"),
            b"Example : 0\nexample : 1\nExample : 1\n",
        )
        .unwrap();

        let report = analyze(temporary.path(), Ue4ssActivationLimits::default());

        assert!(report.complete);
        assert_eq!(
            state(&report, "Example"),
            Ue4ssDeclaredActivation::EnabledByModsTxt
        );
        assert_eq!(module(&report, "Example").mods_txt_lines, vec![1, 3]);
        assert!(
            module(&report, "Example")
                .issues
                .iter()
                .any(|issue| issue.contains("duplicate"))
        );
        assert!(
            report
                .mods_txt
                .issues
                .iter()
                .any(|issue| issue.contains("case-sensitive"))
        );
    }

    #[test]
    fn rejects_permissive_implementation_accidents_as_non_canonical() {
        for line in [
            "Example : 10",
            "Example : true",
            "Example : 1 ; inline",
            "Example : x : 1",
            "Ex ample : 1",
            "Example\t:\t1",
        ] {
            assert!(parse_canonical_line(line).is_err(), "accepted {line:?}");
        }
    }

    #[test]
    fn limit_failures_keep_no_arbitrary_directive_prefix() {
        let temporary = TempDir::new().unwrap();
        let mods = temporary
            .path()
            .join(path_from_relative(MODS_RELATIVE_ROOT));
        create_module(&mods, "One", false);
        create_module(&mods, "Two", false);
        fs::write(mods.join("mods.txt"), b"One : 1\nTwo : 1\n").unwrap();
        let limits = Ue4ssActivationLimits {
            max_entries: 1,
            ..Ue4ssActivationLimits::default()
        };

        let report = analyze(temporary.path(), limits);

        assert!(!report.complete);
        assert_eq!(report.mods_txt.status, ModsTxtAnalysisStatus::LimitExceeded);
        assert!(report.mods_txt.entries.is_empty());
        assert_eq!(
            state(&report, "One"),
            Ue4ssDeclaredActivation::Indeterminate
        );
        assert_eq!(
            state(&report, "Two"),
            Ue4ssDeclaredActivation::Indeterminate
        );
    }

    #[test]
    #[cfg(unix)]
    fn never_follows_a_linked_mods_txt() {
        let temporary = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let mods = temporary
            .path()
            .join(path_from_relative(MODS_RELATIVE_ROOT));
        create_module(&mods, "Example", false);
        fs::write(outside.path().join("mods.txt"), b"Example : 1\n").unwrap();
        std::os::unix::fs::symlink(outside.path().join("mods.txt"), mods.join("mods.txt")).unwrap();

        let report = analyze(temporary.path(), Ue4ssActivationLimits::default());

        assert!(!report.complete);
        assert_eq!(report.mods_txt.status, ModsTxtAnalysisStatus::Unsafe);
        assert!(report.mods_txt.entries.is_empty());
        assert_eq!(
            state(&report, "Example"),
            Ue4ssDeclaredActivation::Indeterminate
        );
    }

    fn analyze(game_root: &Path, limits: Ue4ssActivationLimits) -> Ue4ssActivationReport {
        analyze_ue4ss_activation(game_root, &Ue4ssInventoryLimits::default(), &limits).unwrap()
    }

    fn create_module(mods_root: &Path, name: &str, marker: bool) {
        let module = mods_root.join(name);
        fs::create_dir_all(module.join("Scripts")).unwrap();
        fs::write(module.join("Scripts/main.lua"), b"error('must not run')").unwrap();
        if marker {
            fs::write(module.join("enabled.txt"), b"ignored content").unwrap();
        }
    }

    fn module<'a>(report: &'a Ue4ssActivationReport, name: &str) -> &'a Ue4ssModuleActivation {
        report
            .modules
            .iter()
            .find(|module| module.name == name)
            .unwrap()
    }

    fn state(report: &Ue4ssActivationReport, name: &str) -> Ue4ssDeclaredActivation {
        module(report, name).declared_state
    }
}
