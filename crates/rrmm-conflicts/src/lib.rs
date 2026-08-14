use rrmm_pak::{CookedPackage, PakInventory};
use rrmm_ue4ss::{
    LuaAdvisoryArgument, LuaAdvisoryReport, Ue4ssActivationReport, Ue4ssDeclaredActivation,
    Ue4ssLuaApi,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossLayerPolicy {
    pub build_id: u64,
    pub mount_aliases: Vec<UnrealMountAlias>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnrealMountAlias {
    pub object_root: String,
    pub virtual_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossLayerLimits {
    pub max_paks: usize,
    pub max_packages: usize,
    pub max_matches: usize,
    pub max_unresolved: usize,
}

impl Default for CrossLayerLimits {
    fn default() -> Self {
        Self {
            max_paks: 128,
            max_packages: 1_000_000,
            max_matches: 20_000,
            max_unresolved: 20_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakLuaCorrelationReport {
    pub schema_version: u32,
    pub build_id: u64,
    pub complete: bool,
    pub pak_count: usize,
    pub relevant_finding_count: usize,
    pub matches: Vec<PakLuaPackageMatch>,
    pub unresolved: Vec<PakLuaUnresolvedTarget>,
    pub unresolved_summary: Vec<CrossLayerUnresolvedSummary>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakLuaPackageMatch {
    pub archive_path: PathBuf,
    pub archive_name: String,
    pub package_key: String,
    pub package_members: Vec<String>,
    pub package_warnings: Vec<String>,
    pub module_name: String,
    pub script_path: String,
    pub api: Ue4ssLuaApi,
    pub line: usize,
    pub column: usize,
    pub literal_target: String,
    pub logical_package: String,
    pub confidence: CrossLayerMatchConfidence,
    pub declared_activation: Option<Ue4ssDeclaredActivation>,
    pub warning: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossLayerMatchConfidence {
    ExactConfiguredPolicyPackageKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossLayerUnresolvedSummary {
    pub reason: CrossLayerUnresolvedReason,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakLuaUnresolvedTarget {
    pub module_name: String,
    pub script_path: String,
    pub api: Ue4ssLuaApi,
    pub line: usize,
    pub column: usize,
    pub target: LuaAdvisoryArgument,
    pub logical_package: Option<String>,
    pub reason: CrossLayerUnresolvedReason,
    pub detail: String,
    pub declared_activation: Option<Ue4ssDeclaredActivation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossLayerUnresolvedReason {
    NonLiteralTarget,
    MalformedReflectedTarget,
    NativeScriptPackage,
    UnknownMountRoot,
    AmbiguousMountAlias,
    NoInputPakPackageMatch,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CrossLayerError {
    #[error("cross-layer policy requires a nonzero build ID")]
    MissingBuildId,
    #[error("invalid Unreal mount alias {object_root} -> {virtual_root}: {detail}")]
    InvalidMountAlias {
        object_root: String,
        virtual_root: String,
        detail: String,
    },
    #[error("duplicate PAK inventory path: {0}")]
    DuplicatePak(PathBuf),
    #[error("cross-layer input exceeds {kind} limit: {actual} > {limit}")]
    LimitExceeded {
        kind: &'static str,
        actual: usize,
        limit: usize,
    },
}

pub fn correlate_pak_ue4ss(
    inventories: &[PakInventory],
    lua: &LuaAdvisoryReport,
    activation: Option<&Ue4ssActivationReport>,
    policy: &CrossLayerPolicy,
    limits: &CrossLayerLimits,
) -> Result<PakLuaCorrelationReport, CrossLayerError> {
    validate_policy(policy)?;
    if inventories.len() > limits.max_paks {
        return Err(CrossLayerError::LimitExceeded {
            kind: "PAK count",
            actual: inventories.len(),
            limit: limits.max_paks,
        });
    }
    let package_count = inventories
        .iter()
        .try_fold(0_usize, |total, inventory| {
            total.checked_add(inventory.packages.len())
        })
        .unwrap_or(usize::MAX);
    if package_count > limits.max_packages {
        return Err(CrossLayerError::LimitExceeded {
            kind: "cooked package count",
            actual: package_count,
            limit: limits.max_packages,
        });
    }

    let mut ordered_inventories: Vec<_> = inventories.iter().collect();
    ordered_inventories.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    let mut archive_paths = BTreeSet::new();
    for inventory in &ordered_inventories {
        if !archive_paths.insert(&inventory.archive_path) {
            return Err(CrossLayerError::DuplicatePak(
                inventory.archive_path.clone(),
            ));
        }
    }
    let mut package_index = BTreeMap::<String, Vec<(&PakInventory, &CookedPackage)>>::new();
    for inventory in &ordered_inventories {
        for package in &inventory.packages {
            package_index
                .entry(package.package_key.clone())
                .or_default()
                .push((inventory, package));
        }
    }
    let mut evidence_issues = Vec::new();
    let mut activation_complete = true;
    let mut activation_by_module = BTreeMap::new();
    let mut duplicate_activation_modules = BTreeSet::new();
    if let Some(activation) = activation {
        if activation.schema_version != 1 || activation.game_root != lua.game_root {
            activation_complete = false;
            evidence_issues.push(
                "declared activation input schema or game root does not match the Lua advisory input"
                    .to_owned(),
            );
        } else {
            for module in &activation.modules {
                let key = (module.name.clone(), module.relative_path.clone());
                if duplicate_activation_modules.contains(&key) {
                    continue;
                }
                if activation_by_module
                    .insert(key.clone(), module.declared_state)
                    .is_some()
                {
                    activation_by_module.remove(&key);
                    duplicate_activation_modules.insert(key);
                    activation_complete = false;
                    evidence_issues.push(format!(
                        "declared activation input duplicates module {} at {}",
                        module.name, module.relative_path
                    ));
                }
            }
            for module in &lua.modules {
                if !activation_by_module
                    .contains_key(&(module.name.clone(), module.relative_path.clone()))
                {
                    activation_complete = false;
                    evidence_issues.push(format!(
                        "declared activation input has no matching module {} at {}",
                        module.name, module.relative_path
                    ));
                }
            }
        }
        if !activation.complete {
            activation_complete = false;
        }
        if matches!(
            activation.scope,
            rrmm_ue4ss::Ue4ssActivationScope::SelectedTreeFromAmbiguousLayouts
        ) {
            evidence_issues.push(
                "declared activation came from a tree selected among ambiguous UE4SS layouts"
                    .to_owned(),
            );
        }
        evidence_issues.extend(
            activation
                .issues
                .iter()
                .map(|issue| format!("declared activation: {issue}")),
        );
        evidence_issues.push(
            "Lua and activation reports are separate non-atomic filesystem snapshots".to_owned(),
        );
    }

    let mut complete = lua.complete && activation_complete;
    let mut relevant_finding_count = 0_usize;
    let mut matches = Vec::new();
    let mut unresolved = Vec::new();
    let mut matches_exceeded = false;
    let mut unresolved_exceeded = false;
    let mut unresolved_counts = BTreeMap::<CrossLayerUnresolvedReason, usize>::new();
    for module in &lua.modules {
        let declared_activation = activation_by_module
            .get(&(module.name.clone(), module.relative_path.clone()))
            .copied();
        for script in &module.scripts {
            for finding in &script.findings {
                if !matches!(
                    finding.api,
                    Ue4ssLuaApi::RegisterHook | Ue4ssLuaApi::NotifyOnNewObject
                ) {
                    continue;
                }
                relevant_finding_count = relevant_finding_count.saturating_add(1);
                let literal = match &finding.first_argument {
                    LuaAdvisoryArgument::Literal { value } => value,
                    target => {
                        push_unresolved(
                            &mut unresolved,
                            &mut unresolved_exceeded,
                            &mut unresolved_counts,
                            limits.max_unresolved,
                            PakLuaUnresolvedTarget {
                                module_name: module.name.clone(),
                                script_path: script.relative_path.clone(),
                                api: finding.api,
                                line: finding.line,
                                column: finding.column,
                                target: target.clone(),
                                logical_package: None,
                                reason: CrossLayerUnresolvedReason::NonLiteralTarget,
                                detail: "only direct literal reflected targets can be mapped to cooked packages"
                                    .to_owned(),
                                declared_activation,
                            },
                        );
                        continue;
                    }
                };
                let logical_package = match parse_logical_package(finding.api, literal) {
                    Ok(package) => package,
                    Err(detail) => {
                        push_literal_unresolved(
                            &mut unresolved,
                            &mut unresolved_exceeded,
                            &mut unresolved_counts,
                            limits.max_unresolved,
                            module.name.clone(),
                            script.relative_path.clone(),
                            finding.api,
                            finding.line,
                            finding.column,
                            literal,
                            None,
                            CrossLayerUnresolvedReason::MalformedReflectedTarget,
                            detail,
                            declared_activation,
                        );
                        continue;
                    }
                };
                if logical_package.starts_with("/Script/") {
                    push_literal_unresolved(
                        &mut unresolved,
                        &mut unresolved_exceeded,
                        &mut unresolved_counts,
                        limits.max_unresolved,
                        module.name.clone(),
                        script.relative_path.clone(),
                        finding.api,
                        finding.line,
                        finding.column,
                        literal,
                        Some(logical_package),
                        CrossLayerUnresolvedReason::NativeScriptPackage,
                        "native /Script packages have no direct cooked PAK projection".to_owned(),
                        declared_activation,
                    );
                    continue;
                }
                let mapped = matching_aliases(&logical_package, &policy.mount_aliases);
                if mapped.is_empty() {
                    push_literal_unresolved(
                        &mut unresolved,
                        &mut unresolved_exceeded,
                        &mut unresolved_counts,
                        limits.max_unresolved,
                        module.name.clone(),
                        script.relative_path.clone(),
                        finding.api,
                        finding.line,
                        finding.column,
                        literal,
                        Some(logical_package),
                        CrossLayerUnresolvedReason::UnknownMountRoot,
                        "no build-specific mount alias maps this logical package".to_owned(),
                        declared_activation,
                    );
                    continue;
                }
                if mapped.len() > 1 {
                    push_literal_unresolved(
                        &mut unresolved,
                        &mut unresolved_exceeded,
                        &mut unresolved_counts,
                        limits.max_unresolved,
                        module.name.clone(),
                        script.relative_path.clone(),
                        finding.api,
                        finding.line,
                        finding.column,
                        literal,
                        Some(logical_package),
                        CrossLayerUnresolvedReason::AmbiguousMountAlias,
                        "multiple build-specific mount aliases map this logical package".to_owned(),
                        declared_activation,
                    );
                    continue;
                }
                let package_key = mapped[0].clone();
                let Some(package_sources) = package_index.get(&package_key) else {
                    push_literal_unresolved(
                        &mut unresolved,
                        &mut unresolved_exceeded,
                        &mut unresolved_counts,
                        limits.max_unresolved,
                        module.name.clone(),
                        script.relative_path.clone(),
                        finding.api,
                        finding.line,
                        finding.column,
                        literal,
                        Some(logical_package),
                        CrossLayerUnresolvedReason::NoInputPakPackageMatch,
                        "none of the input PAK inventories provides this cooked package".to_owned(),
                        declared_activation,
                    );
                    continue;
                };
                for (inventory, package) in package_sources {
                    if matches.len() == limits.max_matches {
                        matches_exceeded = true;
                        break;
                    }
                    let mut package_members = package.members.clone();
                    package_members.sort();
                    let mut package_warnings = package.warnings.clone();
                    package_warnings.sort();
                    matches.push(PakLuaPackageMatch {
                        archive_path: inventory.archive_path.clone(),
                        archive_name: inventory.archive_name.clone(),
                        package_key: package.package_key.clone(),
                        package_members,
                        package_warnings,
                        module_name: module.name.clone(),
                        script_path: script.relative_path.clone(),
                        api: finding.api,
                        line: finding.line,
                        column: finding.column,
                        literal_target: literal.clone(),
                        logical_package: logical_package.clone(),
                        confidence: CrossLayerMatchConfidence::ExactConfiguredPolicyPackageKey,
                        declared_activation,
                        warning: "under the configured build mount policy, Lua targets an object owned by a cooked package listed by this PAK; installation build, PAK activation, target presence, behavior, ownership, and compatibility were not runtime-verified"
                            .to_owned(),
                    });
                }
            }
        }
    }

    let mut issues = vec![
        "build ID selects a configured mount policy; the live installation build was not validated by this correlation"
            .to_owned(),
        "input PAK inventories do not prove that those PAKs are installed, active, or runtime winners"
            .to_owned(),
        "package association does not prove that a hooked function or class changed, disappeared, or is incompatible"
            .to_owned(),
        "package ownership is unavailable, so intentional same-mod PAK/Lua associations are not distinguished"
            .to_owned(),
    ];
    issues.append(&mut evidence_issues);
    if !lua.complete {
        issues.push("Lua advisory input was incomplete".to_owned());
    }
    if activation.is_some_and(|report| !report.complete) {
        issues.push("declared activation input was incomplete".to_owned());
    }
    if ordered_inventories
        .iter()
        .any(|inventory| !inventory.integrity.structural_parse_succeeded)
    {
        complete = false;
        issues.push(
            "at least one PAK inventory did not report a successful structural parse".to_owned(),
        );
    }
    if matches_exceeded {
        complete = false;
        matches.clear();
        issues.push(format!(
            "cross-layer matches exceeded the {} result limit; no arbitrary match prefix was retained",
            limits.max_matches
        ));
    }
    if unresolved_exceeded {
        complete = false;
        unresolved.clear();
        issues.push(format!(
            "unresolved targets exceeded the {} result limit; no arbitrary unresolved prefix was retained",
            limits.max_unresolved
        ));
    }
    matches.sort_by(|left, right| {
        left.archive_path
            .cmp(&right.archive_path)
            .then_with(|| left.package_key.cmp(&right.package_key))
            .then_with(|| left.module_name.cmp(&right.module_name))
            .then_with(|| left.script_path.cmp(&right.script_path))
            .then_with(|| left.line.cmp(&right.line))
            .then_with(|| left.column.cmp(&right.column))
    });
    unresolved.sort_by(|left, right| {
        left.module_name
            .cmp(&right.module_name)
            .then_with(|| left.script_path.cmp(&right.script_path))
            .then_with(|| left.line.cmp(&right.line))
            .then_with(|| left.column.cmp(&right.column))
            .then_with(|| left.api.cmp(&right.api))
            .then_with(|| left.reason.cmp(&right.reason))
            .then_with(|| argument_sort_key(&left.target).cmp(&argument_sort_key(&right.target)))
    });
    matches.dedup();
    unresolved.dedup();
    let unresolved_summary = unresolved_counts
        .into_iter()
        .map(|(reason, count)| CrossLayerUnresolvedSummary { reason, count })
        .collect();
    issues.sort();
    issues.dedup();
    Ok(PakLuaCorrelationReport {
        schema_version: 1,
        build_id: policy.build_id,
        complete,
        pak_count: inventories.len(),
        relevant_finding_count,
        matches,
        unresolved,
        unresolved_summary,
        issues,
    })
}

fn validate_policy(policy: &CrossLayerPolicy) -> Result<(), CrossLayerError> {
    if policy.build_id == 0 {
        return Err(CrossLayerError::MissingBuildId);
    }
    let mut roots = BTreeSet::new();
    for alias in &policy.mount_aliases {
        let valid_object_root = alias.object_root.starts_with('/')
            && !alias.object_root.ends_with('/')
            && alias.object_root.len() > 1
            && alias
                .object_root
                .split('/')
                .skip(1)
                .all(valid_path_component);
        let valid_virtual_root = !alias.virtual_root.starts_with('/')
            && !alias.virtual_root.ends_with('/')
            && alias.virtual_root.split('/').all(valid_path_component);
        if !valid_object_root || !valid_virtual_root {
            return Err(CrossLayerError::InvalidMountAlias {
                object_root: alias.object_root.clone(),
                virtual_root: alias.virtual_root.clone(),
                detail: "roots must be normalized nonempty component paths".to_owned(),
            });
        }
        if !roots.insert(&alias.object_root) {
            return Err(CrossLayerError::InvalidMountAlias {
                object_root: alias.object_root.clone(),
                virtual_root: alias.virtual_root.clone(),
                detail: "object root is duplicated".to_owned(),
            });
        }
    }
    Ok(())
}

fn parse_logical_package(api: Ue4ssLuaApi, target: &str) -> Result<String, String> {
    let target = if api == Ue4ssLuaApi::RegisterHook {
        target.strip_prefix("Function ").unwrap_or(target)
    } else {
        target
    };
    if target.contains('\\') || target.contains('\0') || !target.starts_with('/') {
        return Err("target is not a normalized absolute reflected path".to_owned());
    }
    let Some((package, object_path)) = target.split_once('.') else {
        return Err("target has no top-level object separator".to_owned());
    };
    if package.len() <= 1
        || package
            .split('/')
            .skip(1)
            .any(|component| !valid_path_component(component))
    {
        return Err("logical package has invalid path components".to_owned());
    }
    if object_path.is_empty() || object_path.starts_with(':') {
        return Err("target has no top-level object name".to_owned());
    }
    match api {
        Ue4ssLuaApi::RegisterHook => {
            if object_path.matches(':').count() != 1 {
                return Err(
                    "RegisterHook target must contain exactly one function separator".to_owned(),
                );
            }
            let Some((object, function)) = object_path.split_once(':') else {
                return Err("RegisterHook target has no function subobject".to_owned());
            };
            if !valid_reflected_name(object) || !valid_reflected_name(function) {
                return Err("RegisterHook target has an invalid object or function name".to_owned());
            }
        }
        Ue4ssLuaApi::NotifyOnNewObject => {
            if !valid_reflected_name(object_path) {
                return Err(
                    "NotifyOnNewObject target must identify one valid top-level class object"
                        .to_owned(),
                );
            }
        }
        _ => return Err("API does not have a package-mappable target".to_owned()),
    }
    Ok(package.to_owned())
}

fn valid_path_component(component: &str) -> bool {
    !component.is_empty()
        && !matches!(component, "." | "..")
        && component
            .chars()
            .all(|character| character.is_alphanumeric() || character == '_')
}

fn valid_reflected_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(' ')
        && !name.ends_with(' ')
        && name
            .chars()
            .all(|character| character.is_alphanumeric() || matches!(character, '_' | ' '))
}

fn matching_aliases(logical_package: &str, aliases: &[UnrealMountAlias]) -> Vec<String> {
    aliases
        .iter()
        .filter_map(|alias| {
            logical_package
                .strip_prefix(&alias.object_root)
                .filter(|suffix| suffix.starts_with('/'))
                .map(|suffix| format!("{}{}", alias.virtual_root, suffix).to_lowercase())
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn push_literal_unresolved(
    unresolved: &mut Vec<PakLuaUnresolvedTarget>,
    exceeded: &mut bool,
    counts: &mut BTreeMap<CrossLayerUnresolvedReason, usize>,
    limit: usize,
    module_name: String,
    script_path: String,
    api: Ue4ssLuaApi,
    line: usize,
    column: usize,
    literal: &str,
    logical_package: Option<String>,
    reason: CrossLayerUnresolvedReason,
    detail: String,
    declared_activation: Option<Ue4ssDeclaredActivation>,
) {
    push_unresolved(
        unresolved,
        exceeded,
        counts,
        limit,
        PakLuaUnresolvedTarget {
            module_name,
            script_path,
            api,
            line,
            column,
            target: LuaAdvisoryArgument::Literal {
                value: literal.to_owned(),
            },
            logical_package,
            reason,
            detail,
            declared_activation,
        },
    );
}

fn push_unresolved(
    unresolved: &mut Vec<PakLuaUnresolvedTarget>,
    exceeded: &mut bool,
    counts: &mut BTreeMap<CrossLayerUnresolvedReason, usize>,
    limit: usize,
    target: PakLuaUnresolvedTarget,
) {
    *counts.entry(target.reason).or_default() += 1;
    if unresolved.len() == limit {
        *exceeded = true;
    } else if !*exceeded {
        unresolved.push(target);
    }
}

fn argument_sort_key(argument: &LuaAdvisoryArgument) -> String {
    match argument {
        LuaAdvisoryArgument::Literal { value } => format!("literal:{value}"),
        LuaAdvisoryArgument::Symbolic { expression } => format!("symbolic:{expression}"),
        LuaAdvisoryArgument::DynamicUnresolved => "dynamic".to_owned(),
        LuaAdvisoryArgument::Missing => "missing".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrmm_pak::{CookedSidecar, PakIntegrityReport, PakPriorityConfidence, PakPriorityHint};
    use rrmm_ue4ss::{
        EntryObservation, EntryStatus, LuaAdvisoryFinding, LuaAdvisoryModule, LuaAdvisoryScript,
        ModsTxtAnalysis, ModsTxtAnalysisStatus, Ue4ssActivationScope, Ue4ssModuleActivation,
    };

    #[test]
    fn correlates_literal_game_targets_to_exact_cooked_packages() {
        let inventories = vec![inventory("Example_P.pak", "RetroRewind/Content/Foo/Bar")];
        let lua = lua_report(vec![
            finding(
                Ue4ssLuaApi::RegisterHook,
                LuaAdvisoryArgument::Literal {
                    value: "Function /Game/Foo/Bar.Bar_C:Run".to_owned(),
                },
                4,
            ),
            finding(
                Ue4ssLuaApi::NotifyOnNewObject,
                LuaAdvisoryArgument::Literal {
                    value: "/Game/Foo/Bar.Bar_C".to_owned(),
                },
                8,
            ),
        ]);
        let activation = activation_report(Ue4ssDeclaredActivation::EnabledByMarker);

        let report = correlate_pak_ue4ss(
            &inventories,
            &lua,
            Some(&activation),
            &policy(),
            &CrossLayerLimits::default(),
        )
        .unwrap();

        assert!(report.complete);
        assert_eq!(report.matches.len(), 2);
        assert_eq!(report.matches[0].logical_package, "/Game/Foo/Bar");
        assert_eq!(report.matches[0].package_key, "retrorewind/content/foo/bar");
        assert_eq!(
            report.matches[0].declared_activation,
            Some(Ue4ssDeclaredActivation::EnabledByMarker)
        );
        assert!(report.unresolved.is_empty());
    }

    #[test]
    fn preserves_non_mappable_and_unmatched_evidence() {
        let inventories = vec![inventory("Example_P.pak", "RetroRewind/Content/Other")];
        let lua = lua_report(vec![
            finding(
                Ue4ssLuaApi::RegisterHook,
                LuaAdvisoryArgument::DynamicUnresolved,
                1,
            ),
            literal_hook("/Script/Engine.PlayerController:ClientRestart", 2),
            literal_hook("/Plugin/Foo.Bar_C:Run", 3),
            literal_hook("/Game/Foo/Bar.Bar_C:Run", 4),
            literal_hook("/Game/Foo/Bar", 5),
        ]);

        let report = correlate_pak_ue4ss(
            &inventories,
            &lua,
            None,
            &policy(),
            &CrossLayerLimits::default(),
        )
        .unwrap();

        assert!(report.matches.is_empty());
        assert_eq!(report.unresolved.len(), 5);
        let reasons: BTreeSet<_> = report
            .unresolved
            .iter()
            .map(|target| target.reason)
            .collect();
        assert!(reasons.contains(&CrossLayerUnresolvedReason::NonLiteralTarget));
        assert!(reasons.contains(&CrossLayerUnresolvedReason::NativeScriptPackage));
        assert!(reasons.contains(&CrossLayerUnresolvedReason::UnknownMountRoot));
        assert!(reasons.contains(&CrossLayerUnresolvedReason::NoInputPakPackageMatch));
        assert!(reasons.contains(&CrossLayerUnresolvedReason::MalformedReflectedTarget));
        assert_eq!(
            report
                .unresolved_summary
                .iter()
                .map(|summary| summary.count)
                .sum::<usize>(),
            5
        );
    }

    #[test]
    fn mount_aliases_match_on_component_boundaries_only() {
        let inventories = vec![inventory("Example_P.pak", "RetroRewind/Content/Foo/Bar")];
        let lua = lua_report(vec![literal_hook("/Gameplay/Foo/Bar.Bar_C:Run", 1)]);

        let report = correlate_pak_ue4ss(
            &inventories,
            &lua,
            None,
            &policy(),
            &CrossLayerLimits::default(),
        )
        .unwrap();

        assert!(report.matches.is_empty());
        assert_eq!(
            report.unresolved[0].reason,
            CrossLayerUnresolvedReason::UnknownMountRoot
        );
    }

    #[test]
    fn output_is_deterministic_across_pak_input_order() {
        let first = inventory("B_P.pak", "RetroRewind/Content/Foo/Bar");
        let second = inventory("A_P.pak", "RetroRewind/Content/Foo/Bar");
        let lua = lua_report(vec![literal_hook("/Game/Foo/Bar.Bar_C:Run", 1)]);

        let forward = correlate_pak_ue4ss(
            &[first.clone(), second.clone()],
            &lua,
            None,
            &policy(),
            &CrossLayerLimits::default(),
        )
        .unwrap();
        let reverse = correlate_pak_ue4ss(
            &[second, first],
            &lua,
            None,
            &policy(),
            &CrossLayerLimits::default(),
        )
        .unwrap();

        assert_eq!(forward, reverse);
        assert_eq!(forward.matches[0].archive_name, "A_P.pak");
    }

    #[test]
    fn match_limits_retain_no_arbitrary_prefix() {
        let inventories = vec![
            inventory("A_P.pak", "RetroRewind/Content/Foo/Bar"),
            inventory("B_P.pak", "RetroRewind/Content/Foo/Bar"),
        ];
        let lua = lua_report(vec![literal_hook("/Game/Foo/Bar.Bar_C:Run", 1)]);
        let limits = CrossLayerLimits {
            max_matches: 1,
            ..CrossLayerLimits::default()
        };

        let report = correlate_pak_ue4ss(&inventories, &lua, None, &policy(), &limits).unwrap();

        assert!(!report.complete);
        assert!(report.matches.is_empty());
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.contains("match prefix"))
        );
    }

    #[test]
    fn unresolved_limits_preserve_counts_by_reason() {
        let lua = lua_report(vec![
            finding(
                Ue4ssLuaApi::RegisterHook,
                LuaAdvisoryArgument::DynamicUnresolved,
                1,
            ),
            literal_hook("/Script/Engine.Actor:BeginPlay", 2),
        ]);
        let limits = CrossLayerLimits {
            max_unresolved: 1,
            ..CrossLayerLimits::default()
        };

        let report = correlate_pak_ue4ss(&[], &lua, None, &policy(), &limits).unwrap();

        assert!(!report.complete);
        assert!(report.unresolved.is_empty());
        assert_eq!(report.unresolved_summary.len(), 2);
        assert_eq!(
            report
                .unresolved_summary
                .iter()
                .map(|summary| summary.count)
                .sum::<usize>(),
            2
        );
    }

    #[test]
    fn rejects_malformed_reflected_suffixes_before_package_mapping() {
        for target in [
            "/Game/Foo/Bar.Bar_C:Run:Extra",
            "/Game/Foo/Bar.Bar_C/Child:Run",
            "/Game/Foo/Bar.Bar.C:Run",
            "/Game/Foo/Bar.Bar_C:\nRun",
            "/Game/Foo/Bar.Bar_C:Run()",
        ] {
            assert!(
                parse_logical_package(Ue4ssLuaApi::RegisterHook, target).is_err(),
                "accepted {target:?}"
            );
        }
        for target in [
            "/Game/Foo/Bar.Bar_C:Child",
            "/Game/Foo/Bar.Bar.C",
            "/Game/Foo/Bar.Bar_C/Child",
        ] {
            assert!(
                parse_logical_package(Ue4ssLuaApi::NotifyOnNewObject, target).is_err(),
                "accepted {target:?}"
            );
        }
    }

    #[test]
    fn activation_mismatches_do_not_attach_unrelated_state() {
        let inventories = vec![inventory("Example_P.pak", "RetroRewind/Content/Foo/Bar")];
        let lua = lua_report(vec![literal_hook("/Game/Foo/Bar.Bar_C:Run", 1)]);
        let mut activation = activation_report(Ue4ssDeclaredActivation::EnabledByMarker);
        activation.game_root = PathBuf::from("other-game");

        let report = correlate_pak_ue4ss(
            &inventories,
            &lua,
            Some(&activation),
            &policy(),
            &CrossLayerLimits::default(),
        )
        .unwrap();

        assert!(!report.complete);
        assert_eq!(report.matches[0].declared_activation, None);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.contains("does not match"))
        );
    }

    #[test]
    fn duplicate_activation_identity_does_not_attach_last_value() {
        let inventories = vec![inventory("Example_P.pak", "RetroRewind/Content/Foo/Bar")];
        let lua = lua_report(vec![literal_hook("/Game/Foo/Bar.Bar_C:Run", 1)]);
        let mut activation = activation_report(Ue4ssDeclaredActivation::EnabledByMarker);
        let mut duplicate = activation.modules[0].clone();
        duplicate.declared_state = Ue4ssDeclaredActivation::DisabledByModsTxt;
        activation.modules.push(duplicate);

        let report = correlate_pak_ue4ss(
            &inventories,
            &lua,
            Some(&activation),
            &policy(),
            &CrossLayerLimits::default(),
        )
        .unwrap();

        assert!(!report.complete);
        assert_eq!(report.matches[0].declared_activation, None);
    }

    #[test]
    fn rejects_invalid_policies_and_duplicate_archives() {
        let bad_policy = CrossLayerPolicy {
            build_id: 1,
            mount_aliases: vec![UnrealMountAlias {
                object_root: "Game".to_owned(),
                virtual_root: "RetroRewind/Content".to_owned(),
            }],
        };
        let lua = lua_report(Vec::new());
        assert!(matches!(
            correlate_pak_ue4ss(&[], &lua, None, &bad_policy, &CrossLayerLimits::default()),
            Err(CrossLayerError::InvalidMountAlias { .. })
        ));

        let pak = inventory("A_P.pak", "RetroRewind/Content/Foo");
        assert!(matches!(
            correlate_pak_ue4ss(
                &[pak.clone(), pak],
                &lua,
                None,
                &policy(),
                &CrossLayerLimits::default()
            ),
            Err(CrossLayerError::DuplicatePak(_))
        ));
    }

    fn policy() -> CrossLayerPolicy {
        CrossLayerPolicy {
            build_id: 23_896_268,
            mount_aliases: vec![UnrealMountAlias {
                object_root: "/Game".to_owned(),
                virtual_root: "RetroRewind/Content".to_owned(),
            }],
        }
    }

    fn inventory(name: &str, package_stem: &str) -> PakInventory {
        PakInventory {
            archive_path: PathBuf::from(name),
            archive_name: name.to_owned(),
            archive_bytes: 1,
            version: "V11".to_owned(),
            mount_point: "../../../".to_owned(),
            encrypted_index: false,
            compression: Vec::new(),
            path_hash_seed: Some(0),
            priority: PakPriorityHint {
                patch_generation: 1,
                patch_increment: 100,
                explicit_number: None,
                confidence: PakPriorityConfidence::ObservedBuildRule,
            },
            integrity: PakIntegrityReport {
                structural_parse_succeeded: true,
                index_hashes_verified: false,
                index_metadata_sha256: "00".repeat(32),
                detail: "synthetic".to_owned(),
            },
            members: Vec::new(),
            packages: vec![CookedPackage {
                package_key: package_stem.to_lowercase(),
                members: vec![format!("{package_stem}.uasset")],
                sidecars: vec![CookedSidecar::Asset],
                warnings: Vec::new(),
            }],
        }
    }

    fn lua_report(findings: Vec<LuaAdvisoryFinding>) -> LuaAdvisoryReport {
        LuaAdvisoryReport {
            schema_version: 2,
            game_root: PathBuf::from("game"),
            complete: true,
            modules: vec![LuaAdvisoryModule {
                name: "ExampleMod".to_owned(),
                relative_path: "ue4ss/Mods/ExampleMod".to_owned(),
                scripts: vec![LuaAdvisoryScript {
                    relative_path: "ue4ss/Mods/ExampleMod/Scripts/main.lua".to_owned(),
                    bytes: 1,
                    complete: true,
                    findings,
                    property_writes: Vec::new(),
                    issues: Vec::new(),
                }],
            }],
            issues: Vec::new(),
        }
    }

    fn finding(
        api: Ue4ssLuaApi,
        first_argument: LuaAdvisoryArgument,
        line: usize,
    ) -> LuaAdvisoryFinding {
        LuaAdvisoryFinding {
            api,
            line,
            column: 1,
            first_argument,
        }
    }

    fn literal_hook(value: &str, line: usize) -> LuaAdvisoryFinding {
        finding(
            Ue4ssLuaApi::RegisterHook,
            LuaAdvisoryArgument::Literal {
                value: value.to_owned(),
            },
            line,
        )
    }

    fn activation_report(state: Ue4ssDeclaredActivation) -> Ue4ssActivationReport {
        let missing = EntryObservation {
            relative_path: "mods.txt".to_owned(),
            status: EntryStatus::Missing,
            detail: None,
        };
        Ue4ssActivationReport {
            schema_version: 1,
            game_root: PathBuf::from("game"),
            complete: true,
            scope: Ue4ssActivationScope::SelectedTreeOnly,
            mods_root: EntryObservation {
                relative_path: "ue4ss/Mods".to_owned(),
                status: EntryStatus::Directory,
                detail: None,
            },
            mods_txt: ModsTxtAnalysis {
                entry: missing.clone(),
                status: ModsTxtAnalysisStatus::Missing,
                complete: true,
                bytes: 0,
                entries: Vec::new(),
                issues: Vec::new(),
            },
            modules: vec![Ue4ssModuleActivation {
                name: "ExampleMod".to_owned(),
                relative_path: "ue4ss/Mods/ExampleMod".to_owned(),
                declared_state: state,
                enabled_txt: missing,
                mods_txt_lines: Vec::new(),
                issues: Vec::new(),
            }],
            issues: Vec::new(),
        }
    }
}
