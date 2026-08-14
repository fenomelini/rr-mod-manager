use super::{
    EntryStatus, Ue4ssFileKind, Ue4ssInventoryError, Ue4ssInventoryLimits, inventory_ue4ss,
    observe_beneath,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::safe_file::open_file_beneath;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LuaAdvisoryLimits {
    pub max_scripts: usize,
    pub max_script_bytes: u64,
    pub max_total_bytes: u64,
    pub max_findings: usize,
}

impl Default for LuaAdvisoryLimits {
    fn default() -> Self {
        Self {
            max_scripts: 1_024,
            max_script_bytes: 2 * 1024 * 1024,
            max_total_bytes: 16 * 1024 * 1024,
            max_findings: 10_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LuaAdvisoryReport {
    pub schema_version: u32,
    pub game_root: PathBuf,
    pub complete: bool,
    pub modules: Vec<LuaAdvisoryModule>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LuaAdvisoryModule {
    pub name: String,
    pub relative_path: String,
    pub scripts: Vec<LuaAdvisoryScript>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LuaAdvisoryScript {
    pub relative_path: String,
    pub bytes: u64,
    pub complete: bool,
    pub findings: Vec<LuaAdvisoryFinding>,
    #[serde(default)]
    pub property_writes: Vec<LuaPropertyWriteFinding>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LuaAdvisoryFinding {
    pub api: Ue4ssLuaApi,
    pub line: usize,
    pub column: usize,
    pub first_argument: LuaAdvisoryArgument,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LuaPropertyWriteFinding {
    pub kind: LuaPropertyWriteKind,
    pub line: usize,
    pub column: usize,
    pub receiver: LuaAdvisoryArgument,
    pub property: LuaAdvisoryArgument,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LuaPropertyWriteKind {
    DotMemberCandidate,
    LiteralIndexCandidate,
    DynamicIndexCandidate,
    ParameterSetCandidate,
    ReflectionHelperCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ue4ssLuaApi {
    RegisterHook,
    NotifyOnNewObject,
    RegisterConsoleCommandHandler,
    RegisterKeyBind,
    RegisterLoadMapPreHook,
    RegisterLoadMapPostHook,
    Require,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LuaAdvisoryArgument {
    Literal { value: String },
    Symbolic { expression: String },
    DynamicUnresolved,
    Missing,
}

pub fn analyze_ue4ss_lua(
    game_root: &Path,
    inventory_limits: &Ue4ssInventoryLimits,
    analysis_limits: &LuaAdvisoryLimits,
) -> Result<LuaAdvisoryReport, Ue4ssInventoryError> {
    let inventory = inventory_ue4ss(game_root, inventory_limits)?;
    let mut complete = inventory.complete;
    let mut issues = if inventory.complete {
        Vec::new()
    } else {
        vec!["UE4SS inventory was incomplete; Lua analysis covers only reported scripts".to_owned()]
    };
    let mut modules = Vec::new();
    let mut script_count = 0_usize;
    let mut total_bytes = 0_u64;
    let mut finding_count = 0_usize;
    let mut stop_analysis = false;

    for module in inventory.modules {
        let mut scripts = Vec::new();
        for observed in module.files.iter().filter(|file| {
            matches!(
                file.kind,
                Ue4ssFileKind::Lua | Ue4ssFileKind::ConfigurationCandidate
            ) && file.relative_path.to_ascii_lowercase().ends_with(".lua")
        }) {
            if script_count >= analysis_limits.max_scripts {
                complete = false;
                issues.push(format!(
                    "Lua analysis exceeded the {} script limit",
                    analysis_limits.max_scripts
                ));
                stop_analysis = true;
                break;
            }
            let bytes = observed.bytes.unwrap_or(0);
            if bytes > analysis_limits.max_script_bytes {
                complete = false;
                issues.push(format!(
                    "Lua script exceeds the {} byte per-file limit: {}",
                    analysis_limits.max_script_bytes, observed.relative_path
                ));
                continue;
            }
            let remaining_bytes = analysis_limits.max_total_bytes.saturating_sub(total_bytes);
            if bytes > remaining_bytes {
                complete = false;
                issues.push(format!(
                    "Lua analysis exceeded the {} total byte limit",
                    analysis_limits.max_total_bytes
                ));
                stop_analysis = true;
                break;
            }
            script_count += 1;
            let remaining_findings = analysis_limits.max_findings.saturating_sub(finding_count);
            let script = analyze_script(
                &inventory.game_root,
                &observed.relative_path,
                analysis_limits.max_script_bytes.min(remaining_bytes),
                remaining_findings,
            )?;
            let Some(next_total) = total_bytes.checked_add(script.bytes) else {
                complete = false;
                issues.push("Lua analysis byte counter overflowed".to_owned());
                stop_analysis = true;
                break;
            };
            if next_total > analysis_limits.max_total_bytes {
                complete = false;
                issues.push(format!(
                    "Lua script changed while scanning and exceeded the {} total byte limit: {}",
                    analysis_limits.max_total_bytes, observed.relative_path
                ));
                stop_analysis = true;
                break;
            }
            total_bytes = next_total;
            finding_count += script.findings.len() + script.property_writes.len();
            if !script.complete {
                complete = false;
            }
            if script
                .issues
                .iter()
                .any(|issue| issue.starts_with("finding budget"))
            {
                stop_analysis = true;
            }
            scripts.push(script);
            if stop_analysis {
                break;
            }
        }
        modules.push(LuaAdvisoryModule {
            name: module.name,
            relative_path: module.relative_path,
            scripts,
        });
        if stop_analysis {
            break;
        }
    }
    issues.sort();
    issues.dedup();

    Ok(LuaAdvisoryReport {
        schema_version: 2,
        game_root: inventory.game_root,
        complete,
        modules,
        issues,
    })
}

fn analyze_script(
    game_root: &Path,
    relative_path: &str,
    max_bytes: u64,
    max_findings: usize,
) -> Result<LuaAdvisoryScript, Ue4ssInventoryError> {
    let observation = observe_beneath(game_root, relative_path, relative_path);
    if observation.status != EntryStatus::RegularFile {
        return Ok(LuaAdvisoryScript {
            relative_path: relative_path.to_owned(),
            bytes: 0,
            complete: false,
            findings: Vec::new(),
            property_writes: Vec::new(),
            issues: vec![format!(
                "script was no longer a safe regular file: {:?}",
                observation.status
            )],
        });
    }
    let mut file = match open_file_beneath(game_root, relative_path) {
        Ok(file) => file,
        Err(error) => {
            return Ok(incomplete_script(
                relative_path,
                0,
                format!("failed to open script safely: {error}"),
            ));
        }
    };
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            return Ok(incomplete_script(
                relative_path,
                0,
                format!("failed to inspect opened script: {error}"),
            ));
        }
    };
    if !metadata.is_file() {
        return Ok(LuaAdvisoryScript {
            relative_path: relative_path.to_owned(),
            bytes: 0,
            complete: false,
            findings: Vec::new(),
            property_writes: Vec::new(),
            issues: vec!["opened script is not a regular file".to_owned()],
        });
    }
    if metadata.len() > max_bytes {
        return Ok(LuaAdvisoryScript {
            relative_path: relative_path.to_owned(),
            bytes: metadata.len(),
            complete: false,
            findings: Vec::new(),
            property_writes: Vec::new(),
            issues: vec![format!(
                "script changed and now exceeds the {max_bytes} byte limit"
            )],
        });
    }
    let mut input = Vec::new();
    if let Err(error) = file
        .by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut input)
    {
        return Ok(incomplete_script(
            relative_path,
            input.len() as u64,
            format!("failed to read script: {error}"),
        ));
    }
    if input.len() as u64 > max_bytes {
        return Ok(LuaAdvisoryScript {
            relative_path: relative_path.to_owned(),
            bytes: input.len() as u64,
            complete: false,
            findings: Vec::new(),
            property_writes: Vec::new(),
            issues: vec![format!(
                "script exceeded the {max_bytes} byte limit while reading"
            )],
        });
    }
    let source = match std::str::from_utf8(&input) {
        Ok(source) => source,
        Err(error) => {
            return Ok(LuaAdvisoryScript {
                relative_path: relative_path.to_owned(),
                bytes: input.len() as u64,
                complete: false,
                findings: Vec::new(),
                property_writes: Vec::new(),
                issues: vec![format!("script is not valid UTF-8: {error}")],
            });
        }
    };
    let tokenized = tokenize(source);
    let extracted = extract_findings(&tokenized.tokens, max_findings);
    let findings = extracted.findings;
    let property_writes = extracted.property_writes;
    let mut issues = tokenized.issues;
    issues.extend(extracted.issues);
    let complete = issues.is_empty();

    Ok(LuaAdvisoryScript {
        relative_path: relative_path.to_owned(),
        bytes: input.len() as u64,
        complete,
        findings,
        property_writes,
        issues,
    })
}

fn incomplete_script(relative_path: &str, bytes: u64, issue: String) -> LuaAdvisoryScript {
    LuaAdvisoryScript {
        relative_path: relative_path.to_owned(),
        bytes,
        complete: false,
        findings: Vec::new(),
        property_writes: Vec::new(),
        issues: vec![issue],
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    kind: TokenKind,
    line: usize,
    column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    Identifier(String),
    StringLiteral(Option<String>),
    Symbol(char),
    Other(char),
}

struct Tokenized {
    tokens: Vec<Token>,
    issues: Vec<String>,
}

fn tokenize(source: &str) -> Tokenized {
    let normalized = source
        .replace("\r\n", "\n")
        .replace("\n\r", "\n")
        .replace('\r', "\n");
    let chars: Vec<char> = normalized.chars().collect();
    let mut tokens = Vec::new();
    let mut issues = Vec::new();
    let mut index = 0_usize;
    let mut line = 1_usize;
    let mut column = 1_usize;

    while index < chars.len() {
        let current = chars[index];
        if current.is_whitespace() {
            advance(current, &mut line, &mut column);
            index += 1;
            continue;
        }
        if current == '-' && chars.get(index + 1) == Some(&'-') {
            advance('-', &mut line, &mut column);
            advance('-', &mut line, &mut column);
            index += 2;
            if let Some((equals, content_start)) = long_bracket_start(&chars, index) {
                for character in &chars[index..content_start] {
                    advance(*character, &mut line, &mut column);
                }
                index = content_start;
                if !skip_long_bracket(&chars, &mut index, equals, &mut line, &mut column) {
                    issues.push("unterminated Lua long comment".to_owned());
                    break;
                }
            } else {
                while index < chars.len() && chars[index] != '\n' {
                    advance(chars[index], &mut line, &mut column);
                    index += 1;
                }
            }
            continue;
        }
        if current == '\'' || current == '"' {
            let token_line = line;
            let token_column = column;
            let (value, terminated) =
                read_short_string(&chars, &mut index, current, &mut line, &mut column);
            tokens.push(Token {
                kind: TokenKind::StringLiteral(value),
                line: token_line,
                column: token_column,
            });
            if !terminated {
                issues.push(format!(
                    "unterminated Lua short string at {token_line}:{token_column}"
                ));
                break;
            }
            continue;
        }
        if current == '['
            && let Some((equals, content_start)) = long_bracket_start(&chars, index)
        {
            let token_line = line;
            let token_column = column;
            for character in &chars[index..content_start] {
                advance(*character, &mut line, &mut column);
            }
            let value_start = content_start;
            index = content_start;
            let terminated = skip_long_bracket(&chars, &mut index, equals, &mut line, &mut column);
            let closing_len = equals + 2;
            let value_end = index.saturating_sub(closing_len);
            let value = terminated.then(|| {
                let mut value: String = chars[value_start..value_end].iter().collect();
                if value.starts_with('\n') {
                    value.remove(0);
                }
                value
            });
            tokens.push(Token {
                kind: TokenKind::StringLiteral(value),
                line: token_line,
                column: token_column,
            });
            if !terminated {
                issues.push(format!(
                    "unterminated Lua long string at {token_line}:{token_column}"
                ));
                break;
            }
            continue;
        }
        if current == '_' || current.is_ascii_alphabetic() {
            let token_line = line;
            let token_column = column;
            let start = index;
            while chars
                .get(index)
                .is_some_and(|character| *character == '_' || character.is_ascii_alphanumeric())
            {
                advance(chars[index], &mut line, &mut column);
                index += 1;
            }
            tokens.push(Token {
                kind: TokenKind::Identifier(chars[start..index].iter().collect()),
                line: token_line,
                column: token_column,
            });
            continue;
        }
        if "().,:={}[]".contains(current) {
            tokens.push(Token {
                kind: TokenKind::Symbol(current),
                line,
                column,
            });
        } else {
            tokens.push(Token {
                kind: TokenKind::Other(current),
                line,
                column,
            });
        }
        advance(current, &mut line, &mut column);
        index += 1;
    }

    Tokenized { tokens, issues }
}

struct ExtractedFindings {
    findings: Vec<LuaAdvisoryFinding>,
    property_writes: Vec<LuaPropertyWriteFinding>,
    issues: Vec<String>,
}

fn extract_findings(tokens: &[Token], max_findings: usize) -> ExtractedFindings {
    let mut findings = Vec::new();
    let mut issues = Vec::new();
    let mut work_budget = tokens.len().saturating_mul(4).max(1);
    let shadowed = shadowed_apis(tokens);
    let delimiters = delimiter_map(tokens);
    let matching_parentheses = &delimiters.matching;
    for (index, token) in tokens.iter().enumerate() {
        let TokenKind::Identifier(identifier) = &token.kind else {
            continue;
        };
        let Some(api) = api_for_identifier(identifier) else {
            continue;
        };
        if shadowed.contains(&api) {
            continue;
        }
        if matches!(
            index
                .checked_sub(1)
                .and_then(|previous| tokens.get(previous)),
            Some(Token {
                kind: TokenKind::Symbol('.' | ':'),
                ..
            })
        ) || is_function_declaration(tokens, index)
        {
            continue;
        }
        if api == Ue4ssLuaApi::Require
            && let Some(Token {
                kind: TokenKind::StringLiteral(value),
                ..
            }) = tokens.get(index + 1)
        {
            if finding_budget_exhausted(&mut findings, &mut issues, max_findings) {
                break;
            }
            findings.push(LuaAdvisoryFinding {
                api,
                line: token.line,
                column: token.column,
                first_argument: value
                    .clone()
                    .map_or(LuaAdvisoryArgument::DynamicUnresolved, |value| {
                        LuaAdvisoryArgument::Literal { value }
                    }),
            });
            continue;
        }
        let open_index = index + 1;
        if !matches!(
            tokens.get(index + 1).map(|token| &token.kind),
            Some(TokenKind::Symbol('('))
        ) {
            continue;
        }
        let Some(call_end) = matching_parentheses[open_index] else {
            issues.push(format!(
                "unclosed Lua call at {}:{} was not reported as a finding",
                token.line, token.column
            ));
            break;
        };
        if finding_budget_exhausted(&mut findings, &mut issues, max_findings) {
            break;
        }
        let argument = match first_argument(tokens, index + 2, call_end, &mut work_budget) {
            Ok(argument) => argument,
            Err(ArgumentError::WorkBudget) => {
                findings.clear();
                issues.push(
                    "parser work budget was exceeded; no partial finding subset was retained"
                        .to_owned(),
                );
                break;
            }
            Err(ArgumentError::UnclosedCall) => {
                issues.push(format!(
                    "unclosed Lua call at {}:{} was not reported as a finding",
                    token.line, token.column
                ));
                break;
            }
            Err(ArgumentError::FindingBudget) => {
                unreachable!("call argument parsing does not consume finding budget")
            }
        };
        findings.push(LuaAdvisoryFinding {
            api,
            line: token.line,
            column: token.column,
            first_argument: argument,
        });
    }
    for api in shadowed {
        issues.push(format!(
            "{} is assigned or declared in this script; matching calls were not attributed to UE4SS",
            api_name(api)
        ));
    }
    let suppress_all = issues.iter().any(|issue| {
        issue.starts_with("finding budget") || issue.starts_with("parser work budget")
    });
    let mut property_writes = Vec::new();
    if !delimiters.valid {
        issues.push(
            "malformed or crossed Lua delimiters prevented property-write extraction".to_owned(),
        );
    } else if !suppress_all {
        let property_limit = max_findings.saturating_sub(findings.len());
        let extracted = extract_property_writes(
            tokens,
            property_limit,
            matching_parentheses,
            &mut work_budget,
        );
        if extracted.overflowed {
            findings.clear();
        } else {
            property_writes = extracted.findings;
        }
        issues.extend(extracted.issues);
    }
    ExtractedFindings {
        findings,
        property_writes,
        issues,
    }
}

struct ExtractedPropertyWrites {
    findings: Vec<LuaPropertyWriteFinding>,
    issues: Vec<String>,
    overflowed: bool,
}

fn extract_property_writes(
    tokens: &[Token],
    max_findings: usize,
    matching_parentheses: &[Option<usize>],
    work_budget: &mut usize,
) -> ExtractedPropertyWrites {
    let matching_brackets = matching_parentheses;
    let mut findings = Vec::new();
    let mut issues = Vec::new();
    let declaration_names = function_declaration_name_indices(tokens);
    match assignment_property_writes(tokens, matching_brackets, work_budget, max_findings) {
        Ok(assignments) => {
            for finding in assignments {
                if property_budget_exhausted(&mut findings, &mut issues, max_findings) {
                    return ExtractedPropertyWrites {
                        findings,
                        issues,
                        overflowed: true,
                    };
                }
                findings.push(finding);
            }
        }
        Err(ArgumentError::WorkBudget) => {
            issues.push(
                "parser work budget was exceeded while inspecting assignment targets; no partial property subset was retained"
                    .to_owned(),
            );
            return ExtractedPropertyWrites {
                findings: Vec::new(),
                issues,
                overflowed: true,
            };
        }
        Err(ArgumentError::FindingBudget) => {
            issues.push(format!(
                "finding budget of {max_findings} was exceeded while inspecting assignment targets; no partial property subset was retained"
            ));
            return ExtractedPropertyWrites {
                findings: Vec::new(),
                issues,
                overflowed: true,
            };
        }
        Err(ArgumentError::UnclosedCall) => unreachable!("assignment scan uses a delimiter map"),
    }

    for (index, token) in tokens.iter().enumerate() {
        let TokenKind::Identifier(receiver) = &token.kind else {
            continue;
        };
        if matches!(
            (
                tokens.get(index + 1),
                tokens.get(index + 2),
                tokens.get(index + 3)
            ),
            (
                Some(Token {
                    kind: TokenKind::Symbol(':'),
                    ..
                }),
                Some(Token {
                    kind: TokenKind::Identifier(method),
                    ..
                }),
                Some(Token {
                    kind: TokenKind::Symbol('('),
                    ..
                })
            ) if method == "set"
        ) && !declaration_names.contains(&(index + 2))
        {
            let open = index + 3;
            if matching_parentheses[open].is_none() {
                issues.push(format!(
                    "unclosed parameter set candidate at {}:{}",
                    token.line, token.column
                ));
            } else {
                if property_budget_exhausted(&mut findings, &mut issues, max_findings) {
                    return ExtractedPropertyWrites {
                        findings,
                        issues,
                        overflowed: true,
                    };
                }
                findings.push(LuaPropertyWriteFinding {
                    kind: LuaPropertyWriteKind::ParameterSetCandidate,
                    line: token.line,
                    column: token.column,
                    receiver: symbolic_argument(receiver),
                    property: LuaAdvisoryArgument::Missing,
                });
            }
        }

        if receiver == "SetStructurePropertyByName"
            && !declaration_names.contains(&index)
            && matches!(
                tokens.get(index + 1),
                Some(Token {
                    kind: TokenKind::Symbol('('),
                    ..
                })
            )
        {
            let open = index + 1;
            let Some(close) = matching_parentheses[open] else {
                issues.push(format!(
                    "unclosed reflection helper candidate at {}:{}",
                    token.line, token.column
                ));
                continue;
            };
            let helper_receiver = match nth_call_argument(tokens, open + 1, close, 0, work_budget) {
                Ok(Some(argument)) => property_argument(argument),
                Ok(None) => LuaAdvisoryArgument::Missing,
                Err(ArgumentError::WorkBudget) => {
                    findings.clear();
                    issues.push(
                        "parser work budget was exceeded while inspecting property writes; no partial property subset was retained"
                            .to_owned(),
                    );
                    return ExtractedPropertyWrites {
                        findings,
                        issues,
                        overflowed: true,
                    };
                }
                Err(ArgumentError::UnclosedCall) => LuaAdvisoryArgument::DynamicUnresolved,
                Err(ArgumentError::FindingBudget) => {
                    unreachable!("call argument parsing does not consume finding budget")
                }
            };
            let property = match nth_call_argument(tokens, open + 1, close, 1, work_budget) {
                Ok(Some(argument)) => reflection_helper_property(argument),
                Ok(None) => LuaAdvisoryArgument::Missing,
                Err(ArgumentError::WorkBudget) => {
                    findings.clear();
                    issues.push(
                        "parser work budget was exceeded while inspecting property writes; no partial property subset was retained"
                            .to_owned(),
                    );
                    return ExtractedPropertyWrites {
                        findings,
                        issues,
                        overflowed: true,
                    };
                }
                Err(ArgumentError::UnclosedCall) => LuaAdvisoryArgument::DynamicUnresolved,
                Err(ArgumentError::FindingBudget) => {
                    unreachable!("call argument parsing does not consume finding budget")
                }
            };
            if property_budget_exhausted(&mut findings, &mut issues, max_findings) {
                return ExtractedPropertyWrites {
                    findings,
                    issues,
                    overflowed: true,
                };
            }
            findings.push(LuaPropertyWriteFinding {
                kind: LuaPropertyWriteKind::ReflectionHelperCandidate,
                line: token.line,
                column: token.column,
                receiver: helper_receiver,
                property,
            });
        }
    }

    findings.sort_by_key(|finding| (finding.line, finding.column));
    ExtractedPropertyWrites {
        findings,
        issues,
        overflowed: false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArgumentError {
    WorkBudget,
    UnclosedCall,
    FindingBudget,
}

fn first_argument(
    tokens: &[Token],
    start: usize,
    call_end: usize,
    work_budget: &mut usize,
) -> Result<LuaAdvisoryArgument, ArgumentError> {
    let Some(first) = tokens.get(start).filter(|_| start <= call_end) else {
        return Err(ArgumentError::UnclosedCall);
    };
    if matches!(first.kind, TokenKind::Symbol(')')) {
        return Ok(LuaAdvisoryArgument::Missing);
    }
    let end = first_argument_end(tokens, start, call_end, work_budget)?;
    let argument = &tokens[start..end];
    if argument.len() == 1 {
        return Ok(match &argument[0].kind {
            TokenKind::StringLiteral(Some(value)) => LuaAdvisoryArgument::Literal {
                value: value.clone(),
            },
            TokenKind::StringLiteral(None) => LuaAdvisoryArgument::DynamicUnresolved,
            _ => LuaAdvisoryArgument::DynamicUnresolved,
        });
    }
    if let Some(expression) = symbolic_expression(argument) {
        Ok(LuaAdvisoryArgument::Symbolic { expression })
    } else {
        Ok(LuaAdvisoryArgument::DynamicUnresolved)
    }
}

fn first_argument_end(
    tokens: &[Token],
    start: usize,
    call_end: usize,
    work_budget: &mut usize,
) -> Result<usize, ArgumentError> {
    let mut parentheses = 0_i32;
    let mut braces = 0_i32;
    let mut brackets = 0_i32;
    for (offset, token) in tokens[start..call_end].iter().enumerate() {
        let Some(remaining) = work_budget.checked_sub(1) else {
            return Err(ArgumentError::WorkBudget);
        };
        *work_budget = remaining;
        match token.kind {
            TokenKind::Symbol('(') => parentheses += 1,
            TokenKind::Symbol(')') if parentheses == 0 && braces == 0 && brackets == 0 => {
                return Ok(start + offset);
            }
            TokenKind::Symbol(')') => parentheses -= 1,
            TokenKind::Symbol('{') => braces += 1,
            TokenKind::Symbol('}') => braces -= 1,
            TokenKind::Symbol('[') => brackets += 1,
            TokenKind::Symbol(']') => brackets -= 1,
            TokenKind::Symbol(',') if parentheses == 0 && braces == 0 && brackets == 0 => {
                return Ok(start + offset);
            }
            _ => {}
        }
    }
    Ok(call_end)
}

fn symbolic_expression(tokens: &[Token]) -> Option<String> {
    if tokens.len() < 3 || tokens.len().is_multiple_of(2) {
        return None;
    }
    let mut output = String::new();
    for (index, token) in tokens.iter().enumerate() {
        match (&token.kind, index % 2) {
            (TokenKind::Identifier(identifier), 0) => output.push_str(identifier),
            (TokenKind::Symbol('.'), 1) => output.push('.'),
            _ => return None,
        }
    }
    Some(output)
}

fn is_function_declaration(tokens: &[Token], index: usize) -> bool {
    matches!(
        index.checked_sub(1).and_then(|previous| tokens.get(previous)),
        Some(Token {
            kind: TokenKind::Identifier(identifier),
            ..
        }) if identifier == "function"
    )
}

fn shadowed_apis(tokens: &[Token]) -> BTreeSet<Ue4ssLuaApi> {
    let mut shadowed = BTreeSet::new();
    for (index, token) in tokens.iter().enumerate() {
        let TokenKind::Identifier(identifier) = &token.kind else {
            continue;
        };
        let Some(api) = api_for_identifier(identifier) else {
            continue;
        };
        let qualified = matches!(
            index
                .checked_sub(1)
                .and_then(|previous| tokens.get(previous)),
            Some(Token {
                kind: TokenKind::Symbol('.' | ':'),
                ..
            })
        );
        let assigned = !qualified
            && matches!(
                tokens.get(index + 1),
                Some(Token {
                    kind: TokenKind::Symbol('='),
                    ..
                })
            )
            && !matches!(
                tokens.get(index + 2),
                Some(Token {
                    kind: TokenKind::Symbol('='),
                    ..
                })
            );
        let local_declaration = matches!(
            index.checked_sub(1).and_then(|previous| tokens.get(previous)),
            Some(Token {
                kind: TokenKind::Identifier(identifier),
                ..
            }) if identifier == "local"
        );
        if assigned || local_declaration || is_function_declaration(tokens, index) {
            shadowed.insert(api);
        }
    }
    collect_declaration_list_shadows(tokens, &mut shadowed);
    collect_parameter_shadows(tokens, &mut shadowed);
    shadowed
}

fn collect_declaration_list_shadows(tokens: &[Token], shadowed: &mut BTreeSet<Ue4ssLuaApi>) {
    let mut index = 0_usize;
    while index < tokens.len() {
        let TokenKind::Identifier(keyword) = &tokens[index].kind else {
            index += 1;
            continue;
        };
        if keyword != "local" && keyword != "for" {
            index += 1;
            continue;
        }
        index += 1;
        if matches!(
            tokens.get(index),
            Some(Token {
                kind: TokenKind::Identifier(identifier),
                ..
            }) if identifier == "function"
        ) {
            index += 1;
        }
        let mut expect_name = true;
        while index < tokens.len() {
            if expect_name {
                let TokenKind::Identifier(identifier) = &tokens[index].kind else {
                    break;
                };
                if identifier == "in" && keyword == "for" {
                    break;
                }
                if let Some(api) = api_for_identifier(identifier) {
                    shadowed.insert(api);
                }
                expect_name = false;
            } else if keyword == "local" && matches!(tokens[index].kind, TokenKind::Other('<')) {
                let valid_attribute = matches!(
                    tokens.get(index + 1),
                    Some(Token {
                        kind: TokenKind::Identifier(identifier),
                        ..
                    }) if identifier == "const" || identifier == "close"
                ) && matches!(
                    tokens.get(index + 2),
                    Some(Token {
                        kind: TokenKind::Other('>'),
                        ..
                    })
                );
                if !valid_attribute {
                    break;
                }
                index += 3;
                continue;
            } else if matches!(tokens[index].kind, TokenKind::Symbol(',')) {
                expect_name = true;
            } else {
                break;
            }
            index += 1;
        }
    }
}

fn collect_parameter_shadows(tokens: &[Token], shadowed: &mut BTreeSet<Ue4ssLuaApi>) {
    let matching = matching_parentheses(tokens);
    let mut index = 0_usize;
    while index < tokens.len() {
        let token = &tokens[index];
        if !matches!(
            &token.kind,
            TokenKind::Identifier(identifier) if identifier == "function"
        ) {
            index += 1;
            continue;
        }
        let mut open = index + 1;
        while open < tokens.len() && !matches!(tokens[open].kind, TokenKind::Symbol('(')) {
            open += 1;
        }
        if open == tokens.len() {
            break;
        }
        let Some(close) = matching[open] else {
            index = open + 1;
            continue;
        };
        for parameter in &tokens[open + 1..close] {
            if let TokenKind::Identifier(identifier) = &parameter.kind
                && let Some(api) = api_for_identifier(identifier)
            {
                shadowed.insert(api);
            }
        }
        index = close + 1;
    }
}

fn matching_parentheses(tokens: &[Token]) -> Vec<Option<usize>> {
    delimiter_map(tokens).matching
}

struct DelimiterMap {
    matching: Vec<Option<usize>>,
    valid: bool,
}

fn delimiter_map(tokens: &[Token]) -> DelimiterMap {
    let mut matching = vec![None; tokens.len()];
    let mut stack = Vec::new();
    let mut valid = true;
    for (index, token) in tokens.iter().enumerate() {
        match token.kind {
            TokenKind::Symbol(symbol @ ('(' | '[' | '{')) => stack.push((symbol, index)),
            TokenKind::Symbol(close @ (')' | ']' | '}')) => {
                let expected_open = match close {
                    ')' => '(',
                    ']' => '[',
                    '}' => '{',
                    _ => unreachable!(),
                };
                if stack.last().is_some_and(|(open, _)| *open == expected_open) {
                    let (_, open_index) = stack.pop().expect("matching stack entry exists");
                    matching[open_index] = Some(index);
                } else {
                    valid = false;
                }
            }
            _ => {}
        }
    }
    if !stack.is_empty() {
        valid = false;
    }
    DelimiterMap { matching, valid }
}

fn property_argument(tokens: &[Token]) -> LuaAdvisoryArgument {
    if tokens.is_empty() {
        return LuaAdvisoryArgument::Missing;
    }
    if tokens.len() == 1 {
        return match &tokens[0].kind {
            TokenKind::StringLiteral(Some(value)) => LuaAdvisoryArgument::Literal {
                value: value.clone(),
            },
            TokenKind::Identifier(identifier) => LuaAdvisoryArgument::Symbolic {
                expression: identifier.clone(),
            },
            _ => LuaAdvisoryArgument::DynamicUnresolved,
        };
    }
    symbolic_expression(tokens)
        .map(|expression| LuaAdvisoryArgument::Symbolic { expression })
        .unwrap_or(LuaAdvisoryArgument::DynamicUnresolved)
}

fn symbolic_argument(identifier: &str) -> LuaAdvisoryArgument {
    LuaAdvisoryArgument::Symbolic {
        expression: identifier.to_owned(),
    }
}

fn assignment_property_writes(
    tokens: &[Token],
    matching_delimiters: &[Option<usize>],
    work_budget: &mut usize,
    max_findings: usize,
) -> Result<Vec<LuaPropertyWriteFinding>, ArgumentError> {
    let mut findings = Vec::new();
    let mut index = 0_usize;
    while index < tokens.len() {
        let Some((mut cursor, first)) =
            parse_assignment_target(tokens, index, matching_delimiters, work_budget)?
        else {
            index += 1;
            continue;
        };
        let remaining_findings = max_findings.saturating_sub(findings.len());
        let mut targets = Vec::new();
        let mut target_overflow = false;
        if let Some(finding) = first {
            push_bounded_assignment_target(
                &mut targets,
                &mut target_overflow,
                remaining_findings,
                finding,
            );
        }
        while matches!(
            tokens.get(cursor),
            Some(Token {
                kind: TokenKind::Symbol(','),
                ..
            })
        ) {
            consume_work(work_budget, 1)?;
            let Some((next, finding)) =
                parse_assignment_target(tokens, cursor + 1, matching_delimiters, work_budget)?
            else {
                break;
            };
            if let Some(finding) = finding {
                push_bounded_assignment_target(
                    &mut targets,
                    &mut target_overflow,
                    remaining_findings,
                    finding,
                );
            }
            cursor = next;
        }
        let assignment = matches!(
            tokens.get(cursor),
            Some(Token {
                kind: TokenKind::Symbol('='),
                ..
            })
        ) && !matches!(
            tokens.get(cursor + 1),
            Some(Token {
                kind: TokenKind::Symbol('='),
                ..
            })
        );
        if assignment {
            if target_overflow {
                return Err(ArgumentError::FindingBudget);
            }
            findings.extend(targets);
        }
        index = cursor.max(index + 1);
    }
    Ok(findings)
}

fn push_bounded_assignment_target(
    targets: &mut Vec<LuaPropertyWriteFinding>,
    overflowed: &mut bool,
    limit: usize,
    finding: LuaPropertyWriteFinding,
) {
    if targets.len() < limit {
        targets.push(finding);
    } else {
        *overflowed = true;
    }
}

fn parse_assignment_target(
    tokens: &[Token],
    start: usize,
    matching_delimiters: &[Option<usize>],
    work_budget: &mut usize,
) -> Result<Option<(usize, Option<LuaPropertyWriteFinding>)>, ArgumentError> {
    let Some(Token {
        kind: TokenKind::Identifier(first),
        ..
    }) = tokens.get(start)
    else {
        return Ok(None);
    };
    consume_work(work_budget, 1)?;
    let mut components = vec![first.clone()];
    let mut cursor = start + 1;
    while matches!(
        tokens.get(cursor),
        Some(Token {
            kind: TokenKind::Symbol('.'),
            ..
        })
    ) {
        let Some(Token {
            kind: TokenKind::Identifier(component),
            ..
        }) = tokens.get(cursor + 1)
        else {
            break;
        };
        consume_work(work_budget, 2)?;
        components.push(component.clone());
        cursor += 2;
    }
    if matches!(
        tokens.get(cursor),
        Some(Token {
            kind: TokenKind::Symbol('['),
            ..
        })
    ) {
        let Some(close) = matching_delimiters[cursor] else {
            return Ok(Some((cursor + 1, None)));
        };
        consume_work(work_budget, close.saturating_sub(cursor))?;
        let property = property_argument(&tokens[cursor + 1..close]);
        let kind = if matches!(property, LuaAdvisoryArgument::Literal { .. }) {
            LuaPropertyWriteKind::LiteralIndexCandidate
        } else {
            LuaPropertyWriteKind::DynamicIndexCandidate
        };
        return Ok(Some((
            close + 1,
            Some(LuaPropertyWriteFinding {
                kind,
                line: tokens[cursor].line,
                column: tokens[cursor].column,
                receiver: symbolic_argument(&components.join(".")),
                property,
            }),
        )));
    }
    let finding = (components.len() >= 2).then(|| {
        let property_index = cursor - 1;
        LuaPropertyWriteFinding {
            kind: LuaPropertyWriteKind::DotMemberCandidate,
            line: tokens[property_index].line,
            column: tokens[property_index].column,
            receiver: symbolic_argument(&components[..components.len() - 1].join(".")),
            property: LuaAdvisoryArgument::Literal {
                value: components
                    .last()
                    .expect("dot target has a property")
                    .clone(),
            },
        }
    });
    Ok(Some((cursor, finding)))
}

fn consume_work(work_budget: &mut usize, amount: usize) -> Result<(), ArgumentError> {
    let Some(remaining) = work_budget.checked_sub(amount) else {
        return Err(ArgumentError::WorkBudget);
    };
    *work_budget = remaining;
    Ok(())
}

fn function_declaration_name_indices(tokens: &[Token]) -> BTreeSet<usize> {
    let mut names = BTreeSet::new();
    for (index, token) in tokens.iter().enumerate() {
        if !matches!(
            &token.kind,
            TokenKind::Identifier(identifier) if identifier == "function"
        ) {
            continue;
        }
        let mut cursor = index + 1;
        if matches!(
            tokens.get(cursor),
            Some(Token {
                kind: TokenKind::Identifier(_),
                ..
            })
        ) {
            names.insert(cursor);
            cursor += 1;
        }
        while matches!(
            tokens.get(cursor),
            Some(Token {
                kind: TokenKind::Symbol('.' | ':'),
                ..
            })
        ) && matches!(
            tokens.get(cursor + 1),
            Some(Token {
                kind: TokenKind::Identifier(_),
                ..
            })
        ) {
            names.insert(cursor + 1);
            cursor += 2;
        }
    }
    names
}

fn reflection_helper_property(tokens: &[Token]) -> LuaAdvisoryArgument {
    let direct = property_argument(tokens);
    if matches!(direct, LuaAdvisoryArgument::Literal { .. }) {
        return direct;
    }
    if let [
        Token {
            kind: TokenKind::Identifier(function),
            ..
        },
        Token {
            kind: TokenKind::Symbol('('),
            ..
        },
        Token {
            kind: TokenKind::StringLiteral(Some(value)),
            ..
        },
        Token {
            kind: TokenKind::Symbol(')'),
            ..
        },
    ] = tokens
        && function == "FName"
    {
        return LuaAdvisoryArgument::Literal {
            value: value.clone(),
        };
    }
    LuaAdvisoryArgument::DynamicUnresolved
}

fn nth_call_argument<'a>(
    tokens: &'a [Token],
    start: usize,
    call_end: usize,
    requested: usize,
    work_budget: &mut usize,
) -> Result<Option<&'a [Token]>, ArgumentError> {
    let mut parentheses = 0_i32;
    let mut braces = 0_i32;
    let mut brackets = 0_i32;
    let mut argument_index = 0_usize;
    let mut argument_start = start;
    for index in start..call_end {
        let Some(remaining) = work_budget.checked_sub(1) else {
            return Err(ArgumentError::WorkBudget);
        };
        *work_budget = remaining;
        match tokens[index].kind {
            TokenKind::Symbol('(') => parentheses += 1,
            TokenKind::Symbol(')') => parentheses -= 1,
            TokenKind::Symbol('{') => braces += 1,
            TokenKind::Symbol('}') => braces -= 1,
            TokenKind::Symbol('[') => brackets += 1,
            TokenKind::Symbol(']') => brackets -= 1,
            TokenKind::Symbol(',') if parentheses == 0 && braces == 0 && brackets == 0 => {
                if argument_index == requested {
                    return Ok(Some(&tokens[argument_start..index]));
                }
                argument_index += 1;
                argument_start = index + 1;
            }
            _ => {}
        }
    }
    (argument_index == requested)
        .then_some(&tokens[argument_start..call_end])
        .map_or(Ok(None), |argument| Ok(Some(argument)))
}

fn property_budget_exhausted(
    findings: &mut Vec<LuaPropertyWriteFinding>,
    issues: &mut Vec<String>,
    max_findings: usize,
) -> bool {
    if findings.len() < max_findings {
        return false;
    }
    findings.clear();
    issues.push(format!(
        "finding budget of {max_findings} was exceeded while inspecting property writes; no partial subset was retained"
    ));
    true
}

fn finding_budget_exhausted(
    findings: &mut Vec<LuaAdvisoryFinding>,
    issues: &mut Vec<String>,
    max_findings: usize,
) -> bool {
    if findings.len() < max_findings {
        return false;
    }
    findings.clear();
    issues.push(format!(
        "finding budget of {max_findings} was exceeded; analysis stopped without retaining a partial subset"
    ));
    true
}

fn api_for_identifier(identifier: &str) -> Option<Ue4ssLuaApi> {
    match identifier {
        "RegisterHook" => Some(Ue4ssLuaApi::RegisterHook),
        "NotifyOnNewObject" => Some(Ue4ssLuaApi::NotifyOnNewObject),
        "RegisterConsoleCommandHandler" => Some(Ue4ssLuaApi::RegisterConsoleCommandHandler),
        "RegisterKeyBind" => Some(Ue4ssLuaApi::RegisterKeyBind),
        "RegisterLoadMapPreHook" => Some(Ue4ssLuaApi::RegisterLoadMapPreHook),
        "RegisterLoadMapPostHook" => Some(Ue4ssLuaApi::RegisterLoadMapPostHook),
        "require" => Some(Ue4ssLuaApi::Require),
        _ => None,
    }
}

fn api_name(api: Ue4ssLuaApi) -> &'static str {
    match api {
        Ue4ssLuaApi::RegisterHook => "RegisterHook",
        Ue4ssLuaApi::NotifyOnNewObject => "NotifyOnNewObject",
        Ue4ssLuaApi::RegisterConsoleCommandHandler => "RegisterConsoleCommandHandler",
        Ue4ssLuaApi::RegisterKeyBind => "RegisterKeyBind",
        Ue4ssLuaApi::RegisterLoadMapPreHook => "RegisterLoadMapPreHook",
        Ue4ssLuaApi::RegisterLoadMapPostHook => "RegisterLoadMapPostHook",
        Ue4ssLuaApi::Require => "require",
    }
}

fn read_short_string(
    chars: &[char],
    index: &mut usize,
    quote: char,
    line: &mut usize,
    column: &mut usize,
) -> (Option<String>, bool) {
    advance(chars[*index], line, column);
    *index += 1;
    let mut value = String::new();
    let mut exact = true;
    while *index < chars.len() {
        let character = chars[*index];
        if character == quote {
            advance(character, line, column);
            *index += 1;
            return (exact.then_some(value), true);
        }
        if character == '\n' || character == '\r' {
            return (None, false);
        }
        if character == '\\' {
            advance(character, line, column);
            *index += 1;
            let Some(escaped) = chars.get(*index).copied() else {
                return (None, false);
            };
            match escaped {
                'n' => value.push('\n'),
                'r' => value.push('\r'),
                't' => value.push('\t'),
                '\\' => value.push('\\'),
                '\'' => value.push('\''),
                '"' => value.push('"'),
                _ => exact = false,
            }
            advance(escaped, line, column);
            *index += 1;
            continue;
        }
        value.push(character);
        advance(character, line, column);
        *index += 1;
    }
    (None, false)
}

fn long_bracket_start(chars: &[char], index: usize) -> Option<(usize, usize)> {
    if chars.get(index) != Some(&'[') {
        return None;
    }
    let mut cursor = index + 1;
    while chars.get(cursor) == Some(&'=') {
        cursor += 1;
    }
    (chars.get(cursor) == Some(&'[')).then_some((cursor - index - 1, cursor + 1))
}

fn skip_long_bracket(
    chars: &[char],
    index: &mut usize,
    equals: usize,
    line: &mut usize,
    column: &mut usize,
) -> bool {
    while *index < chars.len() {
        if chars[*index] == ']' {
            let mut cursor = *index + 1;
            let mut seen_equals = 0_usize;
            while seen_equals < equals && chars.get(cursor) == Some(&'=') {
                seen_equals += 1;
                cursor += 1;
            }
            if seen_equals == equals && chars.get(cursor) == Some(&']') {
                while *index <= cursor {
                    advance(chars[*index], line, column);
                    *index += 1;
                }
                return true;
            }
        }
        advance(chars[*index], line, column);
        *index += 1;
    }
    false
}

fn advance(character: char, line: &mut usize, column: &mut usize) {
    if character == '\n' {
        *line += 1;
        *column = 1;
    } else {
        *column += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn extracts_literal_symbolic_and_dynamic_calls_without_counting_declarations() {
        let source = r#"
mock.RegisterHook("/Game/AlsoFake", callback)
RegisterHook("/Game/Test.Test_C:Run", callback)
NotifyOnNewObject(CLASS_PATH, callback)
RegisterConsoleCommandHandler('testcommand', callback)
RegisterKeyBind(Key.F8, callback)
        local Config = require("config")
"#;
        let tokenized = tokenize(source);
        assert!(tokenized.issues.is_empty());
        let findings = extract_findings(&tokenized.tokens, 100).findings;

        assert_eq!(findings.len(), 5);
        assert_eq!(findings[0].api, Ue4ssLuaApi::RegisterHook);
        assert_eq!(
            findings[0].first_argument,
            LuaAdvisoryArgument::Literal {
                value: "/Game/Test.Test_C:Run".to_owned()
            }
        );
        assert_eq!(
            findings[1].first_argument,
            LuaAdvisoryArgument::DynamicUnresolved
        );
        assert_eq!(
            findings[3].first_argument,
            LuaAdvisoryArgument::Symbolic {
                expression: "Key.F8".to_owned()
            }
        );
        assert_eq!(findings[4].api, Ue4ssLuaApi::Require);
    }

    #[test]
    fn does_not_attribute_calls_to_an_assigned_or_declared_api_name() {
        let source = r#"
function RegisterHook(path, callback) end
RegisterHook("/Game/Fake", callback)
RegisterConsoleCommandHandler = function(name, callback) end
RegisterConsoleCommandHandler("fake", callback)
"#;
        let extracted = extract_findings(&tokenize(source).tokens, 100);
        assert!(extracted.findings.is_empty());
        assert_eq!(extracted.issues.len(), 2);
    }

    #[test]
    fn handles_parameter_shadows_without_confusing_members_or_equality() {
        let source = r#"
local function mock(RegisterHook)
    RegisterHook("/Game/Fake", callback)
end
mock.RegisterConsoleCommandHandler = callback
if RegisterConsoleCommandHandler == nil then end
RegisterConsoleCommandHandler("real", callback)
"#;
        let extracted = extract_findings(&tokenize(source).tokens, 100);
        assert_eq!(extracted.findings.len(), 1);
        assert_eq!(
            extracted.findings[0].api,
            Ue4ssLuaApi::RegisterConsoleCommandHandler
        );
        assert!(
            extracted
                .issues
                .iter()
                .any(|issue| issue.starts_with("RegisterHook is"))
        );
    }

    #[test]
    fn handles_multi_name_local_and_for_declarations_conservatively() {
        let source = r#"
local first, RegisterHook, last
for item, NotifyOnNewObject in values do
    RegisterHook("/Game/Fake", callback)
    NotifyOnNewObject("/Game/Fake", callback)
end
"#;
        let extracted = extract_findings(&tokenize(source).tokens, 100);
        assert!(extracted.findings.is_empty());
        assert_eq!(extracted.issues.len(), 2);
    }

    #[test]
    fn stops_a_local_declaration_at_the_next_statement() {
        let source = r#"
local unrelated
RegisterHook("/Game/Real", callback)
"#;
        let extracted = extract_findings(&tokenize(source).tokens, 100);
        assert_eq!(extracted.findings.len(), 1);
        assert!(extracted.issues.is_empty());
    }

    #[test]
    fn handles_lua_54_local_attributes() {
        let source = r#"
local first <const>, RegisterHook, last <close> = 1, fake, resource
RegisterHook("/Game/Fake", callback)
"#;
        let extracted = extract_findings(&tokenize(source).tokens, 100);
        assert!(extracted.findings.is_empty());
        assert_eq!(extracted.issues.len(), 1);
    }

    #[test]
    fn extracts_property_write_candidates_without_claiming_reflection() {
        let source = r#"
object.CustomTimeDilation = 2.5
object["Teleport Alpha"] = 0.9
object[PROPERTY_NAME] = value
parameter:set(true)
library:SetStructurePropertyByName(object, FName("Product Struct"), product)
stats.failures = stats.failures + 1
object.first, object.second = one, two
"#;
        let extracted = extract_findings(&tokenize(source).tokens, 100);

        assert!(extracted.findings.is_empty());
        assert!(extracted.issues.is_empty());
        assert_eq!(extracted.property_writes.len(), 8);
        assert_eq!(
            extracted.property_writes[0].kind,
            LuaPropertyWriteKind::DotMemberCandidate
        );
        assert_eq!(
            extracted.property_writes[1].kind,
            LuaPropertyWriteKind::LiteralIndexCandidate
        );
        assert_eq!(
            extracted.property_writes[1].property,
            LuaAdvisoryArgument::Literal {
                value: "Teleport Alpha".to_owned()
            }
        );
        assert_eq!(
            extracted.property_writes[2].property,
            LuaAdvisoryArgument::Symbolic {
                expression: "PROPERTY_NAME".to_owned()
            }
        );
        assert_eq!(
            extracted.property_writes[3].kind,
            LuaPropertyWriteKind::ParameterSetCandidate
        );
        assert_eq!(
            extracted.property_writes[4].kind,
            LuaPropertyWriteKind::ReflectionHelperCandidate
        );
        assert_eq!(
            extracted.property_writes[4].property,
            LuaAdvisoryArgument::Literal {
                value: "Product Struct".to_owned()
            }
        );
        assert_eq!(
            extracted.property_writes[4].receiver,
            LuaAdvisoryArgument::Symbolic {
                expression: "object".to_owned()
            }
        );
        assert_eq!(
            extracted.property_writes[6].property,
            LuaAdvisoryArgument::Literal {
                value: "first".to_owned()
            }
        );
        assert_eq!(
            extracted.property_writes[7].property,
            LuaAdvisoryArgument::Literal {
                value: "second".to_owned()
            }
        );
    }

    #[test]
    fn suppresses_property_candidates_from_declarations_and_malformed_delimiters() {
        let declarations = r#"
function SetStructurePropertyByName(object, property, value) end
function library:SetStructurePropertyByName(object, property, value) end
function ns.library:SetStructurePropertyByName(object, property, value) end
function ns.parameter:set(value) end
"#;
        let extracted = extract_findings(&tokenize(declarations).tokens, 100);
        assert!(extracted.property_writes.is_empty());

        let malformed = extract_findings(&tokenize("object[(key] = value)").tokens, 100);
        assert!(malformed.property_writes.is_empty());
        assert!(
            malformed
                .issues
                .iter()
                .any(|issue| issue.contains("malformed or crossed"))
        );
    }

    #[test]
    fn scans_large_multi_target_assignments_with_bounded_linear_work() {
        let targets = (0..2_000)
            .map(|index| format!("object.property{index}"))
            .collect::<Vec<_>>()
            .join(",");
        let source = format!("{targets} = values");
        let extracted = extract_findings(&tokenize(&source).tokens, 3_000);

        assert!(extracted.issues.is_empty());
        assert_eq!(extracted.property_writes.len(), 2_000);
    }

    #[test]
    fn applies_one_combined_budget_to_api_and_property_findings() {
        let source = r#"
RegisterHook("/Game/Test", callback)
object.Property = value
"#;
        let extracted = extract_findings(&tokenize(source).tokens, 1);

        assert!(extracted.findings.is_empty());
        assert!(extracted.property_writes.is_empty());
        assert!(
            extracted
                .issues
                .iter()
                .any(|issue| issue.starts_with("finding budget"))
        );
    }

    #[test]
    fn ignores_calls_inside_comments_and_strings_including_long_brackets() {
        let source = r#"
-- RegisterHook("/Game/Fake", callback)
--[=[ NotifyOnNewObject("/Game/Fake", callback) ]=]
local short = "RegisterKeyBind(Key.F1, callback)"
local long = [==[RegisterConsoleCommandHandler("fake", callback)]==]
RegisterConsoleCommandHandler("real", callback)
"#;
        let tokenized = tokenize(source);
        assert!(tokenized.issues.is_empty());
        let findings = extract_findings(&tokenized.tokens, 100).findings;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].api, Ue4ssLuaApi::RegisterConsoleCommandHandler);
    }

    #[test]
    fn malformed_strings_are_partial_and_do_not_create_inner_findings() {
        let source = "RegisterHook(\"/Game/Valid\", callback)\nlocal broken = [=[ RegisterHook(\"/Game/Fake\", callback)";
        let tokenized = tokenize(source);
        assert_eq!(tokenized.issues, ["unterminated Lua long string at 2:16"]);
        let findings = extract_findings(&tokenized.tokens, 100).findings;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].api, Ue4ssLuaApi::RegisterHook);
    }

    #[test]
    fn unclosed_calls_and_adversarial_nesting_are_bounded() {
        let unclosed = extract_findings(
            &tokenize("RegisterHook(\"/Game/Test\", callback").tokens,
            100,
        );
        assert!(unclosed.findings.is_empty());
        assert!(
            unclosed
                .issues
                .iter()
                .any(|issue| issue.contains("unclosed Lua call"))
        );

        let reference_only = extract_findings(&tokenize("local saved = RegisterHook").tokens, 0);
        assert!(reference_only.findings.is_empty());
        assert!(reference_only.issues.is_empty());

        let nested = format!("{}value{}", "RegisterHook(".repeat(200), ")".repeat(200));
        let extracted = extract_findings(&tokenize(&nested).tokens, 1_000);
        assert!(extracted.findings.is_empty());
        assert!(
            extracted
                .issues
                .iter()
                .any(|issue| issue.contains("parser work budget"))
        );
    }

    #[test]
    fn analyzes_installed_scripts_with_limits_and_without_execution() {
        let temporary = TempDir::new().unwrap();
        let script = temporary
            .path()
            .join("RetroRewind/Binaries/Win64/ue4ss/Mods/Example/Scripts/main.lua");
        fs::create_dir_all(script.parent().unwrap()).unwrap();
        fs::write(
            &script,
            b"RegisterConsoleCommandHandler('example', function() error('not run') end)",
        )
        .unwrap();

        let report = analyze_ue4ss_lua(
            temporary.path(),
            &Ue4ssInventoryLimits::default(),
            &LuaAdvisoryLimits::default(),
        )
        .unwrap();

        assert!(report.complete);
        assert_eq!(report.modules.len(), 1);
        assert_eq!(report.modules[0].scripts[0].findings.len(), 1);
        assert_eq!(
            fs::read(&script).unwrap(),
            b"RegisterConsoleCommandHandler('example', function() error('not run') end)"
        );
    }

    #[test]
    fn rejects_arbitrary_partial_finding_subsets() {
        let temporary = TempDir::new().unwrap();
        let script = temporary
            .path()
            .join("RetroRewind/Binaries/Win64/ue4ss/Mods/Example/Scripts/main.lua");
        fs::create_dir_all(script.parent().unwrap()).unwrap();
        fs::write(
            &script,
            b"require('one')\nrequire('two')\nrequire('three')\n",
        )
        .unwrap();

        let report = analyze_ue4ss_lua(
            temporary.path(),
            &Ue4ssInventoryLimits::default(),
            &LuaAdvisoryLimits {
                max_findings: 2,
                ..LuaAdvisoryLimits::default()
            },
        )
        .unwrap();

        assert!(!report.complete);
        assert!(report.modules[0].scripts[0].findings.is_empty());
    }

    #[test]
    fn preserves_analyzed_module_evidence_when_the_script_limit_is_reached() {
        let temporary = TempDir::new().unwrap();
        let scripts = temporary
            .path()
            .join("RetroRewind/Binaries/Win64/ue4ss/Mods/Example/Scripts");
        fs::create_dir_all(&scripts).unwrap();
        fs::write(scripts.join("a.lua"), b"require('a')").unwrap();
        fs::write(scripts.join("b.lua"), b"require('b')").unwrap();

        let report = analyze_ue4ss_lua(
            temporary.path(),
            &Ue4ssInventoryLimits::default(),
            &LuaAdvisoryLimits {
                max_scripts: 1,
                ..LuaAdvisoryLimits::default()
            },
        )
        .unwrap();

        assert!(!report.complete);
        assert_eq!(report.modules.len(), 1);
        assert_eq!(report.modules[0].scripts.len(), 1);
        assert_eq!(report.modules[0].scripts[0].findings.len(), 1);
    }
}
