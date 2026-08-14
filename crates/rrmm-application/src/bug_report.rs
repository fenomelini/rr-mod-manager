use anyhow::{Context, Result, bail};
use chrono::DateTime;
use rrmm_ue4ss::{
    EntryStatus, Ue4ssRuntimeLogFile, Ue4ssRuntimeLogLimits, Ue4ssRuntimeSession,
    analyze_ue4ss_runtime_logs, read_ue4ss_runtime_log_tail_text, read_ue4ss_runtime_log_text,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use zip::write::SimpleFileOptions;

const MAX_AFFECTED_MOD_CHARS: usize = 120;
const MAX_SUMMARY_CHARS: usize = 2_000;
const MAX_DETAIL_CHARS: usize = 6_000;
const MAX_REPRODUCIBILITY_CHARS: usize = 120;
const MAX_OCCURRED_AT_CHARS: usize = 64;
const MAX_SESSION_FILE_BYTES: usize = 768 * 1024;
const MAX_EXCERPT_SOURCE_BYTES: u64 = 512 * 1024;
const MAX_EXCERPT_BYTES: usize = 256 * 1024;
const MAX_FULL_LOG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PACKAGE_BYTES: u64 = 5 * 1024 * 1024;
const PACKAGE_OVERHEAD_RESERVE: usize = 64 * 1024;

const SUMMARY_FILE: &str = "resumo.txt";
const DIAGNOSTICS_FILE: &str = "diagnostico.json";
const SESSION_FILE: &str = "ue4ss-sessao.json";
const EXCERPT_FILE: &str = "ue4ss-trecho-redigido.log";
const FULL_LOG_FILE: &str = "ue4ss-completo-redigido.log";
const OPERATIONS_FILE: &str = "rrmm-operations.json";
const SAFE_FILE_NAMES: [&str; 6] = [
    SUMMARY_FILE,
    DIAGNOSTICS_FILE,
    SESSION_FILE,
    EXCERPT_FILE,
    FULL_LOG_FILE,
    OPERATIONS_FILE,
];

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BugReportRequestView {
    #[serde(default)]
    pub subject_kind: BugReportSubjectKind,
    pub affected_mod: String,
    pub problem_summary: String,
    pub steps_to_reproduce: String,
    pub expected_behavior: String,
    pub observed_behavior: String,
    pub reproducibility: String,
    pub occurred_at: Option<String>,
    pub include_active_mods: bool,
    pub include_full_ue4ss_log: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BugReportSubjectKind {
    Manager,
    Game,
    #[default]
    Mod,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IncidentMarkerView {
    pub id: String,
    pub recorded_at: String,
    pub game_running: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BugReportFilePreviewView {
    pub name: String,
    pub content: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BugReportPreviewView {
    pub token: String,
    pub files: Vec<BugReportFilePreviewView>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingBugReport {
    pub files: Vec<BugReportFilePreviewView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BugReportActiveMod {
    pub name: String,
    pub version: String,
    pub mod_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u64>,
}

pub(crate) struct BugReportContext {
    pub generated_at: String,
    pub game_running: bool,
    pub game_detected: bool,
    pub game_build_id: Option<String>,
    pub game_root: Option<PathBuf>,
    pub active_mods: Option<Vec<BugReportActiveMod>>,
    pub incident_marker: Option<IncidentMarkerView>,
    pub technical_summary: Value,
    pub operation_history: Value,
}

pub(crate) fn prepare_bug_report(
    request: BugReportRequestView,
    context: BugReportContext,
) -> Result<(Vec<BugReportFilePreviewView>, Vec<String>)> {
    let request = validate_request(request)?;
    let mut warnings = Vec::new();
    let mut files = vec![BugReportFilePreviewView {
        name: SUMMARY_FILE.to_owned(),
        content: report_summary(&request),
        truncated: false,
    }];

    let mut diagnostics = serde_json::Map::new();
    diagnostics.insert("schemaVersion".to_owned(), json!(1));
    diagnostics.insert("generatedAt".to_owned(), json!(context.generated_at));
    diagnostics.insert(
        "application".to_owned(),
        json!({
            "name": "RR Mod Manager",
            "version": env!("CARGO_PKG_VERSION"),
            "platform": std::env::consts::OS,
            "architecture": std::env::consts::ARCH
        }),
    );
    diagnostics.insert(
        "game".to_owned(),
        json!({
            "detected": context.game_detected,
            "buildId": context.game_build_id,
            "running": context.game_running
        }),
    );
    diagnostics.insert("subjectKind".to_owned(), json!(request.subject_kind));
    diagnostics.insert("affectedMod".to_owned(), json!(request.affected_mod));
    diagnostics.insert("occurredAt".to_owned(), json!(request.occurred_at));
    diagnostics.insert("incidentMarker".to_owned(), json!(context.incident_marker));
    diagnostics.insert("managerState".to_owned(), context.technical_summary);
    if request.include_active_mods
        && let Some(active_mods) = context.active_mods
    {
        diagnostics.insert("activeMods".to_owned(), serde_json::to_value(active_mods)?);
    }
    files.push(BugReportFilePreviewView {
        name: DIAGNOSTICS_FILE.to_owned(),
        content: pretty_json(&Value::Object(diagnostics))?,
        truncated: false,
    });
    files.push(BugReportFilePreviewView {
        name: OPERATIONS_FILE.to_owned(),
        content: pretty_json(&context.operation_history)?,
        truncated: false,
    });

    let mut selected_log_path = None;
    if let Some(game_root) = context.game_root.as_deref() {
        let limits = Ue4ssRuntimeLogLimits {
            max_bytes: MAX_FULL_LOG_BYTES,
            max_line_bytes: 64 * 1024,
            max_lines: 100_000,
            max_sessions: 16,
            max_events: 4_000,
            max_field_chars: 512,
            max_banner_distance_bytes: 8 * 1024,
        };
        match analyze_ue4ss_runtime_logs(game_root, &limits) {
            Ok(report) => {
                let mut sessions: Vec<_> = report
                    .logs
                    .iter()
                    .filter_map(|log| selected_session(log).map(|session| (log, session)))
                    .collect();
                sessions
                    .sort_by(|(left, _), (right, _)| log_sort_key(left).cmp(&log_sort_key(right)));
                if sessions.len() > 1 {
                    warnings.push(
                        "Mais de um UE4SS.log continha uma sessão válida; foi usada a sessão do arquivo modificado mais recentemente."
                            .to_owned(),
                    );
                }
                if let Some((log, session)) = sessions.last().copied() {
                    selected_log_path = Some(log.entry.relative_path.clone());
                    let (content, truncated, filtered) = session_json(
                        session,
                        &log.entry.relative_path,
                        &request.affected_mod,
                        &context.generated_at,
                    )?;
                    if truncated {
                        warnings.push(
                            "Os eventos estruturados do UE4SS foram truncados para respeitar o limite do relato."
                                .to_owned(),
                        );
                    }
                    if !filtered && !session.events.is_empty() {
                        warnings.push(
                            "Não foi possível relacionar eventos UE4SS exclusivamente ao mod afetado; a sessão selecionada foi preservada."
                                .to_owned(),
                        );
                    }
                    files.push(BugReportFilePreviewView {
                        name: SESSION_FILE.to_owned(),
                        content,
                        truncated,
                    });
                } else {
                    warnings.push(
                        "Nenhuma sessão estruturada válida foi encontrada nos logs UE4SS disponíveis."
                            .to_owned(),
                    );
                    if report.multiple_log_candidates {
                        warnings.push(
                            "Mais de um UE4SS.log foi encontrado; para o opt-in de log completo foi escolhido o arquivo modificado mais recentemente."
                                .to_owned(),
                        );
                    }
                    selected_log_path = select_readable_log(&report.logs);
                }
            }
            Err(_) => warnings.push(
                "A análise estruturada dos logs UE4SS não pôde ser realizada com segurança."
                    .to_owned(),
            ),
        }
    } else {
        warnings.push(
            "A instalação do jogo não está disponível; a análise de sessão UE4SS foi omitida."
                .to_owned(),
        );
    }

    if let (Some(game_root), Some(relative_path)) =
        (context.game_root.as_deref(), selected_log_path.as_deref())
    {
        match read_ue4ss_runtime_log_tail_text(
            game_root,
            relative_path,
            MAX_EXCERPT_SOURCE_BYTES,
        ) {
            Ok(Some(log)) => {
                let (content, truncated) = relevant_log_excerpt(
                    &log.content,
                    &request.affected_mod,
                    request.occurred_at.as_deref(),
                    log.truncated,
                );
                if !content.is_empty() {
                    warnings.push(
                        "A redação automática do trecho UE4SS não é infalível; revise-o antes de compartilhar."
                            .to_owned(),
                    );
                    if truncated {
                        warnings.push(
                            "O trecho recente do UE4SS.log foi limitado às linhas mais relevantes."
                                .to_owned(),
                        );
                    }
                    files.push(BugReportFilePreviewView {
                        name: EXCERPT_FILE.to_owned(),
                        content,
                        truncated,
                    });
                }
            }
            Ok(None) | Err(_) => warnings.push(
                "O trecho recente do UE4SS.log foi omitido porque a leitura segura não estava disponível."
                    .to_owned(),
            ),
        }
    }

    if request.include_full_ue4ss_log {
        warnings.push(
            "A redação automática do log UE4SS reduz dados sensíveis, mas não é infalível; revise o arquivo antes de compartilhá-lo."
                .to_owned(),
        );
        match (context.game_root.as_deref(), selected_log_path.as_deref()) {
            (Some(game_root), Some(relative_path)) => {
                match read_ue4ss_runtime_log_text(game_root, relative_path, MAX_FULL_LOG_BYTES) {
                    Ok(Some(log)) => {
                        let mut content = redact_sensitive_text(&log.content);
                        let mut truncated = log.truncated;
                        let used = files.iter().map(|file| file.content.len()).sum::<usize>();
                        let maximum_content = (MAX_PACKAGE_BYTES as usize)
                            .saturating_sub(PACKAGE_OVERHEAD_RESERVE)
                            .saturating_sub(used);
                        if content.len() > maximum_content {
                            truncate_utf8(&mut content, maximum_content);
                            truncated = true;
                        }
                        if truncated {
                            warnings.push(
                                "O log UE4SS redigido foi truncado para respeitar o limite do pacote."
                                    .to_owned(),
                            );
                        }
                        files.push(BugReportFilePreviewView {
                            name: FULL_LOG_FILE.to_owned(),
                            content,
                            truncated,
                        });
                    }
                    Ok(None) | Err(_) => warnings.push(
                        "O log UE4SS completo foi omitido porque a leitura segura não estava disponível."
                            .to_owned(),
                    ),
                }
            }
            _ => warnings.push(
                "O log UE4SS completo foi omitido porque nenhum arquivo seguro pôde ser selecionado."
                    .to_owned(),
            ),
        }
    }

    warnings.sort();
    warnings.dedup();
    let collected_files = files
        .iter()
        .map(|file| {
            json!({
                "name": file.name,
                "truncated": file.truncated
            })
        })
        .collect::<Vec<_>>();
    let diagnostics = files
        .iter_mut()
        .find(|file| file.name == DIAGNOSTICS_FILE)
        .context("bug report diagnostics file is missing")?;
    let mut diagnostics_value: Value = serde_json::from_str(&diagnostics.content)?;
    diagnostics_value
        .as_object_mut()
        .context("bug report diagnostics must be a JSON object")?
        .insert(
            "collection".to_owned(),
            json!({
                "files": collected_files,
                "warnings": warnings.clone()
            }),
        );
    diagnostics.content = pretty_json(&diagnostics_value)?;

    let total = files
        .iter()
        .map(|file| file.content.len() as u64)
        .sum::<u64>();
    if total > MAX_PACKAGE_BYTES.saturating_sub(PACKAGE_OVERHEAD_RESERVE as u64) {
        bail!("bug report preview exceeds the 5 MiB package limit");
    }
    Ok((files, warnings))
}

pub(crate) fn write_bug_report_zip(
    pending: &PendingBugReport,
    destination: &Path,
    temporary_id: &str,
) -> Result<String> {
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("bug report destination has no parent directory")?;
    let parent = fs::canonicalize(parent).context("bug report destination directory is invalid")?;
    if !fs::metadata(&parent)?.is_dir() {
        bail!("bug report destination parent is not a directory");
    }
    let file_name = destination
        .file_name()
        .context("bug report destination has no file name")?;
    if !matches!(
        Path::new(file_name).components().next(),
        Some(Component::Normal(_))
    ) || Path::new(file_name).components().count() != 1
    {
        bail!("bug report destination file name is unsafe");
    }
    let destination = parent.join(file_name);
    validate_destination(&destination)?;
    if pending.files.iter().any(|file| {
        !SAFE_FILE_NAMES.contains(&file.name.as_str())
            || file.content.len() as u64 > MAX_PACKAGE_BYTES
    }) {
        bail!("frozen bug report contains an invalid file");
    }

    let temporary = parent.join(format!(".rrmm-bug-report-{temporary_id}.tmp"));
    let result = (|| {
        let output = private_new_file(&temporary)?;
        let mut archive = zip::ZipWriter::new(output);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o600);
        for file in &pending.files {
            archive.start_file(&file.name, options)?;
            archive.write_all(file.content.as_bytes())?;
        }
        let output = archive.finish()?;
        output.sync_all()?;
        if output.metadata()?.len() > MAX_PACKAGE_BYTES {
            bail!("bug report ZIP exceeds the 5 MiB package limit");
        }
        validate_destination(&destination)?;
        fs::rename(&temporary, &destination)?;
        fs::File::open(&parent)?.sync_all()?;
        Ok(destination.display().to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn private_new_file(path: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).with_context(|| {
        format!(
            "failed to create private temporary ZIP in {}",
            path.display()
        )
    })
}

fn validate_destination(destination: &Path) -> Result<()> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            bail!("bug report destination is not a regular file")
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn validate_request(mut request: BugReportRequestView) -> Result<BugReportRequestView> {
    request.affected_mod = validated_text(
        "affected mod",
        request.affected_mod,
        MAX_AFFECTED_MOD_CHARS,
        request.subject_kind == BugReportSubjectKind::Mod,
    )?;
    request.problem_summary = validated_text(
        "problem summary",
        request.problem_summary,
        MAX_SUMMARY_CHARS,
        true,
    )?;
    request.steps_to_reproduce = validated_text(
        "steps to reproduce",
        request.steps_to_reproduce,
        MAX_DETAIL_CHARS,
        false,
    )?;
    request.expected_behavior = validated_text(
        "expected behavior",
        request.expected_behavior,
        MAX_DETAIL_CHARS,
        false,
    )?;
    request.observed_behavior = validated_text(
        "observed behavior",
        request.observed_behavior,
        MAX_DETAIL_CHARS,
        true,
    )?;
    request.reproducibility = validated_text(
        "reproducibility",
        request.reproducibility,
        MAX_REPRODUCIBILITY_CHARS,
        false,
    )?;
    if let Some(occurred_at) = request.occurred_at.take() {
        let occurred_at =
            validated_text("occurrence time", occurred_at, MAX_OCCURRED_AT_CHARS, true)?;
        DateTime::parse_from_rfc3339(&occurred_at)
            .context("occurrence time must be a valid RFC3339 timestamp")?;
        request.occurred_at = Some(occurred_at);
    }
    Ok(request)
}

fn validated_text(label: &str, value: String, max_chars: usize, required: bool) -> Result<String> {
    if value.contains('\0') {
        bail!("{label} contains a NUL character");
    }
    let value = value.trim().to_owned();
    if required && value.is_empty() {
        bail!("{label} is required");
    }
    if value.chars().count() > max_chars {
        bail!("{label} exceeds the {max_chars} character limit");
    }
    Ok(value)
}

fn report_summary(request: &BugReportRequestView) -> String {
    let subject = match request.subject_kind {
        BugReportSubjectKind::Manager => "RR Mod Manager".to_owned(),
        BugReportSubjectKind::Game => "Retro Rewind".to_owned(),
        BugReportSubjectKind::Mod => request.affected_mod.clone(),
    };
    format!(
        "Componente afetado: {subject}\nResumo do problema: {}\nOcorrido em: {}\nReprodutibilidade: {}\n\nPassos para reproduzir:\n{}\n\nComportamento esperado:\n{}\n\nComportamento observado:\n{}\n",
        request.problem_summary,
        request.occurred_at.as_deref().unwrap_or("não informado"),
        empty_fallback(&request.reproducibility),
        empty_fallback(&request.steps_to_reproduce),
        empty_fallback(&request.expected_behavior),
        empty_fallback(&request.observed_behavior),
    )
}

fn empty_fallback(value: &str) -> &str {
    if value.is_empty() {
        "não informado"
    } else {
        value
    }
}

fn selected_session(log: &Ue4ssRuntimeLogFile) -> Option<&Ue4ssRuntimeSession> {
    let selected = log.selected_session_index?;
    log.sessions
        .iter()
        .find(|session| session.index == selected)
}

fn log_sort_key(log: &Ue4ssRuntimeLogFile) -> (u64, u64, &str) {
    (
        log.modified_unix_seconds.unwrap_or(0),
        log.read_unix_seconds,
        &log.entry.relative_path,
    )
}

fn select_readable_log(logs: &[Ue4ssRuntimeLogFile]) -> Option<String> {
    let mut candidates: Vec<_> = logs
        .iter()
        .filter(|log| log.entry.status == EntryStatus::RegularFile)
        .collect();
    candidates.sort_by_key(|log| log_sort_key(log));
    candidates.last().map(|log| log.entry.relative_path.clone())
}

fn session_json(
    session: &Ue4ssRuntimeSession,
    relative_path: &str,
    affected_mod: &str,
    analyzed_at: &str,
) -> Result<(String, bool, bool)> {
    let affected = normalized_mod_name(affected_mod);
    let matching: Vec<_> = session
        .events
        .iter()
        .filter(|event| mod_names_match(&affected, &normalized_mod_name(&event.module_name)))
        .collect();
    let filtered = !matching.is_empty();
    let source = if filtered {
        matching
    } else {
        session.events.iter().collect()
    };
    let mut events: Vec<Value> = source
        .into_iter()
        .map(|event| {
            json!({
                "sequence": event.sequence,
                "timestamp": event.timestamp,
                "kind": event.kind,
                "moduleName": event.module_name,
                "moduleKind": event.module_kind,
                "phase": event.phase
            })
        })
        .collect();
    let original_len = events.len();
    loop {
        let value = json!({
            "schemaVersion": 1,
            "analyzedAt": analyzed_at,
            "logRelativePath": relative_path,
            "filteredToAffectedMod": filtered,
            "session": {
                "startTimestamp": session.start_timestamp,
                "version": session.version,
                "timezone": session.timezone,
                "buildConfiguration": session.build_configuration,
                "gameExecutableBytes": session.game_executable.as_ref().map(|item| item.bytes),
                "eventLoopStartObserved": session.event_loop_start_observed,
                "events": events
            }
        });
        let content = pretty_json(&value)?;
        if content.len() <= MAX_SESSION_FILE_BYTES {
            return Ok((content, events.len() < original_len, filtered));
        }
        if events.pop().is_none() {
            bail!("structured UE4SS session exceeds its bounded file limit");
        }
    }
}

fn normalized_mod_name(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn mod_names_match(affected: &str, module: &str) -> bool {
    !affected.is_empty()
        && !module.is_empty()
        && (affected == module
            || (affected.len() >= 4 && module.contains(affected))
            || (module.len() >= 4 && affected.contains(module)))
}

fn pretty_json(value: &Value) -> Result<String> {
    let mut content = serde_json::to_string_pretty(value)?;
    content.push('\n');
    Ok(content)
}

fn truncate_utf8(content: &mut String, maximum: usize) {
    if content.len() <= maximum {
        return;
    }
    let mut end = maximum;
    while end > 0 && !content.is_char_boundary(end) {
        end -= 1;
    }
    content.truncate(end);
}

fn relevant_log_excerpt(
    source: &str,
    affected_mod: &str,
    occurred_at: Option<&str>,
    source_truncated: bool,
) -> (String, bool) {
    let lines: Vec<_> = source.lines().collect();
    if lines.is_empty() {
        return (String::new(), source_truncated);
    }
    let affected = normalized_mod_name(affected_mod);
    let occurrence_minute = occurred_at.and_then(|value| {
        let minute = value.get(..16)?;
        Some(minute.replace('T', " "))
    });
    let mut selected = BTreeSet::new();
    for (index, line) in lines.iter().enumerate() {
        let lower = line.to_ascii_lowercase();
        let normalized = normalized_mod_name(line);
        let relevant = [
            "error",
            "exception",
            "failed",
            "failure",
            "fatal",
            "panic",
            "stack traceback",
            "ensure condition failed",
        ]
        .iter()
        .any(|keyword| lower.contains(keyword))
            || (!affected.is_empty() && normalized.contains(&affected))
            || occurrence_minute
                .as_deref()
                .is_some_and(|minute| line.contains(minute));
        if relevant {
            for nearby in index.saturating_sub(3)..=(index + 3).min(lines.len() - 1) {
                selected.insert(nearby);
            }
        }
    }
    if selected.is_empty() {
        selected.extend(lines.len().saturating_sub(160)..lines.len());
    }

    let mut kept = Vec::new();
    let mut bytes = 0usize;
    for index in selected.iter().rev().copied() {
        let next = lines[index].len().saturating_add(1);
        if bytes.saturating_add(next) > MAX_EXCERPT_BYTES.saturating_sub(256) {
            break;
        }
        bytes += next;
        kept.push(index);
    }
    kept.reverse();
    let limited = source_truncated || kept.len() < lines.len() || kept.len() < selected.len();
    let mut content = format!(
        "# Trecho redigido do UE4SS.log\n# Mod afetado: {affected_mod}\n# Momento informado: {}\n# A redação automática não é infalível. Revise antes de compartilhar.\n\n",
        occurred_at.unwrap_or("não informado")
    );
    for index in kept {
        content.push_str(lines[index]);
        content.push('\n');
    }
    content = redact_sensitive_text(&content);
    if content.len() > MAX_EXCERPT_BYTES {
        truncate_utf8(&mut content, MAX_EXCERPT_BYTES);
        return (content, true);
    }
    (content, limited)
}

pub(crate) fn redact_sensitive_text(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    for segment in source.split_inclusive('\n') {
        let (line, ending) = segment
            .strip_suffix('\n')
            .map_or((segment, ""), |line| (line, "\n"));
        output.push_str(&redact_paths_and_urls(&redact_secret_values(line)));
        output.push_str(ending);
    }
    output
}

fn redact_secret_values(line: &str) -> String {
    const KEYS: [&str; 8] = [
        "api_key",
        "api-key",
        "apikey",
        "api key",
        "access_token",
        "access-token",
        "password",
        "token",
    ];
    let lower = line.to_ascii_lowercase();
    let mut ranges = Vec::new();
    for key in KEYS {
        let mut offset = 0;
        while let Some(found) = lower[offset..].find(key) {
            let key_start = offset + found;
            let key_end = key_start + key.len();
            let before_ok =
                key_start == 0 || !lower.as_bytes()[key_start - 1].is_ascii_alphanumeric();
            let after_ok =
                key_end == lower.len() || !lower.as_bytes()[key_end].is_ascii_alphanumeric();
            if before_ok && after_ok {
                let mut value_start = key_end;
                while value_start < line.len() && line.as_bytes()[value_start].is_ascii_whitespace()
                {
                    value_start += 1;
                }
                if value_start < line.len() && matches!(line.as_bytes()[value_start], b'=' | b':') {
                    value_start += 1;
                    while value_start < line.len()
                        && line.as_bytes()[value_start].is_ascii_whitespace()
                    {
                        value_start += 1;
                    }
                    if value_start < line.len() {
                        let quote = match line.as_bytes()[value_start] {
                            b'\'' | b'"' => {
                                let quote = line.as_bytes()[value_start];
                                value_start += 1;
                                Some(quote)
                            }
                            _ => None,
                        };
                        let value_end = quote.map_or_else(
                            || {
                                line[value_start..]
                                    .find(|character: char| {
                                        character.is_whitespace()
                                            || character == ','
                                            || character == ';'
                                    })
                                    .map_or(line.len(), |end| value_start + end)
                            },
                            |quote| {
                                line.as_bytes()[value_start..]
                                    .iter()
                                    .position(|byte| *byte == quote)
                                    .map_or(line.len(), |end| value_start + end)
                            },
                        );
                        ranges.push((value_start, value_end));
                    }
                }
            }
            offset = key_end;
        }
    }
    replace_ranges(line, ranges, "[SEGREDO_REDACTADO]")
}

fn redact_paths_and_urls(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut output = String::with_capacity(line.len());
    let mut index = 0;
    while index < line.len() {
        if line[index..].starts_with("https://") || line[index..].starts_with("http://") {
            let end = token_end(line, index);
            let url = &line[index..end];
            if let Some(query) = url.find('?') {
                output.push_str(&url[..=query]);
                output.push_str("[CONSULTA_REDACTADA]");
            } else {
                output.push_str(url);
            }
            index = end;
            continue;
        }
        let windows_path = index + 2 < line.len()
            && bytes[index].is_ascii_alphabetic()
            && bytes[index + 1] == b':'
            && matches!(bytes[index + 2], b'/' | b'\\');
        let unix_path = bytes[index] == b'/'
            && bytes.get(index + 1).is_some_and(|next| *next != b'/')
            && (index == 0
                || bytes[index - 1].is_ascii_whitespace()
                || matches!(bytes[index - 1], b'\'' | b'"' | b'=' | b':' | b'(' | b'['));
        if windows_path || unix_path {
            output.push_str("[CAMINHO_REDACTADO]");
            index = token_end(line, index);
            continue;
        }
        let character = line[index..].chars().next().expect("valid string boundary");
        output.push(character);
        index += character.len_utf8();
    }
    output
}

fn token_end(line: &str, start: usize) -> usize {
    line[start..]
        .find(|character: char| {
            character.is_whitespace()
                || matches!(character, '\'' | '"' | '<' | '>' | ')' | ']' | '}' | ',')
        })
        .map_or(line.len(), |end| start + end)
}

fn replace_ranges(source: &str, mut ranges: Vec<(usize, usize)>, replacement: &str) -> String {
    ranges.retain(|(start, end)| start < end);
    ranges.sort_unstable();
    let mut output = String::with_capacity(source.len());
    let mut cursor = 0;
    for (start, end) in ranges {
        if start < cursor {
            continue;
        }
        output.push_str(&source[cursor..start]);
        output.push_str(replacement);
        cursor = end;
    }
    output.push_str(&source[cursor..]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn request() -> BugReportRequestView {
        BugReportRequestView {
            subject_kind: BugReportSubjectKind::Mod,
            affected_mod: "TargetMod".to_owned(),
            problem_summary: "Falha ao iniciar".to_owned(),
            steps_to_reproduce: "Abrir o jogo".to_owned(),
            expected_behavior: "Iniciar".to_owned(),
            observed_behavior: "Falhou".to_owned(),
            reproducibility: "Sempre".to_owned(),
            occurred_at: Some("2026-08-09T12:00:00Z".to_owned()),
            include_active_mods: false,
            include_full_ue4ss_log: false,
        }
    }

    fn context(game_root: Option<PathBuf>) -> BugReportContext {
        BugReportContext {
            generated_at: "2026-08-09T12:01:00+00:00".to_owned(),
            game_running: false,
            game_detected: game_root.is_some(),
            game_build_id: game_root.as_ref().map(|_| "23896268".to_owned()),
            game_root,
            active_mods: None,
            incident_marker: None,
            technical_summary: json!({
                "offlineMode": false,
                "counts": { "importedMods": 0, "profiles": 1, "conflicts": 0 }
            }),
            operation_history: json!({ "schemaVersion": 1, "failures": [] }),
        }
    }

    #[test]
    fn request_contract_is_camel_case_and_rejects_unknown_fields() {
        let parsed: BugReportRequestView = serde_json::from_value(json!({
            "subjectKind": "mod",
            "affectedMod": "TargetMod",
            "problemSummary": "Resumo",
            "stepsToReproduce": "Passos",
            "expectedBehavior": "Esperado",
            "observedBehavior": "Observado",
            "reproducibility": "Sempre",
            "occurredAt": null,
            "includeActiveMods": false,
            "includeFullUe4ssLog": false
        }))
        .unwrap();
        assert_eq!(parsed.affected_mod, "TargetMod");
        assert_eq!(parsed.subject_kind, BugReportSubjectKind::Mod);
        assert!(
            serde_json::from_value::<BugReportRequestView>(json!({
                "affectedMod": "TargetMod",
                "problemSummary": "Resumo",
                "stepsToReproduce": "",
                "expectedBehavior": "",
                "observedBehavior": "",
                "reproducibility": "",
                "occurredAt": null,
                "includeActiveMods": false,
                "includeFullUe4ssLog": false,
                "extra": true
            }))
            .is_err()
        );

        let marker = serde_json::to_value(IncidentMarkerView {
            id: "incident-1".to_owned(),
            recorded_at: "2026-08-09T12:00:00Z".to_owned(),
            game_running: true,
        })
        .unwrap();
        assert!(marker.get("recordedAt").is_some());
        assert!(marker.get("gameRunning").is_some());
        assert!(marker.get("recorded_at").is_none());
        let preview = serde_json::to_value(BugReportPreviewView {
            token: "preview-1".to_owned(),
            files: vec![BugReportFilePreviewView {
                name: SUMMARY_FILE.to_owned(),
                content: "content".to_owned(),
                truncated: false,
            }],
            warnings: Vec::new(),
        })
        .unwrap();
        assert!(preview["files"][0].get("truncated").is_some());
    }

    #[test]
    fn rejects_required_empty_oversized_nul_and_invalid_timestamp_fields() {
        let mut invalid = request();
        invalid.affected_mod = " ".to_owned();
        assert!(prepare_bug_report(invalid, context(None)).is_err());

        let mut invalid = request();
        invalid.problem_summary = "x".repeat(MAX_SUMMARY_CHARS + 1);
        assert!(prepare_bug_report(invalid, context(None)).is_err());

        let mut invalid = request();
        invalid.observed_behavior = "bad\0value".to_owned();
        assert!(prepare_bug_report(invalid, context(None)).is_err());

        let mut invalid = request();
        invalid.observed_behavior = " ".to_owned();
        assert!(prepare_bug_report(invalid, context(None)).is_err());

        let mut invalid = request();
        invalid.occurred_at = Some("ontem".to_owned());
        assert!(prepare_bug_report(invalid, context(None)).is_err());
    }

    #[test]
    fn manager_and_game_reports_do_not_require_an_installed_mod() {
        for subject_kind in [BugReportSubjectKind::Manager, BugReportSubjectKind::Game] {
            let mut request = request();
            request.subject_kind = subject_kind;
            request.affected_mod.clear();

            let (files, _) = prepare_bug_report(request, context(None)).unwrap();
            assert!(files[0].content.contains("Componente afetado:"));
            assert!(files[2].name == OPERATIONS_FILE);
        }
    }

    #[test]
    fn reports_structured_analysis_unavailable_without_a_game_root() {
        let (files, warnings) = prepare_bug_report(request(), context(None)).unwrap();
        assert_eq!(files.len(), 3);
        assert!(!files[1].content.contains("activeMods"));
        assert!(files[1].content.contains("managerState"));
        assert!(files[1].content.contains("importedMods"));
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("instalação do jogo"))
        );
    }

    #[test]
    fn includes_active_mod_metadata_only_when_requested() {
        let mut report_context = context(None);
        report_context.active_mods = Some(vec![BugReportActiveMod {
            name: "Target Mod".to_owned(),
            version: "1.2.3".to_owned(),
            mod_type: "pak+ue4ss".to_owned(),
            order: Some(1),
            priority: Some(9),
        }]);
        let (without, _) = prepare_bug_report(request(), report_context).unwrap();
        assert!(!without[1].content.contains("Target Mod"));

        let mut request = request();
        request.include_active_mods = true;
        let mut report_context = context(None);
        report_context.active_mods = Some(vec![BugReportActiveMod {
            name: "Target Mod".to_owned(),
            version: "1.2.3".to_owned(),
            mod_type: "pak+ue4ss".to_owned(),
            order: Some(1),
            priority: Some(9),
        }]);
        let (with, _) = prepare_bug_report(request, report_context).unwrap();
        assert!(with[1].content.contains("Target Mod"));
        assert!(with[1].content.contains("\"priority\": 9"));
    }

    #[cfg(unix)]
    #[test]
    fn selects_latest_session_filters_events_and_redacts_full_log() {
        let temporary = TempDir::new().unwrap();
        let nested = temporary
            .path()
            .join("RetroRewind/Binaries/Win64/ue4ss/UE4SS.log");
        fs::create_dir_all(nested.parent().unwrap()).unwrap();
        fs::write(
            &nested,
            "[2026-08-08 12:00:00] Console created\n\
[2026-08-08 12:00:00] UE4SS - v3.0.0 Beta #0 - Git SHA #d935b5b\n\
[2026-08-08 12:00:00] UE4SS Build Configuration: Game__Shipping__Win64 (Clang)\n\
[2026-08-08 12:00:01] Starting Lua mod 'OldTargetMod'\n\
[2026-08-09 12:00:00] Console created\n\
[2026-08-09 12:00:00] UE4SS - v3.0.1 Beta #0 - Git SHA #662df915\n\
[2026-08-09 12:00:00] UE4SS Build Configuration: Game__Shipping__Win64 (Clang)\n\
[2026-08-09 12:00:00] game executable: C:\\Users\\Private\\RetroRewind.exe (42 bytes)\n\
[2026-08-09 12:00:01] Starting Lua mod 'OtherMod'\n\
[2026-08-09 12:00:02] Starting Lua mod 'TargetMod'\n\
request https://example.invalid/path?token=visible api_key=supersecret /home/private/file\n",
        )
        .unwrap();
        let mut request = request();
        request.include_full_ue4ss_log = true;

        let (files, warnings) =
            prepare_bug_report(request, context(Some(temporary.path().to_path_buf()))).unwrap();

        let session = files.iter().find(|file| file.name == SESSION_FILE).unwrap();
        assert!(session.content.contains("TargetMod"));
        assert!(!session.content.contains("OtherMod"));
        assert!(!session.content.contains("OldTargetMod"));
        assert!(!session.content.contains("C:\\\\Users"));
        assert!(
            !session
                .content
                .contains(&temporary.path().display().to_string())
        );
        let excerpt = files.iter().find(|file| file.name == EXCERPT_FILE).unwrap();
        assert!(excerpt.content.contains("TargetMod"));
        assert!(!excerpt.content.contains("supersecret"));
        assert!(!excerpt.content.contains("/home/private"));
        let full = files
            .iter()
            .find(|file| file.name == FULL_LOG_FILE)
            .unwrap();
        assert!(!full.content.contains("Private"));
        assert!(!full.content.contains("visible"));
        assert!(!full.content.contains("supersecret"));
        assert!(!full.content.contains("/home/private"));
        assert!(full.content.contains("[CAMINHO_REDACTADO]"));
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("não é infalível"))
        );
    }

    #[test]
    fn redacts_linux_windows_url_queries_and_common_secret_assignments() {
        let redacted = redact_sensitive_text(
            "C:\\Users\\Alice\\game.log /home/alice/game.log https://host/path?q=secret token: abc password='def' API_KEY=ghi",
        );
        for secret in ["Alice", "/home/alice", "q=secret", " abc", "def", "ghi"] {
            assert!(!redacted.contains(secret), "secret remained: {secret}");
        }
    }

    #[test]
    fn writes_expected_zip_entries_and_rejects_unsafe_destinations() {
        let temporary = TempDir::new().unwrap();
        let (files, _) = prepare_bug_report(request(), context(None)).unwrap();
        let pending = PendingBugReport { files };
        let destination = temporary.path().join("relato.zip");
        write_bug_report_zip(&pending, &destination, "test").unwrap();
        let mut archive = zip::ZipArchive::new(fs::File::open(&destination).unwrap()).unwrap();
        assert_eq!(archive.len(), 3);
        assert!(archive.by_name(SUMMARY_FILE).is_ok());
        assert!(archive.by_name(DIAGNOSTICS_FILE).is_ok());
        assert!(archive.by_name(OPERATIONS_FILE).is_ok());
        assert!(archive.by_name(FULL_LOG_FILE).is_err());

        let directory = temporary.path().join("not-a-file.zip");
        fs::create_dir(&directory).unwrap();
        assert!(write_bug_report_zip(&pending, &directory, "directory").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlink_destination_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let temporary = TempDir::new().unwrap();
        let target = temporary.path().join("target");
        fs::write(&target, b"untouched").unwrap();
        let destination = temporary.path().join("report.zip");
        symlink(&target, &destination).unwrap();
        let pending = PendingBugReport {
            files: vec![BugReportFilePreviewView {
                name: SUMMARY_FILE.to_owned(),
                content: "summary".to_owned(),
                truncated: false,
            }],
        };

        assert!(write_bug_report_zip(&pending, &destination, "link").is_err());
        assert_eq!(fs::read(target).unwrap(), b"untouched");
    }
}
