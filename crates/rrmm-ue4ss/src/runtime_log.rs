use super::{
    EntryObservation, EntryStatus, FLAT_LOG_RELATIVE_PATH, NESTED_LOG_RELATIVE_PATH,
    Ue4ssInventoryError, observe_beneath,
};
use crate::safe_file::open_file_beneath;
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssRuntimeLogLimits {
    pub max_bytes: u64,
    pub max_line_bytes: usize,
    pub max_lines: usize,
    pub max_sessions: usize,
    pub max_events: usize,
    pub max_field_chars: usize,
    pub max_banner_distance_bytes: usize,
}

impl Default for Ue4ssRuntimeLogLimits {
    fn default() -> Self {
        Self {
            max_bytes: 32 * 1024 * 1024,
            max_line_bytes: 64 * 1024,
            max_lines: 500_000,
            max_sessions: 16,
            max_events: 10_000,
            max_field_chars: 512,
            max_banner_distance_bytes: 8 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssRuntimeLogReport {
    pub schema_version: u32,
    pub game_root: PathBuf,
    pub complete: bool,
    pub multiple_log_candidates: bool,
    pub logs: Vec<Ue4ssRuntimeLogFile>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ue4ssRuntimeLogText {
    pub relative_path: String,
    pub content: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssRuntimeLogFile {
    pub entry: EntryObservation,
    pub status: Ue4ssRuntimeLogStatus,
    pub complete: bool,
    pub bytes: u64,
    pub modified_unix_seconds: Option<u64>,
    pub read_unix_seconds: u64,
    pub age_seconds_at_read: Option<u64>,
    pub freshness: Ue4ssRuntimeLogFreshness,
    pub selected_session_index: Option<usize>,
    pub sessions: Vec<Ue4ssRuntimeSession>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ue4ssRuntimeLogStatus {
    Missing,
    Parsed,
    NoValidSession,
    Unsafe,
    UnsupportedPlatform,
    Unreadable,
    InvalidUtf8,
    LimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ue4ssRuntimeLogFreshness {
    Unassessed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssRuntimeSession {
    pub index: usize,
    pub start_timestamp: String,
    pub start_offset: usize,
    pub version: Ue4ssRuntimeVersion,
    pub timezone: Option<String>,
    pub build_configuration: Option<Ue4ssRuntimeBuildConfiguration>,
    pub game_executable: Option<Ue4ssRuntimeExecutable>,
    pub event_loop_start_observed: bool,
    pub events: Vec<Ue4ssRuntimeModEvent>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssRuntimeVersion {
    pub major: u32,
    pub minor: u32,
    pub hotfix: u32,
    pub prerelease: Option<u32>,
    pub beta: Option<Ue4ssRuntimeBeta>,
    pub git_sha: Ue4ssRuntimeGitSha,
    pub raw_banner: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Ue4ssRuntimeBeta {
    Number(u32),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Ue4ssRuntimeGitSha {
    Hex(String),
    Unknown,
    NoGit,
    Zero,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssRuntimeBuildConfiguration {
    pub configuration: String,
    pub compiler: Ue4ssRuntimeCompiler,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ue4ssRuntimeCompiler {
    Msvc,
    Clang,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssRuntimeExecutable {
    pub path: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ue4ssRuntimeModEvent {
    pub sequence: usize,
    pub timestamp: String,
    pub record_offset: usize,
    pub kind: Ue4ssRuntimeModEventKind,
    pub module_name: String,
    pub module_kind: Option<Ue4ssRuntimeModuleKind>,
    pub phase: Ue4ssRuntimeModPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ue4ssRuntimeModEventKind {
    StartAttempt,
    ConfiguredDisabledObserved,
    EnabledMarkerStartAttempt,
    RuntimeStartAttempt,
    StartCallReturned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ue4ssRuntimeModuleKind {
    Lua,
    Cpp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ue4ssRuntimeModPhase {
    ModsTxt,
    EnabledTxt,
    RuntimeManagement,
    Unknown,
}

pub fn analyze_ue4ss_runtime_logs(
    game_root: &Path,
    limits: &Ue4ssRuntimeLogLimits,
) -> Result<Ue4ssRuntimeLogReport, Ue4ssInventoryError> {
    let game_root = std::fs::canonicalize(game_root).map_err(|source| Ue4ssInventoryError::Io {
        path: game_root.to_path_buf(),
        source,
    })?;
    if !std::fs::metadata(&game_root)
        .map_err(|source| Ue4ssInventoryError::Io {
            path: game_root.clone(),
            source,
        })?
        .is_dir()
    {
        return Err(Ue4ssInventoryError::InvalidGameRoot(game_root));
    }

    let candidates = [NESTED_LOG_RELATIVE_PATH, FLAT_LOG_RELATIVE_PATH];
    let observations: Vec<_> = candidates
        .iter()
        .map(|path| observe_beneath(&game_root, path, path))
        .collect();
    let multiple_log_candidates = observations
        .iter()
        .filter(|entry| entry.status != EntryStatus::Missing)
        .count()
        > 1;
    let mut logs = Vec::with_capacity(observations.len());
    for entry in observations {
        logs.push(analyze_log_file(&game_root, entry, limits));
    }
    let mut issues = vec![
        "UE4SS.log is mutable runtime text and does not prove the current on-disk loader, process, game build, or functional module state"
            .to_owned(),
        "log freshness is unassessed because no external process-start observation window was supplied"
            .to_owned(),
        "mods can emit spoofed loader-like text; recognized records are format matches, not authenticated authorship"
            .to_owned(),
        "runtime-log output contains local paths, timezone, and module names; redact it before sharing"
            .to_owned(),
    ];
    if multiple_log_candidates {
        issues.push(
            "both nested and flat UE4SS.log candidates exist; neither was treated as uniquely active"
                .to_owned(),
        );
    }
    let complete = logs.iter().all(|log| log.complete);
    issues.sort();
    issues.dedup();
    Ok(Ue4ssRuntimeLogReport {
        schema_version: 1,
        game_root,
        complete,
        multiple_log_candidates,
        logs,
        issues,
    })
}

pub fn read_ue4ss_runtime_log_text(
    game_root: &Path,
    relative_path: &str,
    max_bytes: u64,
) -> Result<Option<Ue4ssRuntimeLogText>, Ue4ssInventoryError> {
    if !matches!(
        relative_path,
        NESTED_LOG_RELATIVE_PATH | FLAT_LOG_RELATIVE_PATH
    ) || max_bytes == 0
        || max_bytes > Ue4ssRuntimeLogLimits::default().max_bytes
    {
        return Err(Ue4ssInventoryError::Io {
            path: game_root.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid UE4SS runtime-log read request",
            ),
        });
    }
    let game_root = std::fs::canonicalize(game_root).map_err(|source| Ue4ssInventoryError::Io {
        path: game_root.to_path_buf(),
        source,
    })?;
    if !std::fs::metadata(&game_root)
        .map_err(|source| Ue4ssInventoryError::Io {
            path: game_root.clone(),
            source,
        })?
        .is_dir()
    {
        return Err(Ue4ssInventoryError::InvalidGameRoot(game_root));
    }
    let entry = observe_beneath(&game_root, relative_path, relative_path);
    if entry.status == EntryStatus::Missing {
        return Ok(None);
    }
    if entry.status != EntryStatus::RegularFile {
        return Err(Ue4ssInventoryError::Io {
            path: game_root,
            source: std::io::Error::other("UE4SS.log is not a safe regular file"),
        });
    }
    let mut file =
        open_file_beneath(&game_root, relative_path).map_err(|source| Ue4ssInventoryError::Io {
            path: game_root.clone(),
            source,
        })?;
    if !file
        .metadata()
        .map_err(|source| Ue4ssInventoryError::Io {
            path: game_root.clone(),
            source,
        })?
        .is_file()
    {
        return Err(Ue4ssInventoryError::Io {
            path: game_root,
            source: std::io::Error::other("opened UE4SS.log is not a regular file"),
        });
    }
    let mut input = Vec::new();
    file.by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut input)
        .map_err(|source| Ue4ssInventoryError::Io {
            path: game_root.clone(),
            source,
        })?;
    let truncated = input.len() as u64 > max_bytes;
    if truncated {
        input.truncate(max_bytes as usize);
    }
    let valid_bytes = match std::str::from_utf8(&input) {
        Ok(_) => input.len(),
        Err(error) if truncated && error.error_len().is_none() => error.valid_up_to(),
        Err(error) => {
            return Err(Ue4ssInventoryError::Io {
                path: game_root,
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
            });
        }
    };
    input.truncate(valid_bytes);
    let content = String::from_utf8(input).expect("validated UTF-8 runtime log");
    Ok(Some(Ue4ssRuntimeLogText {
        relative_path: relative_path.to_owned(),
        content: content
            .strip_prefix('\u{feff}')
            .unwrap_or(&content)
            .to_owned(),
        truncated,
    }))
}

pub fn read_ue4ss_runtime_log_tail_text(
    game_root: &Path,
    relative_path: &str,
    max_bytes: u64,
) -> Result<Option<Ue4ssRuntimeLogText>, Ue4ssInventoryError> {
    if !matches!(
        relative_path,
        NESTED_LOG_RELATIVE_PATH | FLAT_LOG_RELATIVE_PATH
    ) || max_bytes == 0
        || max_bytes > Ue4ssRuntimeLogLimits::default().max_bytes
    {
        return Err(Ue4ssInventoryError::Io {
            path: game_root.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid UE4SS runtime-log tail request",
            ),
        });
    }
    let game_root = std::fs::canonicalize(game_root).map_err(|source| Ue4ssInventoryError::Io {
        path: game_root.to_path_buf(),
        source,
    })?;
    if !std::fs::metadata(&game_root)
        .map_err(|source| Ue4ssInventoryError::Io {
            path: game_root.clone(),
            source,
        })?
        .is_dir()
    {
        return Err(Ue4ssInventoryError::InvalidGameRoot(game_root));
    }
    let entry = observe_beneath(&game_root, relative_path, relative_path);
    if entry.status == EntryStatus::Missing {
        return Ok(None);
    }
    if entry.status != EntryStatus::RegularFile {
        return Err(Ue4ssInventoryError::Io {
            path: game_root,
            source: std::io::Error::other("UE4SS.log is not a safe regular file"),
        });
    }
    let mut file =
        open_file_beneath(&game_root, relative_path).map_err(|source| Ue4ssInventoryError::Io {
            path: game_root.clone(),
            source,
        })?;
    let metadata = file.metadata().map_err(|source| Ue4ssInventoryError::Io {
        path: game_root.clone(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(Ue4ssInventoryError::Io {
            path: game_root,
            source: std::io::Error::other("opened UE4SS.log is not a regular file"),
        });
    }
    let bytes = metadata.len();
    let offset = bytes.saturating_sub(max_bytes);
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| Ue4ssInventoryError::Io {
            path: game_root.clone(),
            source,
        })?;
    let mut input = Vec::new();
    file.take(max_bytes)
        .read_to_end(&mut input)
        .map_err(|source| Ue4ssInventoryError::Io {
            path: game_root.clone(),
            source,
        })?;
    if offset > 0
        && let Some(first_newline) = input.iter().position(|byte| *byte == b'\n')
    {
        input.drain(..=first_newline);
    }
    Ok(Some(Ue4ssRuntimeLogText {
        relative_path: relative_path.to_owned(),
        content: String::from_utf8_lossy(&input).into_owned(),
        truncated: offset > 0,
    }))
}

fn analyze_log_file(
    game_root: &Path,
    entry: EntryObservation,
    limits: &Ue4ssRuntimeLogLimits,
) -> Ue4ssRuntimeLogFile {
    let read_unix_seconds = system_time_seconds(SystemTime::now()).unwrap_or(0);
    if entry.status == EntryStatus::Missing {
        return log_result(
            entry,
            Ue4ssRuntimeLogStatus::Missing,
            true,
            0,
            None,
            read_unix_seconds,
            Vec::new(),
            Vec::new(),
        );
    }
    if entry.status != EntryStatus::RegularFile {
        return log_result(
            entry,
            Ue4ssRuntimeLogStatus::Unsafe,
            false,
            0,
            None,
            read_unix_seconds,
            Vec::new(),
            vec!["UE4SS.log candidate is not a safe regular file".to_owned()],
        );
    }
    let mut file = match open_file_beneath(game_root, &entry.relative_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::Unsupported => {
            return log_result(
                entry,
                Ue4ssRuntimeLogStatus::UnsupportedPlatform,
                false,
                0,
                None,
                read_unix_seconds,
                Vec::new(),
                vec![format!("safe UE4SS.log opening is unsupported: {error}")],
            );
        }
        Err(error) => {
            return log_result(
                entry,
                Ue4ssRuntimeLogStatus::Unreadable,
                false,
                0,
                None,
                read_unix_seconds,
                Vec::new(),
                vec![format!("failed to open UE4SS.log safely: {error}")],
            );
        }
    };
    let metadata = match file.metadata() {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => {
            return log_result(
                entry,
                Ue4ssRuntimeLogStatus::Unsafe,
                false,
                0,
                None,
                read_unix_seconds,
                Vec::new(),
                vec!["opened UE4SS.log is not a regular file".to_owned()],
            );
        }
        Err(error) => {
            return log_result(
                entry,
                Ue4ssRuntimeLogStatus::Unreadable,
                false,
                0,
                None,
                read_unix_seconds,
                Vec::new(),
                vec![format!("failed to inspect opened UE4SS.log: {error}")],
            );
        }
    };
    let modified_unix_seconds = metadata.modified().ok().and_then(system_time_seconds);
    if metadata.len() > limits.max_bytes {
        return log_result(
            entry,
            Ue4ssRuntimeLogStatus::LimitExceeded,
            false,
            metadata.len(),
            modified_unix_seconds,
            read_unix_seconds,
            Vec::new(),
            vec![format!(
                "UE4SS.log exceeds the {} byte limit",
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
        return log_result(
            entry,
            Ue4ssRuntimeLogStatus::Unreadable,
            false,
            input.len() as u64,
            modified_unix_seconds,
            read_unix_seconds,
            Vec::new(),
            vec![format!("failed to read UE4SS.log: {error}")],
        );
    }
    if input.len() as u64 > limits.max_bytes {
        return log_result(
            entry,
            Ue4ssRuntimeLogStatus::LimitExceeded,
            false,
            input.len() as u64,
            modified_unix_seconds,
            read_unix_seconds,
            Vec::new(),
            vec![format!(
                "UE4SS.log exceeded the {} byte limit while reading",
                limits.max_bytes
            )],
        );
    }
    let source = match std::str::from_utf8(&input) {
        Ok(source) => source.strip_prefix('\u{feff}').unwrap_or(source),
        Err(error) => {
            return log_result(
                entry,
                Ue4ssRuntimeLogStatus::InvalidUtf8,
                false,
                input.len() as u64,
                modified_unix_seconds,
                read_unix_seconds,
                Vec::new(),
                vec![format!("UE4SS.log is not valid UTF-8: {error}")],
            );
        }
    };
    let records = match collect_records(source, limits) {
        Ok(records) => records,
        Err(issue) => {
            return log_result(
                entry,
                Ue4ssRuntimeLogStatus::LimitExceeded,
                false,
                input.len() as u64,
                modified_unix_seconds,
                read_unix_seconds,
                Vec::new(),
                vec![issue],
            );
        }
    };
    let parsed = match parse_sessions(&records, limits) {
        Ok(parsed) => parsed,
        Err(issue) => {
            return log_result(
                entry,
                Ue4ssRuntimeLogStatus::LimitExceeded,
                false,
                input.len() as u64,
                modified_unix_seconds,
                read_unix_seconds,
                Vec::new(),
                vec![issue],
            );
        }
    };
    let latest_header_valid = parsed.latest_header_valid;
    let mut issues = parsed.issues;
    if parsed.sessions.len() > 1 {
        issues.push(
            "multiple valid session headers are nonstandard; sessions were kept separate and the last was selected"
                .to_owned(),
        );
    }
    let status = if parsed.sessions.is_empty() {
        Ue4ssRuntimeLogStatus::NoValidSession
    } else {
        Ue4ssRuntimeLogStatus::Parsed
    };
    let mut result = log_result(
        entry,
        status,
        true,
        input.len() as u64,
        modified_unix_seconds,
        read_unix_seconds,
        parsed.sessions,
        issues,
    );
    if !latest_header_valid {
        result.selected_session_index = None;
    }
    result
}

#[derive(Clone, Copy)]
struct LogRecord<'a> {
    timestamp: &'a str,
    content: &'a str,
    offset: usize,
}

fn collect_records<'a>(
    source: &'a str,
    limits: &Ue4ssRuntimeLogLimits,
) -> Result<Vec<LogRecord<'a>>, String> {
    let mut records = Vec::new();
    let mut offset = 0_usize;
    for (index, line) in source.lines().enumerate() {
        let line_number = index + 1;
        if line_number > limits.max_lines {
            return Err(format!(
                "UE4SS.log exceeds the {} physical line limit",
                limits.max_lines
            ));
        }
        if line.len() > limits.max_line_bytes {
            return Err(format!(
                "UE4SS.log line {line_number} exceeds the {} byte limit",
                limits.max_line_bytes
            ));
        }
        if let Some((timestamp, content)) = parse_timestamped_line(line) {
            records.push(LogRecord {
                timestamp,
                content,
                offset,
            });
        } else if let Some((_, "Console created")) = split_bracketed_line(line) {
            // An unrecognized timestamp cannot anchor evidence, but it must still end history.
            records.push(LogRecord {
                timestamp: "",
                content: "Console created",
                offset,
            });
        }
        offset = offset.saturating_add(line.len()).saturating_add(1);
    }
    Ok(records)
}

struct ParsedSessions {
    sessions: Vec<Ue4ssRuntimeSession>,
    issues: Vec<String>,
    latest_header_valid: bool,
}

fn parse_sessions(
    records: &[LogRecord<'_>],
    limits: &Ue4ssRuntimeLogLimits,
) -> Result<ParsedSessions, String> {
    let mut anchors = Vec::new();
    let mut console_indices = Vec::new();
    let mut malformed_headers = 0_usize;
    for (index, record) in records.iter().enumerate() {
        if record.content != "Console created" {
            continue;
        }
        console_indices.push(index);
        if record.timestamp.is_empty() {
            malformed_headers += 1;
            continue;
        }
        let banner = records
            .iter()
            .enumerate()
            .skip(index + 1)
            .take_while(|(_, candidate)| {
                candidate.content != "Console created"
                    && candidate.offset.saturating_sub(record.offset)
                        <= limits.max_banner_distance_bytes
            })
            .find_map(|(banner_index, candidate)| {
                parse_version_banner(candidate.content).map(|version| (banner_index, version))
            });
        if let Some((banner_index, version)) = banner {
            anchors.push((index, banner_index, version));
            if anchors.len() > limits.max_sessions {
                return Err(format!(
                    "UE4SS.log exceeds the {} session limit",
                    limits.max_sessions
                ));
            }
        } else {
            malformed_headers += 1;
        }
    }

    let mut sessions = Vec::with_capacity(anchors.len());
    let mut event_count = 0_usize;
    for (session_index, (anchor_index, banner_index, version)) in anchors.iter().enumerate() {
        let end = console_indices
            .iter()
            .copied()
            .find(|candidate| candidate > anchor_index)
            .unwrap_or(records.len());
        let session_records = &records[*anchor_index..end];
        let mut phase = Ue4ssRuntimeModPhase::Unknown;
        let mut timezone = None;
        let mut build_configuration = None;
        let mut game_executable = None;
        let mut event_loop_start_observed = false;
        let mut events = Vec::new();
        let mut issues = Vec::new();
        for record in session_records {
            if record.content.starts_with("Starting mods (from mods.txt") {
                phase = Ue4ssRuntimeModPhase::ModsTxt;
                continue;
            }
            if record
                .content
                .starts_with("Starting mods (from enabled.txt")
            {
                phase = Ue4ssRuntimeModPhase::EnabledTxt;
                continue;
            }
            if record.content == "Event loop start" {
                event_loop_start_observed = true;
                continue;
            }
            if timezone.is_none()
                && let Some(value) = record.content.strip_prefix("Timezone: ")
                && field_within_limit(value, limits)
            {
                timezone = Some(value.to_owned());
                continue;
            }
            if build_configuration.is_none()
                && let Some(value) = parse_build_configuration(record.content, limits)
            {
                build_configuration = Some(value);
                continue;
            }
            if game_executable.is_none()
                && let Some(value) = parse_game_executable(record.content, limits)
            {
                game_executable = Some(value);
                continue;
            }
            let Some(event) = parse_mod_event(record, phase, events.len(), limits) else {
                continue;
            };
            event_count += 1;
            if event_count > limits.max_events {
                return Err(format!(
                    "UE4SS.log exceeds the {} module event limit; no arbitrary session subset was retained",
                    limits.max_events
                ));
            }
            events.push(event);
        }
        if build_configuration.is_none() {
            issues.push("session has no recognized build-configuration record".to_owned());
        }
        let anchor = records[*anchor_index];
        let banner = records[*banner_index];
        if anchor.timestamp != banner.timestamp {
            issues
                .push("session banner timestamp differs from Console created timestamp".to_owned());
        }
        sessions.push(Ue4ssRuntimeSession {
            index: session_index,
            start_timestamp: anchor.timestamp.to_owned(),
            start_offset: anchor.offset,
            version: version.clone(),
            timezone,
            build_configuration,
            game_executable,
            event_loop_start_observed,
            events,
            issues,
        });
    }
    let mut issues = Vec::new();
    if malformed_headers > 0 {
        issues.push(format!(
            "observed {malformed_headers} Console created record(s) without a nearby valid UE4SS banner"
        ));
    }
    let latest_header_valid = console_indices.last().is_some_and(|latest| {
        anchors
            .last()
            .is_some_and(|(anchor, _, _)| anchor == latest)
    });
    if !latest_header_valid && !sessions.is_empty() {
        issues.push(
            "the newest Console created record has no nearby valid banner; no historical session was selected"
                .to_owned(),
        );
    }
    Ok(ParsedSessions {
        sessions,
        issues,
        latest_header_valid,
    })
}

fn parse_timestamped_line(line: &str) -> Option<(&str, &str)> {
    let (timestamp, content) = split_bracketed_line(line)?;
    valid_timestamp(timestamp).then_some((timestamp, content))
}

fn split_bracketed_line(line: &str) -> Option<(&str, &str)> {
    let close = line.find("] ")?;
    let timestamp = line.strip_prefix('[')?.get(..close.saturating_sub(1))?;
    Some((timestamp, &line[close + 2..]))
}

fn valid_timestamp(value: &str) -> bool {
    let (base, fraction) = value
        .split_once('.')
        .map_or((value, None), |(base, fraction)| (base, Some(fraction)));
    if base.len() != 19 {
        return false;
    }
    let bytes = base.as_bytes();
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b' '
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        if !matches!(index, 4 | 7 | 10 | 13 | 16) && !byte.is_ascii_digit() {
            return false;
        }
    }
    let parse_pair = |start: usize| -> Option<u32> { base.get(start..start + 2)?.parse().ok() };
    let year: Option<u32> = base.get(0..4).and_then(|value| value.parse().ok());
    let month = parse_pair(5);
    let day = parse_pair(8);
    let hour = parse_pair(11);
    let minute = parse_pair(14);
    let second = parse_pair(17);
    let Some(year) = year.filter(|year| *year > 0) else {
        return false;
    };
    let Some(month) = month.filter(|month| (1..=12).contains(month)) else {
        return false;
    };
    let max_day = match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !day.is_some_and(|day| (1..=max_day).contains(&day))
        || !matches!(hour, Some(0..=23))
        || !matches!(minute, Some(0..=59))
        || !matches!(second, Some(0..=59))
    {
        return false;
    }
    fraction.is_none_or(|fraction| {
        (1..=9).contains(&fraction.len()) && fraction.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn parse_version_banner(content: &str) -> Option<Ue4ssRuntimeVersion> {
    let body = content.strip_prefix("UE4SS - v")?;
    let (version_and_labels, sha) = body.split_once(" - Git SHA #")?;
    let (base, labels) = version_and_labels
        .find(' ')
        .map_or((version_and_labels, ""), |index| {
            (&version_and_labels[..index], &version_and_labels[index..])
        });
    let mut components = base.split('.');
    let major = components.next()?.parse().ok()?;
    let minor = components.next()?.parse().ok()?;
    let hotfix = components.next()?.parse().ok()?;
    if components.next().is_some() {
        return None;
    }
    let mut remaining = labels;
    let mut prerelease = None;
    let mut beta = None;
    if let Some(after) = remaining.strip_prefix(" PreRelease #") {
        let (value, rest) = split_label_value(after);
        prerelease = Some(value.parse().ok()?);
        remaining = rest;
    }
    if let Some(after) = remaining.strip_prefix(" Beta #") {
        let (value, rest) = split_label_value(after);
        beta = Some(if value == "?" {
            Ue4ssRuntimeBeta::Unknown
        } else {
            Ue4ssRuntimeBeta::Number(value.parse().ok()?)
        });
        remaining = rest;
    }
    if !remaining.is_empty() {
        return None;
    }
    let git_sha = match sha {
        "unknown" => Ue4ssRuntimeGitSha::Unknown,
        "no-git" => Ue4ssRuntimeGitSha::NoGit,
        "0" => Ue4ssRuntimeGitSha::Zero,
        value
            if (4..=40).contains(&value.len())
                && value.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            Ue4ssRuntimeGitSha::Hex(value.to_ascii_lowercase())
        }
        _ => return None,
    };
    Some(Ue4ssRuntimeVersion {
        major,
        minor,
        hotfix,
        prerelease,
        beta,
        git_sha,
        raw_banner: content.to_owned(),
    })
}

fn split_label_value(value: &str) -> (&str, &str) {
    value
        .find(' ')
        .map_or((value, ""), |index| (&value[..index], &value[index..]))
}

fn parse_build_configuration(
    content: &str,
    limits: &Ue4ssRuntimeLogLimits,
) -> Option<Ue4ssRuntimeBuildConfiguration> {
    let value = content.strip_prefix("UE4SS Build Configuration: ")?;
    let (configuration, compiler) = value.rsplit_once(" (")?;
    let compiler = compiler.strip_suffix(')')?;
    if !field_within_limit(configuration, limits) {
        return None;
    }
    let compiler = match compiler {
        "MSVC" => Ue4ssRuntimeCompiler::Msvc,
        "Clang" => Ue4ssRuntimeCompiler::Clang,
        _ => return None,
    };
    Some(Ue4ssRuntimeBuildConfiguration {
        configuration: configuration.to_owned(),
        compiler,
    })
}

fn parse_game_executable(
    content: &str,
    limits: &Ue4ssRuntimeLogLimits,
) -> Option<Ue4ssRuntimeExecutable> {
    let value = content.strip_prefix("game executable: ")?;
    let (path, bytes) = value.rsplit_once(" (")?;
    let bytes = bytes.strip_suffix(" bytes)")?.parse().ok()?;
    if !field_within_limit(path, limits) {
        return None;
    }
    Some(Ue4ssRuntimeExecutable {
        path: path.to_owned(),
        bytes,
    })
}

fn parse_mod_event(
    record: &LogRecord<'_>,
    phase: Ue4ssRuntimeModPhase,
    sequence: usize,
    limits: &Ue4ssRuntimeLogLimits,
) -> Option<Ue4ssRuntimeModEvent> {
    if let Some(rest) = record.content.strip_prefix("Starting Lua mod '") {
        return quoted_event(
            record,
            rest,
            "'",
            sequence,
            Ue4ssRuntimeModEventKind::StartAttempt,
            Some(Ue4ssRuntimeModuleKind::Lua),
            phase,
            limits,
        );
    }
    if let Some(rest) = record.content.strip_prefix("Starting C++ mod '") {
        return quoted_event(
            record,
            rest,
            "'",
            sequence,
            Ue4ssRuntimeModEventKind::StartAttempt,
            Some(Ue4ssRuntimeModuleKind::Cpp),
            phase,
            limits,
        );
    }
    if let Some(rest) = record.content.strip_prefix("Mod '")
        && let Some(name) = rest.strip_suffix("' disabled in mods.txt.")
    {
        return module_event(
            record,
            name,
            sequence,
            Ue4ssRuntimeModEventKind::ConfiguredDisabledObserved,
            None,
            Ue4ssRuntimeModPhase::ModsTxt,
            limits,
        );
    }
    if let Some(rest) = record.content.strip_prefix("Mod '")
        && let Some(name) = rest.strip_suffix("' has enabled.txt, starting mod.")
    {
        return module_event(
            record,
            name,
            sequence,
            Ue4ssRuntimeModEventKind::EnabledMarkerStartAttempt,
            None,
            Ue4ssRuntimeModPhase::EnabledTxt,
            limits,
        );
    }
    if let Some(name) = record.content.strip_prefix("Starting mod: ") {
        return module_event(
            record,
            name,
            sequence,
            Ue4ssRuntimeModEventKind::RuntimeStartAttempt,
            None,
            Ue4ssRuntimeModPhase::RuntimeManagement,
            limits,
        );
    }
    if let Some(rest) = record.content.strip_prefix("Mod '")
        && let Some(name) = rest.strip_suffix("' started")
    {
        return module_event(
            record,
            name,
            sequence,
            Ue4ssRuntimeModEventKind::StartCallReturned,
            None,
            Ue4ssRuntimeModPhase::RuntimeManagement,
            limits,
        );
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn quoted_event(
    record: &LogRecord<'_>,
    value: &str,
    suffix: &str,
    sequence: usize,
    kind: Ue4ssRuntimeModEventKind,
    module_kind: Option<Ue4ssRuntimeModuleKind>,
    phase: Ue4ssRuntimeModPhase,
    limits: &Ue4ssRuntimeLogLimits,
) -> Option<Ue4ssRuntimeModEvent> {
    module_event(
        record,
        value.strip_suffix(suffix)?,
        sequence,
        kind,
        module_kind,
        phase,
        limits,
    )
}

#[allow(clippy::too_many_arguments)]
fn module_event(
    record: &LogRecord<'_>,
    name: &str,
    sequence: usize,
    kind: Ue4ssRuntimeModEventKind,
    module_kind: Option<Ue4ssRuntimeModuleKind>,
    phase: Ue4ssRuntimeModPhase,
    limits: &Ue4ssRuntimeLogLimits,
) -> Option<Ue4ssRuntimeModEvent> {
    if name.is_empty() || !field_within_limit(name, limits) {
        return None;
    }
    Some(Ue4ssRuntimeModEvent {
        sequence,
        timestamp: record.timestamp.to_owned(),
        record_offset: record.offset,
        kind,
        module_name: name.to_owned(),
        module_kind,
        phase,
    })
}

fn field_within_limit(value: &str, limits: &Ue4ssRuntimeLogLimits) -> bool {
    value.chars().count() <= limits.max_field_chars && !value.contains(['\0', '\r', '\n'])
}

#[allow(clippy::too_many_arguments)]
fn log_result(
    entry: EntryObservation,
    status: Ue4ssRuntimeLogStatus,
    complete: bool,
    bytes: u64,
    modified_unix_seconds: Option<u64>,
    read_unix_seconds: u64,
    sessions: Vec<Ue4ssRuntimeSession>,
    issues: Vec<String>,
) -> Ue4ssRuntimeLogFile {
    let age_seconds_at_read =
        modified_unix_seconds.and_then(|modified| read_unix_seconds.checked_sub(modified));
    let selected_session_index = sessions.last().map(|session| session.index);
    Ue4ssRuntimeLogFile {
        entry,
        status,
        complete,
        bytes,
        modified_unix_seconds,
        read_unix_seconds,
        age_seconds_at_read,
        freshness: Ue4ssRuntimeLogFreshness::Unassessed,
        selected_session_index,
        sessions,
        issues,
    }
}

fn system_time_seconds(value: SystemTime) -> Option<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_secs())
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;
    use crate::path_from_relative;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn parses_stable_runtime_identity_and_ordered_start_attempts() {
        let temporary = TempDir::new().unwrap();
        write_log(
            temporary.path(),
            NESTED_LOG_RELATIVE_PATH,
            r#"[2024-02-20 17:42:02] Console created
[2024-02-20 17:42:02] UE4SS - v3.0.1 Beta #0 - Git SHA #d935b5b
[2024-02-20 17:42:02] UE4SS Build Configuration: Game__Shipping__Win64 (MSVC)
[2024-02-20 17:42:02] game executable: C:\Games\RetroRewind\RetroRewind-Win64-Shipping.exe (141241856 bytes)
[2024-02-20 17:42:03] Starting mods (from mods.txt load order)...
[2024-02-20 17:42:03] Starting C++ mod 'NativeMod'
[2024-02-20 17:42:04] Mod 'DisabledMod' disabled in mods.txt.
[2024-02-20 17:42:05] Starting Lua mod 'LuaMod'
[2024-02-20 17:42:06] Starting mods (from enabled.txt, no defined load order)...
[2024-02-20 17:42:06] Mod 'MarkerMod' has enabled.txt, starting mod.
[2024-02-20 17:42:07] Event loop start
"#,
        );

        let report =
            analyze_ue4ss_runtime_logs(temporary.path(), &Ue4ssRuntimeLogLimits::default())
                .unwrap();

        assert!(report.complete);
        let log = &report.logs[0];
        assert_eq!(log.status, Ue4ssRuntimeLogStatus::Parsed);
        assert_eq!(log.sessions.len(), 1);
        let session = &log.sessions[0];
        assert_eq!(session.version.major, 3);
        assert_eq!(
            session.version.git_sha,
            Ue4ssRuntimeGitSha::Hex("d935b5b".to_owned())
        );
        assert_eq!(
            session.build_configuration,
            Some(Ue4ssRuntimeBuildConfiguration {
                configuration: "Game__Shipping__Win64".to_owned(),
                compiler: Ue4ssRuntimeCompiler::Msvc,
            })
        );
        assert_eq!(session.events.len(), 4);
        assert_eq!(session.events[0].module_name, "NativeMod");
        assert_eq!(session.events[0].phase, Ue4ssRuntimeModPhase::ModsTxt);
        assert_eq!(
            session.events[1].kind,
            Ue4ssRuntimeModEventKind::ConfiguredDisabledObserved
        );
        assert_eq!(session.events[2].module_name, "LuaMod");
        assert_eq!(session.events[3].phase, Ue4ssRuntimeModPhase::EnabledTxt);
        assert!(session.event_loop_start_observed);
    }

    #[test]
    fn parses_experimental_fractional_timestamp_timezone_and_commit() {
        let temporary = TempDir::new().unwrap();
        write_log(
            temporary.path(),
            FLAT_LOG_RELATIVE_PATH,
            r#"[2026-03-17 19:01:05.3617704] Console created
[2026-03-17 19:01:05.3829945] UE4SS - v3.0.1 Beta #0 - Git SHA #662df915
[2026-03-17 19:01:05.3831643] Timezone: UTC (local disabled due to wine)
[2026-03-17 19:01:05.3893573] UE4SS Build Configuration: Game__Shipping__Win64 (Clang)
[2026-03-17 19:01:06.0000001] Starting mod: Example
[2026-03-17 19:01:06.0000002] Mod 'Example' started
"#,
        );

        let report =
            analyze_ue4ss_runtime_logs(temporary.path(), &Ue4ssRuntimeLogLimits::default())
                .unwrap();
        let session = &report.logs[1].sessions[0];

        assert_eq!(session.start_timestamp, "2026-03-17 19:01:05.3617704");
        assert_eq!(
            session.version.git_sha,
            Ue4ssRuntimeGitSha::Hex("662df915".to_owned())
        );
        assert_eq!(
            session.timezone.as_deref(),
            Some("UTC (local disabled due to wine)")
        );
        assert_eq!(session.events.len(), 2);
        assert_eq!(
            session.events[1].kind,
            Ue4ssRuntimeModEventKind::StartCallReturned
        );
    }

    #[test]
    fn keeps_nonstandard_multiple_sessions_separate_and_selects_the_last() {
        let temporary = TempDir::new().unwrap();
        write_log(
            temporary.path(),
            NESTED_LOG_RELATIVE_PATH,
            r#"[2025-01-01 10:00:00] Console created
[2025-01-01 10:00:00] UE4SS - v3.0.1 Beta #0 - Git SHA #d935b5b
[2025-01-01 10:00:00] UE4SS Build Configuration: Game__Shipping__Win64 (MSVC)
[2025-01-01 10:00:01] Starting Lua mod 'OldMod'
[2025-01-02 10:00:00] Console created
[2025-01-02 10:00:00] UE4SS - v3.0.1 Beta #0 - Git SHA #662df915
[2025-01-02 10:00:00] UE4SS Build Configuration: Game__Shipping__Win64 (MSVC)
[2025-01-02 10:00:01] Starting Lua mod 'NewMod'
"#,
        );

        let report =
            analyze_ue4ss_runtime_logs(temporary.path(), &Ue4ssRuntimeLogLimits::default())
                .unwrap();
        let log = &report.logs[0];

        assert_eq!(log.sessions.len(), 2);
        assert_eq!(log.selected_session_index, Some(1));
        assert_eq!(log.sessions[0].events[0].module_name, "OldMod");
        assert_eq!(log.sessions[1].events[0].module_name, "NewMod");
    }

    #[test]
    fn a_newest_truncated_header_neither_selects_history_nor_merges_events() {
        let temporary = TempDir::new().unwrap();
        write_log(
            temporary.path(),
            NESTED_LOG_RELATIVE_PATH,
            r#"[2025-01-01 10:00:00] Console created
[2025-01-01 10:00:00] UE4SS - v3.0.1 Beta #0 - Git SHA #d935b5b
[2025-01-01 10:00:00] UE4SS Build Configuration: Game__Shipping__Win64 (MSVC)
[2025-01-01 10:00:01] Starting Lua mod 'Historical'
[2025-01-02 10:00:00] Console created
[2025-01-02 10:00:01] Starting Lua mod 'MustNotMerge'
"#,
        );

        let report =
            analyze_ue4ss_runtime_logs(temporary.path(), &Ue4ssRuntimeLogLimits::default())
                .unwrap();
        let log = &report.logs[0];

        assert_eq!(log.sessions.len(), 1);
        assert_eq!(log.selected_session_index, None);
        assert_eq!(log.sessions[0].events.len(), 1);
        assert_eq!(log.sessions[0].events[0].module_name, "Historical");
    }

    #[test]
    fn an_invalid_timestamp_header_still_ends_historical_events() {
        let temporary = TempDir::new().unwrap();
        write_log(
            temporary.path(),
            NESTED_LOG_RELATIVE_PATH,
            r#"[2025-01-01 10:00:00] Console created
[2025-01-01 10:00:00] UE4SS - v3.0.1 Beta #0 - Git SHA #d935b5b
[2025-01-01 10:00:00] UE4SS Build Configuration: Game__Shipping__Win64 (MSVC)
[2025-01-01 10:00:01] Starting Lua mod 'Historical'
[2025-02-31 10:00:00] Console created
[2025-03-01 10:00:01] Starting Lua mod 'MustNotMerge'
"#,
        );

        let report =
            analyze_ue4ss_runtime_logs(temporary.path(), &Ue4ssRuntimeLogLimits::default())
                .unwrap();
        let log = &report.logs[0];

        assert_eq!(log.selected_session_index, None);
        assert_eq!(log.sessions[0].events.len(), 1);
        assert_eq!(log.sessions[0].events[0].module_name, "Historical");
    }

    #[test]
    fn reports_missing_headers_without_promoting_banner_like_noise() {
        let temporary = TempDir::new().unwrap();
        write_log(
            temporary.path(),
            NESTED_LOG_RELATIVE_PATH,
            r#"[2025-01-01 10:00:00] Console created
[2025-01-01 10:00:01] UE4SS - v3.0 Beta #0 - Git SHA #bad
[2025-01-01 10:00:02] Starting Lua mod 'Noise'
"#,
        );

        let report =
            analyze_ue4ss_runtime_logs(temporary.path(), &Ue4ssRuntimeLogLimits::default())
                .unwrap();

        assert_eq!(report.logs[0].status, Ue4ssRuntimeLogStatus::NoValidSession);
        assert!(report.logs[0].sessions.is_empty());
        assert!(report.logs[0].complete);
    }

    #[test]
    fn result_limits_retain_no_arbitrary_session_prefix() {
        let temporary = TempDir::new().unwrap();
        write_log(
            temporary.path(),
            NESTED_LOG_RELATIVE_PATH,
            r#"[2025-01-01 10:00:00] Console created
[2025-01-01 10:00:00] UE4SS - v3.0.1 Beta #0 - Git SHA #d935b5b
[2025-01-01 10:00:00] UE4SS Build Configuration: Game__Shipping__Win64 (MSVC)
[2025-01-01 10:00:01] Starting Lua mod 'One'
[2025-01-01 10:00:02] Starting Lua mod 'Two'
"#,
        );
        let limits = Ue4ssRuntimeLogLimits {
            max_events: 1,
            ..Ue4ssRuntimeLogLimits::default()
        };

        let report = analyze_ue4ss_runtime_logs(temporary.path(), &limits).unwrap();

        assert!(!report.complete);
        assert_eq!(report.logs[0].status, Ue4ssRuntimeLogStatus::LimitExceeded);
        assert!(report.logs[0].sessions.is_empty());
    }

    #[test]
    fn reports_both_log_locations_without_selecting_one_as_active() {
        let temporary = TempDir::new().unwrap();
        let minimal = r#"[2025-01-01 10:00:00] Console created
[2025-01-01 10:00:00] UE4SS - v3.0.1 Beta #0 - Git SHA #d935b5b
[2025-01-01 10:00:00] UE4SS Build Configuration: Game__Shipping__Win64 (MSVC)
"#;
        write_log(temporary.path(), NESTED_LOG_RELATIVE_PATH, minimal);
        write_log(temporary.path(), FLAT_LOG_RELATIVE_PATH, minimal);

        let report =
            analyze_ue4ss_runtime_logs(temporary.path(), &Ue4ssRuntimeLogLimits::default())
                .unwrap();

        assert!(report.multiple_log_candidates);
        assert_eq!(report.logs.len(), 2);
        assert!(report.logs.iter().all(|log| !log.sessions.is_empty()));
    }

    #[test]
    #[cfg(unix)]
    fn an_unsafe_alternate_log_still_makes_location_ambiguous() {
        let temporary = TempDir::new().unwrap();
        let minimal = r#"[2025-01-01 10:00:00] Console created
[2025-01-01 10:00:00] UE4SS - v3.0.1 Beta #0 - Git SHA #d935b5b
[2025-01-01 10:00:00] UE4SS Build Configuration: Game__Shipping__Win64 (MSVC)
"#;
        write_log(temporary.path(), NESTED_LOG_RELATIVE_PATH, minimal);
        let outside = TempDir::new().unwrap();
        let flat = temporary
            .path()
            .join(path_from_relative(FLAT_LOG_RELATIVE_PATH));
        fs::create_dir_all(flat.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(outside.path(), flat).unwrap();

        let report =
            analyze_ue4ss_runtime_logs(temporary.path(), &Ue4ssRuntimeLogLimits::default())
                .unwrap();

        assert!(report.multiple_log_candidates);
        assert!(!report.complete);
    }

    #[test]
    #[cfg(unix)]
    fn never_follows_a_linked_log() {
        let temporary = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        fs::write(
            outside.path().join("UE4SS.log"),
            b"[2025-01-01 10:00:00] Console created\n",
        )
        .unwrap();
        let path = temporary
            .path()
            .join(path_from_relative(NESTED_LOG_RELATIVE_PATH));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(outside.path().join("UE4SS.log"), &path).unwrap();

        let report =
            analyze_ue4ss_runtime_logs(temporary.path(), &Ue4ssRuntimeLogLimits::default())
                .unwrap();

        assert!(!report.complete);
        assert_eq!(report.logs[0].status, Ue4ssRuntimeLogStatus::Unsafe);
        assert!(
            read_ue4ss_runtime_log_text(temporary.path(), NESTED_LOG_RELATIVE_PATH, 1024).is_err()
        );
    }

    #[test]
    fn safely_reads_only_a_bounded_runtime_log_prefix() {
        let temporary = TempDir::new().unwrap();
        write_log(
            temporary.path(),
            NESTED_LOG_RELATIVE_PATH,
            "first line\nsecond line\n",
        );

        let text = read_ue4ss_runtime_log_text(temporary.path(), NESTED_LOG_RELATIVE_PATH, 12)
            .unwrap()
            .unwrap();

        assert_eq!(text.relative_path, NESTED_LOG_RELATIVE_PATH);
        assert_eq!(text.content, "first line\ns");
        assert!(text.truncated);
    }

    #[test]
    fn safely_reads_complete_lines_from_the_runtime_log_tail() {
        let temporary = TempDir::new().unwrap();
        write_log(
            temporary.path(),
            NESTED_LOG_RELATIVE_PATH,
            "old line\nmiddle line\nrecent error\nlast line\n",
        );

        let text = read_ue4ss_runtime_log_tail_text(temporary.path(), NESTED_LOG_RELATIVE_PATH, 30)
            .unwrap()
            .unwrap();

        assert!(!text.content.contains("old line"));
        assert!(!text.content.starts_with("iddle"));
        assert!(text.content.contains("recent error"));
        assert!(text.content.ends_with("last line\n"));
        assert!(text.truncated);
    }

    #[test]
    fn validates_only_canonical_file_timestamps_and_banners() {
        assert!(valid_timestamp("2024-02-29 23:59:59.123456789"));
        assert!(!valid_timestamp("12:00:00"));
        assert!(!valid_timestamp("2025-13-01 00:00:00"));
        assert!(!valid_timestamp("2025-02-29 00:00:00"));
        assert!(!valid_timestamp("2025-04-31 00:00:00"));
        assert!(!valid_timestamp("0000-01-01 00:00:00"));
        assert!(!valid_timestamp("2025-12-31 23:59:60"));
        assert!(
            parse_version_banner("UE4SS - v3.0.1 PreRelease #2 Beta #? - Git SHA #no-git")
                .is_some()
        );
        assert!(parse_version_banner("UE4SS - v3.0.1 Beta #0 - Git SHA #xyz").is_none());
    }

    fn write_log(game_root: &Path, relative_path: &str, content: &str) {
        let path = game_root.join(path_from_relative(relative_path));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }
}

#[cfg(all(test, not(any(unix, windows))))]
mod non_unix_tests {
    use super::*;
    use crate::path_from_relative;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn regular_logs_fail_closed_without_component_relative_opening() {
        let temporary = TempDir::new().unwrap();
        let log = temporary
            .path()
            .join(path_from_relative(NESTED_LOG_RELATIVE_PATH));
        fs::create_dir_all(log.parent().unwrap()).unwrap();
        fs::write(log, b"[2025-01-01 00:00:00] Console created\n").unwrap();

        let report =
            analyze_ue4ss_runtime_logs(temporary.path(), &Ue4ssRuntimeLogLimits::default())
                .unwrap();

        assert!(!report.complete);
        assert_eq!(
            report.logs[0].status,
            Ue4ssRuntimeLogStatus::UnsupportedPlatform
        );
        assert!(report.logs[0].sessions.is_empty());
    }
}
