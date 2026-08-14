#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::{Context, Result};
use rrmm_application::{
    BugReportRequestView, DesktopApplication, DesktopPaths, ExistingModGroupOperation,
    ImportArchiveConfirmationView,
};
use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tauri::{AppHandle, Manager, State};

struct AppState {
    application: DesktopApplication,
    operation_nonce: AtomicU64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CommandError {
    code: &'static str,
    message: String,
}

type CommandResult = std::result::Result<Value, CommandError>;

fn classify_error(message: &str) -> &'static str {
    let error = message.to_lowercase();
    if error.contains("steam accepted the launch request") && error.contains("did not start within")
    {
        "game_launch_timeout"
    } else if error.contains("steam executable was not found")
        || error.contains("invalid steam executable")
    {
        "steam_unavailable"
    } else if error.contains("failed to launch retro rewind") {
        "game_launch_failed"
    } else if error.contains("timed out") {
        "worker_timeout"
    } else if error.contains("sandbox")
        || error.contains("without the required os sandbox")
        || error.contains("windows sandbox")
        || error.contains("appcontainer")
        || error.contains("process security attribute")
        || error.contains("child-process policy")
        || error.contains("job object")
    {
        "worker_sandbox"
    } else if error.contains("worker rejected") || error.contains("unknown worker error") {
        "worker_protocol"
    } else if error.contains("ue4ss")
        && (error.contains("download") || error.contains("http status"))
    {
        "ue4ss_download"
    } else if error.contains("ue4ss")
        && (error.contains("legacy or customized")
            || error.contains("ambiguous")
            || error.contains("mixed"))
    {
        "ue4ss_layout"
    } else if error.contains("ue4ss")
        && (error.contains("identity verification") || error.contains("unexpected hash"))
    {
        "ue4ss_verification"
    } else if error.contains("review expired") || error.contains("preview expired") {
        "review_expired"
    } else if error.contains("bytes changed")
        || error.contains("source changed")
        || error.contains("plan changed")
    {
        "file_changed"
    } else if error.contains("not a regular file") || error.contains("wrong directory") {
        "invalid_selection"
    } else if error.contains("game") && error.contains("running") {
        "game_running"
    } else if error.contains("recovery")
        || error.contains("journal")
        || error.contains("interrupted")
    {
        "recovery_required"
    } else if error.contains("profile name") {
        "profile_name"
    } else if error.contains("profile") && error.contains("not found") {
        "profile_missing"
    } else if error.contains("active profile") && error.contains("delet") {
        "active_profile_delete"
    } else if error.contains("artifact") && error.contains("not found") {
        "mod_missing"
    } else if error.contains("ue4ss loader policy") && error.contains("blocked deployment") {
        "ue4ss_repair_required"
    } else if error.contains("offline mode") {
        "offline_mode"
    } else if error.contains("permission denied")
        || error.contains("access denied")
        || error.contains("acesso negado")
        || error.contains("os error 5")
        || error.contains("unwritable")
    {
        "permission_denied"
    } else if error.contains("no space") || error.contains("disk full") {
        "disk_full"
    } else {
        "unexpected"
    }
}

fn run_command<T>(
    state: &State<'_, AppState>,
    operation: &'static str,
    action: impl FnOnce(&DesktopApplication) -> Result<T>,
) -> CommandResult
where
    T: Serialize,
{
    let operation_id = format!(
        "{operation}-{}",
        state.operation_nonce.fetch_add(1, Ordering::Relaxed)
    );
    state.application.begin_operation(&operation_id, operation);
    match action(&state.application) {
        Ok(value) => {
            state.application.complete_operation(&operation_id);
            serde_json::to_value(value).map_err(|error| CommandError {
                code: "unexpected",
                message: error.to_string(),
            })
        }
        Err(error) => {
            state.application.fail_operation(&operation_id, &error);
            let message = format!("{error:#}");
            Err(CommandError {
                code: classify_error(&message),
                message,
            })
        }
    }
}

#[tauri::command]
fn bootstrap(state: State<'_, AppState>) -> CommandResult {
    run_command(&state, "bootstrap", DesktopApplication::bootstrap)
}

#[tauri::command]
fn refresh_snapshot(state: State<'_, AppState>) -> CommandResult {
    run_command(
        &state,
        "refreshSnapshot",
        DesktopApplication::refresh_snapshot,
    )
}

#[tauri::command]
fn rediscover_game_installation(state: State<'_, AppState>) -> CommandResult {
    run_command(
        &state,
        "rediscoverGameInstallation",
        DesktopApplication::rediscover_game_installation,
    )
}

#[tauri::command]
fn preflight_archive(state: State<'_, AppState>, path: String) -> CommandResult {
    run_command(&state, "preflightArchive", |app| {
        app.preflight_archive(Path::new(&path))
    })
}

#[tauri::command(rename_all = "camelCase")]
fn review_archive(state: State<'_, AppState>, preflight_token: String) -> CommandResult {
    run_command(&state, "reviewArchive", |app| {
        app.review_archive(&preflight_token)
    })
}

#[tauri::command(rename_all = "camelCase")]
fn import_reviewed_archive(
    state: State<'_, AppState>,
    review_token: String,
    confirmation: ImportArchiveConfirmationView,
) -> CommandResult {
    run_command(&state, "importReviewedArchive", |app| {
        app.import_reviewed_archive(&review_token, confirmation)
    })
}

#[tauri::command(rename_all = "camelCase")]
fn discard_archive_review(state: State<'_, AppState>, review_token: String) -> CommandResult {
    run_command(&state, "discardArchiveReview", |app| {
        app.discard_archive_review(&review_token)
    })
}

#[tauri::command(rename_all = "camelCase")]
fn delete_artifact(state: State<'_, AppState>, artifact_sha256: String) -> CommandResult {
    run_command(&state, "deleteArtifact", |app| {
        app.delete_artifact(&artifact_sha256)
    })
}

#[tauri::command(rename_all = "camelCase")]
fn preview_bulk_delete(
    state: State<'_, AppState>,
    external_mod_ids: Vec<String>,
    artifact_sha256: Vec<String>,
) -> CommandResult {
    run_command(&state, "previewBulkDelete", |app| {
        app.preview_bulk_delete(&external_mod_ids, &artifact_sha256)
    })
}

#[tauri::command]
fn apply_bulk_delete(state: State<'_, AppState>, token: String) -> CommandResult {
    run_command(&state, "applyBulkDelete", |app| {
        app.apply_bulk_delete(&token)
    })
}

#[tauri::command]
fn create_profile(state: State<'_, AppState>, name: String) -> CommandResult {
    run_command(&state, "createProfile", |app| app.create_profile(&name))
}

#[tauri::command(rename_all = "camelCase")]
fn clone_profile(state: State<'_, AppState>, source_id: String, name: String) -> CommandResult {
    run_command(&state, "cloneProfile", |app| {
        app.clone_profile(&source_id, &name)
    })
}

#[tauri::command(rename_all = "camelCase")]
fn rename_profile(state: State<'_, AppState>, profile_id: String, name: String) -> CommandResult {
    run_command(&state, "renameProfile", |app| {
        app.rename_profile(&profile_id, &name)
    })
}

#[tauri::command(rename_all = "camelCase")]
fn set_profile_mods_enabled(
    state: State<'_, AppState>,
    profile_id: String,
    artifact_sha256: Vec<String>,
    enabled: bool,
) -> CommandResult {
    run_command(&state, "setProfileModsEnabled", |app| {
        app.set_profile_mods_enabled(&profile_id, &artifact_sha256, enabled)
    })
}

#[tauri::command(rename_all = "camelCase")]
fn set_pak_conflict_winner(
    state: State<'_, AppState>,
    preview_id: String,
    conflict_id: String,
    winner_pak_sha256: String,
) -> CommandResult {
    run_command(&state, "setPakConflictWinner", |app| {
        app.set_pak_conflict_winner(&preview_id, &conflict_id, &winner_pak_sha256)
    })
}

#[tauri::command(rename_all = "camelCase")]
fn set_pak_load_order(
    state: State<'_, AppState>,
    preview_id: String,
    ordered_pak_sha256: Vec<String>,
) -> CommandResult {
    run_command(&state, "setPakLoadOrder", |app| {
        app.set_pak_load_order(&preview_id, &ordered_pak_sha256)
    })
}

#[tauri::command(rename_all = "camelCase")]
fn remove_blocking_ue4ss_link(
    state: State<'_, AppState>,
    preview_id: String,
    relative_path: String,
) -> CommandResult {
    run_command(&state, "removeBlockingUe4ssLink", |app| {
        app.remove_blocking_ue4ss_link(&preview_id, &relative_path)
    })
}

#[tauri::command(rename_all = "camelCase")]
fn select_profile(state: State<'_, AppState>, profile_id: String) -> CommandResult {
    run_command(&state, "selectProfile", |app| {
        app.select_profile(&profile_id)
    })
}

#[tauri::command(rename_all = "camelCase")]
fn delete_profile(state: State<'_, AppState>, profile_id: String) -> CommandResult {
    run_command(&state, "deleteProfile", |app| {
        app.delete_profile(&profile_id)
    })
}

#[tauri::command]
fn set_offline_mode(state: State<'_, AppState>, enabled: bool) -> CommandResult {
    run_command(&state, "setOfflineMode", |app| {
        app.set_offline_mode(enabled)
    })
}

#[tauri::command]
fn select_game_folder(state: State<'_, AppState>, path: String) -> CommandResult {
    run_command(&state, "selectGameFolder", |app| {
        app.select_game_folder(Path::new(&path))
    })
}

#[tauri::command]
fn mark_game_incident(state: State<'_, AppState>) -> CommandResult {
    run_command(
        &state,
        "markGameIncident",
        DesktopApplication::mark_game_incident,
    )
}

#[tauri::command]
fn preview_bug_report(state: State<'_, AppState>, request: BugReportRequestView) -> CommandResult {
    run_command(&state, "previewBugReport", |app| {
        app.preview_bug_report(request)
    })
}

#[tauri::command]
fn export_bug_report(
    state: State<'_, AppState>,
    token: String,
    destination: String,
) -> CommandResult {
    run_command(&state, "exportBugReport", |app| {
        app.export_bug_report(&token, Path::new(&destination))
    })
}

#[tauri::command]
fn clear_diagnostic_history(state: State<'_, AppState>) -> CommandResult {
    run_command(
        &state,
        "clearDiagnosticHistory",
        DesktopApplication::clear_diagnostic_history,
    )
}

#[tauri::command(rename_all = "camelCase")]
fn set_existing_mod_enabled(
    state: State<'_, AppState>,
    mod_id: String,
    enabled: bool,
) -> CommandResult {
    run_command(&state, "setExistingModEnabled", |app| {
        app.set_existing_mod_enabled(&mod_id, enabled)
    })
}

#[tauri::command(rename_all = "camelCase")]
fn adopt_existing_mod(state: State<'_, AppState>, mod_id: String) -> CommandResult {
    run_command(&state, "adoptExistingMod", |app| {
        app.adopt_existing_mod(&mod_id)
    })
}

#[tauri::command(rename_all = "camelCase")]
fn delete_existing_mod(state: State<'_, AppState>, mod_id: String) -> CommandResult {
    run_command(&state, "deleteExistingMod", |app| {
        app.delete_existing_mod(&mod_id)
    })
}

#[tauri::command(rename_all = "camelCase")]
fn operate_existing_mod_group(
    state: State<'_, AppState>,
    group_id: String,
    operation: ExistingModGroupOperation,
) -> CommandResult {
    run_command(&state, "operateExistingModGroup", |app| {
        app.operate_existing_mod_group(&group_id, operation)
    })
}

#[tauri::command(rename_all = "camelCase")]
fn preview_activation(state: State<'_, AppState>, allow_unmanaged: bool) -> CommandResult {
    run_command(&state, "previewActivation", |app| {
        app.preview_activation(allow_unmanaged)
    })
}

#[tauri::command(rename_all = "camelCase")]
fn approve_managed_file_restore(
    state: State<'_, AppState>,
    preview_id: String,
    relative_path: String,
) -> CommandResult {
    run_command(&state, "approveManagedFileRestore", |app| {
        app.approve_managed_file_restore(&preview_id, &relative_path)
    })
}

#[tauri::command(rename_all = "camelCase")]
fn disable_managed_file_package(
    state: State<'_, AppState>,
    preview_id: String,
    relative_path: String,
) -> CommandResult {
    run_command(&state, "disableManagedFilePackage", |app| {
        app.disable_managed_file_package(&preview_id, &relative_path)
    })
}

#[tauri::command(rename_all = "camelCase")]
fn apply_activation(state: State<'_, AppState>, preview_id: String) -> CommandResult {
    run_command(&state, "applyActivation", |app| {
        app.apply_activation(&preview_id)
    })
}

#[tauri::command]
fn recover_deployment(state: State<'_, AppState>) -> CommandResult {
    run_command(
        &state,
        "recoverDeployment",
        DesktopApplication::recover_deployment,
    )
}

#[tauri::command]
fn refresh_ue4ss(state: State<'_, AppState>) -> CommandResult {
    run_command(&state, "refreshUe4ss", DesktopApplication::refresh_ue4ss)
}

#[tauri::command]
fn install_or_repair_ue4ss(state: State<'_, AppState>) -> CommandResult {
    run_command(
        &state,
        "installOrRepairUe4ss",
        DesktopApplication::install_or_repair_ue4ss,
    )
}

#[tauri::command]
fn analyze_keybinds(state: State<'_, AppState>) -> CommandResult {
    run_command(
        &state,
        "analyzeKeybinds",
        DesktopApplication::analyze_keybinds,
    )
}

#[tauri::command]
async fn launch_game(app: AppHandle) -> CommandResult {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        run_command(&state, "launchGame", DesktopApplication::launch_game)
    })
    .await
    .map_err(|error| CommandError {
        code: "unexpected",
        message: format!("game launch task failed: {error}"),
    })?
}

fn sidecar_path(name: &str) -> Result<PathBuf> {
    let executable = std::env::current_exe().context("failed to locate RR Mod Manager")?;
    let directory = executable
        .parent()
        .context("RR Mod Manager executable has no parent directory")?;
    Ok(directory.join(format!("{name}{}", std::env::consts::EXE_SUFFIX)))
}

fn main() -> Result<()> {
    let application = DesktopApplication::new(
        DesktopPaths::for_local_user()?,
        sidecar_path("rrmm-archive-worker")?,
        sidecar_path("rrmm-pak-worker")?,
    )?;
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState {
            application,
            operation_nonce: AtomicU64::new(1),
        })
        .invoke_handler(tauri::generate_handler![
            bootstrap,
            refresh_snapshot,
            rediscover_game_installation,
            preflight_archive,
            review_archive,
            import_reviewed_archive,
            discard_archive_review,
            delete_artifact,
            preview_bulk_delete,
            apply_bulk_delete,
            create_profile,
            clone_profile,
            rename_profile,
            set_profile_mods_enabled,
            set_pak_conflict_winner,
            set_pak_load_order,
            remove_blocking_ue4ss_link,
            select_profile,
            delete_profile,
            set_offline_mode,
            select_game_folder,
            mark_game_incident,
            preview_bug_report,
            export_bug_report,
            clear_diagnostic_history,
            set_existing_mod_enabled,
            adopt_existing_mod,
            delete_existing_mod,
            operate_existing_mod_group,
            preview_activation,
            approve_managed_file_restore,
            disable_managed_file_package,
            apply_activation,
            recover_deployment,
            refresh_ue4ss,
            install_or_repair_ue4ss,
            analyze_keybinds,
            launch_game,
        ])
        .run(tauri::generate_context!())
        .context("RR Mod Manager desktop runtime failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::classify_error;

    #[test]
    fn classifies_localized_windows_access_denied() {
        assert_eq!(
            classify_error("Acesso negado. (os error 5)"),
            "permission_denied"
        );
    }

    #[test]
    fn classifies_a_rejected_windows_security_attribute_as_a_sandbox_failure() {
        assert_eq!(
            classify_error(
                "archive worker rejected the operation: failed to configure process security attribute (child-process policy): Windows error 24"
            ),
            "worker_sandbox"
        );
    }

    #[test]
    fn classifies_a_rejected_sandbox_path_acl_as_a_sandbox_failure() {
        assert_eq!(
            classify_error(
                "archive worker rejected the operation: failed to read sandbox path ACL: Windows error 1"
            ),
            "worker_sandbox"
        );
    }

    #[test]
    fn classifies_game_launch_failures_separately_from_worker_failures() {
        assert_eq!(
            classify_error(
                "Steam accepted the launch request but Retro Rewind did not start within 30 seconds"
            ),
            "game_launch_timeout"
        );
        assert_eq!(
            classify_error("Steam executable was not found beside the selected installation"),
            "steam_unavailable"
        );
        assert_eq!(
            classify_error("failed to launch Retro Rewind through C:\\Steam\\steam.exe"),
            "game_launch_failed"
        );
    }
}
