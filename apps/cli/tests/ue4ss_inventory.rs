use rrmm_ue4ss::{
    DeclaredModuleState, LuaAdvisoryArgument, LuaAdvisoryReport, LuaPropertyWriteKind,
    ModsTxtAnalysisStatus, ModsTxtSemantics, Ue4ssActivationReport, Ue4ssDeclaredActivation,
    Ue4ssInstallationStatus, Ue4ssInventoryReport, Ue4ssLoaderIdentityReport,
    Ue4ssLoaderIdentityStatus, Ue4ssLoaderLayout, Ue4ssLoaderStatus, Ue4ssLuaApi, Ue4ssModuleKind,
    Ue4ssRuntimeGitSha, Ue4ssRuntimeLogReport, Ue4ssRuntimeModEventKind,
};
use std::fs;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn inventories_a_synthetic_module_tree_without_modifying_it() {
    let temporary = TempDir::new().unwrap();
    let game = temporary.path().join("game");
    let module = game.join("RetroRewind/Binaries/Win64/ue4ss/Mods/FasterReturns");
    fs::create_dir_all(module.join("Scripts")).unwrap();
    fs::write(
        module.join("Scripts/main.lua"),
        b"error('must not execute')",
    )
    .unwrap();
    fs::write(module.join("enabled.txt"), b"").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rrmm-cli"))
        .args(["ue4ss-inventory", "--game-root"])
        .arg(&game)
        .output()
        .unwrap();

    assert!(output.status.success());
    let report: Ue4ssInventoryReport = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report.installation_status,
        Ue4ssInstallationStatus::ModuleTreeDetected
    );
    assert_eq!(report.schema_version, 2);
    assert_eq!(report.loader.status, Ue4ssLoaderStatus::SupportingFilesOnly);
    assert_eq!(report.mods_txt.semantics, ModsTxtSemantics::Missing);
    assert_eq!(report.modules.len(), 1);
    assert_eq!(report.modules[0].name, "FasterReturns");
    assert_eq!(report.modules[0].kind, Ue4ssModuleKind::Lua);
    assert_eq!(
        report.modules[0].declared_state,
        DeclaredModuleState::EnabledMarkerPresent
    );
    assert_eq!(
        fs::read(module.join("Scripts/main.lua")).unwrap(),
        b"error('must not execute')"
    );
    assert!(report.modules[0].files.iter().all(|file| {
        !file
            .relative_path
            .starts_with(game.to_string_lossy().as_ref())
    }));
}

#[test]
#[cfg(unix)]
fn hashes_loader_identity_without_modifying_the_binaries() {
    let temporary = TempDir::new().unwrap();
    let game = temporary.path().join("game");
    let proxy = game.join("RetroRewind/Binaries/Win64/dwmapi.dll");
    let core = game.join("RetroRewind/Binaries/Win64/ue4ss/UE4SS.dll");
    fs::create_dir_all(core.parent().unwrap()).unwrap();
    fs::write(&proxy, b"proxy bytes").unwrap();
    fs::write(&core, b"core bytes").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rrmm-cli"))
        .args(["ue4ss-identity", "--game-root"])
        .arg(&game)
        .output()
        .unwrap();

    assert!(output.status.success());
    let report: Ue4ssLoaderIdentityReport = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report.status, Ue4ssLoaderIdentityStatus::Exact);
    assert_eq!(
        report.identity.as_ref().unwrap().layout,
        Ue4ssLoaderLayout::Nested
    );
    assert_eq!(fs::read(proxy).unwrap(), b"proxy bytes");
    assert_eq!(fs::read(core).unwrap(), b"core bytes");
}

#[test]
fn reports_absence_but_rejects_a_missing_game_root() {
    let temporary = TempDir::new().unwrap();
    let game = temporary.path().join("game");
    fs::create_dir(&game).unwrap();

    let absent = Command::new(env!("CARGO_BIN_EXE_rrmm-cli"))
        .args(["ue4ss-inventory", "--game-root"])
        .arg(&game)
        .output()
        .unwrap();
    assert!(absent.status.success());
    let report: Ue4ssInventoryReport = serde_json::from_slice(&absent.stdout).unwrap();
    assert_eq!(report.installation_status, Ue4ssInstallationStatus::Absent);
    assert!(!game.join("RetroRewind").exists());

    let missing = Command::new(env!("CARGO_BIN_EXE_rrmm-cli"))
        .args(["ue4ss-inventory", "--game-root"])
        .arg(temporary.path().join("missing"))
        .output()
        .unwrap();
    assert!(!missing.status.success());
}

#[test]
#[cfg(unix)]
fn reconciles_activation_evidence_without_executing_or_changing_modules() {
    let temporary = TempDir::new().unwrap();
    let game = temporary.path().join("game");
    let mods = game.join("RetroRewind/Binaries/Win64/ue4ss/Mods");
    let marker_module = mods.join("MarkerMod");
    let list_module = mods.join("ListMod");
    fs::create_dir_all(marker_module.join("Scripts")).unwrap();
    fs::create_dir_all(list_module.join("Scripts")).unwrap();
    fs::write(
        marker_module.join("Scripts/main.lua"),
        b"error('must not execute')",
    )
    .unwrap();
    fs::write(list_module.join("Scripts/main.lua"), b"").unwrap();
    fs::write(marker_module.join("enabled.txt"), b"contents are ignored").unwrap();
    fs::write(mods.join("mods.txt"), b"MarkerMod : 0\nListMod : 1\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rrmm-cli"))
        .args(["ue4ss-state", "--game-root"])
        .arg(&game)
        .output()
        .unwrap();

    assert!(output.status.success());
    let report: Ue4ssActivationReport = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report.complete);
    assert_eq!(report.mods_txt.status, ModsTxtAnalysisStatus::Parsed);
    assert_eq!(
        report.modules[0].declared_state,
        Ue4ssDeclaredActivation::EnabledByModsTxt
    );
    assert_eq!(
        report.modules[1].declared_state,
        Ue4ssDeclaredActivation::EnabledByMarker
    );
    assert_eq!(
        fs::read(marker_module.join("Scripts/main.lua")).unwrap(),
        b"error('must not execute')"
    );
    assert_eq!(
        fs::read(marker_module.join("enabled.txt")).unwrap(),
        b"contents are ignored"
    );
}

#[test]
#[cfg(unix)]
fn extracts_mutable_log_evidence_without_executing_or_changing_modules() {
    let temporary = TempDir::new().unwrap();
    let game = temporary.path().join("game");
    let log = game.join("RetroRewind/Binaries/Win64/ue4ss/UE4SS.log");
    fs::create_dir_all(log.parent().unwrap()).unwrap();
    let contents = b"[2026-01-01 10:00:00] Console created\n\
[2026-01-01 10:00:00] UE4SS - v3.0.1 Beta #0 - Git SHA #662df915\n\
[2026-01-01 10:00:00] UE4SS Build Configuration: Game__Shipping__Win64 (MSVC)\n\
[2026-01-01 10:00:01] Starting Lua mod 'Example'\n";
    fs::write(&log, contents).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rrmm-cli"))
        .args(["ue4ss-log", "--game-root"])
        .arg(&game)
        .output()
        .unwrap();

    assert!(output.status.success());
    let report: Ue4ssRuntimeLogReport = serde_json::from_slice(&output.stdout).unwrap();
    let session = &report.logs[0].sessions[0];
    assert_eq!(
        session.version.git_sha,
        Ue4ssRuntimeGitSha::Hex("662df915".to_owned())
    );
    assert_eq!(
        session.events[0].kind,
        Ue4ssRuntimeModEventKind::StartAttempt
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("redact it before sharing"))
    );
    assert_eq!(fs::read(log).unwrap(), contents);
}

#[test]
fn statically_analyzes_lua_without_counting_comments_or_executing_callbacks() {
    let temporary = TempDir::new().unwrap();
    let game = temporary.path().join("game");
    let script = game.join("RetroRewind/Binaries/Win64/ue4ss/Mods/Example/Scripts/main.lua");
    fs::create_dir_all(script.parent().unwrap()).unwrap();
    fs::write(
        &script,
        br#"
-- RegisterHook("/Game/Fake", callback)
RegisterHook(DYNAMIC_TARGET, callback)
RegisterConsoleCommandHandler("example", function() error("must not execute") end)
object["Product Struct"] = product
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rrmm-cli"))
        .args(["ue4ss-analyze", "--game-root"])
        .arg(&game)
        .output()
        .unwrap();

    assert!(output.status.success());
    let report: LuaAdvisoryReport = serde_json::from_slice(&output.stdout).unwrap();
    let findings = &report.modules[0].scripts[0].findings;
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].api, Ue4ssLuaApi::RegisterHook);
    assert_eq!(
        findings[0].first_argument,
        LuaAdvisoryArgument::DynamicUnresolved
    );
    assert_eq!(
        findings[1].first_argument,
        LuaAdvisoryArgument::Literal {
            value: "example".to_owned()
        }
    );
    assert_eq!(
        report.modules[0].scripts[0].property_writes[0].kind,
        LuaPropertyWriteKind::LiteralIndexCandidate
    );
    assert!(
        fs::read_to_string(&script)
            .unwrap()
            .contains("must not execute")
    );
}
