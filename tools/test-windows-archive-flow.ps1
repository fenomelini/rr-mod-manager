param(
    [Parameter(Mandatory = $true)]
    [string]$ArchivePath,

    [Parameter(Mandatory = $true)]
    [string]$Ue4ssArchivePath,

    [Parameter(Mandatory = $true)]
    [string]$GameRootPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $IsWindows) {
    throw "The archive end-to-end smoke test must run on Windows."
}

$workspace = Split-Path -Parent $PSScriptRoot
$resolvedArchive = (Resolve-Path -LiteralPath $ArchivePath).Path
$resolvedUe4ssArchive = (Resolve-Path -LiteralPath $Ue4ssArchivePath).Path
$resolvedGameRoot = (Resolve-Path -LiteralPath $GameRootPath).Path
$previousArchiveWorker = $env:RRMM_WINDOWS_ARCHIVE_WORKER
$previousPakWorker = $env:RRMM_WINDOWS_PAK_WORKER
$previousArchive = $env:RRMM_WINDOWS_MOD_ARCHIVE
$previousUe4ssArchive = $env:RRMM_WINDOWS_UE4SS_ARCHIVE
$previousGameRoot = $env:RRMM_WINDOWS_GAME_ROOT

try {
    Push-Location $workspace
    try {
        cargo build --locked --package rrmm-archive-worker --package rrmm-pak-worker
        if ($LASTEXITCODE -ne 0) { throw "Failed to build the real parser workers." }

        $env:RRMM_WINDOWS_ARCHIVE_WORKER = (Resolve-Path "target/debug/rrmm-archive-worker.exe").Path
        $env:RRMM_WINDOWS_PAK_WORKER = (Resolve-Path "target/debug/rrmm-pak-worker.exe").Path
        $env:RRMM_WINDOWS_MOD_ARCHIVE = $resolvedArchive
        $env:RRMM_WINDOWS_UE4SS_ARCHIVE = $resolvedUe4ssArchive
        $env:RRMM_WINDOWS_GAME_ROOT = $resolvedGameRoot
        cargo test --locked --package rrmm-application `
            "desktop::tests::windows_real_workers_import_a_unc_mod_archive_end_to_end" `
            -- --ignored --exact --nocapture
        if ($LASTEXITCODE -ne 0) { throw "The complete Windows UNC archive flow failed." }
    }
    finally {
        Pop-Location
    }
}
finally {
    $env:RRMM_WINDOWS_ARCHIVE_WORKER = $previousArchiveWorker
    $env:RRMM_WINDOWS_PAK_WORKER = $previousPakWorker
    $env:RRMM_WINDOWS_MOD_ARCHIVE = $previousArchive
    $env:RRMM_WINDOWS_UE4SS_ARCHIVE = $previousUe4ssArchive
    $env:RRMM_WINDOWS_GAME_ROOT = $previousGameRoot
}
