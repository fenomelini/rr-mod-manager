$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $IsWindows) {
    throw "The generated-mod end-to-end test must run on Windows."
}

$workspace = Split-Path -Parent $PSScriptRoot
$previousArchiveWorker = $env:RRMM_WINDOWS_ARCHIVE_WORKER
$previousPakWorker = $env:RRMM_WINDOWS_PAK_WORKER

try {
    Push-Location $workspace
    try {
        cargo build --locked --package rrmm-archive-worker --package rrmm-pak-worker
        if ($LASTEXITCODE -ne 0) { throw "Failed to build the real parser workers." }

        $env:RRMM_WINDOWS_ARCHIVE_WORKER = (Resolve-Path "target/debug/rrmm-archive-worker.exe").Path
        $env:RRMM_WINDOWS_PAK_WORKER = (Resolve-Path "target/debug/rrmm-pak-worker.exe").Path
        cargo test --locked --package rrmm-application `
            "desktop::tests::windows_real_workers_import_and_deploy_a_generated_mod_end_to_end" `
            -- --ignored --exact --nocapture
        if ($LASTEXITCODE -ne 0) { throw "The complete generated-mod worker flow failed." }
    }
    finally {
        Pop-Location
    }
}
finally {
    $env:RRMM_WINDOWS_ARCHIVE_WORKER = $previousArchiveWorker
    $env:RRMM_WINDOWS_PAK_WORKER = $previousPakWorker
}
