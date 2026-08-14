$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $IsWindows) {
    throw "The UE4SS end-to-end smoke test must run on Windows."
}

$workspace = Split-Path -Parent $PSScriptRoot
$descriptorPath = Join-Path $workspace "catalogs/ue4ss-loader/23896268.json"
$descriptor = Get-Content -Raw $descriptorPath | ConvertFrom-Json
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("rrmm-ue4ss-smoke-" + [Guid]::NewGuid())
$archive = Join-Path $temporaryRoot $descriptor.filename
$previousWorker = $env:RRMM_WINDOWS_ARCHIVE_WORKER
$previousArchive = $env:RRMM_WINDOWS_UE4SS_ARCHIVE

try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    Invoke-WebRequest -Uri $descriptor.url -OutFile $archive -UseBasicParsing

    $archiveInfo = Get-Item $archive
    if ($archiveInfo.Length -ne [long]$descriptor.archive_size) {
        throw "Pinned UE4SS archive size mismatch: $($archiveInfo.Length)"
    }
    $archiveHash = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
    if ($archiveHash -ne $descriptor.archive_sha256) {
        throw "Pinned UE4SS archive SHA-256 mismatch: $archiveHash"
    }

    Push-Location $workspace
    try {
        cargo test --locked --package rrmm-pak-worker --test protocol `
            "sandboxed_worker_" -- --nocapture
        if ($LASTEXITCODE -ne 0) { throw "The Windows PAK worker sandbox flow failed." }

        cargo build --locked --package rrmm-archive-worker
        if ($LASTEXITCODE -ne 0) { throw "Failed to build the real archive worker." }

        $env:RRMM_WINDOWS_ARCHIVE_WORKER = (Resolve-Path "target/debug/rrmm-archive-worker.exe").Path
        $env:RRMM_WINDOWS_UE4SS_ARCHIVE = $archive
        cargo test --locked --package rrmm-application `
            "desktop::tests::windows_real_worker_completes_the_full_ue4ss_installation" `
            -- --ignored --exact --nocapture
        if ($LASTEXITCODE -ne 0) { throw "The complete Windows UE4SS flow failed." }
    }
    finally {
        Pop-Location
    }
}
finally {
    $env:RRMM_WINDOWS_ARCHIVE_WORKER = $previousWorker
    $env:RRMM_WINDOWS_UE4SS_ARCHIVE = $previousArchive
    if (Test-Path $temporaryRoot) {
        Remove-Item -Recurse -Force $temporaryRoot
    }
}
