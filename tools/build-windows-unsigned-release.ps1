$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:GITHUB_ACTIONS -ne "true") {
    throw "The unsigned Windows release build is restricted to the isolated GitHub Actions runner."
}

$workspace = Split-Path -Parent $PSScriptRoot

function Assert-Unsigned([string] $Path) {
    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne "NotSigned") {
        throw "Expected an unsigned artifact at $Path, but Authenticode reported $($signature.Status)."
    }
}

Push-Location $workspace
try {
    node tools/prepare-desktop-sidecars.mjs release x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw "Failed to build the Windows sidecars." }

    $sidecars = Get-ChildItem "apps/desktop/src-tauri/binaries/*-x86_64-pc-windows-msvc.exe"
    if ($sidecars.Count -ne 2) { throw "Expected exactly two Windows sidecars." }
    foreach ($sidecar in $sidecars) { Assert-Unsigned $sidecar.FullName }

    pnpm --filter @rrmm/desktop tauri build --bundles nsis --no-sign --ci
    if ($LASTEXITCODE -ne 0) { throw "Tauri Windows release build failed." }

    $application = "target/release/rrmm-desktop.exe"
    $installer = Get-ChildItem "target/release/bundle/nsis/*.exe"
    if ($installer.Count -ne 1) { throw "Expected exactly one NSIS installer." }
    Assert-Unsigned $application
    Assert-Unsigned $installer[0].FullName
    Write-Output $installer[0].FullName
}
finally {
    Pop-Location
}
