$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:GITHUB_ACTIONS -ne "true") {
    throw "The signed Windows release build is restricted to the isolated GitHub Actions runner."
}
if ([string]::IsNullOrWhiteSpace($env:WINDOWS_CERTIFICATE_BASE64)) {
    throw "WINDOWS_CERTIFICATE_BASE64 is required."
}
if ([string]::IsNullOrWhiteSpace($env:WINDOWS_CERTIFICATE_PASSWORD)) {
    throw "WINDOWS_CERTIFICATE_PASSWORD is required."
}

$workspace = Split-Path -Parent $PSScriptRoot
$temporaryRoot = $env:RUNNER_TEMP
if ([string]::IsNullOrWhiteSpace($temporaryRoot)) {
    throw "RUNNER_TEMP is required."
}
$pfxPath = Join-Path $temporaryRoot "rrmm-signing.pfx"
$configPath = Join-Path $temporaryRoot "rrmm-windows-signing.json"
$timestampUrl = "http://timestamp.digicert.com"
$thumbprint = $null

function Assert-Signed([string] $Path) {
    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne "Valid") {
        throw "Authenticode validation failed for $Path ($($signature.Status))."
    }
}

try {
    [IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($env:WINDOWS_CERTIFICATE_BASE64))
    $password = ConvertTo-SecureString $env:WINDOWS_CERTIFICATE_PASSWORD -AsPlainText -Force
    $certificate = Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\CurrentUser\My -Password $password |
        Where-Object HasPrivateKey |
        Select-Object -First 1
    if ($null -eq $certificate) {
        throw "The PFX contains no certificate with a private key."
    }
    $thumbprint = $certificate.Thumbprint
    if ([string]::IsNullOrWhiteSpace($thumbprint)) {
        throw "The code-signing certificate has no thumbprint."
    }

    $overlay = @{
        bundle = @{
            windows = @{
                certificateThumbprint = $thumbprint
                digestAlgorithm = "sha256"
                timestampUrl = $timestampUrl
                tsp = $true
            }
        }
    }
    $overlay | ConvertTo-Json -Depth 8 | Set-Content -Path $configPath -Encoding utf8

    Push-Location $workspace
    try {
        node tools/prepare-desktop-sidecars.mjs release x86_64-pc-windows-msvc
        $signTool = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source
        if ([string]::IsNullOrWhiteSpace($signTool)) {
            $signTool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" |
                Sort-Object FullName -Descending |
                Select-Object -First 1 -ExpandProperty FullName
        }
        if ([string]::IsNullOrWhiteSpace($signTool)) { throw "signtool.exe was not found." }
        $sidecars = Get-ChildItem "apps/desktop/src-tauri/binaries/*-x86_64-pc-windows-msvc.exe"
        if ($sidecars.Count -ne 2) {
            throw "Expected exactly two Windows sidecars."
        }
        foreach ($sidecar in $sidecars) {
            & $signTool sign /q /sha1 $thumbprint /fd SHA256 /tr $timestampUrl /td SHA256 $sidecar.FullName
            if ($LASTEXITCODE -ne 0) { throw "signtool failed for $($sidecar.FullName)." }
            Assert-Signed $sidecar.FullName
        }

        pnpm --filter @rrmm/desktop tauri build --bundles nsis --config $configPath --ci
        if ($LASTEXITCODE -ne 0) { throw "Tauri Windows release build failed." }

        $application = "target/release/rrmm-desktop.exe"
        $installer = Get-ChildItem "target/release/bundle/nsis/*.exe"
        if ($installer.Count -ne 1) { throw "Expected exactly one NSIS installer." }
        Assert-Signed $application
        Assert-Signed $installer[0].FullName
        Write-Output $installer[0].FullName
    }
    finally {
        Pop-Location
    }
}
finally {
    if (Test-Path $pfxPath) { Remove-Item -Force $pfxPath }
    if (Test-Path $configPath) { Remove-Item -Force $configPath }
    if ($thumbprint -and (Test-Path "Cert:\CurrentUser\My\$thumbprint")) {
        Remove-Item -Force "Cert:\CurrentUser\My\$thumbprint"
    }
    $env:WINDOWS_CERTIFICATE_BASE64 = $null
    $env:WINDOWS_CERTIFICATE_PASSWORD = $null
}
