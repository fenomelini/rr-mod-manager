param(
    [Parameter(Mandatory = $true)]
    [string]$InstallerPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$installer = (Resolve-Path -LiteralPath $InstallerPath).Path
$existing = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -eq "RR Mod Manager" } |
    Select-Object -First 1
if ($existing) {
    $existingLocation = $existing.InstallLocation.Trim('"')
    $uninstaller = Join-Path $existingLocation "uninstall.exe"
    if (-not (Test-Path -LiteralPath $uninstaller)) {
        throw "The existing installation cannot be removed safely."
    }
    $removal = Start-Process -FilePath $uninstaller -ArgumentList "/S" -PassThru -Wait
    if ($removal.ExitCode -ne 0) {
        throw "Uninstaller exited with code $($removal.ExitCode)."
    }
    for ($attempt = 0; $attempt -lt 50 -and (Test-Path -LiteralPath $existingLocation); $attempt++) {
        Start-Sleep -Milliseconds 200
    }
}

$installation = Start-Process -FilePath $installer -ArgumentList "/S" -PassThru -Wait
if ($installation.ExitCode -ne 0) {
    throw "Installer exited with code $($installation.ExitCode)."
}

$entry = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -eq "RR Mod Manager" } |
    Select-Object -First 1
if (-not $entry) {
    throw "The installed application registry entry was not found."
}

$location = $entry.InstallLocation.Trim('"')
if (-not $location) {
    $location = Split-Path -Parent $entry.DisplayIcon.Trim('"')
}
$application = Join-Path $location "rrmm-desktop.exe"
foreach ($worker in @("rrmm-archive-worker.exe", "rrmm-pak-worker.exe")) {
    if (-not (Test-Path -LiteralPath (Join-Path $location $worker))) {
        throw "Installed worker is missing: $worker"
    }
}
if (-not (Test-Path -LiteralPath $application)) {
    throw "The installed application executable was not found."
}

$process = Start-Process -FilePath $application -PassThru
Start-Sleep -Seconds 10
if ($process.HasExited) {
    throw "The installed application exited during launch with code $($process.ExitCode)."
}
Stop-Process -Id $process.Id

[PSCustomObject]@{
    Version = $entry.DisplayVersion
    InstallLocation = $location
    Workers = 2
    Launch = "ok"
} | ConvertTo-Json -Compress
