# RR Mod Manager 0.1.2

RR Mod Manager `0.1.2` is a reliability release for the complete workflow of installing UE4SS,
importing a mod, activating a profile and starting Retro Rewind.

## Fixed

- Fixed UE4SS installation failing on Windows after a valid verified download.
- Revalidated the UE4SS cache by regular-file type, exact size and SHA-256 before extraction.
- Fixed the Windows archive-worker protocol that made valid ZIP and 7z packages appear malformed
  or blocked.
- Copied selected archives into private staging before sandboxed inspection, including UNC and WSL
  selections, and verified the snapshot through review and import.
- Preserved complete preflight acceptance data between the Rust backend and desktop interface.
- Fixed a Windows stack overflow while hashing the Steam manifest before game launch.
- Improved Steam launch detection so the manager reports a timeout instead of closing silently.
- Restored the Retro Rewind logo in packaged desktop builds.
- Removed repetitive mod instructions and reduced the no-conflict result to a compact status.
- Kept stable error codes across operating-system languages and improved support reports when no mod
  is installed.

## Supported baseline

- Retro Rewind Steam build `23896268`
- Unreal Engine `5.4.4`
- UE4SS `3.0.1 Beta #0`, build `662df915`
- Windows 10/11
- Linux Steam/Proton (beta)

This release publishes a Windows installer and a Linux AppImage built from the same source.

## Windows trust notice

The `0.1.2` installer does not have an Authenticode publisher certificate, so Windows SmartScreen
may show “Unknown publisher”. The release includes SHA-256 checksums for every downloadable binary.

After downloading the installer and `SHA256SUMS`, compare its SHA-256 with the recorded value:

```powershell
Get-FileHash -Algorithm SHA256 "RR-Mod-Manager-0.1.2-Windows-x64-Setup.exe"
```

The generated `SHA256SUMS` file is the authoritative identity of the published artifacts. No
installer hash is handwritten in this document.
