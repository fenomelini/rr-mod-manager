# RR Mod Manager 0.1.0 — Release Checklist

This checklist is the single approval record for the first public release. The
application version is exactly `0.1.0` in Cargo, Tauri, and both `package.json`
files. No prerelease suffix is permitted.

## Fixed Scope

- Retro Rewind Steam build `23896268` only.
- Windows 10/11 x64 through a current-user NSIS installer.
- Linux x64 Steam/Proton through an AppImage.
- Manual ZIP/7z import and local PAK, UE4SS, and hybrid mod management.
- Profiles, conflict review, PAK ordering, rollback, recovery, and local support
  bundles.
- No Nexus authentication, managed download, automatic mod update, or automatic
  application update.
- `Smart Shelf Organizer 0.1.0-dev` is an internal prototype and must not appear
  in the desktop catalog or release files.

## Automated Gates

All items must link to one successful `Release candidate 0.1.0` workflow run.

- [ ] `pnpm release:check` accepts reviewed production roots and signed recipe metadata.
- [ ] Rust tests, Clippy, formatting, TypeScript, UI tests, and web build pass.
- [ ] Windows and Linux packaging smoke builds pass in the normal CI workflow.
- [ ] RustSec, pnpm, and Gitleaks scans report no unresolved high/critical finding.
- [ ] The release workflow creates one signed NSIS installer and one AppImage.
- [ ] Authenticode verification passes for the Windows executable, both workers,
      and NSIS installer.
- [ ] `SHA256SUMS`, `release-manifest.json`, SPDX SBOM, and
      `THIRD_PARTY_NOTICES.md` are present and match the final files.

Workflow evidence: `________________________________________`

## Production Inputs

- [ ] Offline root and online signing keys were created according to
      `docs/phase5/KEY_CEREMONY.md`; no private material entered this workspace or CI.
- [ ] `trust/production-roots.json`, signed root metadata, and signed recipe
      catalog passed independent two-person review.
- [ ] The repository secrets `WINDOWS_CERTIFICATE_BASE64` and
      `WINDOWS_CERTIFICATE_PASSWORD` contain the approved code-signing certificate.
- [ ] A private vulnerability-reporting channel is available and linked from the
      public project page.

Reviewers and evidence: `________________________________________`

## Manual Platform Matrix

Use disposable profiles and record exact OS/build details. Never attach game
assets, raw logs, credentials, or personal paths.

| Scenario | Windows 10 | Windows 11 | Linux/Proton |
| --- | --- | --- | --- |
| Clean current-user installation and launch | [ ] | [ ] | [ ] |
| Steam discovery and exact build recognition | [ ] | [ ] | [ ] |
| ZIP and 7z import review | [ ] | [ ] | [ ] |
| PAK-only activation and removal | [ ] | [ ] | [ ] |
| UE4SS-only activation and removal | [ ] | [ ] | [ ] |
| Hybrid activation and removal | [ ] | [ ] | [ ] |
| Profile switch removes obsolete files | [ ] | [ ] | [ ] |
| PAK order change matches the in-game winner | [ ] | [ ] | [ ] |
| Reapplying an unchanged profile uses the fast path | [ ] | [ ] | [ ] |
| Managed drift is detected and restored | [ ] | [ ] | [ ] |
| Interrupted deployment recovers without data loss | [ ] | [ ] | [ ] |
| Unmanaged files remain byte-identical | [ ] | [ ] | [ ] |
| Problem-report preview contains no private data | [ ] | [ ] | [ ] |
| Windows Defender reports no unexpected detection | [ ] | [ ] | N/A |
| Uninstall and reinstall preserve recoverable state | [ ] | [ ] | [ ] |

Windows evidence: `________________________________________`

Linux evidence: `________________________________________`

## Final Decision

- [ ] No unresolved critical/high security issue exists.
- [ ] No known data-loss or unmanaged-file overwrite defect exists.
- [ ] Restore instructions, limitations, supported platforms, and supported game
      build are visible beside the download.
- [ ] Two maintainers compared the uploaded files with `SHA256SUMS`.
- [ ] The release is approved for public distribution as version `0.1.0`.

Approval: `____________________` Date: `____________`

Second approval: `_____________` Date: `____________`
