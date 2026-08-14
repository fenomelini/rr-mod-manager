# RR Mod Manager 0.1.2 — Release Checklist

## Source and contracts

- [x] Cargo, Tauri and JavaScript packages report `0.1.2`.
- [x] The release workflow derives its version from an explicit validated input.
- [x] Windows-only, Linux-only and combined candidates have distinct artifact requirements.
- [x] Actions and the SBOM image are pinned by immutable digests.
- [x] The repository excludes generated binaries, caches, private state and Windows zone metadata.
- [x] Release binaries are explicitly verified as unsigned before attestation.

## Regression coverage

- [x] UE4SS cache finalization and hash validation have regression tests.
- [x] Accepted and rejected archive preflights serialize the complete desktop contract.
- [x] The Steam-manifest hasher runs on a Windows-sized 1 MiB stack in its regression test.
- [x] The Windows CI candidate runs the real archive and PAK workers through generated mod import,
  profile activation and deployment with sandboxing active.
- [x] The Windows CI candidate runs the real archive worker through the complete pinned UE4SS
  install and repair flow with sandboxing active.
- [x] Packaged web assets include the Retro Rewind logo.

## Publication gates

- [ ] The public-source PR passes every GitHub Actions job.
- [ ] The Windows CI candidate is downloaded and matches `SHA256SUMS`.
- [ ] `gh attestation verify --owner fenomelini` accepts the downloaded installer.
- [ ] That exact candidate installs on Windows 11 and completes UE4SS install/repair, Faster Returns
  import, profile activation, deployment and game launch.
- [ ] The public `v0.1.2` release contains only the validated Windows candidate plus checksums,
  manifest, SPDX SBOM, notices and release notes.

Do not mark a publication gate complete from a local build. Generated `SHA256SUMS` and
`release-manifest.json` are authoritative; do not copy a previous installer or handwritten hash.
