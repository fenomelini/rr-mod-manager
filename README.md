# RR Mod Manager

RR Mod Manager is a local-first desktop mod manager for **Retro Rewind - Video Store Simulator**
(Steam App ID `3552140`). It installs and verifies UE4SS, reviews downloaded ZIP/7z packages,
manages profiles, detects conflicts and deploys PAK, UE4SS and hybrid mods transactionally.

## Supported baseline

- Retro Rewind Steam build `23896268`
- Unreal Engine `5.4.4`
- UE4SS `3.0.1 Beta #0`, build `662df915`
- Windows 10/11 as Tier 1
- Linux Steam/Proton as beta

Download published builds from [GitHub Releases](https://github.com/fenomelini/rr-mod-manager/releases).
Release `0.1.2` provides a Windows installer only; Linux remains on its previous public build until a
new Linux artifact passes target-platform validation.

The Windows installer is currently unsigned and can trigger a SmartScreen “Unknown publisher”
warning. Each release includes SHA-256 checksums, an SPDX SBOM and GitHub artifact attestation. See
the matching release notes before installing.

## Safety model

RR Mod Manager:

- imports archives through private staging and sandboxed parser workers;
- rejects unsafe paths, executable installers and malformed worker responses;
- identifies immutable artifacts by SHA-256;
- previews profile changes before applying them;
- deploys with durable journals, backups, rollback and startup recovery;
- uses exact build and exact hash requirements for compatibility recipes;
- never claims that load order merges different cooked assets.

Unknown native DLLs are not considered safe, and compatibility is not claimed for an untested game
build.

## Development

Requirements: Node.js 24, pnpm `10.13.1` and Rust `1.97.1`.

```bash
pnpm install --frozen-lockfile
pnpm check
pnpm test
pnpm desktop:test
pnpm desktop:build:web
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
pnpm release:check
```

Windows-specific worker flows run on Windows:

```powershell
pnpm desktop:test:windows:ue4ss
pnpm desktop:test:windows:archive
```

The first test downloads and verifies the pinned UE4SS archive. The second generates a valid test
mod and exercises the real archive and PAK workers through import, activation and deployment.

## Documentation

- [Security policy](SECURITY.md)
- [Privacy policy](PRIVACY.md)
- [Beta testing and recovery](docs/BETA_TESTING.md)
- [Release policy](docs/RELEASING.md)
- [0.1.2 release notes](docs/RELEASE_0.1.2.md)
- [0.1.2 release checklist](docs/RELEASE_0.1.2_CHECKLIST.md)
- [Roadmap](ROADMAP.md)
