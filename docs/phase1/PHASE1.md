# Phase 1 Execution Record

## Status

Implementation complete locally. Windows registry discovery is implemented and
covered by the Windows CI job, but that hosted job has not run because this
directory is not currently a Git repository. In-game verification is not
required for this read-only phase.

## Toolchain

- Rust `1.97.1` installed through official `rustup` with the minimal profile.
- `rustfmt` and `clippy` installed and pinned by `rust-toolchain.toml`.
- Cargo workspace uses edition 2024 and resolver 3.

## Production Workspace

- `rrmm-domain`: serialized installation, layout, build, hash, and discovery
  contracts.
- `rrmm-steam`: strict VDF parsing, Steam discovery, layout validation,
  critical-file fingerprints, writeability hint, and running-game detection.
- `rrmm-store`: versioned SQLite migrations, installation snapshots, and JSON
  settings.
- `rrmm-cli`: read-only `discover` and `inspect` commands plus database
  initialization.

The CLI embeds the supported-build recipe but accepts an explicit recipe for
diagnostics. Recipe paths and Steam `installdir` values are rejected if they can
escape their expected roots.

## Local Validation

- `cargo test --workspace`: 11 tests passed.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- Windows Steam code cross-check for `x86_64-pc-windows-gnu` with warnings denied:
  passed.
- Phase 0 TypeScript contracts remain available for parity checks in CI.
- Deep discovery against the local Steam installation found one complete,
  writable installation with the game stopped.
- App ID `3552140`, build `23896268`, state flags `4`, and both critical
  SHA-256 fingerprints matched the supported recipe exactly.
- SQLite schema version 1 was created and the discovery snapshot was persisted
  in a temporary database.

## Safety Boundary

Phase 1 reads Steam metadata and game files only. It does not create, rename,
or remove files under the Steam library. The writeability result is a metadata
hint; actual deployment preflight and transactional writes begin in later
phases.

## Remaining External Validation

- Execute the checked-in CI workflow on Windows and Linux once the project is
  hosted in a Git repository.
- Validate Windows registry views against a real Steam installation.
- Validate a real Flatpak Steam installation; its standard path is implemented
  but unavailable on this host.
