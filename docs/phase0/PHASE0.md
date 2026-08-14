# Phase 0 Execution Record

## Status

Complete. Remaining assumptions are recorded in
`docs/phase0/remaining-assumptions.md` and become explicit Phase 1/3 gates.

## Decisions

- [x] Product stack selected: Tauri 2, Rust, React/TypeScript, SQLite.
- [x] TypeScript reference spikes approved because Rust is absent locally.
- [x] Local-first immutable storage and recoverable deployment selected.
- [x] Universal cooked Blueprint merging explicitly rejected.
- [x] Nexus catalog/search treated as separately approved functionality.

## Contracts

- [x] Manifest schema draft.
- [x] Compatibility-recipe schema draft.
- [x] Conflict taxonomy and resolution states.
- [x] Support matrix and terminology.
- [x] Threat model and fixture policy.

## Executable Spikes

- [x] VDF tokenizer/parser.
- [x] Steam AppManifest validator for App ID `3552140`.
- [x] Steam libraryfolders parser.
- [x] Strict Retro Rewind `nxm://` parser with secret-safe output.
- [x] PAK filename priority-hint parser.
- [x] PAK member normalization and cooked-package grouping.
- [x] Read-only `repak` inventory adapter.
- [x] Pairwise PAK overlap report generator.

## Verification

- [x] Install pinned JavaScript dependencies.
- [x] Type-check the Phase 0 spike.
- [x] Run all unit and contract tests.
- [x] Validate the CLI against synthetic Steam fixtures.
- [x] Validate secret redaction against a synthetic `nxm://` URL.
- [x] Validate Steam parsing against the current local installation.
- [x] Generate the current local PAK inventory report.
- [x] Review observed PAK priority and conflict counts.
- [x] Record remaining assumptions and Phase 1 entry requirements.

## Results

- TypeScript type-check: passed.
- Unit/contract tests: 12 passed across 4 files.
- Local Steam manifest: App ID `3552140`, build `23896268`, state flags `4`.
- Local PAK scan: 48 readable archives, 47 mod PAKs, 139,069 indexed
  mod members, 218 pairwise overlap edges, and no read failures.
- Disabled-looking directories: 21 PAKs still located beneath `Content/Paks`.
- Synthetic `nxm://` output did not expose its authorization key.

## Phase 1 Handoff

The Rust installation was approved and completed with pinned Rust `1.97.1`.
Production implementation moved to the Cargo workspace; Phase 0 TypeScript
remains as disposable parity references.
