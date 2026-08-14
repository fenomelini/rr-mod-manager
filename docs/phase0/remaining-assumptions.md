# Phase 0 Remaining Assumptions

Phase 0 is complete as a read-only feasibility baseline. These assumptions must
be converted into evidence before the corresponding production features ship.

## PAK Priority

- Numeric `_N_P.pak` priority is implemented as an observed build rule.
- Lexical tie-breaking at equal numeric priority still needs a controlled
  generated-PAK runtime matrix on Windows and Linux/Proton.
- `repak list` member paths are treated as archive virtual members. Production
  code must also read and normalize the declared PAK mount point.
- PAKs beneath disabled-looking child directories are treated as potentially
  active. Runtime instrumentation must confirm recursive discovery behavior for
  the supported build before the UI says definitely active.

## Conflict Semantics

- Phase 0 reports path/package overlap, not payload differences.
- Member hashing, vanilla ancestry, partial sidecar compatibility, and semantic
  DataTable/localization inspection are deferred to Phase 3.
- An overlap edge cannot be downgraded to safe from names or priority alone.

## Steam Discovery

- The VDF parser supports the current local and synthetic formats.
- Windows registry discovery, Flatpak discovery, ACL handling, junctions, and
  update-in-progress states are Phase 1 work.
- Build ID alone is not a complete game fingerprint.

## Nexus

- The `nxm://` parser follows the documented game/mod/file shape and current
  free-user authorization fields.
- Production behavior requires Nexus application approval and contract tests
  against approved routes.
- Complete catalog/search remains unavailable without separate written access.

## Toolchain

- Production remains Rust/Tauri.
- Rust installation was approved and Rust `1.97.1` is pinned for production.
- Phase 0 fixtures and invariants remain available for Rust parity tests.
