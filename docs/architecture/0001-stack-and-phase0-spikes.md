# ADR 0001: Product Stack And Phase 0 Spikes

## Status

Accepted and implemented in Phase 1.

## Decision

The production application will use Tauri 2, a Rust core, React/TypeScript UI,
and SQLite. Filesystem, archive, PAK, deployment, credential, and Nexus network
operations remain outside the WebView.

The development host initially had Node.js and pnpm but no Rust toolchain. Phase
0 parsers therefore live in `spikes/phase0/` as disposable TypeScript reference
implementations. Their fixtures, contracts, invariants, and tests are intended
to survive the later Rust port; the TypeScript implementations are not the
production security boundary.

Rust installation was explicitly approved for Phase 1. Rust `1.97.1` is pinned
with `rustup`, and the production contracts now live in the Cargo workspace.

## Consequences

- Phase 0 remains executable and testable now.
- Production architecture is not weakened to match one workstation.
- No TypeScript archive or deployment implementation may ship as the privileged
  production backend merely because it exists first.
- Port parity tests must run the same fixtures against TypeScript and Rust before
  deleting the spike.
