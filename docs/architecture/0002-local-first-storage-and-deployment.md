# ADR 0002: Local-First Storage And Recoverable Deployment

## Status

Accepted.

## Decision

RR Mod Manager stores source artifacts and normalized packages outside the game
directory. Artifacts are immutable and content-addressed by SHA-256. A profile
activation is planned and staged completely before any game file changes.

The game directory contains only the active profile's deployed copies and an
ownership relationship recorded in SQLite. Deployment uses a journal, temporary
files, verification, and rollback. Unmanaged files are never silently adopted,
overwritten, or deleted.

## Consequences

- Profile switches are deterministic and recoverable.
- A manager database loss must not make game files unknowable; deployment
  receipts and support diagnostics need a recoverable external representation.
- PAK deployment is blocked while the game is running.
- PAKs that are disabled are moved outside `Content/Paks`, not into a child
  directory with a disabled-looking name.
