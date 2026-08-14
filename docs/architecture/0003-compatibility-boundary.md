# ADR 0003: Compatibility And Merge Boundary

## Status

Accepted.

## Decision

Load priority is not compatibility. If two archives provide different payloads
for the same Unreal virtual package, one wins and the other effect is suppressed.

RR Mod Manager will not perform universal cooked Blueprint merges. It may apply
reviewed, signed, exact-hash compatibility recipes that select a winner, require
a filename, disable a component, or replace known standalone artifacts with a
known combined artifact.

Semantic generation is permitted only through separately reviewed build-specific
tools and recipes with exact ancestry, offline validation, and in-game tests.

## Consequences

- The UI uses `ordered with loss` instead of `compatible` when priority chooses
  one package.
- Unknown same-package modifications remain `patch required` or `unknown`.
- A user cannot override this safety statement with a generic merge button.
- Native DLL combinations remain unverified regardless of load order.
