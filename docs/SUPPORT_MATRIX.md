# Support Matrix

## Product Platforms

| Platform | Tier | Initial Commitment |
| --- | --- | --- |
| Windows 10/11 Steam | Tier 1 | Full local management and approved Nexus integration. |
| Linux Steam/Proton | Tier 2 | Local management beta; runtime UE4SS behavior is best-effort. |
| macOS | Tier 3 | Build architecture and offline tooling only. |

Tier describes the product commitment, not current alpha readiness. Windows
sidecar naming, an NSIS current-user configuration, and static GNU-target checks
are prepared. Archive and PAK workers now use an AppContainer broker, Job Object
limits, network denial, per-run ephemeral profiles, and temporary filesystem ACLs. The implementation still
requires runtime validation on clean Windows 10/11 systems before Tier 1 support
can be declared.

## Game Baseline

| Item | Supported Baseline |
| --- | --- |
| Steam App ID | `3552140` |
| Steam build | `23896268` |
| Unreal Engine | `5.4.4` |
| Container | PAK V11 |
| IoStore | Not present in the current installation; detect-only future work. |
| UE4SS | `3.0.1 Beta #0`, plus per-mod minimum commit/build rules. |

## Build States

- `SUPPORTED_EXACT`: build and critical fingerprints match.
- `SUPPORTED_MODIFIED`: known build with modified critical files.
- `KNOWN_UNSUPPORTED`: recognized but unsupported build.
- `UNKNOWN`: no validated build recipe.
- `PARTIAL`: installation is incomplete or updating.
- `WRONG_DIRECTORY`: required Steam/game layout is absent.
- `UNWRITABLE`: inspection works but deployment cannot proceed.
- `RUNNING`: read-only inspection allowed; PAK deployment blocked.

Unknown builds may be inventoried. They do not satisfy a mod's exact build
requirement and cannot receive generated compatibility packages.
