# Phase 0 Threat Model

## Protected Assets

- Retro Rewind installation and saves.
- User-downloaded mod archives.
- Managed profile state and rollback material.
- Nexus API keys, SSO tokens, and temporary `nxm` authorization.
- User privacy: paths, usernames, installed-mod lists, and diagnostics.
- Application and compatibility-recipe update trust.

## Trust Boundaries

| Input | Trust Level | Phase 0 Rule |
| --- | --- | --- |
| Steam VDF/ACF | Local but untrusted syntax | Parse with bounds; validate App ID and build ID. |
| Downloaded archive | Hostile | Never extract during Phase 0. |
| PAK index/member paths | Hostile | Read only; reject traversal and case collisions. |
| Manifest in archive | Untrusted declaration | Validate schema; scanner observations win. |
| Remote recipe | Untrusted until signed | No remote recipes in Phase 0. |
| `nxm://` URL | Secret-bearing and hostile | Strict game/path/query parsing; redact key. |
| Nexus response | Authenticated but changeable | No live integration in Phase 0. |
| UE4SS Lua | Untrusted code | Static observation only. |
| Native DLL | Unrestricted code | Mark unverified; never execute. |

## Primary Threats

- Archive traversal, bombs, symlinks, and device paths.
- PAK mount traversal and malformed indexes.
- Split cooked-package sidecars from incompatible sources.
- Wrong game build receiving build-specific bytecode.
- A failed deployment deleting or partially replacing user files.
- A fake compatibility recipe selecting malicious content.
- Nexus credential leakage through logs, URLs, diagnostics, or a server.
- Global `nxm` handler hijacking another mod manager.
- Unknown DLL execution.
- UI claims that encourage an unsafe combination.

## Phase 0 Mitigations

- Spikes are read-only and do not deploy files.
- VDF, `nxm`, and PAK member parsers have malformed-input tests.
- `safeNxmSummary` cannot include the authorization key.
- Current local PAK reporting uses relative paths.
- Contracts reject unknown fields and require exact build/hash identities.
- Product documentation explicitly excludes universal merging and scraping.

## Deferred Mitigations

- Isolated archive worker, quotas, and fuzzing: Phase 2.
- Deployment journal and rollback: Phase 4.
- Signed recipes: Phase 5.
- OS keyring and Nexus SSO: Phase 8.
- Signed installers, updater, SBOM, and external review: Phase 10.
