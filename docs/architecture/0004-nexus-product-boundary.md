# ADR 0004: Nexus Product Boundary

## Status

Accepted pending Nexus review.

## Decision

RR Mod Manager is useful without Nexus authentication. Public Nexus integration
will ship only after application registration and a staff-issued SSO slug.

Development may use a maintainer personal API key in a private testing build.
Public builds must not ask users for personal API keys. Complete in-app catalog
and search features remain disabled unless Nexus provides or approves a
supported game-scoped workflow.

No Nexus page scraping, private frontend API use, central key storage, metadata
mirror, or free-user download bypass is permitted.

## Consequences

- Nexus approval cannot block the local alpha.
- The fallback is browser discovery plus local archive import.
- `nxm://` registration is optional and must respect an existing global handler.
- All credentials stay in the OS keyring and all requests identify the real app.
