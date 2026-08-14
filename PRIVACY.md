# Privacy Policy

## Summary

RR Mod Manager is local-first and does not use behavioral telemetry. It does not
automatically send installed mod lists, game paths, profile names, archive
hashes, diagnostics, logs, or database content.

This policy describes the current pre-release implementation. Authentication,
automatic mod downloads and application updates are not enabled.

## Local Data

The application stores data under the operating system's local application-data
directory, including:

- SQLite state for installations, profiles, preferences, and verified caches.
- Immutable imported artifacts identified internally by SHA-256.
- Deployment receipts, journals, backups, and temporary staging.
- User-selected game and archive locations needed to perform requested work.

Profile and artifact deletion is user initiated. Deployment backups and recovery
evidence may remain while required to restore user files safely. A future data
retention or cleanup control must not remove evidence needed by an incomplete
transaction.

## Network Access

Current network access is user initiated:

- Downloading the single pinned UE4SS build from its fixed HTTPS host after
  validating host, size, and SHA-256.

Offline mode is persisted locally and blocks network cache misses before a
request is made. Verified cached artifacts remain usable offline.

Future authentication must store credentials only in the operating-system
credential store. Credentials, temporary `nxm` authorization, and presigned URLs
must never enter SQLite, logs, analytics, problem reports, or unrelated hosts.

## Problem Reports

Problem reports are user-initiated local ZIP exports. Their preview can include
an anonymized manager-state summary, the affected mod, the user's own description,
game and loader build information, a bounded redacted excerpt from the latest safe
`UE4SS.log`, and, with explicit consent, the active-mod list or a larger redacted
log. Complete log inclusion is disabled by default. Automatic redaction is not
infallible, so every generated file is shown for review before the user chooses a local save
destination. RR Mod Manager does not upload or transmit these reports.

## External Services

Opening a reviewed mod page transfers control to the user's browser and is
subject to Nexus Mods' privacy terms. RR Mod Manager does not scrape Nexus pages,
mirror its catalog, or send Nexus API keys to CDN or presigned storage hosts.

## Changes

Any addition of authentication, updates, crash reporting, analytics, or new
network hosts requires updating this policy and the in-app privacy disclosure
before release. Mandatory telemetry is not planned.
