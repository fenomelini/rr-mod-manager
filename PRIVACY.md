# Privacy

RR Mod Manager is local-first and does not use behavioral telemetry. It does
not automatically send installed mod lists, game paths, profile names, file
hashes, diagnostics, logs, or database contents.

## Local Data

The application stores the information required to manage mods in the current
user's local application-data directory. This includes profiles, preferences,
imported mod files, verified caches, deployment records, backups, temporary
staging, and interrupted-operation recovery data.

Profile and mod deletion is initiated by the user. Recovery records and backups
may remain while they are needed to restore an incomplete operation safely.

## Network Access

Network access occurs only for actions started by the user, such as installing
the supported UE4SS build. Nexus Mods login, managed Nexus downloads, and
automatic application updates are not available in version `0.1.0`.

Offline mode blocks new network requests. Files that were already downloaded,
verified, and cached remain available locally.

## Problem Reports

Problem reports are local files created only after the user requests them. RR
Mod Manager shows a preview before saving and does not upload or transmit the
report.

A report may include an anonymized manager-state summary, the affected mod, the
user's description, game and loader versions, and a bounded redacted log
excerpt. Additional details require explicit selection. Automatic redaction is
not infallible, so review every included file before sharing the report.

## External Services

Opening a mod page transfers control to the user's web browser and is governed
by that website's privacy policy. RR Mod Manager does not scrape Nexus Mods or
send credentials to third-party download hosts.
