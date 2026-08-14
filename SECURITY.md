# Security Policy

## Status

RR Mod Manager is pre-release software. The Windows worker sandbox uses AppContainer
and Job Object boundaries. Archives from unknown sources must still be treated as
untrusted input.

The Linux worker requires Landlock ABI V4 and observable filesystem and network
denials. Windows workers require an AppContainer token, mandatory Job Object
limits, child-process mitigation, and successful broker verification. Parent
applications reject successful unsandboxed responses on every platform.

## Reporting

Do not include credentials, complete `nxm://` URLs, presigned URLs, personal
paths, game files, copyrighted assets, database files, or raw logs in a report.
Use the repository host's private vulnerability-reporting channel when the
public repository is available. Until that channel is published, security
reports must not be filed in a public issue; this is a release blocker rather
than permission to disclose secrets publicly.

Include only:

- The affected RR Mod Manager version and operating system.
- Reproduction steps using synthetic files where possible.
- The security impact and whether user interaction is required.
- A local problem report after reviewing its exact contents.

Maintainers should acknowledge a private report within seven days, provide a
triage result within fourteen days, and coordinate disclosure after a fix or
mitigation is available. These are response targets, not a bug-bounty promise.

## Scope

High-priority issues include:

- Archive or PAK worker sandbox escape.
- Path traversal, link following, or writes outside approved roots.
- Unconfirmed deletion or overwrite of unmanaged game files.
- Deployment journal, rollback, or receipt behavior that can lose user data.
- Credential or personal-path disclosure.
- Signature, catalog rollback-protection, updater, or protocol-handler bypass.
- WebView-to-native command access outside declared Tauri capabilities.

Unknown native DLLs and game/mod behavior are not automatically security defects
unless RR Mod Manager executes, misclassifies, or exposes them contrary to its
documented trust boundary.

## Release Requirements

Release files must be built from the tagged source, checked on their target platform,
and published with SHA-256 checksums. The unsigned Windows installer must be identified
as unsigned until an Authenticode certificate is available.
