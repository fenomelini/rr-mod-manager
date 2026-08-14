# Nexus Mods Access And Approval Plan

## 1. Current Feasibility

Status reviewed against the live v3.0.0 OpenAPI on August 8, 2026.

An approved Nexus-connected RR Mod Manager is viable for:

- Authenticating users through Nexus SSO.
- Receiving Nexus `nxm://` handoffs.
- Resolving known mods, files, versions, and supported dependencies.
- Downloading known files under the documented free/Premium rules.
- Checking updates for mods already managed by RR Mod Manager.
- Keeping Nexus identities attached to local install receipts.

A complete searchable in-app Retro Rewind catalog is not currently available
through the documented public APIs. Neither the live v3 OpenAPI nor the
officially linked legacy v1 API exposes a complete paginated game catalog and
text-search operation.

Obtaining approved catalog/search access is possible to request, but it is not
promised by the published application-registration process. It must be treated
as a separate partner-access request with a fallback product design.

## 2. Current Public API Boundary

### Confirmed Useful V3 Operations

Production base URL:

```text
https://api.nexusmods.com/v3
```

Relevant operations include:

- `GET /games/{game_domain}/trending-mods`: five public trending mods only.
- `GET /games/{game_domain}/mods/{game_scoped_id}`: minimal known-mod identity.
- `POST /mods/batch`: display details for already-known internal mod IDs.
- `GET /mods/{id}/files`: persistent file chains for a known mod.
- `GET /mod-files/{id}/versions`: versions in a known file chain.
- `GET /mod-file-versions/{id}`: one known version.
- Version dependency and materialized dependency operations.

Only the trending-mods, game-DLC, and Vortex-extension operations explicitly
override v3's global authentication requirement. The other read-only operations
above still require an API key or bearer token; read-only does not mean public.

Many mod/file/dependency operations remain marked Experimental and must be
validated defensively before each release.

The initial `rrmm-nexus` substrate implements only the anonymous Retro Rewind
trending feed and a strict `nxm://` parser. It fixes the production API origin and
game domain, sends no credentials, disables redirects and retries, bounds JSON,
validates exposed mod-page URLs, sends truthful application headers, and applies
a local cooldown after `429`. Temporary `nxm` authorization is zeroized and
redacted from `Debug`, summaries, and errors. No protocol handler, authenticated
operation, download, or live API test is enabled yet.

### Confirmed Legacy V1 Role

The currently linked legacy API provides known-mod metadata, known-mod file
lists, update feeds, user validation, endorsements, and download-link behavior.

Free-user download links require the temporary `key` and `expires` values from a
website-generated `nxm://` link. The manager must not bypass that website step.
Premium users can request direct links for known files under the documented
legacy flow.

### Missing Public Capabilities

The public schemas do not provide:

- Complete paginated mod enumeration for one game.
- General text search.
- Full site filters and sorts.
- Full image galleries.
- A supported central mirror/index workflow.
- Standard OAuth/OIDC authorization and token endpoints.

The website currently exposes a Retro Rewind catalog, but scraping the website
or private frontend services is prohibited without written exemption.

## 3. Official Registration Requirements

The Nexus API Acceptable Use Policy requires a public-facing application to be
registered after a functional testing build exists.

Official sequence:

1. Build a working test version that uses the developer's personal API key.
2. Contact `support@nexusmods.com` and include the testing build.
3. Implement any changes requested by Nexus.
4. Submit the final application name, short description, and logo.
5. Receive a staff-issued application slug for Nexus SSO.

Personal API keys are tolerated only for personal use and development/testing.
They are not an acceptable production authentication mechanism for public users.

Nexus strongly encourages open-source applications and may review how user data
and API data are handled. Providing source code may accelerate approval.

Every request must identify the application truthfully:

```text
Application-Name: RR Mod Manager
Application-Version: <current-version>
User-Agent: RRModManager/<version> (<os>; <arch>)
```

## 4. Production Authentication Design

Nexus's documented public SSO is a browser plus WebSocket API-key flow, not a
standard OAuth PKCE flow.

Expected production sequence:

1. Generate a cryptographically random request UUID.
2. Connect directly to `wss://sso.nexusmods.com`.
3. Send the UUID and protocol version `2`.
4. Receive and retain the reconnection token only for that attempt.
5. Open the system browser at:

```text
https://www.nexusmods.com/sso?id=<uuid>&application=<staff-issued-slug>
```

6. Receive the user API key through the matching WebSocket session.
7. Validate the key.
8. Store it only in the operating-system credential store.
9. Support local disconnect and link to Nexus server-side revocation.

The key must never enter SQLite, application logs, crash reports, analytics,
download URLs, or an RR Mod Manager server.

## 5. `nxm://` And Download Design

Expected flow:

1. User selects Mod Manager Download on Nexus.
2. Browser invokes RR Mod Manager through `nxm://`.
3. The manager validates the exact Retro Rewind domain and numeric IDs.
4. Temporary `key` and `expires` values are treated as secrets.
5. The manager resolves the known mod/file through approved API operations.
6. It requests a download link.
7. It downloads to temporary content-addressed storage.
8. It computes SHA-256 while streaming.
9. It passes the archive through the secure import pipeline.

Rules:

- Protocol registration is opt-in because `nxm` is global and may belong to
  Vortex or another manager.
- Preserve information that helps restore the previous protocol handler.
- Reject non-Retro-Rewind links instead of forwarding them to an arbitrary app.
- Never log a complete `nxm` URL.
- Do not send the Nexus API key to CDN or presigned download hosts.
- Do not bypass free-user website authorization.
- Treat `410` as expired authorization requiring a new Nexus website action.

## 6. Rate Limits And Caching

The Nexus help article updated June 3, 2026 states:

- 20,000 requests per 24-hour period.
- 500 requests per hour after the daily allowance is exhausted.
- Daily reset at 00:00 GMT.
- Hourly reset at the start of each hour.

Older legacy documentation contains lower figures. RR Mod Manager must trust
live rate-limit response headers and `429` responses instead of hardcoding a
single quota.

Required behavior:

- Cache only what is needed for managed mods and approved catalog behavior.
- Coalesce duplicate concurrent requests.
- Use manual refresh and avoid aggressive background polling.
- Read remaining quota and reset headers on every response.
- Stop nonessential requests when quota is low.
- Respect `429` and reset times.
- Avoid a central metadata mirror unless Nexus approves it explicitly.

## 7. Requirements Before Contacting Nexus

The registration request should not be sent with only mockups. Prepare:

- [ ] Functional Windows testing build.
- [ ] Personal-key developer authentication behind a testing-only flag.
- [ ] Known-mod metadata and file-resolution flow.
- [ ] Free-user `nxm` flow.
- [ ] Premium known-file flow if a Premium tester is available.
- [ ] Managed-mod update checking.
- [ ] OS keyring credential storage.
- [ ] Rate-limit and cache implementation.
- [ ] Request-count report for login, download, and update workflows.
- [ ] Public source repository under an OSI-compatible license.
- [ ] Privacy policy.
- [ ] Security policy and security contact.
- [ ] Threat model and data-flow diagram.
- [ ] Redacted problem-report demonstration.
- [ ] Windows installer tied to an exact source commit.
- [ ] Application name and short description.
- [ ] High-resolution logo legible on a dark background.
- [ ] Maintainer and support contact addresses.

## 8. Requesting Catalog And Search Access

### Viability

The request is reasonable because RR Mod Manager targets one small game and can
offer a bounded traffic model. Approval is still discretionary. The published
registration process grants an application slug; it does not promise a private
catalog endpoint.

The strongest proposal is not "let us scrape all Nexus data." It is:

> Provide an approved, paginated, game-scoped catalog/search workflow for a
> local desktop client, with bounded local caching, no central rehosting, and
> all downloads continuing through Nexus membership rules.

### What To Ask For

Request one of these, in preferred order:

1. Access to an existing supported paginated game catalog/search endpoint.
2. Partner access to a supported search service.
3. A Nexus-provided game-scoped feed/export with update cursor.
4. Written approval for a specific local per-user indexing strategy.

Required capabilities:

- Stable game domain and game-scoped mod ID.
- Cursor-based or paginated enumeration.
- Incremental updates or a changed-since cursor.
- Name, summary, status, thumbnail, category, adult flag, and update timestamp.
- Search and basic sorting, or permission to search a bounded local cache.
- Clear rules for local metadata and image cache retention.
- A supported age-verification/filtering signal or required handling rules.

### Traffic Proposal

The request should commit to:

- Retro Rewind only at launch.
- Direct client-to-Nexus traffic.
- No central user-key storage.
- No central metadata or image mirror.
- Bounded local cache with documented eviction.
- Conditional and incremental refresh where supported.
- User-visible quota handling.
- Downloads remaining on official Nexus/CDN flows.
- No scraping or undocumented private endpoint use.
- Adult content hidden unless Nexus confirms compliant eligibility handling.

### Evidence That Improves Approval Odds

- Working local manager with meaningful value independent of Nexus.
- Open-source code and reproducible request traces.
- Demonstrated request reduction through batching and caching.
- A one-game catalog rather than an all-Nexus crawler.
- Clear free-user and Premium compliance.
- Privacy and age-content controls.
- A conservative fallback that works without special access.

## 9. Proposed Submission Package

Send to `support@nexusmods.com`:

- Testing installer download.
- Source repository and exact commit.
- Application name: `RR Mod Manager`.
- Short product description.
- High-resolution logo.
- Privacy and security policy URLs.
- Maintainer and security contacts.
- API route inventory.
- Measured request budget.
- Cache behavior.
- Data-flow and credential-storage diagrams.
- Free and Premium workflow videos or reproducible steps.
- Explicit registration/SSO slug request.
- Separate catalog/search access proposal.

### Draft Email Structure

```text
Subject: RR Mod Manager application registration and game-scoped catalog request

Hello Nexus Mods Support,

We are developing RR Mod Manager, an open-source, local-first desktop mod
manager dedicated to Retro Rewind - Video Store Simulator.

The attached testing build currently uses a developer personal API key only in
testing mode. User credentials remain in the operating-system credential store;
we do not operate a credential or metadata proxy.

We would like to request:

1. Registration of RR Mod Manager as a public application.
2. An application slug for the documented Nexus SSO flow.
3. Confirmation of the approved v1/v3 operations for known-file download and
   managed-mod update checks.
4. Guidance or approval for a paginated, game-scoped catalog/search workflow
   for retrorewindvideostoresimulator.

The project does not scrape Nexus pages, does not rehost Nexus metadata or
images, and keeps free-user downloads dependent on website-generated nxm links.

Included are the test build, source commit, privacy/security policies, route
inventory, measured request counts, caching policy, data-flow diagram, product
description, and logo.

We are happy to make any changes required for compliance and rate efficiency.
```

## 10. Questions For Nexus

- Is there an approved paginated catalog/search operation for all mods in one game?
- If not, can a local client receive a game-scoped feed or approved local index?
- Which legacy v1 routes remain approved for new public managers?
- Is a v3 download-link operation planned?
- Is API-key SSO still the recommended public desktop authentication flow?
- What local metadata and image cache lifetimes are permitted?
- How should the client determine age-restricted-content eligibility?
- What is the supported mapping between v1 file IDs and v3 version IDs?
- How should legacy mod-level requirements be retrieved?
- Are background update checks acceptable after explicit local opt-in?
- Are there additional application-specific rate or header requirements?

## 11. Approval Gates

| Gate | Requirement |
| --- | --- |
| Development | Personal key used only by maintainers and selected testers. |
| Submission | Working build, source, policies, logo, and request inventory ready. |
| Production auth | Staff-issued application slug received. |
| Public downloads | Nexus confirms the route and membership flow. |
| Public updates | Managed-only update checks use approved operations. |
| Catalog | Explicit endpoint or indexing approval received in writing. |
| Release | Public build contains no personal-key onboarding. |
| Maintenance | Schema and policies reviewed before Nexus-related releases. |

## 12. Fallback If Special Access Is Denied

RR Mod Manager remains useful without a complete Nexus catalog:

- Open Nexus Retro Rewind pages in the system browser.
- Register `nxm://` only after standard application approval.
- Import browser-downloaded archives.
- Manage local profiles and conflicts fully offline.
- Check updates only for mods already known to the manager.
- Never ask public users to paste personal API keys.
- Never scrape Nexus or brute-force mod IDs.

## 13. Official Sources

- Nexus API documentation: <https://api-docs.nexusmods.com/>
- Live v3 OpenAPI: <https://api.nexusmods.com/openapi.yaml>
- Legacy v1 API: <https://app.swaggerhub.com/apis-docs/NexusMods/nexus-mods_public_api_params_in_form_data/1.0>
- API Acceptable Use Policy: <https://help.nexusmods.com/article/114-api-acceptable-use-policy>
- SSO integration demo: <https://github.com/Nexus-Mods/sso-integration-demo>
- Rate-limit guidance: <https://help.nexusmods.com/article/105-i-have-reached-a-daily-or-hourly-limit-api-requests-have-been-consumed-rate-limit-exceeded-what-does-this-mean>
- Terms of Service: <https://help.nexusmods.com/article/18-terms-of-service>
