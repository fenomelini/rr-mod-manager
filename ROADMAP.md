# RR Mod Manager Roadmap

## 1. Objective

Deliver a secure, local-first desktop manager that makes Retro Rewind mod state
deterministic and understandable. Version 1.0 must manage local profiles,
explain real PAK and UE4SS conflicts, recover failed deployments, and support an
approved Nexus download/update workflow.

The manager must distinguish these outcomes:

| Outcome | Meaning |
| --- | --- |
| Compatible | No relevant overlap was detected. |
| Benign duplicate | Overlapping content is byte-identical. |
| Ordered with loss | One mod wins; the losing effect is suppressed. |
| Declared dependency | One artifact intentionally builds on another. |
| Patch available | A reviewed combined artifact or recipe preserves both effects. |
| Patch required | Both effects need a compatibility patch that does not exist. |
| Incompatible | The requested combination is known to be unsafe. |
| Unknown | Available evidence cannot establish a safe result. |
| Native unverified | A DLL or native hook cannot be proven safe statically. |

## 2. Product Principles

- Keep source archives and normalized packages immutable.
- Never extract an archive directly into the game.
- Never overwrite or delete unmanaged files silently.
- Block PAK deployment while the game is running.
- Make every deployment recoverable through a journal and rollback.
- Treat exact hashes and build IDs as evidence; do not infer compatibility from
  filenames alone.
- Show the effective winner without calling an ordered conflict compatible.
- Keep Nexus credentials on the user's machine in the OS credential store.
- Require explicit, reviewable compatibility recipes for generated variants.
- Preserve author-required filenames where numeric PAK priority is meaningful.
- Support offline local management without a Nexus account.
- Collect no behavioral telemetry in 1.0.

## 3. Scope

### Included In 1.0

- Steam discovery and build validation.
- Windows primary support and Linux/Proton beta support.
- ZIP and 7z import.
- PAK V11 inventory and conflict detection.
- PAK, UE4SS, and hybrid package deployment.
- Managed profiles, backups, rollback, and drift detection.
- Declarative package manifests.
- Signed compatibility-recipe catalogs.
- UE4SS installation, module, hook, property, command, and keybind analysis.
- Nexus SSO and `nxm://` integration after approval.
- Managed-mod update checks.
- Diagnostics and redacted problem reports.

### Explicitly Excluded From 1.0

- Universal Blueprint or cooked-package merging.
- Automatic compatibility after an unknown game update.
- Complete in-app Nexus search without an approved endpoint.
- Nexus web scraping or private frontend API use.
- Arbitrary executable installers, FOMOD scripts, or archive-provided commands.
- Automatic installation of unknown native loaders or proxy DLLs.
- IoStore writing or conversion.
- Managing games other than Retro Rewind.

## 4. Technical Architecture

### Recommended Stack

| Layer | Technology | Purpose |
| --- | --- | --- |
| Desktop | Tauri 2 | Cross-platform shell with narrow system capabilities. |
| Core | Stable Rust | Filesystem transactions, parsing, conflict analysis, networking. |
| UI | React + TypeScript + Vite | Accessible desktop interface. |
| Database | SQLite | Profiles, receipts, journals, metadata, and caches. |
| Async/network | Tokio + reqwest + rustls | Nexus HTTP and application updates. |
| SSO | tokio-tungstenite | Nexus SSO WebSocket protocol. |
| PAK | Pinned `repak` library or audited fork | V11 inventory and payload access. |
| Archives | Rust ZIP and 7z libraries in a worker | Isolated, limited extraction. |
| Secrets | OS keyring abstraction | Credential Manager / Secret Service / Keychain. |
| Logging | `tracing` | Structured logs with mandatory redaction. |
| UI tests | Vitest + Testing Library + Playwright | Components and end-to-end flows. |
| Core tests | cargo test + proptest + cargo-fuzz | Logic, parsers, and security boundaries. |

All network and filesystem access stays in Rust. The WebView receives typed
domain objects through narrow Tauri commands and cannot request arbitrary paths
or URLs.

### Planned Repository Structure

```text
rr-mod-manager/
|-- README.md
|-- ROADMAP.md
|-- NEXUS_ACCESS.md
|-- SECURITY.md
|-- PRIVACY.md
|-- CONTRIBUTING.md
|-- Cargo.toml
|-- package.json
|-- apps/
|   |-- desktop/
|   `-- cli/
|-- crates/
|   |-- rrmm-domain/
|   |-- rrmm-store/
|   |-- rrmm-steam/
|   |-- rrmm-archive/
|   |-- rrmm-pak/
|   |-- rrmm-ue4ss/
|   |-- rrmm-manifest/
|   |-- rrmm-recipes/
|   |-- rrmm-conflicts/
|   |-- rrmm-deploy/
|   |-- rrmm-nexus/
|   `-- rrmm-diagnostics/
|-- workers/
|   `-- rrmm-extract/
|-- schemas/
|-- recipes/
|-- fixtures/
|-- docs/
`-- .github/workflows/
```

### Local Storage Model

```text
RRModManager/
|-- rrmm.sqlite3
|-- downloads/<sha256>/
|-- packages/<package-id>/<version>/
|-- profiles/<profile-id>/
|-- recipes/
|-- cache/
|-- journals/
|-- backups/
`-- logs/
```

Key entities:

- Source artifact: original archive identified by SHA-256.
- Package: immutable normalized installable content.
- Component: PAK, UE4SS module, configuration, or documentation unit.
- Profile: selected package versions, variants, and deployment policy.
- Deployment receipt: exact manager-owned paths and hashes.
- Unmanaged file: game-directory content without a manager ownership record.
- Recipe: signed compatibility knowledge for exact artifacts and builds.

## 5. Conflict Model

### PAK Conflicts

The scanner must normalize each archived member to its effective Unreal virtual
path using the PAK mount point. It must group package sidecars:

```text
Foo.uasset
Foo.uexp
Foo.ubulk
Foo.uptnl
```

Two PAKs changing different functions in `Foo` still conflict. Runtime load
order selects one physical package representation; it does not merge exports or
Blueprint functions.

The priority engine must account for:

- Base/project PAK order.
- `_P.pak` patch priority.
- Explicit suffixes such as `_2301_P.pak` and `_9999_P.pak`.
- Lexical order only when effective numeric priority is equal.
- Mount points and case-folded Windows virtual paths.
- Recursive PAK discovery beneath the game PAK directory.

A directory named `disabled` under `Content/Paks` must not be considered safe.
Disabled PAKs must be moved outside the engine search tree or have their
extension changed.

### UE4SS Conflicts

The analyzer should inventory:

- `mods.txt` and `enabled.txt` activation.
- Module start order from `UE4SS.log`.
- Literal `RegisterHook` targets and effective callback phase.
- `NotifyOnNewObject` registrations.
- Reflected property writes.
- Console commands.
- Key chords and modifiers.
- Lua dependencies.
- Native DLLs and proxy loaders.
- Cross-layer cases where a PAK replaces a Blueprint targeted by Lua.

Static analysis is advisory. A registered hook may still not intercept the
runtime path, and delayed registration may defeat nominal module order.

### Compatibility Recipes

Recipes may:

- Require or prohibit exact artifact hashes.
- Select a known variant.
- Require a fixed PAK filename and priority.
- Replace two standalone packages with a known combined package.
- Mark an exact collision as intentional, unresolved, or unsafe.
- Require a minimum game or UE4SS build.
- Disable a component known to crash a supported build.

Recipes may not:

- Run scripts or processes.
- Rewrite arbitrary cooked assets.
- Modify downloaded Lua code.
- Declare broad compatibility from names alone.
- Remain valid after a matched hash changes unless explicitly versioned.

## 6. Milestones

Estimated duration assumes one experienced full-time engineer. Nexus approval is
external and may extend the calendar without blocking a local-only release.

| Phase | Name | Estimate | Cumulative Target |
| --- | --- | ---: | ---: |
| 0 | Product contract and spikes | 2-3 weeks | Week 3 |
| 1 | Core state and Steam discovery | 3-4 weeks | Week 7 |
| 2 | Secure archive intake | 4-6 weeks | Week 13 |
| 3 | PAK scanner and conflict graph | 4-6 weeks | Week 19 |
| 4 | Profiles and recoverable deployment | 4-6 weeks | Week 25 |
| 5 | Manifests and compatibility recipes | 3-5 weeks | Week 30 |
| 6 | UE4SS analysis | 3-5 weeks | Week 35 |
| 7 | Complete local desktop alpha | 4-6 weeks | Week 41 |
| 8 | Nexus testing integration | 5-8 weeks | Week 49 |
| 9 | Nexus approval | External | External |
| 10 | Security hardening and beta | 4-6 weeks | Week 55 |
| 11 | 1.0 release | 2-4 weeks | Week 59 |

### Phase 0: Product Contract And Technical Spikes

Goal: remove architectural uncertainty before creating production code.

Deliverables:

- [x] Architecture decision records for stack, storage, IPC, and deployment.
- [x] Product support matrix and terminology.
- [x] Threat model and trust boundaries.
- [x] Manifest and compatibility-recipe drafts.
- [x] Synthetic fixture policy that does not commit game assets.
- [x] Steam VDF/AppManifest parser spike.
- [x] PAK V11 inventory spike.
- [x] Effective `_N_P` priority validation against controlled fixtures.
- [x] Strict `nxm://` parser spike.
- [x] Written acceptance of Nexus catalog limitations.

Verification:

- Parse representative Steam libraries and App ID `3552140` manifests.
- Inventory representative PAK-only, UE4SS-only, and hybrid mods.
- Reproduce known `_2301_P` versus `_9999_P` priority behavior.
- Produce a conflict report for the current local installation.

Exit criteria:

- No unresolved Windows architecture blocker.
- All unsupported assumptions are labeled as such.
- Security boundaries are agreed before archive parsing starts.

Major risks:

- Incorrect Unreal priority assumptions.
- Designing around conventions used only by our own mods.
- Treating Nexus approval as guaranteed.

### Phase 1: Core State, Steam Discovery, And Build Validation

Goal: reliably locate and classify the game without scanning arbitrary disks.

Deliverables:

- [x] Rust workspace, CLI skeleton, CI, formatting, linting, and tests.
- [x] SQLite migrations and domain model.
- [x] Windows Steam registry and library discovery.
- [x] Linux native and Flatpak Steam discovery.
- [x] User-selected fallback directory.
- [x] App ID and build ID validation.
- [x] Required-layout and critical-hash checks.
- [x] Game-running detector.
- [x] Quick validation and deep validation modes.

Validation states:

- Supported exact build.
- Supported build with modified critical files.
- Known unsupported build.
- Unknown build.
- Partial or updating installation.
- Wrong directory.
- Unwritable directory.
- Game currently running.

Tests:

- Golden and malformed VDF fixtures.
- Multiple Steam libraries and Unicode paths.
- Flatpak and Proton layouts.
- Missing manifests, stale manifests, and permission failures.
- Property tests for path normalization.

Exit criteria:

- Build `23896268` is recognized correctly.
- Wrong folders cannot be accepted accidentally.
- Unknown builds remain inspectable but cannot satisfy strict requirements.

### Phase 2: Secure Archive Intake And Package Normalization

Goal: safely inspect untrusted ZIP and 7z archives before installation.

Deliverables:

- [x] Content-addressed immutable download/import store.
- [x] Isolated extraction worker on Linux.
- [x] OS-level extraction-worker sandbox implementation on Windows.
- [x] ZIP and 7z support.
- [x] Archive safety preflight and quarantine.
- [x] Package-layout inference and manual review UI model.
- [x] Duplicate artifact detection.
- [x] DLL/EXE risk reporting.

The extraction worker is a separate, timeout-controlled process with a cleared
environment. On Linux, Landlock ABI V4 limits reads to the selected archive,
writes to the staging directory, and denies TCP access; resource limits bound
CPU, address space, file size, open files, and core dumps. Linux activation is
fail-closed and verifies an outside filesystem read and TCP connection are
denied before parsing. Windows now uses an AppContainer broker, Job Object limits,
child-process mitigation, network denial, and temporary filesystem grants.
Windows sidecar naming, an NSIS configuration, and a static GNU-target CI check
are prepared. Successful unsandboxed worker output is rejected on every platform;
clean-system Windows runtime validation remains open.

Mandatory protections:

- Reject absolute paths, traversal, device names, and alternate data streams.
- Reject symlinks, hardlinks, and reparse points in 1.0.
- Reject case-folding and Unicode-normalization collisions.
- Enforce limits for expanded bytes, entry count, depth, per-file size, and time.
- Reject encrypted and multipart archives initially.
- Never preserve executable permissions from archives.
- Never run archive-provided commands.

Tests:

- Zip Slip corpus.
- ZIP and 7z bombs.
- Duplicate and overlapping entries.
- Truncated archives and forged sizes.
- Disk-full and worker-termination recovery.
- Continuous parser fuzzing.

The deterministic hostile corpus now covers truncated ZIP/7z inputs, forged ZIP
sizes, ZIP/7z compression bombs, path collisions, and escape attempts. Storage
publication failure, a mid-copy file-size-limit failure, and worker termination
have cleanup tests. Local libFuzzer targets cover member-path validation and
archive preflight. Hermetic round trips cover common 7z codecs, while an
explicit preflight allowlist rejects unknown methods. Bounded CI sessions and a
Windows worker isolation remain open. On Linux hosts that permit unprivileged
user-namespace mounts, a 1 MiB `tmpfs` integration test forces real `ENOSPC` and
verifies staging and incoming-artifact cleanup.

Exit criteria:

- No malicious fixture writes outside its temporary root.
- Failed extraction leaves no accepted partial package.
- Existing workspace release archives normalize correctly.

### Phase 3: PAK Scanning, Priority, And Conflict Graph

Goal: explain exact package overlaps and effective winners.

Deliverables:

- [x] V11 PAK reader with integrity reporting.
- [x] Mount-point and virtual-path normalization.
- [x] Lazy member hashing.
- [x] Cooked-package sidecar grouping.
- [x] Base-game PAK index cache.
- [x] Conservative effective priority model.
- [x] Conflict graph and initial severity taxonomy.
- [x] Identical duplicate recognition.
- [x] Localization conflict detection.
- [x] Split-package and orphan-sidecar warnings.

The first Rust inventory slice uses Trumank `repak` 0.2.3 pinned by commit,
without Oodle loading. It reports readable V8B/V11 containers honestly, applies
the mount point before full Unicode case folding, rejects unsafe or colliding
virtual paths, groups cooked sidecars, and hashes requested members lazily. The
integrity report remains explicit that upstream does not verify every index
hash. Hostile parsing and member hashing run in a timeout-controlled worker that
shares the mandatory Linux Landlock and resource-limit policy with archive
intake. The initial graph recognizes hash-proven benign duplicates, ordered loss
when numeric patch generations differ, split sidecar sets, and unknown order for
equal generations. Lexical tie behavior and the complete effective-priority
model are deliberately still open.

Localization edges are tagged only from real overlaps involving `.locres`,
`.locmeta`, or paths under `Localization`/`L10N`; no semantic merge is inferred.
The PAK reader also validates bounded index ranges, strings, entry counts, and
compression-block counts before calling upstream. Instrumented PAK fuzzing found
and fixed an excessive-allocation regression, now preserved as a unit test.

SQLite schema 3 caches deterministic inventories by canonical path, exact game
build, file size, nanosecond modification time, and SHA-256 of the footer plus
primary/secondary index metadata. Cache lookup still recomputes the bounded
index digest in the sandbox, but never reads base-game payloads. Corrupt or stale
rows become misses and are replaced after a complete worker inventory.

Recursive discovery includes `.pak` case-insensitively at every depth, skips
filesystem links, and flags rather than suppresses files beneath directories
named `disabled`. Numeric patch generations produce an observed winner; equal
generations remain `unverified_lexical_tie` with no winner until controlled
runtime evidence establishes the engine's lexical behavior.

Tests:

- Generated valid and malformed PAK fixtures.
- Compression variants and traversal mount points.
- `_P`, `_2301_P`, and `_9999_P` priority cases.
- Case-only virtual path collisions.
- Known workspace overlap examples.
- Comparison against a pinned `repak` CLI.

Exit criteria:

- Every readable PAK produces a deterministic inventory.
- Known local conflicts and winners match controlled runtime behavior.
- Uncertain order is shown as uncertain rather than guessed.

### Phase 4: Managed Profiles, Deployment, And Recovery

Goal: activate complete mod profiles without losing user files.

Deliverables:

- [x] Profile create, clone, edit, select, and delete operations.
- [x] Immutable artifact-hash and variant selection state.
- [ ] Complete deployment planner and preview.
- [x] Unmanaged-file inventory.
- [x] Manager ownership receipts.
- [x] Content-addressed backups.
- [x] Deployment journal and startup recovery core.
- [x] Drift detection for manager-owned deployment paths.
- [x] Game launch action.

The deployment core accepts an explicit complete file set, and Phase 5 can now
materialize verified PAK and non-native UE4SS selections into that request. It
revalidates the live Steam build plus source and destination hashes, binds the
request to the active profile, blocks while the game process is present,
requires explicit unmanaged-file approval, stages all desired files, and writes
an external receipt. Activation and recovery tests use temporary game trees
only; the real installation has not been modified.
The standalone inventory reports managed matches, drift, missing ownership,
unmanaged files, cross-platform path collisions, links, and special entries;
hashing is limited to manager-owned files. Launch uses a validated Steam
executable and the fixed `-applaunch 3552140` argument pair.

The desktop now exposes profile creation, selection, configuration, and deletion.
Managed artifacts can be deleted only after they are disabled in every profile
and no matching deployed hashes remain in the ownership receipt. Disabled
profile references are removed transactionally with the artifact record, and
the content-addressed directory is quarantined before database mutation. The
planner checkbox remains open pending complete drift-resolution UX, package
attribution in previews, and the full injected-failure/platform matrix.
Rollback now preflights the receipt, every affected destination, and required
backups before mutation; tests cover multi-file drift, receipt drift, a game
starting during activation, and retry after a pre-journal interruption.

Deployment sequence:

1. Resolve requirements, variants, recipes, build support, and conflicts.
2. Materialize the complete next state under profile staging.
3. Block activation while the game is running.
4. Compare planned paths with managed and unmanaged files.
5. Ask before replacing unmanaged content.
6. Back up replaced content by hash.
7. Apply temporary files and atomic per-file renames.
8. Verify deployed hashes.
9. Commit the ownership record.
10. Roll back or resume an interrupted transaction at next startup.

Tests:

- Profile switching and repeated idempotent activation.
- Unmanaged-file coexistence.
- Read-only paths, antivirus locks, and disk full.
- Fault injection after every journal step.
- External drift and complete uninstall.

Exit criteria:

- Every injected failure reaches the intended state or restores the previous one.
- Unmanaged files are never deleted without explicit confirmation.
- Profile activation is deterministic and idempotent.

### Phase 5: Manifests And Signed Compatibility Recipes

Goal: represent author intent and known safe combinations declaratively.

Deliverables:

- [x] `rrmm-manifest.json` schema.
- [x] Locally inferred manifest format and confidence labels.
- [x] Requirement and variant solver core.
- [x] Recipe schema and exact-hash matching.
- [x] Offline root key and rotatable online signing key design.
- [x] Signed catalog verification and persisted rollback protection core.
- [x] Author documentation and validation CLI.
- [x] Verified PAK and UE4SS deployment-plan materialization.
- [x] Initial exact combined recipe for Unrewound Tape Fee and Employee Fee Policy.
- [x] Deterministic Smart Shelf Organizer development package with exact UE4SS policy.
- [x] Tested generation-1 offline-root and online-catalog bootstrap tooling.
- [x] Authenticated online-key rotation and emergency revocation tooling.
- [ ] Remaining workspace knowledge blocked on package records or Phase 6 policy.

The initial manifest core rejects unknown fields and unsafe paths, validates
exact build IDs, component hashes, variants, one-of requirements,
incompatibilities, and replacements. Inference only reads a fully revalidated
immutable artifact root and emits `reviewed: false`; the resolver cannot report
ready until inferred evidence is explicitly reviewed. Materialization revalidates
selected artifacts and embedded manifests, maps only PAK and UE4SS components,
and rejects component types without explicit destination semantics.

The local Smart Shelf Organizer development bundle embeds its exact declared
manifest and is bound to artifact SHA-256
`32be01dd47833f8f61d0bfbe7b831b428bf10f4677f2db62aa4aba2b319d036e`.
It remains explicitly non-public and does not bypass its incomplete in-game
verification or production catalog-signing gates.

Recipe application accepts only an in-memory verified catalog created from an
Ed25519-signed envelope. Offline-root metadata delegates time-bounded online
keys; SQLite schema 6 persists generation, sequence, and payload hashes so equal
versions cannot be substituted. Sequence is monotonic within a root generation;
a higher authenticated generation starts a recoverable catalog epoch. Public application reloads exact artifacts from
the immutable store, recomputes package resolution, and requires catalog
semantics to equal an embedded `rrmm-manifest.json`. Production root-key
generation and embedding remain release-key ceremonies, not repository test
fixtures. `select_winner` remains non-deployable until controlled tests prove a
load-order mechanism that enforces the selected winner. SQLite schema 6 binds
logical installation IDs to canonical Steam roots, and recipe plans carry
profile/build evidence that is revalidated immediately before apply.

Initial knowledge should cover:

- Combined Unrewound Tape Fee + Employee Fee Policy artifact.
- Better Hand Inventory Standard versus Plus exclusivity.
- Chronological New Releases dependencies and `_9999_P` filename.
- Faster Returns scanner override prohibition.
- Smart Shelf Organizer minimum UE4SS build.
- Localization resources that need explicit winner review.

Tests:

- Invalid schemas and unknown fields.
- Invalid, expired, and rolled-back signatures.
- Cyclic and one-of dependencies.
- Artifact hash changes invalidating recipes.

Exit criteria:

- Workspace mods can be represented without executable rules.
- Unsigned remote recipes cannot affect deployment.

### Phase 6: UE4SS Inventory And Advisory Analysis

Goal: manage UE4SS modules and expose compatibility risks honestly.

Deliverables:

- [x] UE4SS installation-layout detector.
- [x] Proxy candidate and native module inventory.
- [ ] Reliable installed UE4SS version and commit evidence.
- [x] `mods.txt` and `enabled.txt` selected-tree state model.
- [x] `UE4SS.log` mutable runtime evidence and start-attempt order.
- [x] Lua/config inventory.
- [x] Literal hook and notifier extraction.
- [x] Keybind and console-command extraction.
- [x] Reflected property-write candidate extraction.
- [x] Exact loader-pair policy and known unsafe-build rules.
- [x] Cross-layer PAK-to-hook package-association warnings.

Tests:

- Current workspace modules.
- Dynamic and malformed Lua.
- Duplicate keybind and hook targets.
- Partial UE4SS installations and multiple proxies.
- Minimum-version and commit requirements.

Exit criteria:

- PAK-only, UE4SS-only, and hybrid packages deploy correctly.
- Static findings are labeled declared, inferred, or runtime-verified.
- Unknown native code is never presented as safe.

The first read-only slice inventories stable flat and current development nested
UE4SS layouts, independent `enabled.txt` evidence, Lua/configuration candidates,
links, special entries, and native/executable files without reading or executing
their contents. Schema 2 separately reports canonical `dwmapi.dll`, core,
override, and obsolete `xinput1_3.dll` candidates without claiming binary
identity or activation. Metadata inventory reports `mods.txt` as present but
unparsed. Official sources expose no stable installed version/commit metadata
contract, so exact identity remains `unknown`; runtime load evidence remains
open.

The second slice adds bounded lexical advisory analysis for direct UE4SS API
calls. It distinguishes literal, symbolic, dynamic-unresolved, and missing first
arguments; ignores comments, string contents, and recognized mock declarations;
and never executes Lua. Current workspace hooks/notifiers are mostly dynamic at
their callsites, so their exact targets remain unresolved rather than guessed.
Script-content analysis uses component-relative no-follow descriptors on Unix
and component-relative Windows handles that reject every reparse-point component.
Windows runtime validation remains a public-beta gate.

Schema 2 adds separately typed property-write candidates for dot assignments,
literal/dynamic indexes, UE4SS parameter `:set(...)` calls, and
`SetStructurePropertyByName`. Generic Lua member writes remain candidates rather
than asserted reflected properties; receiver-provenance inference is still open.

The selected-tree state slice adds `ue4ss-state`, a bounded strict parser for the
official `Name : 0|1` grammar and independent `enabled.txt` existence evidence.
It preserves duplicate and case-sensitive directives, rejects permissive parser
accidents as non-canonical, and never treats `: 0` as overriding a marker.
Settings-selected roots, `ControllingModsTxt`, environment roots, `mods.json`,
and runtime starts are explicitly outside this report, so its states remain
declared evidence rather than effective activation. Safe content opening is
implemented on Unix and Windows without following links or reparse points.

The cross-layer slice adds the planned `rrmm-conflicts` crate and
`pak-ue4ss-correlate`. For build `23896268`, direct literal `/Game` hook and
notifier targets are mapped through the configured `RetroRewind/Content` mount
and compared with validated cooked-package keys from sandboxed PAK inventories.
Dynamic, native, malformed, unknown-mount, and unmatched targets remain typed
unresolved evidence. Matches are package associations only: build installation,
PAK activation/winner, export changes, source ownership, and runtime
compatibility are explicitly unverified.

The runtime-log slice adds `ue4ss-log` for bounded, no-follow inspection of flat
and nested `UE4SS.log` candidates. It separates nonstandard multiple sessions,
requires `Console created` plus a nearby valid banner, and reports observed
version/SHA, build configuration, executable metadata, event-loop marker, and
ordered module start/disable records. Freshness remains unassessed without an
external observation window, and mutable or module-spoofable log text never
becomes installed-version identity or proof that a module or hook worked.

The exact-loader slice adds `ue4ss-identity`, which hashes a single unambiguous
canonical proxy/core pair from bounded no-follow handles. Build recipe
`23896268` maps reviewed exact pairs to opaque build IDs and named policies; it
does not order Git SHAs or authorize from mutable logs. Recipe deployment
requires every selected UE4SS package to name a loader policy, records exact
identity evidence in preview, repeats it at apply, and fails closed for unknown,
unsafe, recognized-but-insufficient, redirected, ambiguous, or changed loaders.

### Phase 7: Complete Local Desktop Alpha

Goal: make all local capabilities usable without command-line knowledge.

Core screens:

- [x] Onboarding and Steam discovery.
- [x] Game/build status dashboard.
- [x] Mod library.
- [x] Archive safety and install review.
- [x] Profiles and activation preview.
- [x] Conflict explorer with effective winners.
- [x] UE4SS status and keybinds.
- [ ] Downloads/imports.
- [x] Diagnostics and redacted problem report.
- [x] Settings, storage, privacy, and offline mode.

Implementation status as of August 2026:

- Automatic Steam discovery, manual folder selection, persisted selection, and
  binding-safe validation are available. The dashboard distinguishes exact,
  modified, unfingerprinted, unsupported, unknown, partial, unwritable, and
  running installations and explains their activation impact.
- The local library manages imported artifacts, external PAKs, UE4SS modules,
  reviewed hybrid groups, bulk actions, profile state, and safe deletion.
- Archive preflight and immutable import expose a bounded entry inventory plus
  executable candidates. A separate post-extraction review now freezes inferred
  identity, real layout, native/executable evidence, file hashes, and provable
  destinations in private staging before publication. Source/staging drift,
  mismatched confirmation hashes, and missing executable acknowledgement are
  rejected. Active destination and PAK conflict evidence is frozen into the
  review hash and recomputed immediately before publication.
- Profile create/select/configure/delete/clone/rename and activation preview/apply
  exist. Changes retain exact package attribution, and drift can be restored only
  with hash-bound approval or resolved by disabling the exact owning package.
- Activation preview and the standalone conflict explorer preserve typed PAK
  outcome, winner, confidence, reason, domains, affected-member counts, and
  split-package evidence. The explorer identifies proven winners separately from
  blockers that cannot be resolved safely.
- UE4SS exact-pair diagnosis plus install/repair and on-demand static keybind
  analysis are available. The UI labels symbolic, literal, dynamic, missing,
  incomplete, and exact-duplicate evidence without executing Lua.
- Local import accepts and independently reviews batches of up to 50 ZIP/7z
  archives, then adds every accepted mod through the existing verified pipeline.
  The pinned UE4SS download also exists, but a persistent transfer queue,
  progress, interruption recovery, and import history remain open.
- Diagnostics and interrupted-deployment recovery include an allowlist-based,
  exact-preview support JSON export that omits paths, mod/profile names, archive
  identifiers, raw logs/database content, credentials, and URLs.
- The support center also creates local game/mod bug-report ZIPs with a guided
  description, incident timestamp, structured UE4SS session evidence, bounded
  redacted error excerpts, and an optional complete redacted log. Nothing is
  uploaded, every generated file is previewed, and complete-log collection is
  disabled by default.
- The settings view exposes storage locations and fixed privacy guarantees.
  Offline mode is persisted in SQLite and enforced before network access while
  still permitting already verified cached artifacts. Relocating the data root
  remains future work requiring a separately journaled migration.

UX requirements:

- Keyboard-only operation.
- Screen-reader labels.
- 200% zoom support.
- Narrow-window support.
- Clear destructive-action confirmation.
- Plain-language distinction between priority and compatibility.

Exit criteria:

- A new user can import a mod, understand blockers, activate a profile, switch
  profiles, and recover drift without editing game folders manually.

### Cross-Platform Local Public Beta Milestone

Decision as of August 2026: the first public beta targets local mod management on
Windows and Linux/Proton without waiting for Nexus application approval. Nexus
authentication, managed downloads, update checks, and automatic application
updates are post-beta integrations. Users download archives in their browser and
import them locally. The beta label must clearly state that defects may remain,
but it does not relax filesystem safety, rollback, privacy, or platform-isolation
requirements.

Included in the first public beta:

- Windows 10/11 Steam through a current-user NSIS installer.
- Linux Steam/Proton through an AppImage.
- Manual ZIP/7z import with review before publication to the immutable store.
- PAK, UE4SS, and hybrid mod management.
- Profiles, deterministic PAK order, conflict explanation, activation preview,
  drift handling, rollback, and interrupted-deployment recovery.
- UE4SS installation/repair, module diagnostics, keybind analysis, and local bug
  reports.
- Manual installation of new RR Mod Manager versions.

Explicitly deferred until after the first public beta:

- Nexus SSO, Premium downloads, free-user handoff, and managed-mod updates.
- Automatic application updates and updater metadata.
- In-app Nexus search or catalog browsing.
- Linux DEB packaging, macOS distribution, and IoStore management.

Public-beta blockers:

- [ ] Implement and validate OS-level archive/PAK worker isolation on Windows;
  successful unsandboxed worker responses must remain rejected.
  As an interim fail-closed measure, workers on unsupported platforms now reject
  valid requests before invoking archive or PAK parsers rather than parsing first
  and reporting `sandboxed: false` afterward.
- [x] Implement safe Windows handle-based access for hostile game-tree paths,
  including reparse-point defenses needed by UE4SS diagnostics and bug reports.
- [x] Complete post-extraction review of inferred package identity, layout,
  destinations, executable payloads, and real conflicts before import acceptance.
  Identity, layout, destinations, executable/native evidence, cancellation, and
  hash-bound publication, active destinations, and PAK conflict evidence are
  implemented and revalidated before acceptance.
- [ ] Integrate signed manifests/catalog/compatibility recipes into the desktop
  path, or explicitly disable and remove those promises from the beta UI/docs.
  The desktop integration, preview, apply-time revalidation, and release build
  gate are implemented. Production roots and a signed non-placeholder catalog
  still require the documented offline key ceremony before this item can close.
- [x] Complete per-package activation attribution and guided drift resolution.
- [ ] Run desktop typecheck, UI tests, web build, Rust tests, and packaging smoke
  checks in CI for the supported Linux and Windows surfaces.
  The shared CI now runs desktop typecheck, all React UI tests, the production web
  build, and packaging-configuration checks on Linux. Native Tauri/sidecar smoke
  builds and Windows sandbox tests remain open.
- [ ] Validate import, activation, removal, profile switching, order changes, and
  recovery with representative PAK, UE4SS, and hybrid mods on build `23896268`.
- [ ] Test rollback and interrupted-deployment recovery on clean Windows hardware
  or a clean Windows VM, in addition to Linux/Proton.
- [ ] Validate the Windows installer and runtime with Windows Defender and a clean
  current-user installation.
- [ ] Sign the Windows executable and NSIS installer. Unsigned Windows packages
  may be distributed only as private testing builds, not as the public beta.
- [ ] Publish versioned artifacts, SHA-256 checksums, an SBOM, license notices,
  dependency/secret-scan results, privacy/security policies, and a private
  vulnerability-reporting channel.
- [ ] Publish restore instructions, known limitations, supported platforms, and
  the exact supported game build before download.
- [ ] Confirm no unresolved critical/high security finding, data-loss defect, or
  unmanaged-file overwrite defect remains.

Exit criteria:

- A clean Windows user and a clean Linux/Proton user can import a manually
  downloaded archive, activate and switch profiles, diagnose blockers, remove the
  mod, and recover an interrupted deployment without editing the game directory.
- Windows no longer fails its core archive/PAK workflows solely because a safe
  worker sandbox is unavailable.
- The published limitations clearly state that Nexus integration and automatic
  updates are absent from the first beta.

### Phase 8: Nexus Development Integration

Goal: produce the functional testing build required for Nexus registration.

This phase does not block the cross-platform local public beta. It may proceed in
parallel, but none of its incomplete authentication or download surfaces may be
partially exposed in public builds.

Deliverables:

- [ ] Nexus API adapter with defensive schemas.
- [ ] Personal-key developer mode excluded from public builds.
- [ ] OS keyring storage.
- [ ] Nexus SSO proof of concept.
- [x] Strict `nxm://` protocol parser and optional handler registration.
- [ ] Free-user website handoff.
- [ ] Premium direct-download flow for known files.
- [ ] Download queue and interruption recovery.
- [ ] Managed-mod update checks.
- [ ] Rate-limit headers, `429`, and reset handling.
- [ ] Request metrics for the approval package.

The first credential-free adapter slice fixes the production v3 origin and Retro
Rewind domain, exposes only the anonymous trending feed through defensive models,
and sends truthful application headers without credentials. It bounds response
bodies, rejects redirects and unreviewed page URLs, honors numeric `Retry-After`
with a local no-retry cooldown, and is covered by loopback mock tests. The parser
keeps temporary `nxm` authorization private, zeroized, and redacted. OS handler
registration remains intentionally optional and is not enabled by this slice.

Tests:

- Mock server and contract fixtures.
- Free and Premium flows.
- Expired `key`/`expires` and HTTP `410`.
- Revoked credentials.
- API outages and Experimental schema changes.
- Secret redaction in logs and diagnostics.

Exit criteria:

- A private test build demonstrates intended API use with a personal key.
- Request counts and caching behavior are measurable.
- Public approval materials are complete.

### Phase 9: Nexus Registration And Approved Access

Goal: replace personal-key testing with an approved public integration.

This phase begins after a local-only beta is available or when Nexus is ready to
review a private testing build. External approval, an SSO slug, and route access
must not delay the local public beta.

Deliverables:

- [ ] Testing installer and source commit submitted to Nexus.
- [ ] Privacy policy, security policy, threat model, and data-flow diagram.
- [ ] Application name, description, and dark-background-compatible logo.
- [ ] API route inventory and request budget.
- [ ] Staff-issued SSO application slug.
- [ ] Written confirmation of approved v1/v3 route use.
- [ ] Separate decision on catalog/search access.
- [ ] Production SSO, disconnect, and revocation UX.

Exit criteria:

- Nexus registration and slug received in writing.
- Public builds do not ask users for personal API keys.
- Catalog features stay disabled unless explicitly approved.

Fallback if delayed or denied:

- Ship local management without Nexus authentication.
- Open Nexus pages in the browser.
- Import archives downloaded by the user.
- Never scrape Nexus or ask public users to paste personal keys.

### Phase 10: Security Hardening And Beta Stabilization

Goal: stabilize the cross-platform beta and prepare signed, recoverable 1.0
builds with no known critical risk.

Deliverables:

- [ ] Audit narrow Tauri capabilities and strict CSP for the final beta surface.
- [ ] Audit the HTTPS host allowlist for every enabled network surface.
- [ ] Audit secret and personal-path redaction, including game/mod bug reports.
- [ ] Signed Windows executable and NSIS installer.
- [ ] Linux AppImage public beta.
- [ ] SBOM and license inventory.
- [ ] Dependency audit and secret scanning.
- [x] Parser fuzzing in CI.
- [ ] Published SECURITY.md, PRIVACY.md, and private reporting channel.
- [ ] Protocol-handler ownership and restoration UX before public registration.
- [ ] Signed updater and rollback metadata before automatic updates are enabled.

DEB packaging is optional for the first beta and does not block the AppImage
release. Automatic updating is also absent from the first beta; updater safety
becomes a release gate only when that feature is introduced.

Current hardening already includes a default-deny Tauri CSP, narrow plugin
capabilities for the present UI, a Nexus page opener restriction, a pinned
HTTPS/host/hash policy for the UE4SS downloader, bounded redacted support exports,
and repeatable AppImage packaging through the checked-in container script. These
checkboxes remain open until the final beta surfaces are audited and published.
Windows isolation/signing, SBOM, notices, release checksums, scans, and beta
publication are not complete.
Bounded CI fuzz smoke jobs now exercise archive paths, archive preflight, PAK
inventory, and strict `nxm` parsing. Local `SECURITY.md` and `PRIVACY.md` drafts
document the implemented boundaries, but their checkbox remains open until a
public repository and private vulnerability-reporting channel exist.

Exit criteria:

- No open critical/high security findings.
- Clean Windows VM and Windows Defender tests pass.
- If automatic updates are introduced, failed updates do not damage profiles or
  game files.
- Public beta meets deployment-success and crash-free targets without mandatory
  telemetry.

### Phase 11: Version 1.0 And Maintenance

Release gates:

- [ ] Current Steam build validated in game.
- [ ] Representative PAK, UE4SS, and hybrid mods installed and removed.
- [ ] Profile rollback tested on physical Windows hardware.
- [ ] Nexus free and Premium flows tested if included; otherwise all Nexus
  authentication/download surfaces remain absent from the public build.
- [ ] No unresolved data-loss or unmanaged-overwrite defect.
- [ ] Signed artifacts, checksums, and SBOM published; updater metadata is also
  published if automatic updates are enabled.
- [ ] Database migrations tested from every supported prior version.
- [ ] Restore instructions and limitations visible before download.

Maintenance policy:

- Recheck the game build at application launch.
- Mark exact-build mods unverified after a game update.
- Publish build recipes only after static and in-game validation.
- Recheck Nexus OpenAPI and policies before Nexus-related releases.
- Run monthly dependency triage and quarterly parser/fuzz review.
- Maintain stable and beta channels.
- Keep the previous stable installer available for rollback.

## 7. Future IoStore Program

IoStore is out of scope for 1.0. If Retro Rewind adopts `.utoc`/`.ucas`:

1. Detect and preserve complete container sets as opaque components.
2. Add read-only inventory using a pinned and audited `retoc` integration.
3. Model conflicts by package ID and IoChunk ID.
4. Validate priority against the exact game build in runtime tests.
5. Add managed deployment only after read-only analysis is deterministic.
6. Do not add writing or automatic PAK conversion without a separate threat model.

## 8. Quality Strategy

| Test Layer | Coverage |
| --- | --- |
| Unit | VDF, manifests, requirements, priorities, paths, `nxm` URLs. |
| Property | Path normalization, graph determinism, dependency resolution. |
| Fuzz | Archives, PAK indexes, VDF, JSON, URL parsers. |
| Integration | Synthetic Steam trees, SQLite, package store, deployment. |
| Fault injection | Disk full, lock failure, crash at every journal boundary. |
| UI | Accessibility, profile switching, conflict decisions, recovery. |
| Network contract | Mock and recorded Nexus schemas and failures. |
| Platform | Windows primary and Linux beta. |
| In-game | Exact supported build and representative mod combinations. |

Extracted game assets must not be committed as test fixtures. Use generated
PAKs, synthetic Steam trees, and minimal legally distributable metadata.

## 9. Privacy And Network Policy

Version 1.0 should have no behavioral telemetry.

Allowed network activity:

- User-initiated Nexus authentication, metadata, downloads, and update checks.
- RR Mod Manager application-update checks.
- Signed compatibility-recipe update checks.

The manager must not send installed mod lists, game paths, archive hashes, or
diagnostics automatically. Problem reports must be redacted and previewed before
export. Nexus credentials must remain in the OS credential store.

## 10. Definition Of Done

RR Mod Manager 1.0 is complete when:

- Local mod state is deterministic and recoverable.
- The manager accurately reports effective PAK winners.
- It never claims that priority preserves a suppressed mod effect.
- Known compatibility recipes are exact-hash guarded and signed.
- UE4SS risks are clearly advisory rather than guaranteed.
- Nexus integration is approved or cleanly absent from the public build.
- Security, privacy, installer signing, updater signing, and support procedures
  are operational.
- The supported Retro Rewind build passes the full in-game smoke matrix.
