# Phase 6 UE4SS Inventory

## Scope

The first Phase 6 slice is a read-only inventory of the Retro Rewind UE4SS
loader candidates and module tree. It never loads DLLs, executes Lua, changes
`enabled.txt`, parses module configuration semantics, or writes beneath the
game root.

```bash
rrmm ue4ss-inventory --game-root path/to/RetroRewind-installation
rrmm ue4ss-identity --game-root path/to/RetroRewind-installation
rrmm ue4ss-state --game-root path/to/RetroRewind-installation
rrmm ue4ss-log --game-root path/to/RetroRewind-installation
rrmm ue4ss-analyze --game-root path/to/RetroRewind-installation
rrmm pak-ue4ss-correlate --pak path/to/mod.pak \
  --game-root path/to/RetroRewind-installation --build-id 23896268
```

The supplied game root is the Steam installation directory that contains the
inner `RetroRewind/` project directory. RRMM observes these fixed candidates:

```text
RetroRewind/Binaries/Win64/dwmapi.dll
RetroRewind/Binaries/Win64/override.txt
RetroRewind/Binaries/Win64/ue4ss/UE4SS.dll
RetroRewind/Binaries/Win64/ue4ss/UE4SS-settings.ini
RetroRewind/Binaries/Win64/ue4ss/Mods
RetroRewind/Binaries/Win64/UE4SS.dll
RetroRewind/Binaries/Win64/UE4SS-settings.ini
RetroRewind/Binaries/Win64/Mods
RetroRewind/Binaries/Win64/xinput1_3.dll
```

Child paths in the report are relative to the canonical game root. The command
does not require the game to be stopped because it performs no deployment.

## Installation States

- `absent`: no recognized current loader, support, or module-tree candidate was
  observed. This does not disprove manual or externally redirected injection.
- `partial`: some recognized evidence exists but no module tree was found.
- `module_tree_detected`: the selected flat or nested `Mods` path is a real
  directory. This proves only that a candidate module tree exists, not that a
  loader is active.
- `unsafe`: a required path is a link, special object, unreadable entry, or the
  wrong object type.

Schema 2 adds a loader status independent of the installation state:

- `nested_automatic_candidate`: regular `dwmapi.dll` and
  `ue4ss/UE4SS.dll` candidates exist.
- `flat_automatic_candidate`: regular `dwmapi.dll` and flat `UE4SS.dll`
  candidates exist.
- `override_target_unverified`: a regular proxy and `override.txt` coexist, so
  the filesystem fallback cannot establish the selected core.
- `core_present_without_canonical_proxy` and
  `canonical_proxy_without_core`: incomplete or manual/custom arrangements.
- `supporting_files_only`: only settings, module-tree, or override evidence was
  found.
- `ambiguous`: both flat and nested layout evidence exists.
- `unsafe`: a candidate is a link, special object, unreadable entry, or wrong
  object type.

Every DLL observation in `ue4ss-inventory` remains a filename candidate. That
metadata-only command does not load, hash, parse, or otherwise establish binary
identity. The separate `ue4ss-identity` command can establish an exact byte
identity for one unambiguous canonical proxy/core pair. The official 3.0 release
notes identify `xinput1_3.dll` as an
obsolete 2.x proxy that should be removed during a 3.x upgrade. RRMM therefore
reports a typed risk only when that filename is co-located with regular
canonical 3.x proxy and core candidates; the filename alone is not called
UE4SS.

Version evidence remains `unknown`. UE4SS has no documented stable installed
metadata or PE `VERSIONINFO` contract that proves a version or commit. A runtime
`UE4SS.log` is mutable and potentially stale, `UE4SS-settings.ini` describes
configuration rather than loader identity, and filenames are not accepted as
version evidence.

## Exact Loader Policy

`ue4ss-identity` accepts only a canonical `dwmapi.dll` plus exactly one flat or
nested `UE4SS.dll`. It refuses redirected, ambiguous, incomplete, linked,
special, oversized, or obsolete-`xinput1_3.dll` arrangements. On Unix, every
component is opened relative to no-follow directory descriptors and SHA-256 is
streamed from the already opened regular-file handle. The default bound is 256
MiB per binary. Platforms without the safe content-opening implementation return
`unsupported` rather than reopening a pathname optimistically.

An exact pair is bytes evidence, not self-described version or provenance.
Build recipe `23896268` separately catalogs reviewed pairs and named policies.
The initial catalog recognizes official stable v3.0.1, experimental commit
`0196ef294f8525d6a492ae0b41b0c18ad5ccd84b`, and experimental commit
`662df91503379fc383bc745f7ade795d7b2ca215`. The Smart Shelf policy allows only
the exact `662df915` pair and marks the exact `0196ef29` pair unsafe. Stable is a
recognized but unsatisfied build for that policy. Unrecognized bytes, unknown
policies, unsafe paths, and absent identities are blocked.

Git object IDs are never ordered lexically. “`662df915` or newer” is represented
only by an explicit reviewed set of exact descendants in the named policy;
currently that set contains `662df915` itself. Adding another accepted build
requires cataloging its exact proxy/core pair and policy membership.

Package manifests may declare:

```json
{
  "runtime_requirements": {
    "ue4ss_loader_policy": "ue4ss:smart-shelf-662df915-compatible"
  }
}
```

When a recipe deployment selects a UE4SS component, absence of this requirement
blocks materialization. Preview inspects the live pair, requires every selected
policy to return `allowed_exact`, and records the identity and evaluations. Apply
repeats resolution and inspection and rejects any difference from the reviewed
preview. PAK-only selections do not require a loader identity. `UE4SS.log` is
not an input to this evaluator.

Official release artifacts used for the exact catalog:

- `UE4SS_v3.0.1.zip`, ZIP SHA-256 `4b47d4bceddd2f561a4e395bfa00924ccfc945af576a2d0c613e6537846c57ec`.
- `UE4SS_v3.0.1-944-g0196ef29.zip`, ZIP SHA-256 `b7be182458695a95d5d862d0a5f279e23fa5ef5b93566648e181191958ea45bd`.
- `UE4SS_v3.0.1-1018-g662df915.zip`, ZIP SHA-256 `590ae4c6463db61497123b9ed35373596c39fb27f736e2078a02b476599671ba`.

Official evidence used for this policy:

- [stable v3.0.1 installation guide](https://github.com/UE4SS-RE/RE-UE4SS/blob/v3.0.1/docs/installation-guide.md)
- [v3.0.0 release notes](https://github.com/UE4SS-RE/RE-UE4SS/releases/tag/v3.0.0)
- [v3.0.1 release notes](https://github.com/UE4SS-RE/RE-UE4SS/releases/tag/v3.0.1)
- [current development installation guide](https://github.com/UE4SS-RE/RE-UE4SS/blob/662df91503379fc383bc745f7ade795d7b2ca215/docs/installation-guide.md)
- [current proxy selection implementation](https://github.com/UE4SS-RE/RE-UE4SS/blob/662df91503379fc383bc745f7ade795d7b2ca215/UE4SS/proxy_generator/main.cpp)
- [current release layout implementation](https://github.com/UE4SS-RE/RE-UE4SS/blob/662df91503379fc383bc745f7ade795d7b2ca215/tools/buildscripts/release.py)

The stable flat layout and current development nested layout are both
inventoried. Core evidence selects the diagnostic module tree; when no core is
observed, a single available `Mods` tree is selected. Multiple substantive
layouts remain ambiguous because command-line and `override.txt` redirection
cannot be established from metadata. An empty stale `ue4ss` directory does not
hide a complete flat layout. The flat `Win64` directory is never recursively
scanned because it also contains game binaries; only its fixed candidates and
selected `Mods` tree are inventoried.

## Module Evidence

Every real direct child directory of the selected nested `ue4ss/Mods` or flat
`Win64/Mods` tree is inventoried. Files are classified as Lua, configuration
candidates, state markers, native-unverified, executable-unverified, other,
links, or special objects. Configuration classification is based only on names
and extensions; it does not imply that a file came from the package rather than
being mutable runtime state.

Module kinds are structural:

- `lua`: at least one Lua file and no native/executable file.
- `native`: native/executable files and no Lua file.
- `hybrid`: both categories are present.
- `unknown`: neither category is present.
- `indeterminate`: a bound or filesystem problem prevented a complete module
  scan, so unseen files could change the structural classification.

`Scripts/main.lua` and root-level `enabled.txt` are reported independently.
`enabled_marker_present` means only that a regular marker file was observed. It
does not prove that UE4SS loaded the module or that module-internal configuration
enabled its behavior. Native and executable files are always unverified.

## `mods.txt`

The selected nested `ue4ss/Mods/mods.txt` or flat `Win64/Mods/mods.txt` path is
observed without reading its contents by `ue4ss-inventory`, where a regular file
remains `present_unparsed`. Content parsing is isolated in `ue4ss-state` so the
metadata-only inventory contract does not change.

Official UE4SS documentation defines one directive per line:

```text
ExampleMod : 1
OtherMod : 0
```

`1` selects a module and `0` does not. A full-line `;` comment is accepted.
RRMM parses only this canonical form as bounded UTF-8 with an optional BOM. It
rejects tabs, inline comments, multiple colons, embedded spaces in names, and
values other than exactly `0` or `1`. Those inputs may trigger permissive,
version-specific implementation behavior in UE4SS, so RRMM reports them as
non-canonical rather than emulating accidents such as accepting `10` as true.

Names match observed module directories case-sensitively. Unknown and case-only
matches are retained as diagnostics. Duplicate directives are retained in line
order and warned because repeated-start behavior differs by UE4SS revision; RRMM
does not apply a last-value-wins rule. Any canonical `: 1` is positive selection
evidence. A negative conclusion from `: 0` requires the complete file to have
parsed successfully.

UE4SS processes `enabled.txt` independently after `mods.txt`. Existence enables
the module even when `mods.txt` contains `: 0`; file contents are irrelevant and
are never read. RRMM reports these selected-tree states:

- `enabled_by_marker`
- `enabled_by_mods_txt`
- `enabled_by_both`
- `disabled_by_mods_txt`
- `unlisted`
- `indeterminate`

A directory named `enabled.txt` is positive existence evidence but receives a
non-canonical warning. Links, unreadable entries, and incomplete observations
remain indeterminate and are never followed.

The state report is deliberately scoped to the selected inventoried tree. It is
not effective runtime evidence: `UE4SS-settings.ini`, `ControllingModsTxt`,
additional module roots, `UE4SS_MODS_PATHS`, command-line redirection, and actual
module starts are not evaluated. `mods.json` is current release-packager metadata
and is not read by the examined UE4SS runtime, so RRMM does not merge it into
activation state.

Official evidence used for the state policy:

- [stable Lua mod guide](https://docs.ue4ss.com/release/guides/creating-a-lua-mod.html)
- [stable C++ mod installation guide](https://github.com/UE4SS-RE/RE-UE4SS/blob/v3.0.1/docs/guides/installing-a-c%2B%2B-mod.md)
- [stable activation implementation](https://github.com/UE4SS-RE/RE-UE4SS/blob/v3.0.1/UE4SS/src/UE4SSProgram.cpp)
- [current activation implementation](https://github.com/UE4SS-RE/RE-UE4SS/blob/662df91503379fc383bc745f7ade795d7b2ca215/UE4SS/src/UE4SSProgram.cpp)
- [official canonical `mods.txt`](https://github.com/UE4SS-RE/RE-UE4SS/blob/v3.0.1/assets/Mods/mods.txt)
- [current `mods.json` packager use](https://github.com/UE4SS-RE/RE-UE4SS/blob/662df91503379fc383bc745f7ade795d7b2ca215/tools/buildscripts/release.py)

## Filesystem Safety

- Metadata-visible filesystem links are reported and never intentionally
  traversed as module descendants.
- Special entries are not opened.
- Cross-platform path validation rejects traversal, Windows-invalid names, and
  reserved device names.
- Case-folded and Unicode-normalized collisions make the report incomplete.
- Scanning is bounded to 20,000 entries and depth 32 by default.
- A directory that exceeds the remaining entry budget contributes no arbitrary
  partial subset; the report is marked incomplete.
- Invalid-Unicode entries are not used as module identities.
- Lua, configuration, `mods.txt`, loader override, and native contents are not
  read by inventory.

Metadata-visible unsafe required paths are returned in the report. A failure to
enumerate a directory after metadata inspection marks the report incomplete;
only an invalid or inaccessible game root is a fatal command error.

The inventory is a non-atomic filesystem snapshot. A concurrently modified tree
can change between metadata operations. The current slice minimizes exposure by
not reading executable or script contents, but stronger platform-specific
no-follow handles remain part of Windows hardening.

On Linux, directory enumeration is rooted in no-follow descriptors and uses the
fixed `/proc/self/fd` handle rather than reopening queued directories by path.
Other platforms retain best-effort metadata-only inventory, but pathname reopen
and concurrent reparse-point replacement are not hardened yet; reports do not
claim race-free containment there. `mods.txt` and script-content analysis remain
disabled until equivalent component-relative reparse-point protection exists.

`ue4ss-state` defaults to 1 MiB for `mods.txt`, 16 KiB per line, 20,000 lines,
and 10,000 directives. Component-relative `O_NOFOLLOW|O_NONBLOCK` opening is used
on Unix. A byte, line, or directive limit retains no arbitrary directive prefix;
the report becomes incomplete and marker-absent negative states become
`indeterminate`.

## Runtime Log Evidence

`ue4ss-log` separately inspects both canonical candidates:

```text
RetroRewind/Binaries/Win64/ue4ss/UE4SS.log
RetroRewind/Binaries/Win64/UE4SS.log
```

Neither location is assumed active. If both exist, including an unsafe alternate
path, the report is explicitly ambiguous. Logs are opened component-relative
with `O_NOFOLLOW|O_NONBLOCK` on Unix and fail closed elsewhere.

A session candidate requires a canonical file timestamp, exact `Console created`
record, and a valid UE4SS banner within 8 KiB. Supported banner evidence includes
the three-component version, optional prerelease/beta labels, and Git SHA token:

```text
[2024-02-20 17:42:02] Console created
[2024-02-20 17:42:02] UE4SS - v3.0.1 Beta #0 - Git SHA #d935b5b
[2024-02-20 17:42:02] UE4SS Build Configuration: Game__Shipping__Win64 (MSVC)
```

The parser also observes timezone, reported game executable path/size,
`Event loop start`, and these exact module-management formats:

- typed Lua/C++ start attempts;
- modules observed disabled in `mods.txt`;
- untyped `enabled.txt` start attempts;
- current runtime-management start attempts and returned start calls.

Physical record order is preserved per session. C++ and Lua attempts remain
typed where the log says so, but this is not callback or hook-registration order.
`Starting ...` occurs before `start_mod()` and is never called successful loading;
even `Mod 'name' started` proves only that a current start call returned. Module
code can emit spoofed loader-like text, so all recognized records are
unauthenticated format matches.

Normal UE4SS logging overwrites the file, so multiple valid session headers are
nonstandard and remain separate. Any later `Console created`, even with an
invalid timestamp or missing banner, ends historical event collection. When the
newest header is invalid, no older session is selected.

The report includes file size, mtime, read time, and age at read, but freshness
is `unassessed` without an externally observed process-start window. Runtime
version/SHA evidence does not change inventory `version_evidence`: the log can be
stale, copied, spoofed, or left by a binary since replaced. It does not establish
Steam build, PID, current process identity, active PAKs, current marker state, or
functional hooks.

Default limits are 32 MiB, 64 KiB per physical line, 500,000 lines, 16 sessions,
10,000 module events, 512 characters per captured field, and an 8 KiB
banner-distance window. Limit failures retain no arbitrary session prefix.
Output includes canonical game/executable paths, timezone, and module names and
must be redacted before sharing.

Official evidence used for this parser:

- [stable v3.0.1 startup and mod records](https://github.com/UE4SS-RE/RE-UE4SS/blob/v3.0.1/UE4SS/src/UE4SSProgram.cpp)
- [current startup and mod records](https://github.com/UE4SS-RE/RE-UE4SS/blob/662df91503379fc383bc745f7ade795d7b2ca215/UE4SS/src/UE4SSProgram.cpp)
- [stable file timestamp formatter](https://github.com/UE4SS-RE/RE-UE4SS/blob/v3.0.1/deps/first/DynamicOutput/src/OutputDevice.cpp)
- [current timestamp/timezone implementation](https://github.com/UE4SS-RE/RE-UE4SS/blob/662df91503379fc383bc745f7ade795d7b2ca215/deps/first/Helpers/src/Time.cpp)

## Lua Advisory Analysis

`ue4ss-analyze` is separate from metadata-only inventory. On supported Unix
hosts it opens every path component relative to no-follow directory descriptors,
opens the final script with `O_NOFOLLOW|O_NONBLOCK`, reads bounded UTF-8 text,
and never executes it. On unsupported platforms each script is reported
incomplete without reading content.

The lexer ignores short and long strings, line and long comments, and API mock
declarations. It validates complete call parentheses and extracts only direct
calls to:

- `RegisterHook`
- `NotifyOnNewObject`
- `RegisterConsoleCommandHandler`
- `RegisterKeyBind`
- `RegisterLoadMapPreHook` and `RegisterLoadMapPostHook`
- `require`

First arguments are classified as `literal`, `symbolic`, `dynamic_unresolved`,
or `missing`. No constant propagation, wrapper expansion, table-flow analysis,
or callback execution occurs. In particular, current workspace hook and
notifier registrations mostly remain `dynamic_unresolved`; console commands and
dependencies commonly produce direct literals. Static evidence is advisory and
never `runtime_verified`.

Schema 2 adds a separate `property_writes` list. These entries are candidates,
not proof of Unreal reflection:

- `dot_member_candidate` for assignments such as `object.Property = value`.
- `literal_index_candidate` for `object["Property Name"] = value`.
- `dynamic_index_candidate` for unresolved or symbolic bracket keys.
- `parameter_set_candidate` for UE4SS-style `parameter:set(value)` calls.
- `reflection_helper_candidate` for direct
  `SetStructurePropertyByName(target, property, value)` calls.

The report preserves the candidate receiver and property evidence independently.
Ordinary Lua table writes such as `stats.failures = ...` intentionally remain
candidates and are never promoted to reflected writes without additional
evidence. Multi-target assignments are parsed once, malformed or crossed
delimiters suppress property extraction, and function declarations are not
reported as writes.

Default analysis limits are 1,024 scripts, 2 MiB per script, 16 MiB total, and
10,000 findings. Tokenization and argument extraction use bounded work. If a
finding or parser-work budget is exceeded, RRMM retains no arbitrary partial
subset from the failed boundary and marks the report incomplete.

## Cross-Layer PAK Associations

`pak-ue4ss-correlate` inventories one or more PAKs through the sandboxed worker,
runs Lua and selected-tree activation analysis, then passes typed reports to the
pure `rrmm-conflicts` correlator. The host revalidates worker output without
reading PAK payloads: requested path and observed size, filename-derived
priority, structural digest shape, member normalization and ordering, cooked
sidecars, and reconstructed package groups must all agree.

The first policy is restricted to build `23896268` and maps the configured
logical mount `/Game` to `RetroRewind/Content`. A common literal target such as:

```text
/Game/VideoStore/core/Market.Market_C:Update
```

produces logical package `/Game/VideoStore/core/Market`, which maps to package
key `retrorewind/content/videostore/core/market`. Only exact equality with a
`PakInventory.packages` key creates a match. The optional exact `Function `
prefix accepted by `RegisterHook` is removed; object/class and function suffixes
never become filename suffixes.

The serialized confidence is `exact_configured_policy_package_key`. It means
only that a literal reflected target and cooked package key agree under the
selected build policy. The command does not prove that the live installation is
that build, that an input PAK is installed or active, that it wins load order,
that the target export changed or still exists, or that the Lua and PAK belong
to different mods. Every result is an advisory package association, never an
automatic incompatibility.

The correlator records but does not match:

- symbolic, dynamic, and missing targets;
- malformed reflected paths;
- native `/Script` packages;
- unknown or ambiguous mount roots;
- valid mapped targets absent from the input PAK set.

Unresolved details are bounded and accompanied by complete per-reason counts.
Literal parsing currently accepts conservative top-level class/function forms;
unusual nested reflected paths remain unresolved instead of being guessed.
Declared activation is attached only when schema, canonical game root, module
name, and module path agree across the two non-atomic reports.

Default correlation limits are 128 PAKs, 1,000,000 cooked packages, 20,000
matches, and 20,000 unresolved details. PAK count is rejected before any worker
starts; cumulative package count is checked after each validated response. A
result limit retains no arbitrary detail prefix and marks the report incomplete.

Official path evidence used by this policy:

- [UE4SS `RegisterHook`](https://docs.ue4ss.com/dev/lua-api/global-functions/registerhook.html)
- [UE4SS `NotifyOnNewObject`](https://docs.ue4ss.com/dev/lua-api/global-functions/notifyonnewobject.html)
- [UE4SS object-dumper path examples](https://docs.ue4ss.com/dev/feature-overview/dumpers.html)
- [Unreal `FPackageName::LongPackageNameToFilename`](https://dev.epicgames.com/documentation/en-us/unreal-engine/API/Runtime/CoreUObject/UObject/FPackageName/LongPackageNameToFilename)
- [Unreal mount-point registration](https://dev.epicgames.com/documentation/en-us/unreal-engine/API/Runtime/CoreUObject/UObject/FPackageName/RegisterMountPoint)

## Deferred Work

- Reliable installed UE4SS version and commit evidence.
- Binary provenance for proxy/core candidates and effective runtime loader
  selection.
- Constant-derived and wrapper-expanded hook/notifier targets.
- Receiver provenance needed to distinguish Lua tables from reflected objects.
- Additional reviewed exact descendants for policies described as “or newer.”
