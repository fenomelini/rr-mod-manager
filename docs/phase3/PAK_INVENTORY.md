# Phase 3 PAK Inventory Contract

## Status

The initial Linux-first PAK inventory is implemented in `rrmm-pak` and executed
through the separate `rrmm-pak-worker`. Production code uses Trumank `repak`
0.2.3 pinned to commit
`e215472c51db69328b1ce77be2db24d24c1d646b`; it does not parse human-readable
CLI output. The dependency enables general compression but not Oodle loading or
encryption.

The current slice provides:

- V11 and other readable PAK version reporting.
- Mount-point application and deterministic virtual paths.
- NFKD/full-case-fold/NFC collision keys.
- Rejection of absolute, drive-qualified, traversing, empty, and colliding paths.
- Grouping of `.uasset`, `.umap`, `.uexp`, `.ubulk`, and `.uptnl` sidecars.
- Advisory orphan and incomplete-package warnings.
- `_P` and explicit numeric suffix priority hints.
- Lazy SHA-256 hashing for one requested stored member.
- Batched lazy hashing for only the members shared by multiple PAKs.
- Stored, Zlib, Gzip, Zstd, and LZ4 payload support through the pinned parser.
- Parent-enforced timeout, bounded JSON, cleared environment, and mandatory
  Linux worker sandboxing.
- Bounded validation of footer/index ranges, strings, record counts, secondary
  indexes, encoded references, and compression-block counts before upstream
  parsing.
- Host-side validation of worker inventory paths, sizes, names, priority hints,
  normalized members, collision ordering, cooked sidecars, and reconstructed
  package groups before cross-layer evidence is accepted.

On Linux, the PAK worker receives read access only to the selected PAK. It
shares `rrmm-worker-sandbox` with archive intake: Landlock ABI V4 handles all
available filesystem and TCP rights, grants no network or write paths, requires
`no_new_privs` and full enforcement, verifies concrete read/TCP denials, and
applies CPU, address-space, file-size, and file-descriptor limits. Successful
unsandboxed responses are rejected by the CLI.

## Integrity Meaning

`structural_parse_succeeded: true` means the footer and indexes were readable
enough to produce an inventory. It does not mean every PAK index hash was
verified. `index_hashes_verified` remains `false` because upstream `repak`
0.2.3 leaves path-hash and full-directory-index verification as TODOs.

The manager must not describe a structurally readable PAK as cryptographically
verified. Encrypted indexes and Oodle member reads are unsupported in this
slice. Inventorying an Oodle PAK may succeed because payloads are not read;
hashing an Oodle member fails rather than downloading a library implicitly.

## Path Model

Retro Rewind PAK mounts are rooted from the Unreal engine prefix `../../../`.
The normalizer requires exactly that prefix, removes it, validates the remaining
mount and stored member independently, then joins them. For example:

```text
mount:  ../../../RetroRewind/Content/VideoStore/
stored: core/blueprint/Market.uasset
virtual: RetroRewind/Content/VideoStore/core/blueprint/Market.uasset
```

The original spelling is retained for display. A normalized Unicode case-folded
key is used for collision and future conflict detection.

## CLI

```bash
cargo run --package rrmm-cli -- pak-inspect --pak path/to/mod.pak
cargo run --package rrmm-cli -- pak-inspect --pak path/to/mod.pak \
  --hash-member RetroRewind/Content/Foo.uexp
cargo run --package rrmm-cli -- pak-conflicts --pak first.pak second.pak
```

The command is read-only and emits deterministic JSON. Hash lookup uses the
stored path, not the effective virtual path. `--timeout-seconds` defaults to
120, and `--worker` exists for controlled testing.

## Conflict Graph

`pak-conflicts` requires at least two distinct PAK paths. It inventories each
PAK in the sandbox, discovers exact member and cooked-package overlaps, groups
overlapping hash requests per PAK, and then builds deterministic pairwise edges.

Current outcomes are intentionally narrow:

- `benign_duplicate`: every overlapping member is hash-identical and every
  overlapping cooked package has the same complete member set with no package
  integrity warnings. Two equally incomplete groups are not called benign.
- `ordered_with_loss`: content differs or sidecar sets are split, and one PAK
  has a higher observed numeric patch generation.
- `unknown_order`: the overlap is not benign and numeric generations tie. The
  manager does not guess lexical runtime order.

Each edge retains member identity evidence, package member sets, split-package
flags, the effective numeric winner when known, and a human-readable reason.
Hash evidence is mandatory for `benign_duplicate`; missing evidence can never
produce that classification.

Edges also expose deterministic domains: `cooked_package`, `loose_file`, and
`localization`. Localization is path-based and conservative: exact overlaps in
`.locres`/`.locmeta` files or content beneath `Localization`/`L10N` are tagged,
but the manager does not claim that their contents can be merged.

## Discovery And Priority

`pak-discover` recursively walks the selected PAK root without following
filesystem links. Extension matching is case-insensitive. Every result includes
its relative path, parsed priority hint, and a `disabled_looking_ancestor` flag.
A directory named `disabled` remains inside Unreal's recursive search tree, so
its PAKs are reported rather than treated as inactive.

Priority decisions currently use only observed numeric patch generations:

- No `_P` suffix: generation 0.
- `_P.pak`: generation 1.
- `_2301_P.pak`: generation 2302.
- `_9999_P.pak`: generation 10000.

A higher generation produces a winner with `observed_patch_generation`
confidence. Equal generations produce no winner and
`unverified_lexical_tie`; filenames are not used to guess an unverified runtime
rule.

### Desktop Winner Choices

The desktop can persist an explicit winner for a non-benign pair when the user
chooses to keep both PAKs and accepts that the loser is overridden. A choice is
scoped to the active profile, exact Steam build, and the complete SHA-256 of
both PAK files. Artifact, external-file, build, or profile drift invalidates the
reviewed preview instead of transferring the choice by filename.

Pairwise choices become loser-to-winner constraints in a deterministic directed
graph. Cycles are rejected. PAKs involved in non-benign edges receive distinct
`RRMM_<hash-prefix>_<slot>_P.pak` destinations, and the final projected archives
are inspected again before activation. The preview remains blocked until every
non-benign edge has a choice and its effective numeric winner matches that
choice. A split cooked package remains visibly high risk but can be explicitly
accepted; the UI never describes ordered loss as compatibility or merging.

This profile-local acknowledgement is separate from signed recipe
`select_winner` operations. Recipe materialization remains subject to the
reviewed-recipe policy documented in Phase 5.

```bash
cargo run --package rrmm-cli -- pak-discover \
  --root path/to/RetroRewind/Content/Paks
```

## Base Index Cache

`pak-cache` stores a typed `PakInventory` in SQLite schema 3. Its key evidence
contains:

- Canonical PAK path.
- Exact Steam build ID.
- File byte size.
- Nanosecond-resolution modification time.
- SHA-256 over the PAK footer, primary index, and referenced secondary indexes.

Lookup first asks the sandboxed worker for only the bounded structural digest.
A hit avoids upstream parsing and returns the typed cached inventory. Any build,
metadata, or digest mismatch is a miss. The CLI fingerprints file metadata
before and after worker operations and refuses to cache a file that changes
during inspection. Invalid cached JSON is deleted and rebuilt rather than
surfaced as an inventory.

```bash
cargo run --package rrmm-cli -- pak-cache \
  --pak path/to/RetroRewind-Windows.pak \
  --database path/to/rrmm.sqlite \
  --build-id 23896268
```

## Verification

- Generated V11 fixtures cover default and non-default mounts, stored and Zlib
  payloads, sidecars, orphan warnings, traversal mounts, case collisions,
  truncation, priority suffixes, lazy hashes, and member output limits.
- Employee Fee Policy V11 produced two members and one complete cooked package.
- Better Movie Database was reported as V8B rather than incorrectly labeled V11.
- Installed `BlackMarketEveryDay_2301_P.pak` applied its non-default mount and
  produced patch generation `2302` for explicit suffix `2301`.
- The 1.84 GB base-game V11/Oodle PAK produced its complete 21,705-entry index
  through the sandbox without reading member payloads.
- Caching that base index produced a roughly 11 MB SQLite database. The first
  call was a miss and the second an exact hit with structural digest
  `bbed2028ec95082044826ed9c05aab7e7c1ba5a722425b06720e1e88038e6d8f`.
- Recursive discovery of the installed PAK root found the same 48 PAK files as
  the Phase 0 scan, with no followed links and no current `disabled` ancestor.
- Employee Fee Policy's `.uexp` SHA-256 matched pinned `repak hash-list` output:
  `b9489b781ce6c0d369347848cde36a9853281e96d1fd36fa5ddfe2d0639638dc`.
- Worker protocol tests require sandboxed inventory and hashing on Linux. CLI
  tests cover timeout termination and refusal of successful unsandboxed output.
- The two Chronological New Releases PAK names were classified as a benign
  duplicate after all four overlapping members matched by SHA-256, despite
  different numeric suffixes.
- Employee Fee Policy and its LateWaive/DamageWaive variant produced one package
  overlap with identical `.uasset`, differing `.uexp`, and `unknown_order`
  because both filenames have the same `_P` generation.
- Generated tests cover loose `.locres` and cooked localization-package
  conflicts as separate graph domains.
- The `pak_inventory` libFuzzer target alternates raw bytes, generated V11 PAKs,
  and single-byte mutations. Its first run found an internal entry count that
  requested an excessive allocation; bounded pre-validation fixed the case and
  a subsequent 5,000-run campaign completed without findings.

## Remaining Gates

- Complete engine-priority behavior with controlled runtime tests. Desktop
  ordering deliberately avoids lexical ties by assigning distinct numeric
  generations.
- Differential-test generated fixtures against the pinned `repak` CLI.
