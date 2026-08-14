# Phase 2 Archive Intake Contract

## Status

Path policy, resource limits, ZIP/7z preflight, streamed quarantine extraction,
package-layout inference, and content-addressed artifact acceptance are
implemented. The worker runs as a separate process with a cleared environment,
bounded request/response sizes, and a parent-enforced timeout. On Linux it also
runs under a mandatory Landlock ABI V4 ruleset and process resource limits.

The Linux sandbox only permits reading the selected archive and writing beneath
the private staging directory. It handles all available Landlock filesystem and
TCP rights, grants no TCP rights, requires full kernel enforcement with
`no_new_privs`, and fails closed if an outside read or TCP connection is not
denied. CPU time, address space, output-file size, open files, and core dumps are
also bounded. Linux hosts without Landlock ABI V4 reject archive processing
rather than running with weaker isolation. Windows uses an AppContainer broker,
Job Object limits, child-process mitigation, network denial, and temporary input
and staging ACLs. Each worker run uses a unique AppContainer profile that is deleted, together with
its private storage, after the worker exits. Runtime validation of that boundary on clean Windows
remains a release gate. Parent applications reject every successful unsandboxed response.

The CLI exposes the current archive gates:

```bash
cargo build --workspace
cargo run --package rrmm-cli -- archive-preflight --archive path/to/mod.zip
cargo run --package rrmm-cli -- archive-extract --archive path/to/mod.zip --staging path/to/empty-staging
cargo run --package rrmm-cli -- archive-import --archive path/to/mod.zip --store path/to/store
```

## Trust Boundary

Every imported archive is hostile input. Parsing and extraction occur in a
separate worker process; the parent withholds its database and credentials,
enforces a deadline, and kills the worker on timeout. On Linux, the worker must
activate the Landlock sandbox before parsing. The archive is the only readable
file granted by the ruleset; extraction receives one private, empty staging
directory with the minimum read/write/create/remove rights needed for streamed
extraction. Windows workers report `sandboxed: true` only after validating the
AppContainer token, Job Object membership and limits, and child-process policy.

No archive member path is passed directly to an OS filesystem API. The common
path policy first:

- Treats `/` and `\\` as separators on every host.
- Rejects absolute paths, drive paths, traversal, NULs, alternate data streams,
  Windows-invalid characters, device names, and trailing dot/space aliases.
- Enforces a maximum component depth.
- Detects collisions with Unicode normalization plus full Unicode case folding.

## Resource Handling

Desktop imports enforce ceilings of 8 GiB compressed, 32 GiB expanded, 16 GiB
per file, 100,000 entries, depth 32, and compression ratio 10,000. Accepted mods
are hashed and extracted as streams. Before extraction, RRMM compares the archive's declared expanded
size with the actual free space needed for staging and immutable publication.
If the filesystem cannot provide that space, the import stops with the required
and available byte counts. Actual write failures also abort the transaction and
remove partial staging.

Path components remain bounded by cross-platform filesystem rules. Worker CPU
watchdogs scale with the selected file size instead of imposing the former
fixed two-minute processing window. Metadata is never trusted as the sole
verification mechanism.

## Parser Selection

- ZIP: pure Rust `zip` parser. Require a policy-safe path, reject encrypted,
  overlapping, symlink, and non-file/non-directory entries before extraction.
- 7z: pure Rust `sevenz-rust2` parser. Accepted content codecs are COPY, LZMA,
  LZMA2, PPMd, BZip2, and Deflate. Supported BCJ/BCJ2 architecture filters and
  Delta may be chained with them. Preflight rejects every other method ID as
  `unsupported_codec`, and separately rejects encryption, anti-items, reparse
  or link-like entries, and multipart inputs.
- Never call an archive-provided executable or shell command.
- The locally installed `7z` executable is not part of the product trust
  boundary and will not be used for extraction.

## Acceptance Transaction

1. Hash the original archive with SHA-256 before extraction.
2. Preflight all entries and reject the entire archive on any policy violation.
3. Extract to a unique empty staging directory with streamed limits.
4. Rewalk staging without following links and verify count, bytes, type, and
   normalized path set against preflight.
5. Infer package layout. A top-level `rrmm-manifest.json` is optional for desktop
   imports; ordinary PAK and non-native UE4SS releases do not need to be
   repackaged for RRMM.
6. Revalidate and copy the archive and every extracted file into a temporary
   artifact directory in the parent process.
7. Atomically rename the complete read-only artifact into a SHA-256-addressed
   store.
8. Verify an existing artifact before treating a repeated import as a duplicate.
9. Remove staging on success or extraction failure; never expose a partial
   accepted item.

After acceptance, the desktop may create deterministic local package metadata
bound to the immutable archive SHA-256. Automatic activation is available only
when every non-documentation file maps to a recognized PAK, its paired SIG, or a
non-native UE4SS module with `Scripts/main.lua` and `enabled.txt`. Enabling such
a locally inferred package requires user confirmation. Unknown layouts,
unclassified files, native payloads, and incomplete UE4SS modules remain stored
but cannot be activated automatically.

## Current Verification

- Unit tests accept a valid mod ZIP and reject Zip Slip, case/Unicode
  collisions, file/directory prefix conflicts, per-file limits, and aggregate
  expanded-size limits.
- The deterministic hostile corpus rejects ZIP/7z truncations at multiple
  boundaries, forged ZIP expanded sizes, and high-ratio ZIP/7z compression
  bombs without creating staging.
- Hermetic tests preflight and extract a generated 7z archive.
- Hermetic round trips preflight and extract COPY, LZMA, LZMA2, PPMd, BZip2,
  and Deflate 7z archives; a structurally valid unknown method ID is rejected
  during preflight as `unsupported_codec`.
- Archives produced independently by 7-Zip 26.02 with those six codecs passed
  the sandboxed worker preflight. A Deflate64 archive was rejected as
  `unsupported_codec` with method ID `0x040109`.
- Worker protocol tests cover valid and malformed JSON requests and extraction
  into staging under the mandatory Linux sandbox. Successful Linux responses
  require observable filesystem and TCP denials before parsing begins.
- A timeout integration test confirms that a hung worker is killed and its
  partial staging directory is removed.
- A storage-failure integration test confirms that a completed extraction is
  cleaned when artifact publication cannot create its destination.
- A Linux file-size-limit integration test forces a write failure during source
  copying and confirms both the `.incoming-*` artifact and import staging are
  removed.
- A capability-gated Linux integration test mounts a 1 MiB `tmpfs` in an
  unprivileged user namespace, requires the import to fail with `ENOSPC` (`os
  error 28`), and verifies staging and `.incoming-*` cleanup before unmounting.
- Artifact tests cover atomic acceptance, duplicate detection, staging
  tampering, and tampering with an existing stored artifact.
- `Better-Movie-Database-1.0.1.zip`: accepted, 7 entries, 40,817 expanded
  bytes, SHA-256 recorded.
- `Chronological-New-Releases-Era-Specific-1.0.0.zip`: accepted, 2 entries,
  143,773 expanded bytes, SHA-256 recorded.
- `vgmstream-linux.zip`: metadata accepted, demonstrating why post-extraction
  magic-byte inspection is required for extensionless native binaries. That
  inspection is now part of extraction.
- `Better-Movie-Database-1.0.1.zip`: imported into a temporary content-addressed
  store as a hybrid PAK/UE4SS package; a second import was deduplicated.
- A generated normal 7z was accepted and extracted; a header-encrypted 7z was
  rejected as `encrypted_archive`.
- Instrumented libFuzzer smoke runs completed 10,000 member-path cases and 1,000
  archive-preflight cases without a crash or sanitizer finding. Generated local
  corpora are ignored; minimized regressions belong in the deterministic tests.

## Remaining Gates

- Validate the Windows AppContainer/Job Object sandbox on clean Windows systems.
- Run the maintained local libFuzzer targets continuously in CI and preserve
  minimized findings as deterministic corpus regressions.
