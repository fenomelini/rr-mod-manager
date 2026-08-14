# Phase 4 Deployment Core

## Scope

The current Phase 4 slice provides persisted profile state and recoverable
deployment for an explicit complete file set. Package manifests, requirement
resolution, compatibility recipes, and automatic mapping from imported
artifacts belong to Phase 5 and are not inferred here.

All development and fault-injection tests target temporary installation trees.
The real Retro Rewind installation has not been modified.

## Profiles

SQLite schema 4 stores profile names, optimistic revisions, exact artifact
SHA-256 selections, optional variants, and the selected profile per installation
identifier. Profile IDs and installation IDs contain only ASCII letters,
numbers, `_`, and `-`.

Available commands:

```bash
rrmm profile-create --database rrmm.sqlite --id default --name Default
rrmm profile-clone --database rrmm.sqlite --source-id default --id testing --name Testing
rrmm profile-edit --database rrmm.sqlite --profile edited-profile.json --expected-revision 0
rrmm profile-list --database rrmm.sqlite
rrmm profile-select --database rrmm.sqlite --installation-id retro_rewind --profile-id default
rrmm profile-delete --database rrmm.sqlite --id testing
```

`profile-edit` uses optimistic concurrency. A stale `expected_revision` is
rejected instead of silently replacing a newer edit. An active profile cannot
be deleted because the database foreign key uses `ON DELETE RESTRICT`.

## Preview

`deploy-preview` accepts a JSON `DeploymentRequest`. Each desired file names an
immutable source path, normalized game-relative destination, exact byte count,
and lowercase SHA-256. The command checks the live game-process state itself;
the JSON value cannot bypass the guard.

```json
{
  "transaction_id": "activate_default_1",
  "installation_id": "retro_rewind",
  "profile_id": "default",
  "game_root": "/path/to/RetroRewind",
  "state_root": "/path/to/RRModManager",
  "files": [
    {
      "source": "/path/to/immutable/files/Example_P.pak",
      "relative_path": "RetroRewind/Content/Paks/Example_P.pak",
      "bytes": 1234,
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  ],
  "allow_unmanaged": false,
  "game_running": false
}
```

The preview automatically loads the active external receipt when one exists. It
classifies creates, managed replacements, unmanaged replacements, identical
unmanaged adoption, managed removals, and unchanged managed files. It blocks:

- A running Retro Rewind process.
- Missing or drifted manager-owned files.
- Unmanaged destinations without `--allow-unmanaged`.
- Case or Unicode collisions with existing game content.
- Traversal, absolute paths, file/directory prefix conflicts, and unsafe links.
- Sources whose size or hash changed.

Preview does not create the state root or modify the game.

The desktop exposes managed drift as structured evidence with exact ownership.
The user may restore the selected package bytes only through a hash-bound
approval, or disable the exact owning package and recalculate the preview. Apply
rejects an approval if the external file changes again. Replaced drift is backed
up without replacing the receipt's original displaced-file restoration record.

`deploy-inventory` independently walks the game tree and skips links observed
during the scan.
It reports manager-owned matches, drift, missing files, unmanaged files,
case/Unicode collisions, links, and special entries. Only manager-owned files
are hashed; unmanaged files are inventoried by path, type, and size so scanning
does not hash the large base-game PAK unnecessarily.

```bash
rrmm deploy-inventory \
  --game-root /path/to/RetroRewind \
  --state-root /path/to/RRModManager \
  --installation-id retro_rewind
```

## Transaction

`deploy-apply --confirm` performs these steps:

1. Recompute the complete plan from current source and destination state.
2. Recheck the active receipt and game process.
3. Materialize and verify every desired file under transaction staging.
4. Copy every replaced or removed file into the content-addressed backup store.
5. Persist and sync an immutable journal before changing the game tree.
6. Apply same-directory temporary files and per-file renames, rechecking the
   game process after every operation.
7. Verify every deployed hash and every planned removal, then recheck the game
   process before committing ownership.
8. Replace the external ownership receipt.
9. Persist a commit marker before journal cleanup.

The state root is rejected if it contains the game root or is contained by it.
Backups, journals, receipts, and staging paths reject filesystem links.
An operating-system file lock serializes apply and recovery, and a new apply is
rejected while any older journal still requires recovery.

When unmanaged content is explicitly replaced or adopted, its original hash is
retained in the ownership receipt and its bytes remain in the backup store. A
later profile that omits the path restores the original unmanaged file instead
of deleting it.

PAK load ordering uses a separate external-file receipt rather than adopting
manually installed PAKs as manager-owned files. External PAK and same-stem SIG
sources are verified and backed up, all sources are first moved to unique
same-directory temporary paths, and only then are the numeric target names
created. This supports swaps and chains without overwriting an intermediate
source. The journal records every external move, rollback restores the original
paths, and committed recovery verifies the ordered targets. Removing an order
constraint explicitly moves a still-active external file back to its recorded
original path.

If application fails after the journal becomes durable, the same process rolls
back from content-addressed backups. `deploy-recover --confirm` processes
journals left by process or machine interruption. A journal with a durable
commit marker is cleaned without rollback; an uncommitted journal is rolled
back. Recovery refuses to overwrite content that changed externally after the
interruption. Before its first rollback mutation, recovery checks the active
receipt, every affected game file, and every required content-addressed backup;
drift therefore cannot cause an avoidable partial multi-file rollback. Staging
left by an interruption before journal creation is removed under the deployment
lock so the transaction can be retried.

## Current Limits

- Deployment requests are explicit JSON rather than generated from Phase 5
  package manifests.
- The running-game detector is process-name based and global.
- Windows directory durability and physical antivirus-lock behavior still need
  validation on a Windows host.
- Full disk, permission, and process-kill campaigns remain release-gate work;
  Linux write-limit failure during staging is covered.
- Inventory is a filesystem snapshot, not a stable-handle traversal. The game
  and external file-management tools should remain stopped during its scan.
- Steam launch currently requires an explicit entry path named `steam`,
  `steam.exe`, `steam_osx`, or `steam.sh`. A wrapper symlink is accepted only
  when it resolves to a regular file. Launch refuses while the game is already
  running and always uses fixed arguments
  `-applaunch 3552140`.
