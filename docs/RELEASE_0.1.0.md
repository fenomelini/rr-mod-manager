# RR Mod Manager 0.1.0

RR Mod Manager `0.1.0` is the first public release for local Retro Rewind mod
management. It supports Retro Rewind Steam build `23896268` on Windows 10/11 x64
and Linux x64 with Steam/Proton.

## Included

- Manual ZIP and 7z import with review before installation.
- PAK, UE4SS, and hybrid mod management.
- Profiles, activation preview, deterministic PAK ordering, and conflict details.
- Managed-file ownership, drift detection, backups, rollback, and interrupted
  deployment recovery.
- UE4SS installation/repair, diagnostics, keybind analysis, and redacted local
  support exports.

## Not Included

- Nexus authentication or managed Nexus downloads.
- Automatic mod or application updates.
- Support for game builds other than `23896268`.
- Safety guarantees for unknown native UE4SS DLLs.
- Universal merging of conflicting cooked Unreal assets.

Read `BETA_TESTING.md` before installation. Close Retro Rewind before applying a
profile, review every activation preview, and do not manually delete RR Mod
Manager journals, receipts, or backups while recovery is pending.
