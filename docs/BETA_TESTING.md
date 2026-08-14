# Beta Testing

## Supported Baseline

- Retro Rewind Steam App ID `3552140`.
- Steam build `23896268` only.
- Windows 10/11 Steam and Linux Steam/Proton.
- Manual ZIP/7z imports; Nexus login, managed downloads, and automatic updates
  are not included.

Do not continue when RR Mod Manager reports a modified, unsupported, partial,
unknown, or running game installation.

## Required Smoke Test

Use disposable test profiles and representative PAK-only, UE4SS-only, and hybrid
mods. For each supported platform:

1. Install RR Mod Manager as a current user and confirm the game is discovered.
2. Import one ZIP and one 7z archive and review every destination and conflict.
3. Activate a profile, launch the game, and verify the expected mod behavior.
4. Change PAK order and confirm the reported winner in game.
5. Switch to a second profile and confirm removed files are no longer active.
6. Modify and then remove one managed file; verify guided drift restoration.
7. Interrupt an activation in a disposable game copy and run recovery.
8. Disable and remove every test mod and verify unmanaged files were preserved.
9. Create a problem report and inspect every included file before saving it.

Record the RR Mod Manager version, operating system, game build, mod archive
hashes, result, and any Windows Defender alert. Never attach game assets, raw
logs, personal paths, credentials, or complete `nxm://` URLs to a public report.

## Restore Procedure

1. Close Retro Rewind and Steam game processes.
2. Open RR Mod Manager and use the recovery action when an interrupted operation
   is reported.
3. Do not manually delete journals, receipts, backups, or staging while recovery
   is pending.
4. Disable all managed mods, apply the empty profile, and verify game files
   through Steam if the exact supported baseline must be restored.
5. Keep the RR Mod Manager data directory until all profiles are removed and no
   recovery is pending; it contains the backups needed to restore displaced files.

Report recovery failures privately according to `SECURITY.md`.

## Known Beta Limits

- Windows sandbox and reparse-point behavior require clean-system runtime
  validation before public distribution.
- Signed recipes require the production key ceremony and a non-placeholder
  embedded catalog before a release build is allowed.
- Equal-generation lexical PAK ordering remains unverified and is shown as
  unknown rather than guessed.
- Nexus authentication/downloads and automatic application updates are absent.
- Native UE4SS DLL safety cannot be established by static inspection.
