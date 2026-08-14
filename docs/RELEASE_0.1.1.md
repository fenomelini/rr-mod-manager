# RR Mod Manager 0.1.1

RR Mod Manager `0.1.1` is a bug-fix release for Linux and Windows 11.

## Fixed

- Restored automatic UE4SS installation and repair by using the permanent
  official archive URL for the exact verified `662df915` build.
- Allowed the recognized `0196ef29` UE4SS build to be upgraded while preserving
  the existing nested settings and `Mods` tree.
- Stopped repeating deep Steam discovery and critical-file hashing after every
  profile or UI refresh when the saved installation is still present.
- Located the Steam client independently from a secondary Steam library before
  launching Retro Rewind.
- Added the option to launch the game without applying pending profile changes.
- Added specific messages for UE4SS download, layout, and identity failures.
- Added a local history of the last 20 failed manager operations, including the
  failed stage, duration, error category, and rollback result.
- Added detailed UE4SS repair evidence for cache, download, archive hashes,
  installed binaries, final verification, and recovery status.
- Included the redacted failure history as `rrmm-operations.json` in support
  report previews and ZIP files, with a button to clear it at any time.
- Kept diagnostic history entirely local and redacted paths, URL queries, and
  common secret values before saving it.
- Changed the local Windows packaging flow to produce optimized release
  binaries instead of debug binaries.
- Allowed optimized builds to omit the still-unused compatibility recipe
  catalog. No unsigned recipe is accepted or applied.

## Supported baseline

- Retro Rewind Steam build `23896268`
- Unreal Engine `5.4.4`
- UE4SS `3.0.1 Beta #0`, build `662df915`
- Linux Steam/Proton and Windows 11
