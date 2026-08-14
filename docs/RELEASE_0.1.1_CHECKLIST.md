# RR Mod Manager 0.1.1 — Release Checklist

- [x] Cargo, Tauri, JavaScript packages, installers, and metadata report `0.1.1`.
- [x] The Linux AppImage is built in release mode and starts successfully.
- [x] The Windows NSIS installer and both workers are built in release mode.
- [ ] A clean Windows 11 machine runs both sandboxed workers successfully.
- [ ] Steam launches Retro Rewind from a secondary library on Windows 11.
- [x] The official `0196ef29` UE4SS fixture repairs to `662df915`.
- [x] Automated repair tests preserve UE4SS settings, modules, scripts, and activation markers.
- [ ] An interrupted UE4SS repair restores the previous binaries.
- [x] Profile selection persists in automated application tests.
- [x] Pending profile changes can be applied before launch or intentionally left unapplied.
- [x] Startup and profile changes no longer trigger redundant deep discovery.
- [x] The last 20 failed operations are stored locally with stage, duration, category, and rollback status.
- [x] Paths, URL queries, and common secret assignments are redacted before failure history is persisted.
- [x] Support previews and ZIPs include `rrmm-operations.json`.
- [x] The Support center can clear the saved failure history without changing mods or profiles.
- [x] Final AppImage, Linux ZIP, and Windows installer hashes are recorded.
- [ ] GitHub and Nexus keep `0.1.0` files available when `0.1.1` is published.
