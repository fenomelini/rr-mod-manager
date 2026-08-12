# RR Mod Manager

Local-first desktop mod manager for Retro Rewind - Video Store Simulator.

[Releases](https://github.com/fenomelini/rr-mod-manager/releases) |
[Issues](https://github.com/fenomelini/rr-mod-manager/issues) |
[Privacy](PRIVACY.md)

RR Mod Manager keeps PAK, UE4SS, and hybrid mods together in one library. It
lets you build profiles, review conflicts, apply the selected setup, and open
the game without manually moving files every time.

## Features

- Finds Retro Rewind across Steam libraries and verifies the installed build.
- Detects PAK and UE4SS mods already installed in the game.
- Imports one or more ZIP or 7z mod archives after reviewing their contents.
- Keeps imported archives in local storage and identifies them by SHA-256.
- Manages PAK-only, UE4SS-only, and hybrid PAK + UE4SS mods.
- Creates, duplicates, renames, and deletes independent mod profiles.
- Enables or disables multiple mods together from the mod list.
- Detects file, PAK-content, load-order, UE4SS, and shortcut conflicts.
- Shows which PAK wins when the load order can be determined safely.
- Previews every game-file change before applying a profile.
- Uses backups, ownership records, rollback, and interrupted-operation recovery.
- Installs or repairs the supported UE4SS build when an advanced mod needs it.
- Opens Retro Rewind through Steam after the selected profile is ready.
- Works without behavioral telemetry or automatic diagnostic uploads.

## How It Works

RR Mod Manager separates three states:

- **My mods** is the complete local library of imported and detected mods.
- **Selected profile** is the setup currently being edited.
- **Applied profile** is the setup currently present in the game directory.

Enabling or disabling a mod edits only the selected profile. The game files do
not change until you review the preview and choose **Apply profile**. This makes
it possible to prepare a different setup without changing the game immediately.

Imported mods are not enabled automatically. Mods installed manually before RR
Mod Manager remain identifiable as external mods until they are adopted into
the managed library.

## Requirements

- Retro Rewind Steam App ID `3552140`.
- Retro Rewind Steam build `23896268`.
- Windows 11 x64, or Linux x64 with Steam and Proton.
- Write access to the Retro Rewind installation directory.

Close Retro Rewind before installing UE4SS, applying a profile, changing an
installed mod, or running recovery.

## Installation

Download the files from the [Releases](https://github.com/fenomelini/rr-mod-manager/releases)
page. Do not download the repository source archive; it is not the application.

### Windows 11

1. Download `RR.Mod.Manager_0.1.0_x64-setup.exe`.
2. Run the installer.
3. Complete the current-user installation. Administrator access is not needed.
4. Open **RR Mod Manager** from the Start menu.

The installer is not digitally signed yet. Windows may display an unknown
publisher warning. Verify the SHA-256 value shown in the Release before running
the file.

### Linux

1. Download `RR.Mod.Manager_0.1.0_amd64.AppImage`.
2. Open a terminal in the download directory.
3. Make the AppImage executable:

```bash
chmod +x RR.Mod.Manager_0.1.0_amd64.AppImage
```

4. Start it:

```bash
./RR.Mod.Manager_0.1.0_amd64.AppImage
```

The AppImage is portable and does not require a system-wide installation.

## First Start

1. Install Retro Rewind through Steam and allow Steam to finish any update.
2. Close the game if it is running.
3. Open RR Mod Manager.
4. Wait while it checks Steam libraries, the game build, installed mods, and
   UE4SS.
5. If the game is not found, choose **Choose game folder** and select the
   `RetroRewind` directory directly inside your Steam library's
   `steamapps/common` directory.
6. On **Overview**, confirm that the game installation is compatible and that
   no recovery action is required.
7. Open **Profiles** and select an existing profile or choose **New profile**.

Do not apply mods when the manager reports an unsupported, modified,
incomplete, unwritable, or running game installation. Repair or update the game
through Steam first when instructed.

## Adding Mods

Keep downloaded mods as ZIP or 7z archives. RR Mod Manager accepts up to 50
archives in one selection and reviews each archive separately.

1. Open **Add mod**.
2. Choose **Browse files** and select one or more ZIP or 7z archives.
3. Wait for the archive, destination, and conflict checks to finish.
4. Review the identified mod, included files, planned destinations, warnings,
   and conflicts.
5. If executable or native files are reported, continue only when you trust the
   download and understand the mod author's instructions.
6. Choose **Add to My mods**, or use the batch button to add every accepted
   archive.
7. Open **My mods** and confirm that the new mod appears as disabled in the
   selected profile.

Adding a mod stores it in the manager library. It does not alter the game until
the mod is enabled in a profile and that profile is applied.

## Creating and Editing a Profile

1. Open **Profiles**.
2. Choose **New profile**, enter a name, and create it. You can also duplicate
   an existing profile when only a few mods need to change.
3. Select the profile you want to edit.
4. Open **My mods**.
5. Enable the mods that belong to this profile and disable the others. You can
   select multiple rows and use **Enable selected** or **Disable selected**.
6. Open a mod's details to review its files, type, origin, and inspection state.

Changing the selected profile does not apply it automatically. A pending state
is shown until its preview is reviewed and applied.

## Reviewing Problems and Conflicts

Open **Problems** before applying a profile.

- Disable one of two incompatible mods when they replace the same game content.
- Follow any required dependency or game-build message.
- Review PAK load order when two active PAKs overlap.
- Treat a reported PAK winner only as the file that loads later; it does not
  merge two conflicting mods or guarantee that both effects remain available.
- Keep locally inspected or native mods disabled when their origin or behavior
  is not trusted.

The **Apply profile** button remains unavailable while a blocking problem is
unresolved.

## UE4SS Mods

PAK-only mods do not require UE4SS. Lua, native, and hybrid mods may require it.

1. Open **UE4SS**.
2. Review the detected installation and version.
3. If the supported loader is missing, choose **Install UE4SS** and confirm the
   operation.
4. If the installed files are incomplete, mixed, or unsupported, choose
   **Repair UE4SS**.
5. Wait for the download, installation, and hash verification to finish.
6. Return to **Problems** and review the selected profile again.

UE4SS installation requires network access and is started only after user
confirmation. RR Mod Manager cannot prove that an unknown native DLL is safe.

## Applying a Profile and Starting the Game

1. Close Retro Rewind.
2. Select the profile you want to use.
3. Enable or disable its mods in **My mods**.
4. Open **Problems** and resolve every blocking item.
5. Choose **Apply profile**.
6. Review every planned addition, removal, replacement, and load-order change.
7. Choose **Apply now** and wait for **Profile applied successfully**.
8. Return to **Overview** and choose **Open game**.

If you choose **Open game** while safe changes are still pending, RR Mod Manager
offers **Apply and open game**. The game opens only after the profile is applied
successfully. If a blocker is found, the game is not opened and the manager
returns you to the items that need attention.

The game is launched through Steam. Once Retro Rewind is running, close it
before making another file change.

## Switching Profiles

1. Close Retro Rewind.
2. Open **Profiles** and select the new profile.
3. Review its enabled mods and any reported problems.
4. Choose **Apply profile** and confirm the preview.
5. Start the game only after the new profile is shown as applied.

Files that belong only to the previous profile are removed or disabled during
the same reviewed operation.

## Existing Mods

PAK and UE4SS mods already present in the game are shown in **My mods**.

- **Enable** restores or updates the files that control an external mod.
- **Disable** stores the mod safely so it can be enabled again.
- **Adopt into library** adds a supported external mod to the selected profile.
- **Delete permanently** removes the selected mod files and cannot be undone.

Review grouped hybrid mods as one unit. RR Mod Manager preserves unrelated and
unmanaged game files.

## Recovery and Support

If an apply operation is interrupted, reopen RR Mod Manager and use the recovery
action shown in **Support center** before changing mods again. Do not manually
delete manager backups, journals, or stored files while recovery is pending.

The Support center can create a local problem-report preview. Nothing is sent
automatically. Review the exact contents before choosing where to save it.

## Removing a Managed Mod

1. Disable the mod in every profile that uses it.
2. Apply the selected profile so the mod is no longer active in the game.
3. Open **My mods**, select the mod, and choose **Delete permanently**.
4. Review the deletion preview and confirm only when the listed files are
   correct.

## Uninstallation

Before uninstalling RR Mod Manager, apply a profile with every managed mod
disabled if you want to return the game to an unmodded state.

- **Windows 11:** remove RR Mod Manager from **Settings > Apps > Installed
  apps**.
- **Linux:** close the application and delete the AppImage.

Application data and recovery backups may remain in the user's local data
directory. Keep them while any restoration is pending.

## Current Limitations

- Only Steam build `23896268` is supported.
- Nexus Mods login and managed downloads are not available.
- Automatic application and mod updates are not available.
- Unknown native UE4SS DLLs cannot be declared safe through static inspection.
- The Windows installer and Linux AppImage are not digitally signed.
- Equal-generation PAK ordering is reported as unknown when the winner cannot be
  proven safely.

## Privacy

RR Mod Manager does not use behavioral telemetry and does not automatically
upload mod lists, paths, logs, or diagnostic information. See
[PRIVACY.md](PRIVACY.md) for details.

## Version

`0.1.0`
