#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { sidecarFileName } from "./prepare-desktop-sidecars.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const readJson = async (path) => JSON.parse(await readFile(resolve(root, path), "utf8"));
const base = await readJson("apps/desktop/src-tauri/tauri.conf.json");
const windows = await readJson("apps/desktop/src-tauri/tauri.windows.conf.json");

const expectedExternalBins = [
  "binaries/rrmm-archive-worker",
  "binaries/rrmm-pak-worker",
];
if (JSON.stringify(base.bundle.externalBin) !== JSON.stringify(expectedExternalBins)) {
  throw new Error("Tauri externalBin must contain the two unqualified worker base names");
}
if (JSON.stringify(windows.bundle.targets) !== JSON.stringify(["nsis"])) {
  throw new Error("the Windows bundle target must be NSIS only");
}
if (windows.bundle.windows?.nsis?.installMode !== "currentUser") {
  throw new Error("the Windows installer must use current-user mode");
}
if (windows.bundle.windows?.allowDowngrades !== true) {
  throw new Error("the Windows installer must allow replacement of accidental higher-version test builds");
}
const windowsTarget = "x86_64-pc-windows-msvc";
for (const binary of ["rrmm-archive-worker", "rrmm-pak-worker"]) {
  if (sidecarFileName(binary, windowsTarget) !== `${binary}-${windowsTarget}.exe`) {
    throw new Error(`incorrect Windows sidecar name for ${binary}`);
  }
  if (sidecarFileName(binary, "x86_64-unknown-linux-gnu").endsWith(".exe")) {
    throw new Error(`incorrect Linux sidecar name for ${binary}`);
  }
}

process.stdout.write("desktop packaging configuration is consistent\n");
