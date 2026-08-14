#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const production = process.argv.slice(2).includes("--production");
const expectedVersion = "0.1.2";

const readText = (path) => readFile(resolve(root, path), "utf8");
const readJson = async (path) => JSON.parse(await readText(path));
const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const cargo = await readText("Cargo.toml");
const cargoVersion = cargo.match(/\[workspace\.package\][\s\S]*?\nversion\s*=\s*"([^"]+)"/u)?.[1];
assert(cargoVersion === expectedVersion, `workspace version must remain ${expectedVersion}`);

for (const path of [
  "package.json",
  "apps/desktop/package.json",
  "apps/desktop/src-tauri/tauri.conf.json",
]) {
  const value = await readJson(path);
  assert(value.version === expectedVersion, `${path} version must remain ${expectedVersion}`);
}

const demoSource = await readText("apps/desktop/src/app.js");
assert(
  demoSource.includes(`appVersion: \`${expectedVersion}\``),
  `desktop demo version must remain ${expectedVersion}`,
);
assert(
  !demoSource.match(/appVersion:\s*`[^`]*-/u),
  "desktop demo version must not use a prerelease suffix",
);

const windows = await readJson("apps/desktop/src-tauri/tauri.windows.conf.json");
assert(JSON.stringify(windows.bundle?.targets) === JSON.stringify(["nsis"]), "Windows must bundle NSIS only");
assert(windows.bundle?.windows?.nsis?.installMode === "currentUser", "NSIS must use current-user installation");
assert(windows.bundle?.windows?.allowDowngrades === true, "Windows test builds must allow version correction");

const desktopSource = await readText("crates/rrmm-application/src/desktop.rs");
assert(
  desktopSource.includes('package.manifest.id != "local:smart-shelf-organizer"'),
  "the non-public Smart Shelf Organizer prototype must stay out of the desktop catalog",
);

for (const path of [
  "SECURITY.md",
  "PRIVACY.md",
  "docs/BETA_TESTING.md",
  "docs/RELEASING.md",
  "docs/RELEASE_0.1.2.md",
  "docs/RELEASE_0.1.2_CHECKLIST.md",
]) {
  await readText(path);
}

const releaseWorkflow = await readText(".github/workflows/release-candidate.yml");
assert(!releaseWorkflow.includes("0.1.3"), "release workflow must not contain the unpublished 0.1.3 version");
assert(releaseWorkflow.includes("platform:"), "release workflow must expose a platform selector");
for (const platform of ["windows", "linux", "both"]) {
  assert(releaseWorkflow.includes(`- ${platform}`), `release workflow must support ${platform}`);
}
assert(
  releaseWorkflow.includes("tools/build-windows-unsigned-release.ps1"),
  "Windows release must use the explicit unsigned build contract",
);
assert(
  releaseWorkflow.includes("pnpm desktop:test:windows:launch") &&
    releaseWorkflow.includes("pnpm desktop:test:windows:ue4ss") &&
    releaseWorkflow.includes("pnpm desktop:test:windows:archive"),
  "Windows release must run launch tests and both real-worker end-to-end flows",
);
assert(
  releaseWorkflow.includes("actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"),
  "release artifacts must receive a pinned GitHub artifact attestation",
);
assert(
  !/uses:\s+[^\s]+@(v\d+|main|master)\b/u.test(releaseWorkflow),
  "release workflow actions must use immutable commit SHAs",
);

const metadataGenerator = await readText("tools/generate-release-metadata.mjs");
assert(metadataGenerator.includes('schemaVersion: 2'), "release manifest schema must remain version 2");
assert(metadataGenerator.includes('--platform'), "release metadata must support selective platforms");

if (production) {
  const roots = await readJson("trust/production-roots.json");
  const rootMetadata = await readJson("catalogs/signed/root-metadata.json");
  const recipeCatalog = await readJson("catalogs/signed/recipe-catalog.json");
  assert(Array.isArray(roots), "production trust roots must be an array");
  if (roots.length === 0) {
    assert(rootMetadata.signed?.online_keys?.length === 0, "placeholder root metadata must not authorize online keys");
    assert(rootMetadata.signatures?.length === 0, "placeholder root metadata must not contain signatures");
    assert(recipeCatalog.signed?.recipes?.length === 0, "an unsigned recipe catalog must stay empty");
    assert(recipeCatalog.signatures?.length === 0, "an unsigned recipe catalog must not contain signatures");
  } else {
    assert(rootMetadata.signed?.online_keys?.length > 0, "signed root metadata has no production online key");
    assert(rootMetadata.signatures?.length > 0, "signed root metadata has no production signature");
    assert(recipeCatalog.signed?.recipes?.length > 0, "signed recipe catalog is still a placeholder");
    assert(recipeCatalog.signatures?.length > 0, "signed recipe catalog has no production signature");
  }
}

process.stdout.write(
  production
    ? `production release contract is ready for cryptographic build verification (${expectedVersion})\n`
    : `release contract is consistent (${expectedVersion})\n`,
);
