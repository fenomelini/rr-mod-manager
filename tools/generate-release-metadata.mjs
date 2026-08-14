#!/usr/bin/env node

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, readdir, stat, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
let directoryArgument = "release";
let directoryWasSet = false;
let platform = "both";
for (let index = 0; index < args.length; index += 1) {
  const argument = args[index];
  if (argument === "--platform") {
    platform = args[index + 1];
    index += 1;
  } else if (!argument.startsWith("-") && !directoryWasSet) {
    directoryArgument = argument;
    directoryWasSet = true;
  } else {
    throw new Error(`unknown release metadata argument: ${argument}`);
  }
}
if (!new Set(["windows", "linux", "both"]).has(platform)) {
  throw new Error("--platform must be windows, linux, or both");
}

const directory = resolve(directoryArgument);
const { version } = JSON.parse(await readFile(resolve(root, "package.json"), "utf8"));
const excluded = new Set(["SHA256SUMS", "release-manifest.json"]);
const entries = [];
for (const name of (await readdir(directory)).sort()) {
  if (excluded.has(name)) continue;
  const path = resolve(directory, name);
  const details = await stat(path);
  if (!details.isFile()) continue;
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  entries.push({ name, bytes: details.size, sha256: hash.digest("hex") });
}

const has = (suffix) => entries.some((entry) => entry.name.endsWith(suffix));
const versioned = entries.filter((entry) => /\.(?:AppImage|exe|zip|spdx\.json)$/u.test(entry.name));
if (versioned.some((entry) => !entry.name.includes(version))) {
  throw new Error(`every binary and SBOM filename must include version ${version}`);
}
if ((platform === "windows" || platform === "both") && !has(".exe")) {
  throw new Error("selected Windows release has no NSIS installer");
}
if ((platform === "linux" || platform === "both") && !has(".AppImage")) {
  throw new Error("selected Linux release has no AppImage");
}
if ((platform === "linux" || platform === "both") && !has(".zip")) {
  throw new Error("selected Linux release has no ZIP containing the AppImage");
}
if (!has(".spdx.json")) throw new Error("release directory has no SPDX JSON SBOM");

const platforms = platform === "both" ? ["windows", "linux"] : [platform];
await writeFile(
  resolve(directory, "SHA256SUMS"),
  `${entries.map((entry) => `${entry.sha256}  ${entry.name}`).join("\n")}\n`,
  "utf8",
);
await writeFile(
  resolve(directory, "release-manifest.json"),
  `${JSON.stringify(
    {
      schemaVersion: 2,
      product: "RR Mod Manager",
      version,
      platforms,
      supportedGameBuild: 23896268,
      artifacts: entries,
    },
    null,
    2,
  )}\n`,
  "utf8",
);
process.stdout.write(
  `wrote release metadata for ${entries.length} files (${version}; ${platforms.join(", ")})\n`,
);
