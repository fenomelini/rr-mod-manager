import { cp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const desktopRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoot = resolve(desktopRoot, "src");
const outputRoot = resolve(desktopRoot, "dist");
const assetsRoot = resolve(outputRoot, "assets");

await rm(outputRoot, { recursive: true, force: true });
await mkdir(assetsRoot, { recursive: true });
await Promise.all([
  cp(resolve(sourceRoot, "app.js"), resolve(assetsRoot, "app.js")),
  cp(resolve(sourceRoot, "app.css"), resolve(assetsRoot, "app.css")),
  cp(resolve(sourceRoot, "assets"), assetsRoot, { recursive: true }),
]);
const html = await readFile(resolve(sourceRoot, "index.html"), "utf8");
await writeFile(resolve(outputRoot, "index.html"), html, "utf8");

const emittedSources = await Promise.all([
  readFile(resolve(outputRoot, "index.html"), "utf8"),
  readFile(resolve(assetsRoot, "app.js"), "utf8"),
  readFile(resolve(assetsRoot, "app.css"), "utf8"),
]);
const assetReferences = new Set(
  emittedSources.flatMap((source) => source.match(/\/assets\/[A-Za-z0-9._/-]+/gu) ?? []),
);
for (const reference of assetReferences) {
  const details = await stat(resolve(outputRoot, reference.slice(1))).catch(() => null);
  if (!details?.isFile()) {
    throw new Error(`desktop asset reference was not emitted: ${reference}`);
  }
}

process.stdout.write(`desktop web assets built (${assetReferences.size} references verified)\n`);
