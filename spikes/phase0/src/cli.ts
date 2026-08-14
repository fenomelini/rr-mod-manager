#!/usr/bin/env node
import { promises as fs } from "node:fs";
import path from "node:path";
import { safeNxmSummary, parseNxmUrl } from "./nxm.js";
import { analyzePakConflictEdges, discoverPakFiles, inventoryPak } from "./pak.js";
import { renderPakScanReport, type PakScanFailure } from "./report.js";
import { parseSteamAppManifest, parseSteamLibraries } from "./vdf.js";

function usage(exitCode = 2): never {
  console.error(`Usage:
  pnpm phase0 steam-manifest <appmanifest.acf>
  pnpm phase0 steam-libraries <libraryfolders.vdf>
  pnpm phase0 nxm <nxm-url>
  pnpm phase0 scan-paks --root <Content/Paks> --repak <repak> --output <report.md>`);
  process.exit(exitCode);
}

function option(args: string[], name: string): string {
  const index = args.indexOf(name);
  const value = index < 0 ? undefined : args[index + 1];
  if (value === undefined) throw new Error(`Missing ${name}`);
  return value;
}

async function main(): Promise<void> {
  const [, , command, ...args] = process.argv;
  if (command === undefined) usage();
  if (command === "--help" || command === "-h" || command === "help") usage(0);

  if (command === "steam-manifest") {
    const file = args[0];
    if (file === undefined) usage();
    console.log(JSON.stringify(parseSteamAppManifest(await fs.readFile(file, "utf8")), null, 2));
    return;
  }
  if (command === "steam-libraries") {
    const file = args[0];
    if (file === undefined) usage();
    console.log(JSON.stringify(parseSteamLibraries(await fs.readFile(file, "utf8")), null, 2));
    return;
  }
  if (command === "nxm") {
    const input = args[0];
    if (input === undefined) usage();
    console.log(JSON.stringify(safeNxmSummary(parseNxmUrl(input)), null, 2));
    return;
  }
  if (command === "scan-paks") {
    const root = path.resolve(option(args, "--root"));
    const repak = path.resolve(option(args, "--repak"));
    const output = path.resolve(option(args, "--output"));
    const archives = await discoverPakFiles(root);
    const inventories = [];
    const failures: PakScanFailure[] = [];
    for (const archive of archives) {
      try {
        inventories.push(await inventoryPak(repak, archive));
      } catch (error) {
        failures.push({ archivePath: archive, error: error instanceof Error ? error.message : String(error) });
      }
    }
    const edges = analyzePakConflictEdges(inventories, "RetroRewind-Windows.pak");
    await fs.mkdir(path.dirname(output), { recursive: true });
    await fs.writeFile(output, renderPakScanReport({ root, inventories, failures, edges }), "utf8");
    console.log(JSON.stringify({ archives: archives.length, readable: inventories.length, failures: failures.length, conflictEdges: edges.length, report: output }, null, 2));
    return;
  }
  usage();
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
