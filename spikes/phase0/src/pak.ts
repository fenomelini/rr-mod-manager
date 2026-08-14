import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import type { PakPriorityHint } from "./domain.js";

const execFileAsync = promisify(execFile);
const PACKAGE_EXTENSIONS = new Set([".uasset", ".umap", ".uexp", ".ubulk", ".uptnl"]);

export interface PakInventory {
  archivePath: string;
  archiveName: string;
  priority: PakPriorityHint;
  members: string[];
  packages: Record<string, string[]>;
}

export interface PakConflictEdge {
  first: string;
  second: string;
  overlappingMembers: number;
  overlappingPackages: number;
}

export function parsePakPriorityHint(filename: string): PakPriorityHint {
  if (!filename.endsWith("_P.pak")) {
    return { patchGeneration: 0, patchIncrement: 0, confidence: "no-patch-suffix" };
  }
  const explicit = filename.match(/_(\d+)_P\.pak$/);
  const explicitNumber = explicit?.[1] === undefined ? undefined : Number(explicit[1]);
  const patchGeneration = explicitNumber !== undefined && explicitNumber > 0 ? explicitNumber + 1 : 1;
  return {
    patchGeneration,
    patchIncrement: patchGeneration * 100,
    ...(explicitNumber === undefined ? {} : { explicitNumber }),
    confidence: "observed-build-rule",
  };
}

export function normalizePakMember(member: string): string {
  const normalized = member.replaceAll("\\", "/").replace(/^\.\//, "");
  if (normalized.length === 0 || normalized.startsWith("/") || /^[A-Za-z]:\//.test(normalized)) {
    throw new Error(`Invalid absolute PAK member: ${member}`);
  }
  const segments = normalized.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
    throw new Error(`Invalid traversing PAK member: ${member}`);
  }
  return normalized;
}

export function packageKey(member: string): string | undefined {
  const extension = path.posix.extname(member).toLowerCase();
  if (!PACKAGE_EXTENSIONS.has(extension)) return undefined;
  return member.slice(0, -extension.length).toLowerCase();
}

export async function inventoryPak(repakPath: string, archivePath: string): Promise<PakInventory> {
  const { stdout } = await execFileAsync(repakPath, ["list", archivePath], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  const members = stdout
    .split(/\r?\n/)
    .filter((line) => line.length > 0)
    .map(normalizePakMember);
  const caseFolded = new Set<string>();
  for (const member of members) {
    const key = member.toLowerCase();
    if (caseFolded.has(key)) throw new Error(`Case-insensitive duplicate PAK member: ${member}`);
    caseFolded.add(key);
  }

  const packages: Record<string, string[]> = {};
  for (const member of members) {
    const key = packageKey(member);
    if (key === undefined) continue;
    (packages[key] ??= []).push(member);
  }
  const archiveName = path.basename(archivePath);
  return {
    archivePath,
    archiveName,
    priority: parsePakPriorityHint(archiveName),
    members,
    packages,
  };
}

export async function discoverPakFiles(root: string): Promise<string[]> {
  const results: string[] = [];
  async function visit(directory: string): Promise<void> {
    const entries = await fs.readdir(directory, { withFileTypes: true });
    entries.sort((first, second) => first.name.localeCompare(second.name));
    for (const entry of entries) {
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) await visit(fullPath);
      else if (entry.isFile() && entry.name.toLowerCase().endsWith(".pak")) results.push(fullPath);
    }
  }
  await visit(root);
  return results;
}

export function analyzePakConflictEdges(inventories: PakInventory[], ignoredArchive?: string): PakConflictEdge[] {
  const memberSources = new Map<string, Set<string>>();
  const packageSources = new Map<string, Set<string>>();
  for (const inventory of inventories) {
    if (inventory.archiveName === ignoredArchive) continue;
    for (const member of inventory.members) {
      const sources = memberSources.get(member.toLowerCase()) ?? new Set<string>();
      sources.add(inventory.archivePath);
      memberSources.set(member.toLowerCase(), sources);
    }
    for (const key of Object.keys(inventory.packages)) {
      const sources = packageSources.get(key) ?? new Set<string>();
      sources.add(inventory.archivePath);
      packageSources.set(key, sources);
    }
  }

  const pairs = new Map<string, PakConflictEdge>();
  function addPair(firstPath: string, secondPath: string, field: "overlappingMembers" | "overlappingPackages"): void {
    const ordered = [firstPath, secondPath].sort();
    const first = ordered[0];
    const second = ordered[1];
    if (first === undefined || second === undefined) return;
    const key = `${first}\0${second}`;
    const edge = pairs.get(key) ?? { first, second, overlappingMembers: 0, overlappingPackages: 0 };
    edge[field] += 1;
    pairs.set(key, edge);
  }

  for (const sources of memberSources.values()) {
    const list = [...sources];
    for (let first = 0; first < list.length; first += 1) {
      for (let second = first + 1; second < list.length; second += 1) {
        const firstPath = list[first];
        const secondPath = list[second];
        if (firstPath !== undefined && secondPath !== undefined) addPair(firstPath, secondPath, "overlappingMembers");
      }
    }
  }
  for (const sources of packageSources.values()) {
    const list = [...sources];
    for (let first = 0; first < list.length; first += 1) {
      for (let second = first + 1; second < list.length; second += 1) {
        const firstPath = list[first];
        const secondPath = list[second];
        if (firstPath !== undefined && secondPath !== undefined) addPair(firstPath, secondPath, "overlappingPackages");
      }
    }
  }
  return [...pairs.values()].sort((first, second) =>
    second.overlappingPackages - first.overlappingPackages
    || second.overlappingMembers - first.overlappingMembers
    || first.first.localeCompare(second.first)
    || first.second.localeCompare(second.second));
}
