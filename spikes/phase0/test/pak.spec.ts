import { describe, expect, it } from "vitest";
import { analyzePakConflictEdges, normalizePakMember, packageKey, parsePakPriorityHint, type PakInventory } from "../src/pak.js";

function inventory(archivePath: string, members: string[]): PakInventory {
  const packages: Record<string, string[]> = {};
  for (const member of members) {
    const key = packageKey(member);
    if (key !== undefined) (packages[key] ??= []).push(member);
  }
  return {
    archivePath,
    archiveName: archivePath.split("/").at(-1) ?? archivePath,
    priority: parsePakPriorityHint(archivePath),
    members,
    packages,
  };
}

describe("PAK Phase 0 model", () => {
  it("parses observed patch-priority suffixes", () => {
    expect(parsePakPriorityHint("Example_P.pak")).toMatchObject({ patchGeneration: 1, patchIncrement: 100 });
    expect(parsePakPriorityHint("Example_2301_P.pak")).toMatchObject({ patchGeneration: 2302, patchIncrement: 230200, explicitNumber: 2301 });
    expect(parsePakPriorityHint("Example_9999_P.pak")).toMatchObject({ patchGeneration: 10000, patchIncrement: 1000000 });
    expect(parsePakPriorityHint("Example.pak")).toMatchObject({ patchGeneration: 0, patchIncrement: 0 });
  });

  it("normalizes safe members and rejects traversal", () => {
    expect(normalizePakMember("RetroRewind\\Content\\Foo.uasset")).toBe("RetroRewind/Content/Foo.uasset");
    expect(() => normalizePakMember("../Foo.uasset")).toThrow("traversing");
    expect(() => normalizePakMember("C:/Foo.uasset")).toThrow("absolute");
  });

  it("groups package sidecars and creates deterministic conflict edges", () => {
    expect(packageKey("RetroRewind/Content/Foo.uexp")).toBe("retrorewind/content/foo");
    const edges = analyzePakConflictEdges([
      inventory("/mods/A_P.pak", ["RetroRewind/Content/Foo.uasset", "RetroRewind/Content/Foo.uexp"]),
      inventory("/mods/B_P.pak", ["RetroRewind/Content/Foo.uasset", "RetroRewind/Content/Foo.uexp"]),
      inventory("/mods/C_P.pak", ["RetroRewind/Content/Bar.uasset"]),
    ]);
    expect(edges).toEqual([
      {
        first: "/mods/A_P.pak",
        second: "/mods/B_P.pak",
        overlappingMembers: 2,
        overlappingPackages: 1,
      },
    ]);
  });
});
