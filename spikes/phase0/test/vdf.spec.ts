import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseSteamAppManifest, parseSteamLibraries, parseVdf } from "../src/vdf.js";

const root = fileURLToPath(new URL("../../..", import.meta.url));

describe("VDF parser", () => {
  it("parses the supported Retro Rewind manifest", () => {
    const content = readFileSync(`${root}/fixtures/steam/appmanifest_3552140.acf`, "utf8");
    expect(parseSteamAppManifest(content)).toEqual({
      appId: 3552140,
      buildId: "23896268",
      installDir: "RetroRewind",
      stateFlags: "4",
    });
  });

  it("discovers libraries and app membership", () => {
    const content = readFileSync(`${root}/fixtures/steam/libraryfolders.vdf`, "utf8");
    expect(parseSteamLibraries(content)).toEqual([
      { path: "C:\\Program Files (x86)\\Steam", containsExpectedApp: true },
      { path: "D:\\SteamLibrary", containsExpectedApp: false },
    ]);
  });

  it("supports comments and escaped quotes", () => {
    expect(parseVdf('// comment\n"root" { "value" "a\\\"b" }')).toEqual({
      root: { value: 'a"b' },
    });
  });

  it("rejects malformed and wrong-app manifests", () => {
    expect(() => parseVdf('"root" { "missing" "brace"')).toThrow("Unterminated VDF object");
    expect(() => parseSteamAppManifest('"AppState" { "appid" "1" "buildid" "2" "installdir" "x" }')).toThrow("Expected Steam App ID");
  });
});
