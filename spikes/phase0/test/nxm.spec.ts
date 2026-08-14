import { describe, expect, it } from "vitest";
import { parseNxmUrl, safeNxmSummary } from "../src/nxm.js";

describe("nxm parser", () => {
  it("parses a free-user handoff while keeping authorization out of summaries", () => {
    const request = parseNxmUrl("nxm://retrorewindvideostoresimulator/mods/123/files/456?key=supersecret&expires=1999999999&user_id=42");
    expect(request.authorization).toEqual({ key: "supersecret", expires: 1999999999 });
    expect(safeNxmSummary(request)).toEqual({
      gameDomain: "retrorewindvideostoresimulator",
      modId: 123,
      fileId: 456,
      hasAuthorization: true,
      userId: 42,
    });
    expect(JSON.stringify(safeNxmSummary(request))).not.toContain("supersecret");
  });

  it("accepts a known-file handoff without free-user authorization", () => {
    expect(parseNxmUrl("nxm://retrorewindvideostoresimulator/mods/1/files/2")).toMatchObject({
      modId: 1,
      fileId: 2,
    });
  });

  it("rejects other games, duplicates, partial authorization, and unknown fields", () => {
    expect(() => parseNxmUrl("nxm://skyrim/mods/1/files/2")).toThrow("Unsupported Nexus game domain");
    expect(() => parseNxmUrl("nxm://retrorewindvideostoresimulator/mods/1/files/2?key=abcdefgh&key=ijklmnop&expires=1")).toThrow("Duplicate");
    expect(() => parseNxmUrl("nxm://retrorewindvideostoresimulator/mods/1/files/2?key=abcdefgh")).toThrow("supplied together");
    expect(() => parseNxmUrl("nxm://retrorewindvideostoresimulator/mods/1/files/2?token=nope")).toThrow("Unsupported nxm query parameter");
  });
});
