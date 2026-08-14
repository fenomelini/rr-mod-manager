import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { compileContract, formatContractErrors } from "../src/contracts.js";

const root = fileURLToPath(new URL("../../..", import.meta.url));

function json(relativePath: string): object {
  return JSON.parse(readFileSync(`${root}/${relativePath}`, "utf8")) as object;
}

describe("Phase 0 contracts", () => {
  it("accepts the manifest fixture and rejects an unsupported app", () => {
    const validate = compileContract(json("schemas/manifest.schema.json"));
    const manifest = json("fixtures/manifest.valid.json");
    expect(validate(manifest), formatContractErrors(validate).join("; ")).toBe(true);
    expect(validate({ ...manifest, game: { steam_app_id: 1, supported_build_ids: ["1"], unreal_engine: "5.4.4" } })).toBe(false);
    expect(validate({ ...manifest, source: { provider: "other", url: "not a URL" } })).toBe(false);
  });

  it("accepts an exact-hash compatibility recipe", () => {
    const validate = compileContract(json("schemas/recipe.schema.json"));
    expect(validate(json("fixtures/recipe.valid.json")), formatContractErrors(validate).join("; ")).toBe(true);
    expect(
      validate(json("recipes/compatibility/23896268/unrewound-tape-fee--employee-fee-policy.json")),
      formatContractErrors(validate).join("; "),
    ).toBe(true);
  });

  it("accepts authored package manifests", () => {
    const validate = compileContract(json("schemas/manifest.schema.json"));
    const manifests = [
      "manifests/unrewound-tape-fee/1.0.0/rrmm-manifest.json",
      "manifests/employee-fee-policy/1.0.0/rrmm-manifest.json",
      "manifests/unrewound-tape-fee-employee-fee-policy/1.0.0/rrmm-manifest.json",
    ];
    for (const manifest of manifests) {
      expect(validate(json(manifest)), `${manifest}: ${formatContractErrors(validate).join("; ")}`).toBe(true);
    }
  });
});
