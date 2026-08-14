#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const output = resolve(root, process.argv[2] ?? "release/THIRD_PARTY_NOTICES.md");
const runJson = (command, args, env = process.env) =>
  JSON.parse(execFileSync(command, args, { cwd: root, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, env }));

const cargo = runJson("cargo", ["metadata", "--locked", "--format-version", "1"]);
const pnpm = runJson("pnpm", ["licenses", "list", "--prod", "--json"], {
  ...process.env,
  NODE_NO_WARNINGS: "1",
});

const records = new Map();
for (const pkg of cargo.packages) {
  const source = pkg.source ?? "workspace";
  records.set(`Rust\0${pkg.name}\0${pkg.version}\0${source}`, {
    ecosystem: "Rust",
    name: pkg.name,
    version: pkg.version,
    license: pkg.license ?? (pkg.license_file ? `see ${pkg.license_file}` : "not declared"),
    source,
  });
}
for (const [license, packages] of Object.entries(pnpm)) {
  for (const pkg of packages) {
    for (const version of pkg.versions ?? []) {
      const source = pkg.homepage ?? "npm registry";
      records.set(`JavaScript\0${pkg.name}\0${version}\0${source}`, {
        ecosystem: "JavaScript",
        name: pkg.name,
        version,
        license: pkg.license ?? license,
        source,
      });
    }
  }
}

const sorted = [...records.values()].sort((left, right) =>
  [left.ecosystem, left.name, left.version].join("\0").localeCompare([right.ecosystem, right.name, right.version].join("\0")),
);
const escape = (value) => String(value).replaceAll("|", "\\|").replaceAll("\n", " ");
const lines = [
  "# Third-Party Notices",
  "",
  "Generated from the locked Rust and production JavaScript dependency graphs for RR Mod Manager 0.1.2.",
  "",
  "| Ecosystem | Package | Version | Declared license | Source |",
  "| --- | --- | --- | --- | --- |",
  ...sorted.map((record) =>
    `| ${escape(record.ecosystem)} | ${escape(record.name)} | ${escape(record.version)} | ${escape(record.license)} | ${escape(record.source)} |`,
  ),
  "",
];
await mkdir(dirname(output), { recursive: true });
await writeFile(output, lines.join("\n"), "utf8");
process.stdout.write(`wrote ${sorted.length} dependency records to ${output}\n`);
