#!/usr/bin/env node

import { chmod, copyFile, mkdir } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const root = resolve(dirname(scriptPath), "..");

export function sidecarFileName(binary, target) {
  const extension = target.includes("windows") ? ".exe" : "";
  return `${binary}-${target}${extension}`;
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    stdio: options.capture ? "pipe" : "inherit",
  });
  if (result.status !== 0) {
    if (options.capture) process.stderr.write(result.stderr ?? "");
    process.exit(result.status ?? 1);
  }
  return result.stdout ?? "";
}

function hostTarget() {
  const output = run("rustc", ["-vV"], { capture: true });
  const host = output
    .split(/\r?\n/u)
    .find((line) => line.startsWith("host: "))
    ?.slice("host: ".length);
  if (!host) throw new Error("failed to determine Rust host target");
  return host;
}

async function main() {
  const profile = process.argv[2] ?? "release";
  if (profile !== "debug" && profile !== "release") {
    throw new Error("usage: prepare-desktop-sidecars.mjs [debug|release] [target]");
  }
  const explicitTarget = process.argv[3];
  const target = explicitTarget ?? hostTarget();
  const cargoArgs = [
    "build",
    "--locked",
    "--package",
    "rrmm-archive-worker",
    "--package",
    "rrmm-pak-worker",
  ];
  if (profile === "release") cargoArgs.push("--release");
  if (explicitTarget) cargoArgs.push("--target", target);
  run("cargo", cargoArgs);

  const outputRoot = explicitTarget
    ? resolve(root, "target", target, profile)
    : resolve(root, "target", profile);
  const destination = resolve(root, "apps", "desktop", "src-tauri", "binaries");
  const sourceExtension = target.includes("windows") ? ".exe" : "";
  await mkdir(destination, { recursive: true });
  for (const binary of ["rrmm-archive-worker", "rrmm-pak-worker"]) {
    const source = resolve(outputRoot, `${binary}${sourceExtension}`);
    const targetPath = resolve(destination, sidecarFileName(binary, target));
    await copyFile(source, targetPath);
    if (process.platform !== "win32") await chmod(targetPath, 0o755);
  }
  process.stdout.write(`prepared desktop sidecars for ${target} (${profile})\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(scriptPath)) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  });
}
