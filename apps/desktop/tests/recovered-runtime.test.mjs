import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const desktopRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const runtime = await readFile(resolve(desktopRoot, "src/app.js"), "utf8");

test("maps stable and localized Windows permission errors", () => {
  assert.match(runtime, /permission_denied: `errorPermissionDenied`/u);
  assert.match(runtime, /r\.includes\(`acesso negado`\)/u);
  assert.match(runtime, /r\.includes\(`os error 5`\)/u);
});

test("maps rejected Windows security attributes to the sandbox error", () => {
  assert.match(runtime, /r\.includes\(`sandbox`\)/u);
  assert.match(runtime, /r\.includes\(`process security attribute`\)/u);
  assert.match(runtime, /return t\(`errorWorkerSandbox`\)/u);
});

test("maps launch failures and only confirms a detected game start", () => {
  assert.match(runtime, /game_launch_timeout: `errorGameLaunchTimeout`/u);
  assert.match(runtime, /steam_unavailable: `errorSteamUnavailable`/u);
  assert.match(runtime, /game_launch_failed: `errorGameLaunchFailed`/u);
  assert.match(runtime, /e\.launchGame\(\), t\(`successGameStarted`\)/u);
  assert.match(runtime, /successGameStarted: `Retro Rewind iniciado com sucesso\.`/u);
});

test("validates the archive preflight contract before classifying it", () => {
  assert.match(runtime, /typeof e\.accepted !== `boolean`/u);
  assert.match(runtime, /t\.code = `worker_protocol`/u);
  assert.match(runtime, /preflightArchive = async e => validateArchivePreflight\(await xN/u);
  assert.match(runtime, /archivePreflightBlocked\(t\)\) continue/u);
});

test("uses the stable emitted Retro Rewind logo asset", () => {
  assert.match(runtime, /bN = `\/assets\/retro-rewind-logo\.png`/u);
  assert.doesNotMatch(runtime, /retro-rewind-logo-[A-Za-z0-9_-]+\.png/u);
});

test("offers manager and game bug-report subjects", () => {
  assert.match(runtime, /`RR Mod Manager`, `Retro Rewind`, \.\.\.e\.artifacts/u);
  assert.match(runtime, /subjectKind: o === `RR Mod Manager` \? `manager` : o === `Retro Rewind` \? `game` : `mod`/u);
});

test("keeps routine mod states compact", () => {
  assert.doesNotMatch(runtime, /Desative este mod em todos os perfis antes de excluí-lo\./u);
  assert.doesNotMatch(runtime, /Adicionar armazena o mod, mas não o ativa/u);
  assert.doesNotMatch(runtime, /noArchiveConflictsDetail/u);
  assert.match(runtime, /noArchiveConflicts: `Sem conflitos conhecidos`/u);
  assert.match(runtime, /color: `success`,\s*children: t\(`noArchiveConflicts`\)/u);
});
