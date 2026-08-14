export type VdfValue = string | VdfObject;
export interface VdfObject {
  [key: string]: VdfValue;
}

type Token = string | "{" | "}";

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let index = 0;

  while (index < input.length) {
    const char = input[index];
    if (char === undefined) break;
    if (/\s/.test(char)) {
      index += 1;
      continue;
    }
    if (char === "/" && input[index + 1] === "/") {
      index += 2;
      while (index < input.length && input[index] !== "\n") index += 1;
      continue;
    }
    if (char === "{" || char === "}") {
      tokens.push(char);
      index += 1;
      continue;
    }
    if (char !== '"') throw new Error(`Unexpected VDF character at ${index}`);

    index += 1;
    let value = "";
    let closed = false;
    while (index < input.length) {
      const current = input[index];
      if (current === undefined) break;
      if (current === '"') {
        index += 1;
        closed = true;
        break;
      }
      if (current === "\\") {
        const escaped = input[index + 1];
        if (escaped === undefined) throw new Error("Unterminated VDF escape");
        const replacements: Record<string, string> = {
          "\\": "\\",
          '"': '"',
          n: "\n",
          r: "\r",
          t: "\t",
        };
        value += replacements[escaped] ?? escaped;
        index += 2;
        continue;
      }
      value += current;
      index += 1;
    }
    if (!closed) throw new Error("Unterminated VDF string");
    tokens.push(value);
  }

  return tokens;
}

export function parseVdf(input: string): VdfObject {
  const tokens = tokenize(input);
  let index = 0;

  function parseObject(expectClosingBrace: boolean): VdfObject {
    const result: VdfObject = {};
    while (index < tokens.length) {
      const key = tokens[index];
      if (key === "}") {
        if (!expectClosingBrace) throw new Error("Unexpected VDF closing brace");
        index += 1;
        return result;
      }
      if (key === "{" || key === undefined) throw new Error("Expected VDF key");
      index += 1;

      const value = tokens[index];
      if (value === undefined || value === "}") throw new Error(`Missing VDF value for ${key}`);
      if (value === "{") {
        index += 1;
        result[key] = parseObject(true);
      } else {
        result[key] = value;
        index += 1;
      }
    }
    if (expectClosingBrace) throw new Error("Unterminated VDF object");
    return result;
  }

  const result = parseObject(false);
  if (index !== tokens.length) throw new Error("Unexpected trailing VDF tokens");
  return result;
}

function objectValue(parent: VdfObject, key: string): VdfObject | undefined {
  const value = parent[key];
  return value !== null && typeof value === "object" ? value : undefined;
}

function stringValue(parent: VdfObject, key: string): string | undefined {
  const value = parent[key];
  return typeof value === "string" ? value : undefined;
}

export interface SteamAppManifest {
  appId: number;
  buildId: string;
  installDir: string;
  stateFlags?: string;
}

export function parseSteamAppManifest(input: string, expectedAppId = 3552140): SteamAppManifest {
  const root = parseVdf(input);
  const appState = objectValue(root, "AppState");
  if (appState === undefined) throw new Error("Steam manifest has no AppState object");

  const appIdText = stringValue(appState, "appid");
  const buildId = stringValue(appState, "buildid");
  const installDir = stringValue(appState, "installdir");
  if (appIdText === undefined || !/^\d+$/.test(appIdText)) throw new Error("Invalid Steam app ID");
  if (buildId === undefined || !/^\d+$/.test(buildId)) throw new Error("Invalid Steam build ID");
  if (installDir === undefined || installDir.length === 0) throw new Error("Missing Steam install directory");

  const appId = Number(appIdText);
  if (appId !== expectedAppId) throw new Error(`Expected Steam App ID ${expectedAppId}, got ${appId}`);

  const stateFlags = stringValue(appState, "StateFlags");
  return {
    appId,
    buildId,
    installDir,
    ...(stateFlags === undefined ? {} : { stateFlags }),
  };
}

export interface SteamLibrary {
  path: string;
  containsExpectedApp: boolean;
}

export function parseSteamLibraries(input: string, expectedAppId = 3552140): SteamLibrary[] {
  const root = parseVdf(input);
  const folders = objectValue(root, "libraryfolders");
  if (folders === undefined) throw new Error("Steam library file has no libraryfolders object");

  const libraries: SteamLibrary[] = [];
  for (const value of Object.values(folders)) {
    if (typeof value === "string") {
      libraries.push({ path: value, containsExpectedApp: false });
      continue;
    }
    const libraryPath = stringValue(value, "path");
    if (libraryPath === undefined || libraryPath.length === 0) continue;
    const apps = objectValue(value, "apps");
    libraries.push({
      path: libraryPath,
      containsExpectedApp: apps?.[String(expectedAppId)] !== undefined,
    });
  }
  return libraries;
}
