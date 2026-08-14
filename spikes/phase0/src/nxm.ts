export const RETRO_REWIND_NEXUS_DOMAIN = "retrorewindvideostoresimulator";

export interface NxmAuthorization {
  key: string;
  expires: number;
}

export interface NxmRequest {
  gameDomain: string;
  modId: number;
  fileId: number;
  authorization?: NxmAuthorization;
  userId?: number;
}

function parsePositiveInteger(value: string, label: string): number {
  if (!/^[1-9]\d*$/.test(value)) throw new Error(`Invalid ${label}`);
  const result = Number(value);
  if (!Number.isSafeInteger(result)) throw new Error(`${label} exceeds the safe integer range`);
  return result;
}

export function parseNxmUrl(input: string): NxmRequest {
  if (input.length > 4096) throw new Error("nxm URL is too long");
  const url = new URL(input);
  if (url.protocol !== "nxm:") throw new Error("Expected nxm protocol");
  if (url.username || url.password || url.hash) throw new Error("nxm URL contains forbidden credentials or fragment");
  if (url.hostname !== RETRO_REWIND_NEXUS_DOMAIN) {
    throw new Error(`Unsupported Nexus game domain: ${url.hostname}`);
  }

  const match = url.pathname.match(/^\/mods\/(\d+)\/files\/(\d+)\/?$/);
  if (match === null) throw new Error("Unsupported nxm path");
  const modText = match[1];
  const fileText = match[2];
  if (modText === undefined || fileText === undefined) throw new Error("Missing nxm identifiers");

  const allowed = new Set(["key", "expires", "user_id"]);
  const seen = new Set<string>();
  for (const [name] of url.searchParams) {
    if (!allowed.has(name)) throw new Error(`Unsupported nxm query parameter: ${name}`);
    if (seen.has(name)) throw new Error(`Duplicate nxm query parameter: ${name}`);
    seen.add(name);
  }

  const key = url.searchParams.get("key");
  const expiresText = url.searchParams.get("expires");
  if ((key === null) !== (expiresText === null)) {
    throw new Error("nxm key and expires must be supplied together");
  }
  if (key !== null && (key.length < 8 || key.length > 512)) throw new Error("Invalid nxm authorization key");

  const userIdText = url.searchParams.get("user_id");
  return {
    gameDomain: url.hostname,
    modId: parsePositiveInteger(modText, "mod ID"),
    fileId: parsePositiveInteger(fileText, "file ID"),
    ...(key === null || expiresText === null
      ? {}
      : {
          authorization: {
            key,
            expires: parsePositiveInteger(expiresText, "expiry"),
          },
        }),
    ...(userIdText === null ? {} : { userId: parsePositiveInteger(userIdText, "user ID") }),
  };
}

export function safeNxmSummary(request: NxmRequest): Record<string, string | number | boolean> {
  return {
    gameDomain: request.gameDomain,
    modId: request.modId,
    fileId: request.fileId,
    hasAuthorization: request.authorization !== undefined,
    ...(request.userId === undefined ? {} : { userId: request.userId }),
  };
}
