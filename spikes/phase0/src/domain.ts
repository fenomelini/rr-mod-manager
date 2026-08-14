export const CONFLICT_CODES = {
  A0: "Archive unreadable, encrypted, or mounted outside the expected root",
  A1: "PAK discovered beneath a directory that appears disabled",
  P0: "No overlapping package or resource",
  P1: "Byte-identical duplicate content",
  P2: "Different non-package files at one virtual path",
  P3: "Different complete replacements of one cooked package",
  P4: "Package sidecars selected from incompatible sources",
  P5: "Verified partial override from an exact base",
  P6: "Declared derivative or supersedence relationship",
  P7: "Semantic DataTable or localization merge candidate",
  P8: "Same Blueprint export or function changed",
  I0: "IoStore analysis required",
  L0: "Duplicate observer hook with no detected shared mutation",
  L1: "Duplicate mutating hook",
  L2: "Competing workflow ownership",
  L3: "Same reflected property write",
  L4: "Persistent SaveGame field overlap",
  K0: "Exact key chord collision",
  K1: "Same base key with different modifiers",
  X0: "PAK replaces a package targeted by a Lua hook",
  N0: "Unverified native DLL",
  N1: "Native proxy, detour, or address collision",
  B0: "Unsupported game, engine, or UE4SS build",
} as const;

export type ConflictCode = keyof typeof CONFLICT_CODES;

export type ConflictResolution =
  | "SAFE"
  | "BENIGN_DUPLICATE"
  | "ORDERABLE_WITH_LOSS"
  | "ORDERABLE_DEPENDENCY"
  | "PATCH_REQUIRED"
  | "CONFIG_REMAP_REQUIRED"
  | "UNSAFE"
  | "UNKNOWN";

export interface ConflictFinding {
  code: ConflictCode;
  resolution: ConflictResolution;
  resource: string;
  sources: string[];
  explanation: string;
}

export interface ObservedPakComponent {
  archivePath: string;
  memberCount: number;
  packageCount: number;
  priority: PakPriorityHint;
}

export interface PakPriorityHint {
  patchGeneration: number;
  patchIncrement: number;
  explicitNumber?: number;
  confidence: "observed-build-rule" | "no-patch-suffix";
}
