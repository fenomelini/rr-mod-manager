# Terminology

- Artifact: immutable imported or downloaded file identified by SHA-256.
- Package: normalized installable mod version derived from one artifact.
- Component: one deployable unit such as a PAK or UE4SS module.
- Profile: selected package versions, variants, and deployment decisions.
- Virtual path: effective Unreal member path after applying the PAK mount point.
- Cooked package: `.uasset` or `.umap` plus compatible sidecars.
- Conflict edge: two components competing for one resource or invariant.
- Winner: content that the effective runtime priority selects.
- Suppressed effect: behavior hidden because another package wins.
- Ordered with loss: deterministic winner without preservation of both effects.
- Compatibility patch: exact combined artifact preserving declared effects.
- Recipe: signed declarative knowledge for exact artifacts and builds.
- Inferred manifest: local scanner output, not author-declared intent.
- Managed file: deployed path with an RR Mod Manager ownership receipt.
- Unmanaged file: existing game file with no RR Mod Manager ownership receipt.
- Drift: managed path no longer matching the deployed receipt.
- Runtime-verified: behavior confirmed in the supported game build.
- Native unverified: code with unrestricted process access that static inspection
  cannot establish as safe.
