# Phase 5 Package Manifests

## Scope

The current Phase 5 foundation defines strict package metadata, conservative
local inference, and deterministic requirement and variant resolution. Signed
compatibility recipes are described in [`RECIPES.md`](RECIPES.md). Deployment
materialization currently supports verified PAK and non-native UE4SS components.

## Validation

Authored package manifests live under
`manifests/<package-slug>/<version>/rrmm-manifest.json`. Stable IDs use a source
namespace such as `nexus:unrewound-tape-fee`; versions and provider IDs remain
separate fields. `catalogs/packages/<build-id>.json` binds those manifests to
exact importable artifact hashes. Catalog copies are tested for exact equality
with their source manifests to prevent authoring drift.

`manifest-validate` parses with unknown-field rejection and then applies
semantic validation that JSON Schema cannot express fully. It validates:

- Schema version, package/component IDs, text bounds, and exact App ID.
- Nonzero canonical build IDs and Unreal Engine `5.4.4`.
- Normalized, traversal-free component roots and install names.
- Lowercase SHA-256 values and required PAK hashes.
- Unique cross-platform PAK and UE4SS install names.
- Variant component references and a single optional default variant.
- Package and one-of requirements, incompatibilities, and replacements.
- Optional normalized named UE4SS loader policy requirements.
- Nexus source fields and absolute HTTP/HTTPS source URLs.

```bash
rrmm manifest-validate --manifest rrmm-manifest.json
```

The JSON Schema is the structural authoring contract. Rust semantic validation
is authoritative for platform path rules such as Windows reserved names.

## Inference

Inference accepts an immutable artifact directory created by `archive-import`,
not an arbitrary extraction report. Before inference, RRMM revalidates the
artifact manifest, source archive, every stored payload hash, normalized paths,
file counts, and expanded byte count.

For the desktop workflow, an embedded `rrmm-manifest.json` is optional and the
authored package catalog does not decide whether an imported mod can be used.
Every archive receives the same deterministic local inspection based on its
actual files. Safe PAK and non-native UE4SS layouts receive local deployment
metadata bound to the archive SHA-256. The user must explicitly confirm enabling
a locally inspected package.

```bash
rrmm manifest-infer \
  --artifact-root RRModManager/artifacts/aa/<artifact-sha256> \
  --id local:example \
  --name Example \
  --version 1.0.0 \
  --build-id 23896268
```

Recognized PAKs and UE4SS module roots become components. Documentation may be
omitted from deployment. Every other artifact file becomes an explicit issue
and lowers confidence. Hybrid and native/executable packages also require
review.

The output is a `CatalogPackage` with exact artifact SHA-256 and provenance:

```json
{
  "artifact_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "manifest": {},
  "provenance": {
    "kind": "inferred",
    "confidence": "high",
    "reviewed": false,
    "issues": []
  }
}
```

An inferred record with `reviewed: false` always produces an
`unreviewed_inference` blocker. Confidence is structural evidence, not author
intent. The desktop creates a reviewed local record only for its narrow safe
layout policy and requires confirmation when that package is enabled. Signed
recipe application remains stricter and does not trust this desktop-local
review.

## Resolution

`manifest-resolve` receives a build ID, exact artifact selections, and a catalog
array. Catalog records use either declared provenance:

```json
{ "kind": "declared" }
```

or the inferred provenance shown above.

```bash
rrmm manifest-resolve --request resolve-request.json --catalog catalog.json
```

The resolver:

- Selects components required by the package and chosen variant.
- Applies the sole default variant or requires an explicit choice.
- Adds a requirement automatically only when one exact build-compatible
  artifact can satisfy it.
- Allows replacement packages to satisfy requirements for replaced IDs.
- Blocks missing and ambiguous requirements, conflicting variant selections,
  incompatible packages, replacement/original coexistence, dependency cycles,
  unsupported builds, and unreviewed inference.
- Revalidates all one-of targets after dependency closure so a late second
  alternative cannot silently change the result.

`ready: true` means package selection is internally resolvable. It does not by
itself prove that recipes were applied or that a deployment plan was
materialized; `recipe-deploy-preview` performs those additional checks.

## UE4SS Runtime Requirement

An authored package that can select a UE4SS component declares one named exact
loader policy when that module needs a constrained loader build:

```json
"runtime_requirements": {
  "ue4ss_loader_policy": "ue4ss:smart-shelf-662df915-compatible"
}
```

The field names a build-recipe policy; it is not a version range and cannot
contain a minimum Git SHA. During recipe deployment, every selected UE4SS
package must declare a policy, even if its manifest omitted the optional field
for compatibility with older PAK-only records. The deployment gate permits only
an exact proxy/core pair listed by every required policy. Unselected optional
UE4SS components impose no runtime gate.
