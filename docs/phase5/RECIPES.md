# Phase 5 Compatibility Recipes

## Boundary

Compatibility recipes are declarative data. They cannot run scripts, execute
processes, rewrite arbitrary cooked assets, or modify downloaded Lua. Every
recipe is build-specific and matches exact package IDs and source artifact
SHA-256 values.

Supported operations are:

- Select one exact matched package as winner for a normalized resource path.
- Replace at least two exact matched packages with one exact combined artifact.
- Require a collision-free PAK install filename for one exact matched package.
- Disable one selected component with a reviewable reason.

Unknown fields, unmatched targets, traversal, duplicate hashes, unsafe install
names, overlapping recipes, conflicting winners, and filename collisions are
rejected.

```bash
rrmm recipe-validate --recipe compatibility-recipe.json
```

Validation alone never authorizes an unsigned recipe for application.

## Trust Model

RRMM uses two Ed25519 layers:

1. A pinned offline root key signs root metadata.
2. Root metadata delegates time-bounded online signing keys.
3. An online key signs a recipe catalog with issue time, expiry, and increasing
   sequence.

Signatures cover a type-specific context prefix plus compact serialization of
the strict typed payload. This prevents a root signature from being reused as a
catalog signature. Unknown operation fields are rejected before verification,
preventing split-parser interpretations.

The CLI loads trusted roots embedded at build time. Debug builds additionally
accept `--trusted-roots` for development and key-ceremony testing; release
builds hide and reject that override. Production builds require at least one
offline-generated public root in `trust/production-roots.json`. No private
signing key belongs in this repository.

The separate `rrmm-catalog-author` binary implements the tested generation-1
bootstrap, authenticated catalog updates, and emergency online-key revocation
without adding any private-key input path to the runtime CLI. See
[`KEY_CEREMONY.md`](KEY_CEREMONY.md).

## Rollback State

SQLite schema 6 stores the accepted root generation, root payload hash, catalog
sequence, and catalog payload hash under the fixed `stable` channel. A lower
version is rejected. A different payload at an accepted generation or sequence
is also rejected. Catalog sequence is monotonic within a root generation. A
higher authenticated root generation starts a new sequence epoch, allowing a
revocation to recover from sequence poisoning by an old online key. The same
schema binds each logical installation ID to one canonical Steam manifest and
game root. The first successful verified preview establishes the binding; later
previews and applies cannot reuse that ID for another copy.

```bash
rrmm recipe-catalog-verify \
  --root-metadata signed-root.json \
  --recipe-catalog signed-catalog.json \
  --database rrmm.sqlite
```

The command uses the system clock. Callers cannot supply a historical time to
bypass issue, delegation, or expiry windows. Malformed extra signatures are
ignored when another trusted signature verifies, supporting key rotation
without allowing signature-list denial of service.

## Application

Recipe application is a preview transformation, not a game-directory write. It
performs the complete trust path in one operation:

1. Read the persisted rollback floor.
2. Verify root delegation, online signature, time window, generation, sequence,
   and same-version hashes.
3. Load every catalog artifact from the immutable content-addressed store.
4. Rehash the source archive and every stored payload.
5. Require package semantics to equal the artifact's embedded
   `rrmm-manifest.json` exactly.
6. Recompute variants and requirements instead of trusting a supplied
   resolution report.
7. Match and apply recipes atomically; a blocker returns the original
   resolution.
8. Advance the SQLite rollback floor after successful catalog verification.

Unsigned authoring recipes live under
`recipes/compatibility/<build-id>/`. They can be schema- and semantics-checked,
but application never trusts those files directly. A release process must copy
reviewed recipes into a signed catalog. Initial workspace decisions and their
evidence limits are recorded in [`INITIAL_KNOWLEDGE.md`](INITIAL_KNOWLEDGE.md).

```bash
rrmm recipe-apply \
  --root-metadata signed-root.json \
  --recipe-catalog signed-catalog.json \
  --database rrmm.sqlite \
  --request resolve-request.json \
  --package-catalog package-catalog.json \
  --artifact-store path/to/RRModManager
```

Locally inferred manifests are intentionally rejected by signed-recipe
application, even if JSON claims they were reviewed. Supporting them requires a
future authenticated local review record. This prevents an external catalog
from changing package identity, dependencies, variants, or install semantics
for exact artifact bytes.

`recipe-deploy-preview` performs the same verification and resolution in one
process, revalidates every selected artifact and embedded manifest, materializes
PAK and UE4SS components, and emits a strict recipe-plan envelope containing a
Phase 4 `DeploymentPlan`. The output is accepted only by
`recipe-deploy-apply`; generic `deploy-apply` cannot deserialize it. Preview
never changes the game itself. PAKs are placed under
`RetroRewind/Content/Paks` and UE4SS module trees under
`RetroRewind/Binaries/Win64/ue4ss/Mods`.

The preview requires an inventoried installation with an active profile. It
re-inspects the live Steam manifest, layout, build, and critical-file hashes,
then requires the resolution request to equal that active profile's enabled
artifact and variant selections. UE4SS components must include `enabled.txt`;
any executable or native descendant is rejected until Phase 6 has a dedicated
native-module trust policy.

Materialization rejects config, documentation, and native components until the
manifest contract defines explicit destinations for them. It also rejects
`select_winner` results until controlled in-game tests establish a load-order
mechanism that can enforce each winner rather than merely record it.

```bash
rrmm recipe-deploy-preview \
  --root-metadata signed-root.json \
  --recipe-catalog signed-catalog.json \
  --database rrmm.sqlite \
  --request resolve-request.json \
  --package-catalog package-catalog.json \
  --artifact-store path/to/RRModManager \
  --game-root path/to/RetroRewind \
  --state-root path/to/RRModManager/state \
  --installation-id steam-3552140 \
  --profile-id default \
  --transaction-id preview-001 > deployment-plan.json

rrmm recipe-deploy-apply \
  --plan deployment-plan.json \
  --root-metadata signed-root.json \
  --recipe-catalog signed-catalog.json \
  --database rrmm.sqlite \
  --package-catalog package-catalog.json \
  --artifact-store path/to/RRModManager \
  --confirm
```

Apply reverifies the supplied signed metadata with the system clock and current
rollback floor, repeats resolution and artifact materialization, checks the live
Steam build and active profile, reloads the active receipt, and recomputes the
complete Phase 4 plan. It activates only if the recomputed plan and validation
evidence exactly equal the reviewed envelope. Removed or edited validation,
expired catalogs, newer accepted catalogs, profile changes, artifact drift, and
game-build changes are therefore rejected.

## Remaining Work

- Generate and embed the production offline root public key.
- Add signed catalogs and reviewed recipes for known workspace combinations.
- Define explicit deployment destinations for config, documentation, and native
  components.
- Verify PAK winner enforcement through controlled in-game load-order tests.
