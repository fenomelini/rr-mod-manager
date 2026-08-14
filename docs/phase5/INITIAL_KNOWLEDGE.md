# Phase 5 Initial Compatibility Knowledge

## Accepted Recipe

The first authored compatibility recipe covers the exact combination of:

- `nexus:unrewound-tape-fee` 1.0.0.
- `nexus:employee-fee-policy` 1.0.0.
- Retro Rewind build `23896268`.

The standalone manifests declare their real cooked-package incompatibility. The
exact-hash recipe replaces both with
`nexus:unrewound-tape-fee-employee-fee-policy` 1.0.0. The combined package is an
existing author-built and in-game-tested PAK, not a runtime merge performed by
RRMM.

Authoring sources:

- `manifests/unrewound-tape-fee/1.0.0/rrmm-manifest.json`
- `manifests/employee-fee-policy/1.0.0/rrmm-manifest.json`
- `manifests/unrewound-tape-fee-employee-fee-policy/1.0.0/rrmm-manifest.json`
- `catalogs/packages/23896268.json`
- `recipes/compatibility/23896268/unrewound-tape-fee--employee-fee-policy.json`

`tools/build-rrmm-packages.sh` creates separate deterministic RRMM bundles under
the ignored `dist/rrmm-packages/` directory. It verifies each released PAK hash,
copies the PAK without modification, embeds its declared manifest, normalizes
timestamps, and creates a ZIP suitable for normal hostile-archive intake. It
does not modify or replace the public release ZIPs.

Current bundle hashes:

| Package | RRMM bundle SHA-256 |
| --- | --- |
| Unrewound Tape Fee | `8be6b46d8dea03e38794fe37c9c44daf1229518b44299ddcbd78dd40473c7504` |
| Employee Fee Policy | `bc4e67959f9ef9220eb5fb2c981e0669fde3b75c08d354200c4465c5ee19cfce` |
| Combined package | `8a151b1f80c6e43444e303711fb5470058875a7816dd141864452a1d73ad47d9` |

These hashes are authoring inputs for a future signed catalog. The recipe file
alone is not trusted or deployable. Production use still requires root metadata
and a catalog signed through the release-key process.

## Deferred Knowledge

### Better Hand Inventory Editions

The Standard and Plus releases are author-declared alternatives using the same
PAK and UE4SS module names. They must not be installed together. This belongs in
package identity/variant modeling rather than a compatibility recipe. RRMM
authoring is deferred until exact release hashes and embedded manifests are
prepared.

### Chronological New Releases

The Era-Specific package requires the exact
`zzzzzzzz_ChronologicalNewReleases_9999_P.pak` filename and an Era-Specific Movie
Pak dependency. `require_install_name` can represent the filename, while the
dependency belongs in its package manifest. Authoring remains deferred because
the release ZIP and required dependency do not yet have RRMM package records and
recorded exact artifact hashes.

### Faster Returns Scanner

The released package intentionally contains no cooked scanner override; scanner
behavior comes from UE4SS hooks. There is no exact unsafe released artifact or
component to target with `disable_component`, and recipes cannot prohibit
hypothetical future files. The scanner asset remains excluded until its
documented save/load crash risk is resolved and tested.

### Smart Shelf Organizer

The prototype requires UE4SS `3.0.1 Beta #0` build `662df915` or newer. The
manifest contract can now name
`ue4ss:smart-shelf-662df915-compatible`, whose initial exact allowlist contains
only `662df915`; `0196ef29` is explicitly unsafe and stable v3.0.1 is recognized
but insufficient. “Or newer” descendants must be added by exact proxy/core hash
after review because Git SHAs are not ordered.

A deterministic local development bundle now embeds the authored manifest and
is recorded as `local:smart-shelf-organizer` version `0.1.0-dev` with artifact
SHA-256 `32be01dd47833f8f61d0bfbe7b831b428bf10f4677f2db62aa4aba2b319d036e`.
This closes local package representation only. Employee routing and visual tags
remain disabled, required in-game coverage is incomplete, and the artifact is
not a public release or an entry in a production signed catalog.

### Localization Winners

Unrewound Tape Fee intentionally extends the 18 Genres localization base, but
the relevant PAKs have equal numeric priority and lexical tie behavior has not
been proven in game. `select_winner` remains non-deployable, so no localization
winner recipe is authored yet.
