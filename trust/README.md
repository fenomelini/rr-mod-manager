# Production Trust Anchors

`production-roots.json` is compiled into release builds of `rrmm-cli`. It may
contain public Ed25519 root records only. Private keys and online private keys
must never enter this directory or workspace.

The file intentionally contains an empty array before the production key
ceremony. Debug and test builds may use an explicit trusted-root override.
Release builds fail in `apps/cli/build.rs` while the array is empty, malformed,
duplicated, or contains a key ID that does not match its public key.

Generate the final array with `rrmm-catalog-author trusted-roots-export` after
the independently reviewed offline ceremony. Root replacement requires a new
application release and a separate migration review.

```bash
rrmm-catalog-author trusted-roots-export \
  --trusted-root root.public.json \
  --output production-roots.reviewed.json
```

After independent comparison and two-person approval, replace this directory's
placeholder with the exact reviewed array. The export command deliberately
refuses to overwrite the tracked placeholder or any other existing path.
