# Fixture Policy

## Allowed Fixtures

- Synthetic Steam VDF and ACF files.
- Generated minimal PAKs containing original test-only data.
- Minimal package-member path inventories with no game payload.
- Redacted UE4SS log fragments.
- Synthetic ZIP/7z security corpora.
- Synthetic `nxm://` URLs using fake keys and IDs.
- Public API schemas and hand-authored mock responses containing no credentials.
- Manifest and recipe examples with fake hashes.

## Prohibited Fixtures

- Extracted Retro Rewind assets or executable game payload.
- Real Nexus API keys, SSO tokens, `nxm` keys, download URLs, or presigned URLs.
- User saves or logs containing personal paths without explicit redaction.
- Third-party mod payloads without redistribution permission.
- Native malware samples in the normal repository.

## Golden Data Rules

- Every binary fixture must document its generator and expected hash.
- Generated PAKs must use a test mount/path namespace.
- Malformed fixtures must have a bounded expected failure.
- Network fixtures must be reviewed for secret-like strings before commit.
- Local installation reports use paths relative to the scanned game root.
