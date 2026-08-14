# Release policy

RR Mod Manager has one source version shared by every platform. A GitHub release may publish only
the platform artifacts that passed their own target-platform validation.

- Do not bump an unpublished version for test builds.
- Do not copy binaries from a previous release into a new version.
- Select `windows`, `linux` or `both` when dispatching the release-candidate workflow.
- Publish only files created by that workflow run.
- Keep a platform on its previous public version when its new artifact was not validated.

## Windows 0.1.2 process

1. Merge a reviewed source PR only after CI passes.
2. Dispatch `Release candidate` with version `0.1.2` and platform `windows`.
3. Download the candidate artifact and verify `SHA256SUMS`.
4. Run `gh attestation verify <installer> --owner fenomelini`.
5. Install that exact candidate on Windows 11 and test UE4SS install/repair, mod import, profile
   activation, deployment and game launch.
6. Publish `v0.1.2` as the latest non-prerelease only after every checklist gate is complete.

The Windows installer is intentionally unsigned until an Authenticode certificate is available.
The workflow rejects an unexpectedly signed or invalidly signed binary and provides GitHub artifact
attestation as build provenance. SmartScreen may still display “Unknown publisher”; attestation does
not replace Authenticode reputation.
