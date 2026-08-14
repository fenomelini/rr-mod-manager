# Production Trust Anchors

`production-roots.json` is compiled into the desktop application. It may contain
public Ed25519 root records only. Private keys must never enter this directory or
workspace. Changing a trusted root requires a new application release and an
independent review of the exact public key and key identifier.
