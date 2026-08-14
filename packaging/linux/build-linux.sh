#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="rrmm-linux:bookworm"
profile="${1:-release}"
runtime="${RRMM_CONTAINER_RUNTIME:-podman}"

case "$profile" in
    release)
        build_command='./tools/prepare-desktop-sidecars.sh release && CI=1 pnpm install --frozen-lockfile && pnpm --filter @rrmm/desktop tauri build --bundles appimage && ./tools/postprocess-linux-appimage.sh "target/release/bundle/appimage/RR Mod Manager_0.1.2_amd64.AppImage"'
        ;;
    debug)
        build_command='./tools/prepare-desktop-sidecars.sh debug && CI=1 pnpm install --frozen-lockfile && pnpm --filter @rrmm/desktop tauri build --debug --bundles appimage --no-sign && ./tools/postprocess-linux-appimage.sh "target/debug/bundle/appimage/RR Mod Manager_0.1.2_amd64.AppImage"'
        ;;
    *)
        printf 'usage: %s [release|debug]\n' "$0" >&2
        exit 2
        ;;
esac

command -v "$runtime" >/dev/null || {
    printf 'container runtime not found: %s\n' "$runtime" >&2
    exit 1
}

"$runtime" build --file "$root/packaging/linux/Containerfile" --tag "$image" "$root"
"$runtime" run --rm \
    --security-opt label=disable \
    --volume "$root:/workspace" \
    --workdir /workspace \
    "$image" \
    bash -lc "$build_command"
