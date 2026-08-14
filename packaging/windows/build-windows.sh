#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="rrmm-windows:bookworm"
runtime="${RRMM_CONTAINER_RUNTIME:-podman}"
target="x86_64-pc-windows-msvc"
installer="RR Mod Manager_0.1.2_x64-setup.exe"

command -v "$runtime" >/dev/null || {
    printf 'container runtime not found: %s\n' "$runtime" >&2
    exit 1
}

"$runtime" build --file "$root/packaging/windows/Containerfile" --tag "$image" "$root"
"$runtime" run --rm \
    --security-opt label=disable \
    --volume "$root:/workspace" \
    --workdir /workspace \
    "$image" \
    bash -lc '
        set -euo pipefail
        CI=1 pnpm install --frozen-lockfile
        cargo xwin build --locked --release --target x86_64-pc-windows-msvc \
            --package rrmm-archive-worker \
            --package rrmm-pak-worker
        install -Dm755 \
            target/x86_64-pc-windows-msvc/release/rrmm-archive-worker.exe \
            apps/desktop/src-tauri/binaries/rrmm-archive-worker-x86_64-pc-windows-msvc.exe
        install -Dm755 \
            target/x86_64-pc-windows-msvc/release/rrmm-pak-worker.exe \
            apps/desktop/src-tauri/binaries/rrmm-pak-worker-x86_64-pc-windows-msvc.exe
        pnpm desktop:packaging:check
        pnpm --filter @rrmm/desktop tauri build \
            --runner cargo-xwin \
            --target x86_64-pc-windows-msvc \
            --bundles nsis \
            --no-sign
        install -Dm644 \
            "target/x86_64-pc-windows-msvc/release/bundle/nsis/RR Mod Manager_0.1.2_x64-setup.exe" \
            "dist/RR Mod Manager_0.1.2_x64-setup.exe"
    '

test -f "$root/dist/$installer"
printf '%s\n' "$root/dist/$installer"
