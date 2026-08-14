#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
target="x86_64-pc-windows-msvc"
version="$(node -p "require('$root/package.json').version")"
source_installer="$root/target/$target/release/bundle/nsis/RR Mod Manager_${version}_x64-setup.exe"
output="$root/dist/RR-Mod-Manager-${version}-Windows-x64-Setup.exe"

for command in cargo cargo-xwin node pnpm makensis; do
    command -v "$command" >/dev/null || { printf 'required command not found: %s\n' "$command" >&2; exit 1; }
done

cd "$root"
CI=1 pnpm install --frozen-lockfile
cargo xwin build --locked --release --target "$target" \
    --package rrmm-archive-worker \
    --package rrmm-pak-worker
install -Dm755 "target/$target/release/rrmm-archive-worker.exe" \
    "apps/desktop/src-tauri/binaries/rrmm-archive-worker-$target.exe"
install -Dm755 "target/$target/release/rrmm-pak-worker.exe" \
    "apps/desktop/src-tauri/binaries/rrmm-pak-worker-$target.exe"
pnpm desktop:packaging:check
pnpm --filter @rrmm/desktop tauri build \
    --runner cargo-xwin \
    --target "$target" \
    --bundles nsis \
    --no-sign

test -f "$source_installer"
install -Dm644 "$source_installer" "$output"
if command -v powershell.exe >/dev/null && command -v wslpath >/dev/null; then
    windows_output="$(wslpath -w "$output")"
    signature_status="$(powershell.exe -NoProfile -Command "(Get-AuthenticodeSignature -LiteralPath '$windows_output').Status" | tr -d '\r')"
    [[ "$signature_status" == "NotSigned" ]] || {
        printf 'unexpected Authenticode status: %s\n' "$signature_status" >&2
        exit 1
    }
fi
sha256sum "$output"
