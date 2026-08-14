#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
version="$(node -p "require('$root/package.json').version")"
source_appimage="$root/target/release/bundle/appimage/RR Mod Manager_${version}_amd64.AppImage"
output_appimage="$root/dist/RR-Mod-Manager-${version}-Linux-x64.AppImage"
output_zip="$root/dist/RR-Mod-Manager-${version}-Linux-x64.zip"
tool_dir="$root/target/release-tools"
appimagetool="$tool_dir/appimagetool"
appimagetool_sha256="a6d71e2b6cd66f8e8d16c37ad164658985e0cf5fcaa950c90a482890cb9d13e0"

for command in cargo curl node pnpm pkg-config sha256sum xdg-open zip; do
    command -v "$command" >/dev/null || { printf 'required command not found: %s\n' "$command" >&2; exit 1; }
done
for module in webkit2gtk-4.1 ayatana-appindicator3-0.1; do
    pkg-config --exists "$module" || {
        printf 'missing Linux build dependency: %s\n' "$module" >&2
        printf 'install build-essential libayatana-appindicator3-dev librsvg2-dev libssl-dev libwebkit2gtk-4.1-dev libxdo-dev patchelf xdg-utils zip\n' >&2
        exit 1
    }
done

mkdir -p "$tool_dir"
if [[ ! -x "$appimagetool" ]]; then
    download="$tool_dir/appimagetool.download"
    curl --proto '=https' --tlsv1.2 -fL \
        https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage \
        -o "$download"
    printf '%s  %s\n' "$appimagetool_sha256" "$download" | sha256sum -c -
    mv "$download" "$appimagetool"
    chmod 0755 "$appimagetool"
fi

cd "$root"
CI=1 pnpm install --frozen-lockfile
node tools/prepare-desktop-sidecars.mjs release
PATH="$tool_dir:$PATH" pnpm --filter @rrmm/desktop tauri build --bundles appimage
PATH="$tool_dir:$PATH" ./tools/postprocess-linux-appimage.sh "$source_appimage"
install -Dm755 "$source_appimage" "$output_appimage"
mkdir -p "$(dirname "$output_zip")"
zip -j -9 "$output_zip" "$output_appimage"
sha256sum "$output_appimage" "$output_zip"
