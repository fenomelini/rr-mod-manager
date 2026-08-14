#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    printf 'usage: %s <appimage>\n' "$0" >&2
    exit 2
fi

appimage="$(realpath "$1")"
[[ -f "$appimage" ]] || { printf 'AppImage not found: %s\n' "$appimage" >&2; exit 1; }
command -v appimagetool >/dev/null || { printf 'appimagetool is required\n' >&2; exit 1; }

work="$(mktemp -d "${TMPDIR:-/tmp}/rrmm-appimage.XXXXXX")"
trap 'rm -rf "$work"' EXIT

runtime_offset="$("$appimage" --appimage-offset)"
[[ "$runtime_offset" =~ ^[0-9]+$ ]] || {
    printf 'invalid AppImage runtime offset: %s\n' "$runtime_offset" >&2
    exit 1
}
dd if="$appimage" of="$work/runtime" bs=1 count="$runtime_offset" status=none

(
    cd "$work"
    "$appimage" --appimage-extract >/dev/null
)

appdir="$work/squashfs-root"
libdir="$appdir/usr/lib"
[[ -x "$appdir/AppRun" && -d "$libdir" ]] || {
    printf 'invalid extracted AppDir\n' >&2
    exit 1
}

# Tauri 2.11 over-bundles old infrastructure libraries. On Mesa 25+ this
# makes WebKit fail with EGL_BAD_PARAMETER (tauri-apps/tauri#15665).
shopt -s nullglob
libraries=(
    "$libdir"/libwayland-*.so*
    "$libdir"/libglib-2.0.so*
    "$libdir"/libgio-2.0.so*
    "$libdir"/libgobject-2.0.so*
    "$libdir"/libgmodule-2.0.so*
    "$libdir"/libgst*.so*
    "$libdir"/libgstreamer-1.0.so*
    "$libdir"/libmount.so*
    "$libdir"/libblkid.so*
    "$libdir"/libselinux.so*
    "$libdir"/libpcre2-8.so*
    "$libdir"/libzstd.so*
    "$libdir"/libelf.so*
    "$libdir"/libffi.so*
)
if (( ${#libraries[@]} > 0 )); then
    rm -f -- "${libraries[@]}"
fi

output="$work/patched.AppImage"
ARCH=x86_64 appimagetool --appimage-extract-and-run \
    --no-appstream --runtime-file "$work/runtime" "$appdir" "$output"
install -m 0755 "$output" "$appimage"
printf 'post-processed AppImage for Mesa 25+ compatibility: %s\n' "$appimage"
