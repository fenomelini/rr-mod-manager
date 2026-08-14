#!/usr/bin/env bash
set -euo pipefail
umask 022

manager_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace_root="$(cd "${manager_root}/.." && pwd)"
output_root="${manager_root}/dist/rrmm-packages"
mkdir -p "${output_root}"
temporary="$(mktemp -d "${output_root}/.build-XXXXXX")"
trap 'rm -rf "${temporary}"' EXIT

build_package() {
  local slug="$1"
  local source_pak="$2"
  local pak_name="$3"
  local expected_pak_sha256="$4"
  local expected_bundle_sha256="$5"
  local manifest="${manager_root}/manifests/${slug}/1.0.0/rrmm-manifest.json"
  local staging="${temporary}/${slug}"
  local output="${output_root}/${slug}-1.0.0.rrmm.zip"
  local candidate="${temporary}/${slug}-1.0.0.rrmm.zip"
  local actual_pak_sha256
  local actual_bundle_sha256

  actual_pak_sha256="$(sha256sum "${source_pak}" | cut -d ' ' -f 1)"
  if [[ "${actual_pak_sha256}" != "${expected_pak_sha256}" ]]; then
    printf 'PAK hash mismatch for %s\n' "${source_pak}" >&2
    exit 1
  fi

  mkdir -p "${staging}"
  cp "${source_pak}" "${staging}/${pak_name}"
  cp "${manifest}" "${staging}/rrmm-manifest.json"
  chmod 0644 "${staging}/${pak_name}" "${staging}/rrmm-manifest.json"
  touch -t 200001010000 "${staging}/${pak_name}" "${staging}/rrmm-manifest.json"
  (
    cd "${staging}"
    zip -X -9 -q "${candidate}" rrmm-manifest.json "${pak_name}"
  )
  actual_bundle_sha256="$(sha256sum "${candidate}" | cut -d ' ' -f 1)"
  if [[ "${actual_bundle_sha256}" != "${expected_bundle_sha256}" ]]; then
    printf 'RRMM bundle hash mismatch for %s: expected %s, got %s\n' \
      "${slug}" "${expected_bundle_sha256}" "${actual_bundle_sha256}" >&2
    exit 1
  fi
  mv -f "${candidate}" "${output}"
  sha256sum "${output}"
}

build_package \
  "unrewound-tape-fee" \
  "${workspace_root}/unrewound-tape-fee/dist/zzzzzzzz_UnrewoundTapeFee_P.pak" \
  "zzzzzzzz_UnrewoundTapeFee_P.pak" \
  "699870c011643e7cf7e631d7815773adb7e334ca51bad9282b936e757318da28" \
  "8be6b46d8dea03e38794fe37c9c44daf1229518b44299ddcbd78dd40473c7504"

build_package \
  "employee-fee-policy" \
  "${workspace_root}/employee-fee-policy/dist/zzzzzzzz_EmployeeFeePolicy_P.pak" \
  "zzzzzzzz_EmployeeFeePolicy_P.pak" \
  "60a9cdf5f2e6b9c35aad6401298ed11e307644491a90687ff613d63a0365cb1b" \
  "bc4e67959f9ef9220eb5fb2c981e0669fde3b75c08d354200c4465c5ee19cfce"

build_package \
  "unrewound-tape-fee-employee-fee-policy" \
  "${workspace_root}/unrewound-tape-fee/dist/zzzzzzzz_UnrewoundTapeFee_EmployeeFeePolicy_P.pak" \
  "zzzzzzzz_UnrewoundTapeFee_EmployeeFeePolicy_P.pak" \
  "6dc3fb78211ea1bb9118926a09dae4956ebc7d3744651b329ad8e9049f11d66e" \
  "8a151b1f80c6e43444e303711fb5470058875a7816dd141864452a1d73ad47d9"
