#!/usr/bin/env bash
set -euo pipefail

plugin_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
php "${plugin_dir}/scripts/rule-manifest.php" --check
php "${plugin_dir}/scripts/passkey-vendor-manifest.php"
output_path="${1:-${plugin_dir}/dist/amazing-security-0.1.0-preview.zip}"
mkdir -p "$(dirname "${output_path}")"
staging_dir="$(mktemp -d)"
trap 'rm -rf "${staging_dir}"' EXIT
mkdir -p "${staging_dir}/amazing-security"
rsync -a "${plugin_dir}/amazing-security.php" "${plugin_dir}/uninstall.php" "${plugin_dir}/readme.txt" "${plugin_dir}/LICENSE" "${plugin_dir}/src" "${plugin_dir}/assets" "${staging_dir}/amazing-security/"
find "${staging_dir}/amazing-security" -type f -exec touch -t 202001010000 {} +
rm -f "${output_path}"
( cd "${staging_dir}" && find amazing-security -type f -print | LC_ALL=C sort | zip -Xq "${output_path}" -@ )
unzip -tq "${output_path}"
shasum -a 256 "${output_path}"
