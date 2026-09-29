#!/usr/bin/env bash
set -euo pipefail

plugin_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_path="${1:-${plugin_dir}/dist/amazing-security-0.1.0-preview.zip}"
mkdir -p "$(dirname "${output_path}")"
staging_dir="$(mktemp -d)"
trap 'rm -rf "${staging_dir}"' EXIT
mkdir -p "${staging_dir}/amazing-security"
rsync -a "${plugin_dir}/amazing-security.php" "${plugin_dir}/uninstall.php" "${plugin_dir}/readme.txt" "${plugin_dir}/LICENSE" "${plugin_dir}/src" "${plugin_dir}/assets" "${staging_dir}/amazing-security/"
rm -f "${output_path}"
( cd "${staging_dir}" && zip -qr "${output_path}" amazing-security )
unzip -tq "${output_path}"
shasum -a 256 "${output_path}"
