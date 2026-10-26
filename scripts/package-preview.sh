#!/usr/bin/env bash
set -euo pipefail

plugin_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
php "${plugin_dir}/scripts/rule-manifest.php" --check
version="$(sed -n 's/^ \* Version: *//p' "${plugin_dir}/amazing-security-scanner.php" | head -1)"
stable="$(sed -n 's/^Stable tag: *//p' "${plugin_dir}/readme.txt" | head -1)"
[[ -n "${version}" && "${version}" == "${stable}" ]] || { echo "Header version '${version}' and readme Stable tag '${stable}' differ." >&2; exit 1; }
output_path="${1:-${plugin_dir}/dist/amazing-security-scanner-${version}.zip}"
mkdir -p "$(dirname "${output_path}")"
staging_dir="$(mktemp -d)"
trap 'rm -rf "${staging_dir}"' EXIT
mkdir -p "${staging_dir}/amazing-security-scanner"
rsync -a "${plugin_dir}/amazing-security-scanner.php" "${plugin_dir}/uninstall.php" "${plugin_dir}/readme.txt" "${plugin_dir}/LICENSE" "${plugin_dir}/src" "${plugin_dir}/assets" "${staging_dir}/amazing-security-scanner/"
find "${staging_dir}/amazing-security-scanner" -type f -exec touch -t 202001010000 {} +
rm -f "${output_path}"
( cd "${staging_dir}" && find amazing-security-scanner -type f -print | LC_ALL=C sort | zip -Xq "${output_path}" -@ )
unzip -tq "${output_path}"
# The release must hold only runtime files under the slug folder.
if unzip -Z1 "${output_path}" | grep -vE '^amazing-security-scanner/(amazing-security-scanner\.php|uninstall\.php|readme\.txt|LICENSE|src/|assets/)' | grep -q .; then echo "Unexpected top-level entry in ZIP." >&2; exit 1; fi
if unzip -Z1 "${output_path}" | grep -E '(^|/)(\.[^/]+|tests?|vendor|node_modules|\.wordpress-org|composer\.(json|lock)|phpunit[^/]*|phpcs[^/]*)(/|$)' | grep -v '^amazing-security-scanner/src/Vendor/' | grep -q .; then echo "Development file found in ZIP." >&2; exit 1; fi
shasum -a 256 "${output_path}"
