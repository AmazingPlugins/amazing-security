=== Amazing Security ===
Contributors: amazingplugins
Tags: security, hardening, audit
Requires at least: 6.6
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Read-only WordPress hardening, release file checks, and opt-in vulnerability lookups. Private preview.

== Description ==

Run five local hardening checks from wp-admin. An administrator can also compare WordPress core and eligible WordPress.org plugin files with published release checksums. That scan contacts api.wordpress.org and downloads.wordpress.org. It doesn't send file contents.

A changed checksum means a file differs from the published release. It doesn't identify malware. Missing or unsupported packages show an unknown or partial result. The integrity scan reads a bounded number of files per request and asks you to continue when more work remains.

Vulnerability checks are off until an administrator enables them. When enabled, this site asks the public WPVulnerability API for its WordPress core version and installed plugin and theme slugs. Requests go directly from your server to https://www.wpvulnerability.net/. The provider can see the request IP and requested component. AmazingPlugins does not receive your inventory. The plugin stores responses and reports locally. You can turn off future lookups in wp-admin; older reports remain until separately cleared. See the provider's privacy policy at https://www.wpvulnerability.com/privacy/ and license at https://www.wpvulnerability.com/license/. Data is credited to WPVulnerability and linked to its original sources.

The lookup compares published issues with installed versions. Unknown package identity, unsupported ranges, stale data, and provider errors are marked unknown or possible affected. It does not update installed software or claim the site is vulnerability-free. This preview has no repair action, firewall, malware signature scan, or MCP endpoint.
