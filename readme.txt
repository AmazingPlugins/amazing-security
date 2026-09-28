=== Amazing Security ===
Contributors: amazingplugins
Tags: security, hardening, audit
Requires at least: 6.6
Requires PHP: 8.1
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Read-only WordPress hardening and release file checks. Private preview.

== Description ==

Run five local hardening checks from wp-admin. An administrator can also compare WordPress core and eligible WordPress.org plugin files with published release checksums. That scan contacts api.wordpress.org and downloads.wordpress.org. It doesn't send file contents.

A changed checksum means a file differs from the published release. It doesn't identify malware. Missing or unsupported packages show an unknown or partial result. The integrity scan reads a bounded number of files per request and asks you to continue when more work remains.

This preview has no repair action, firewall, malware signature scan, or MCP endpoint.
