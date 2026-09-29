=== Amazing Security ===
Contributors: amazingplugins
Tags: security, hardening, audit
Requires at least: 6.6
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress hardening checks, release file checks, opt-in vulnerability lookups, and local login protection. Private preview.

== Description ==

Run six local hardening checks from wp-admin. An administrator can also compare WordPress core and eligible WordPress.org plugin files with published checksums. Eligible WordPress.org themes are compared with their exact release ZIP. These checks contact api.wordpress.org and downloads.wordpress.org. They don't send file contents.

A changed checksum means a file differs from the published release. It doesn't identify malware. Missing or unsupported packages show an unknown or partial result. A custom or child theme stays unknown for release comparison. The integrity scan reads a bounded number of files per request and asks you to continue when more work remains.

The file scan checks for extra files in compared packages and scans PHP-like files in plugins, themes, and uploads for six bundled suspicious-code patterns. It scans only unexpected executable files under core directories. A hit is suspected code, not proof of malware. A scan without hits does not prove the site is clean. The rules update with plugin releases; this preview has no maintained malware feed. Files stay on your server. The scan stops after 5,000 files, 128 MiB read, or 30 seconds of work, and may need several steps. Unreadable, oversized, changed, or skipped files show partial coverage. You can save a note on a finding; notes do not hide it from later scans.

If a finished integrity check finds a changed WordPress.org plugin file, an administrator can review a repair. The page shows the file path and SHA-256 hashes before approval. Repair stops if the installed version, file, published checksum, or approved replacement no longer matches.

The plugin keeps a private backup outside the served site. You can roll back in wp-admin or run `wp amazing-security repair rollback <finding-id>`. Other files remain review-only. This doesn't remove malware or repair a whole plugin.

WP-Cron starts the local hardening checks daily, then queues bounded integrity and file scan steps. You can still run them manually. WP-Cron needs site traffic, so a quiet site may run them late. The dashboard shows when daily hardening was missed or incomplete and keeps partial scan results visible. Completed integrity and file scans can email the site administrator about changed published files or selected suspicious PHP matches. The message contains finding IDs and a dashboard link, not file contents. You can turn these emails off in wp-admin. “Accepted for sending” does not prove the message reached an inbox.

The REST request watch is observe only. It checks public REST query values for two patterns, skips logged-in requests, and records rule IDs and counts without storing query values. It does not inspect bodies or block requests. Set `AMSEC_DISABLE_FIREWALL` to `true` in `wp-config.php` to stop it.

Vulnerability checks are off until an administrator enables them. When enabled, this site asks the public WPVulnerability API for its WordPress core version and installed plugin and theme slugs. Requests go directly from your server to https://www.wpvulnerability.net/. The provider can see the request IP and requested component. AmazingPlugins does not receive your inventory. The plugin stores responses and reports locally. You can turn off future lookups in wp-admin; older reports remain until separately cleared. See the provider's privacy policy at https://www.wpvulnerability.com/privacy/ and license at https://www.wpvulnerability.com/license/. Data is credited to WPVulnerability and linked to its original sources.

The lookup compares published issues with installed versions. Unknown package identity, unsupported ranges, stale data, and provider errors are marked unknown or possible affected. It does not update installed software or claim the site is vulnerability-free.

Login protection is off when you install the plugin. You can observe failed logins first, then choose to block a server address after five failures in 15 minutes. The block lasts 15 minutes. Shared networks can affect more than one visitor. The plugin uses the server connection address, not forwarded headers, and ignores counter records after 24 hours. Expired records are deleted by WP-Cron or on the next failed login or dashboard view. WP-Cron needs site traffic to run. Turning protection off deletes the counters. If the counter store fails or reaches its 10,000-address limit, login attempts are allowed and the dashboard reports incomplete coverage. Password reset is not blocked.

Administrators can enroll a TOTP authenticator over HTTPS. WordPress and WooCommerce login forms then ask that administrator for a six-digit code or one of ten single-use recovery codes after a valid password. Save the recovery codes when they appear; the plugin does not show them again. TOTP seeds are encrypted with site-specific key material, and recovery codes are stored as hashes. If site keys change, use a recovery code or the local WP-CLI command below. Customer accounts, application passwords, and XML-RPC requests are outside this TOTP rule. Custom interactive login forms that omit the code field deny enrolled administrators rather than bypassing the check.

The XML-RPC setting blocks methods that require authentication. It does not turn off pingbacks or the whole XML-RPC endpoint. Check Jetpack or mobile publishing before enabling it.

If you lose admin access, run `wp amazing-security login disable` from the site's WP-CLI environment. To remove one administrator's TOTP requirement, run `wp amazing-security totp disable --user=<id>`. These commands act locally; they do not need an AmazingPlugins account. The plugin keeps login settings and enrollment data on uninstall unless you select **Erase login protection data on uninstall** first.

AI assistant access starts off. On WordPress 6.9 or newer, install the official MCP Adapter separately, then turn on access in Amazing Security. An authenticated administrator can list findings, inspect a finding, run the six local hardening checks, and read that scan. Two more abilities can prepare a login-rate change and read its status.

Each call checks the current WordPress user's permission and the site's MCP setting. Scan requests have a concurrency guard and a 60-second cooldown per administrator. They don't start file, integrity, or vulnerability scans. The MCP Adapter handles the connection and authentication; Amazing Security doesn't bundle a server. Turn access off in wp-admin to stop further calls.

An assistant can propose only two staged changes: off to observe, then observe to block. The proposal lasts 15 minutes and changes nothing by itself. Open its wp-admin link to review and approve the exact setting. Approval requires an administrator cookie session and a proposal-specific nonce. Block mode also requires HTTPS and the administrator's current password. A changed setting or a second approval is refused. After approval, the page offers a 24-hour rollback. Turning assistant access off stops pending approvals, but an already applied change can still be rolled back. The assistant cannot start file repair. The plugin does not offer a general firewall or a maintained malware signature feed.
