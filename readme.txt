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

The first list is six checks: HTTPS, WordPress updates, the admin login, debug display, the theme and plugin editor, and login monitoring. More checks follow on the same screen. An administrator can also compare WordPress core and eligible WordPress.org plugin files with published checksums. Eligible WordPress.org themes are compared with their exact release ZIP. These checks contact api.wordpress.org and downloads.wordpress.org. They don't send file contents.

A changed checksum means a file differs from the published release. It doesn't identify malware. Missing or unsupported packages show an unknown or partial result. A custom or child theme stays unknown for release comparison. The integrity scan reads a bounded number of files per request and asks you to continue when more work remains.

Run local checks also starts three scans that stay on this server. It reads plugin, theme, and uploads PHP with the 31 local patterns. It lists selected public file names. It checks posts and comments for suspicious links, one bounded batch at a time. They don't contact WordPress.org. One click keeps reading until the scan finishes or about 12 seconds pass, and the row says how many files were read. A match lists the file, the line, and the rule. If a scan still has work left, run local checks again. A finished pattern scan with no hits doesn't prove the site is clean. The homepage header check stays off until you tick "Request this site's homepage and read its response headers" on that same form.

The separate file scan looks for extra files in compared packages. It also reads PHP-like files in plugins, themes, and uploads with 31 local patterns. It can follow six copied assignments, three copies before create_function, and a preg_replace /e pattern held in two variables. A seventh assignment, a fourth create_function copy, and a third variable are still missed. Each finding says why it needs a look and what to open next. It scans only unexpected executable files under core directories. A hit is suspected code. It isn't proof of malware. A scan without hits doesn't prove the site is clean. The rules update with plugin releases. This preview has no maintained malware feed. Files stay on your server. The scan stops after 5,000 files, 128 MiB read, or 30 seconds of work, and may need several steps. Unreadable, oversized, changed, or skipped files show partial coverage. A conservative memory check can leave large or dense PHP files unscanned instead of exhausting the site's memory. You can save a note on a finding. Notes don't hide it from later scans.

If a finished integrity check finds a changed WordPress.org plugin file, an administrator can review a repair. The page shows the file path and SHA-256 hashes before approval. Repair stops if the installed version, file, published checksum, or approved replacement no longer matches.

The plugin keeps a private backup outside the served site. You can roll back in wp-admin or run `wp amazing-security repair rollback <finding-id>`. Other files remain review-only. This doesn't remove malware or repair a whole plugin.

WP-Cron starts the local hardening checks daily, then queues bounded integrity and file scan steps. You can still run them yourself. WP-Cron needs site traffic, so a quiet site may run them late. The dashboard shows when daily hardening was missed or incomplete and keeps partial scan results visible. Completed integrity and file scans can email the site administrator about changed published files or selected suspicious PHP matches. When vulnerability checks are on, confirmed high and critical findings can also send an alert. Severity comes from a valid provider CVSS score. Missing scores stay unknown. Partial checks keep earlier alert history until a complete check resolves it. The message contains finding IDs and a dashboard link, not file contents. You can turn these emails off in wp-admin. "Accepted for sending" doesn't prove the message reached an inbox.

The REST request watch only records matches. It checks public REST query values and five levels of the request body for six patterns, including six layers of URL encoding. Values aren't stored. A seventh encoding layer and a sixth nested level are still missed. It doesn't block requests. Set `AMSEC_DISABLE_FIREWALL` to `true` in `wp-config.php` to stop it.

Vulnerability checks stay off until an administrator turns them on. When they're on, this site asks the public WPVulnerability API for its WordPress core version and installed plugin and theme slugs. Requests go directly from your server to https://www.wpvulnerability.net/. The provider can see the request IP and the component you asked about. AmazingPlugins doesn't receive your inventory. The plugin stores responses and reports them locally. You can turn off future lookups in wp-admin. Older reports stay until you clear them. See the provider's privacy policy at https://www.wpvulnerability.com/privacy/ and license at https://www.wpvulnerability.com/license/. Data is credited to WPVulnerability and linked to its original sources.

The lookup compares published issues with installed versions. Unknown package identity, unsupported ranges, stale data, and provider errors are marked unknown or possible affected. It doesn't update installed software, and it doesn't claim the site is vulnerability-free.

Login protection is off when you install the plugin. You can watch failed logins first, then choose to block a server address after five failures in 15 minutes. The block lasts 15 minutes. Shared networks can affect more than one visitor. The plugin uses the server connection address, not forwarded headers, and ignores counter records after 24 hours. Expired records are deleted by WP-Cron or on the next failed login or dashboard view. WP-Cron needs site traffic to run. Turning protection off deletes the counters. If the counter store fails or reaches its 10,000-address limit, login attempts are allowed and the dashboard reports incomplete coverage. Password reset isn't blocked.

Administrators can enroll a TOTP authenticator over HTTPS. WordPress and WooCommerce login forms then ask that administrator for a six-digit code or one of ten single-use recovery codes after a valid password. Save the recovery codes when they appear. The plugin doesn't show them again. TOTP seeds are encrypted with site-specific key material, and recovery codes are stored as hashes. If site keys change, use a recovery code or the local WP-CLI command below. Customer accounts, application passwords, and XML-RPC requests are outside this TOTP rule. Custom interactive login forms that omit the code field deny enrolled administrators rather than skipping the check.

The XML-RPC setting blocks methods that require authentication. It doesn't turn off pingbacks or the whole XML-RPC endpoint. Check Jetpack or mobile publishing before you turn it on.

If you lose admin access, run `wp amazing-security login disable` from the site's WP-CLI environment. To remove one administrator's TOTP requirement, run `wp amazing-security totp disable --user=<id>`. These commands act locally. They don't need an AmazingPlugins account. The plugin keeps login settings and enrollment data on uninstall unless you select **Erase login protection data on uninstall** first.

AI assistant access starts off. On WordPress 6.9 or newer, install the official MCP Adapter separately, then turn on access in Amazing Security. An authenticated administrator can list findings, inspect a finding, run the six local hardening checks, and read that scan. Two more abilities can prepare a login-rate change and read its status.

Each call checks the current WordPress user's permission and the site's MCP setting. Scan requests have a concurrency guard and a 60-second cooldown per administrator. They don't start file, integrity, or vulnerability scans. The MCP Adapter handles the connection and authentication; Amazing Security doesn't bundle a server. Turn access off in wp-admin to stop further calls.

An assistant can propose only two staged changes: off to observe, then observe to block. The proposal lasts 15 minutes and changes nothing by itself. Open its wp-admin link to review and approve the exact setting. Approval needs an administrator cookie session and a proposal-specific nonce. Block mode also needs HTTPS and the administrator's current password. A changed setting or a second approval is refused. After approval, the page offers a 24-hour rollback. Turning assistant access off stops pending approvals, but an already applied change can still be rolled back. The assistant can't start file repair. The plugin doesn't offer a general firewall or a maintained malware signature feed.

== Installation ==

Upload the plugin ZIP from Plugins, Add New, Upload Plugin. Activate it, then open Amazing Security. The first six checks stay in that order. Extra checks, emails, vulnerability lookups, and login rules stay off until an administrator turns them on.

== Frequently Asked Questions ==

= Does a finished scan mean the site is clean? =

No. A pass means that one check didn't find the thing it looks for. Run the checks again after you change files or settings.

= Does this plugin send my pages to someone else? =

Local checks stay on the server. The separate file and integrity scans contact WordPress.org only when you start them. Vulnerability lookups contact WPVulnerability only after you turn them on. The homepage header check runs only if you tick that box on the local-checks form.

= What stays off after activation? =

Login blocking, the sign-in confirmation, the common-password list, required verification, version-tag hiding, discovery-link hiding, and assistant access all stay off until you turn them on.

== Changelog ==

= 0.1.0 =
* Private preview. Local starting-list checks, optional WordPress.org file comparison, and opt-in vulnerability lookups.
