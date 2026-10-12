=== Amazing Security ===
Contributors: amazingplugins
Tags: security, hardening, audit
Requires at least: 6.6
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress hardening checks, release file checks, opt-in vulnerability lookups and local login protection. Most protections start off.

== Description ==

Amazing Security looks at your WordPress site, tells you what it found in plain words, and lets you decide what to change. It reports first. Nothing that changes how visitors or administrators sign in is on after you activate it.

**What you see**

The Scan screen sorts every check into Success, Error, Critical, Warning or Recommended, with the reason and a next step. A pass means one check didn't find the thing it looks for. It doesn't mean the site is clean.

**Checks that read your site**

* Hardening: HTTPS, WordPress updates, the admin login, debug display, the theme and plugin editor, login monitoring, file permissions and more.
* Release file comparison: WordPress core, eligible WordPress.org plugins and eligible WordPress.org themes are compared with the published release. A changed file differs from the release. It isn't proof of malware. Custom and child themes stay unknown.
* Suspicious file review: PHP-like files in plugins, themes and uploads are read with 43 local patterns. A match is suspected code, and a scan with no matches doesn't prove the site is clean. There is no maintained malware feed, and the rules update with plugin releases. The scan stops after 5,000 files, 128 MiB read or 30 seconds, and it says when coverage is partial. It can follow six copied assignments, three copies before create_function, and a preg_replace /e pattern held in two variables. A seventh assignment, a fourth create_function copy and a third variable are still missed.
* Published content review: posts and comments are checked locally for suspicious links and hidden frames.
* Local inventory of selected public file names, security headers for your homepage (only if you tick the box), and plugin directory status (only after you consent).

**Protections you can turn on**

* Login limiting: watch failed logins first, then optionally block a server address for 15 minutes after five failures in 15 minutes. The plugin uses the server connection address, not forwarded headers. Shared networks can affect more than one visitor.
* Sign-in extras: a confirmation checkbox, a two-number question, an email code, idle logout, administrator approval for new registrations, password rules, and a common-password check.
* XML-RPC: block methods that need a login. This doesn't turn off pingbacks. Check Jetpack or mobile publishing first.
* Bot controls for the comment form and registration, hotlink protection for uploads, and manual address rules.
* Two-factor and passkeys: the plugin tells you whether an authenticator or passkey plugin is active and suggests Two Factor. It doesn't enroll codes or passkeys.

**Reviewing and fixing**

* If a finished check finds a changed WordPress.org plugin file, an administrator can review a repair. The page shows the file path and SHA-256 hashes before approval, and repair stops if anything no longer matches. The previous file is kept so you can roll back in wp-admin or with `wp amazing-security repair rollback <finding-id>`.
* A Recovery page (administrator, HTTPS, nonce) can download the prefixed database tables as SQL and move one unexpected file out of uploads, themes or plugins after you type DELETE. The file goes to a private backup first and the page shows where. This plugin's own files can't be removed this way.
* Every action that changes files, including plugin repair and moving a file, refuses to run when your site sets DISALLOW_FILE_MODS.
* Activity log, session manager, incident panel for administrator accounts, weekly digest and finding emails are available and off until you turn them on.

**Scheduled work**

WP-Cron runs the local hardening checks daily and then queues a bounded file scan. The daily comparison of release files with WordPress.org is off until an administrator ticks "Compare release files with WordPress.org every day" under Daily checks. You can run a release comparison by hand at any time. WP-Cron needs site traffic, so a quiet site may run late. The dashboard shows when daily checks were missed or incomplete.

**The REST request watch** only records matches. It checks public REST query values and five levels of the request body for seven patterns, including six layers of URL encoding. Values aren't stored and nothing is blocked. A seventh encoding layer and a sixth nested level are still missed. Set `AMSEC_DISABLE_FIREWALL` to `true` in `wp-config.php` to stop it.

**AI assistant access** starts off. On WordPress 6.9 or newer, install the official MCP Adapter separately, then turn on access in Amazing Security. An authenticated administrator can list findings, inspect one, run the local hardening checks and read that scan. Two more abilities can prepare a login-rate change and read its status. Each call checks the current user's permission. A proposal changes nothing until an administrator approves the exact setting in wp-admin with a cookie session and a nonce. Block mode also needs HTTPS and the administrator's current password. An applied change can be rolled back for 24 hours.

**If you lose access**

Run `wp amazing-security login disable` from the site's WP-CLI environment to turn off login blocking and the XML-RPC restriction. If the sign-in question, confirmation, email code or common-password check stops you, turn it off with `wp option update amsec_login_challenge 0`, `amsec_login_confirm`, `amsec_email_factor` or `amsec_common_passwords` in the same way. Other commands turn off bot, network, proxy, traffic and REST-rate rules. These act locally and don't need an AmazingPlugins account.

== External services ==

Amazing Security talks to outside services only in the cases below. Nothing is sent to AmazingPlugins. File contents, page content and passwords are never sent.

* **WordPress.org** (api.wordpress.org and downloads.wordpress.org). Used for the release file comparison when you start one or turn on the daily comparison, and for plugin repair downloads you approve. Sends the WordPress version, the plugin and theme slugs and versions being checked, and your server's IP address as part of the request. Terms: https://wordpress.org/about/privacy/
* **WPVulnerability** (www.wpvulnerability.net). Off until an administrator turns on vulnerability checks. Sends the WordPress core version and installed plugin and theme slugs. The provider sees your server's IP address. Privacy: https://www.wpvulnerability.com/privacy/ License: https://www.wpvulnerability.com/license/ Data is credited to WPVulnerability and linked to its original sources.
* **Plugin directory status** (api.wordpress.org/plugins/info). Off until an administrator consents. Sends the slugs of installed plugins.
* **Have I Been Pwned** (api.pwnedpasswords.com). Off until an administrator turns on the common-password check. When a password is set or an administrator signs in, only the first five characters of its SHA-1 hash are sent, so the password is never shared. The reply is cached for an hour. Privacy: https://haveibeenpwned.com/Privacy
* **Your own homepage.** If you tick the box on the local-checks form, the plugin requests your site's homepage once to read its security headers.

== Data and uninstall ==

The plugin stores its settings and scan results in options, and some features keep their own database tables: login counters, the activity log, bot counters, traffic history, repair proposals and audit records, and passkey status. Plugin repair keeps a backup of the replaced file in a private folder outside the served site.

Deactivating stops scheduled work, resets any scan in progress and removes the hotlink rule this plugin may have added to the uploads .htaccess file. Settings and data stay.

Deleting the plugin removes cached lookups and the same hotlink rule and keeps your settings and data unless you select **Erase all Amazing Security data on uninstall** on the Log In and Register screen before you delete it. With that box ticked, every Amazing Security option, user meta row and table is removed.

== Installation ==

Upload the plugin ZIP from Plugins, Add New, Upload Plugin. Activate it, then open Amazing Security. The first six checks stay in order at the top. Extra checks, emails, vulnerability lookups and login rules stay off until an administrator turns them on.

== Frequently Asked Questions ==

= Does a finished scan mean the site is clean? =

No. A pass means that one check didn't find the thing it looks for. Run the checks again after you change files or settings.

= Does this plugin send my pages to someone else? =

No. File contents, pages and passwords are never sent. The release file comparison contacts WordPress.org only when you start it or turn on the daily comparison. Vulnerability lookups contact WPVulnerability only after you turn them on. See External services for the full list.

= What stays off after activation? =

Login blocking, the sign-in confirmation, the common-password check, idle logout, registration approval, XML-RPC blocking, bot controls, hotlink protection, live traffic history, the daily release file comparison, vulnerability lookups, assistant access and email alerts all stay off until you turn them on.

= Does it change the login screen? =

Not until you turn something on. With nothing changed, the login, lost-password and registration pages and the login response are identical with or without the plugin.

= Can it lock me out? =

Login blocking is off by default and can be set to observe first. The email code, the sign-in question, the confirmation checkbox and the common-password check can stop a sign-in when they are on. See "If you lose access" above for the WP-CLI commands that turn each one off.

== Changelog ==

= 0.1.0 =
* Initial release. Local starting-list checks, optional WordPress.org file comparison, and opt-in vulnerability lookups.
