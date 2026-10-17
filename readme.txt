=== Amazing Security ===
Contributors: amazingplugins
Tags: security, hardening, malware scan, login security, file integrity
Requires at least: 6.6
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Security checks that show their evidence: hardening, file integrity, suspicious PHP, opt-in vulnerability lookups, and login protection.

== Description ==

Amazing Security scans your site and shows what it found, with the evidence. Nothing changes until you approve it. Every protection is off when you install the plugin, so you choose what to turn on.

= Scan =

One button runs the local hardening checks: HTTPS, WordPress updates, the admin login, debug display, the theme and plugin file editor, login monitoring, and more. Results are sorted into tabs, and each finding says what to open next.

A passing check means that check didn't find the problem it looks for. It doesn't prove the site is clean.

= Files =

* **Integrity scan.** Compares WordPress core and WordPress.org plugin files with the published checksums. WordPress.org themes are compared with their release ZIP. A changed file is different from the release, which doesn't make it malware. Custom and child themes stay "unknown".
* **File scan.** Reads PHP-like files in plugins, themes, and uploads with 43 local patterns. A match shows the file, the line, and the rule, with a note on why it needs a look. A hit is suspected code, not proof of malware. Files never leave your server. The scan works in bounded steps (5,000 files, 128 MiB, or 30 seconds per step) and picks up where it stopped.
* **Repair.** When a WordPress.org plugin file differs from its release, an administrator can review a repair. The page shows the path and both SHA-256 hashes before you approve. The old file goes to a private backup outside the public site folder, and you can roll it back from wp-admin or with `wp amazing-security repair rollback <finding-id>`.

= Login and accounts =

All of these are off until you turn them on under **Log In & Register**:

* Limit repeated sign-in attempts per address (record only, or limit).
* Turn off password sign-in through xmlrpc.php. Pingbacks are separate.
* Sign out idle wp-admin sessions after 15, 30 or 60 minutes.
* Hold new registrations until an administrator approves them.
* Email a six-digit sign-in code. A code expires after 10 minutes and stops working after five wrong tries.
* Ask a simple sum on the login form. This slows down basic bots. It isn't a CAPTCHA.
* Block administrators from signing in with a password found in public breach data (see External services).
* Password rules, session lists, and a sign-in email to the account owner.

If you get locked out, run `wp amazing-security login disable` from WP-CLI on the server.

= Traffic =

Hostname, browser and referrer block lists, a live request log, hotlink protection, comment and registration limits, REST rate controls, manual network rules, security headers, and trusted proxy settings. Each one stays off until you save it. Every blocking control has a WP-CLI command to turn it off again, for example `wp amazing-security traffic disable`.

The REST request watch only records matches. It doesn't block requests. Set `AMSEC_DISABLE_FIREWALL` to `true` in `wp-config.php` to stop it.

= Notifications =

Optional emails for changed files, suspicious PHP matches, and high-severity vulnerabilities, plus a weekly digest. They use your site's WordPress mail and go to the admin email. Both are off by default.

= AI assistant access (MCP) =

Off by default. On WordPress 6.9 or newer, with the official MCP Adapter plugin installed, an administrator can let an AI assistant list findings, run the local hardening checks, and propose a sign-in limit change. A proposal changes nothing until an administrator approves it in wp-admin. The assistant can't start a file repair.

= What this plugin doesn't do =

* It doesn't have a maintained malware signature feed. Patterns update with plugin releases.
* It doesn't remove malware or repair a whole plugin.
* Scheduled scans run on WP-Cron, which needs site traffic. A quiet site may run them late.

== External services ==

The plugin contacts these services only for the features listed below. It never sends file contents, passwords, or personal data, and AmazingPlugins doesn't receive any of it.

**WordPress.org (api.wordpress.org, downloads.wordpress.org)**
Used by the integrity scan, which runs when you start it and once a day on WP-Cron. It sends the WordPress version and installed plugin and theme slugs and versions, then downloads published checksums and theme release ZIPs. The Directory status screen also asks api.wordpress.org/plugins/info about installed plugin slugs when you click to look them up.
[Terms](https://wordpress.org/about/domains/) · [Privacy policy](https://wordpress.org/about/privacy/)

**WPVulnerability (www.wpvulnerability.net)**
Used only after an administrator turns on vulnerability checks. It sends the WordPress core version and installed plugin and theme slugs. The provider can see your server's IP address. You can turn lookups off at any time.
[License and terms](https://www.wpvulnerability.com/license/) · [Privacy policy](https://www.wpvulnerability.com/privacy/)

**Have I Been Pwned, Pwned Passwords (api.pwnedpasswords.com)**
Used only after an administrator turns on the breached-password check, and only when an administrator signs in. It sends the first 5 characters of the password's SHA-1 hash, never the password or the full hash. The match is checked on your server.
[Terms](https://haveibeenpwned.com/API/v3#AcceptableUse) · [Privacy policy](https://haveibeenpwned.com/Privacy)

**Your own site**
The security headers check requests your own homepage to read its response headers, only when you tick that option.

== Installation ==

1. In wp-admin, go to Plugins, Add New, Upload Plugin, and upload the ZIP. Or search for "Amazing Security".
2. Activate the plugin and open **Amazing Security** in the admin menu.
3. Press **Scan**. Then go through Recommendations to choose which protections to turn on.

== Frequently Asked Questions ==

= Does a finished scan mean the site is clean? =

No. A pass means that check didn't find what it looks for. Run the scan again after you change files or settings.

= Does this plugin send my site's data somewhere? =

Local checks stay on your server. See External services for the few lookups that leave it, and when they happen.

= What happens when I delete the plugin? =

By default, your settings are kept in case you reinstall. To remove everything, tick **Erase all Amazing Security settings, logs and scan results when the plugin is deleted** under Log In & Register before you delete the plugin. Repair backups stored outside the site folder are not removed.

= I'm locked out. What do I do? =

Run `wp amazing-security login disable` on the server. Other controls have their own commands, such as `wp amazing-security traffic disable` and `wp amazing-security network disable`.

== Credits ==

* Fraunces and Inter fonts, bundled under the SIL Open Font License 1.1 (see assets/fonts/).
* WebAuthn library by Lukas Buchs (lbuchs/WebAuthn 2.2.0), MIT license, bundled in src/Vendor/WebAuthn.
* Vulnerability data from WPVulnerability, credited to its original sources.

== Changelog ==

= 0.1.0 =
* First release: local hardening scan, file integrity and pattern scans, reviewed file repair, opt-in vulnerability lookups, login and traffic protection, and email notifications.
