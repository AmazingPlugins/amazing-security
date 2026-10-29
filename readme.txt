=== AmazingPlugins Security Scanner ===
Contributors: amazingplugins
Tags: security, hardening, malware scan, login security, file integrity
Requires at least: 6.6
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 0.1.3
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Security checks that show their evidence: hardening, file integrity, suspicious PHP, opt-in vulnerability lookups, and login protection.

== Description ==

AmazingPlugins Security Scanner scans your site and shows what it found, with the evidence. Nothing changes until you approve it. Every protection is off when you install the plugin, so you choose what to turn on. Nothing runs in the background until you press Scan for the first time. After that, the scan repeats once a day.

= Scan =

One button runs the local hardening checks: HTTPS, WordPress updates, the admin login, debug display, the theme and plugin file editor, login monitoring, and more. Results are sorted into tabs, and each finding says what to open next.

A passing check means that check didn't find the problem it looks for. It doesn't prove the site is clean.

**Malware scan.** Every scan also looks for code shaped like web shells and injected malware. It reads plugins, themes, uploads and mu-plugins. It also reads folders WordPress doesn't list as a plugin or theme, plus loose PHP files in the site root and in wp-content. There are 63 local rules. 43 read the PHP code. The other 20 read the raw file, so files too big for the code rules still get checked, up to 2 MB. A bigger PHP file is listed as not checked. On a large site the scan keeps going in the background until it has read every file. A hit names the file, the line and the rule. Nothing gets deleted, and your files stay on your server.

= Files =

* **Integrity scan.** Compares WordPress core and WordPress.org plugin files with the published checksums. Up to three WordPress.org themes are compared with their release ZIP. On a big site one pass may not reach them all, and the result says so. A changed file is different from the release, which doesn't make it malware. Custom and child themes stay "unknown".
* **File scan.** Reads PHP-like files in plugins, themes, and uploads with the same 63 local rules. A match shows the file, the line, and the rule, with a note on why it needs a look. A hit is suspected code, not proof of malware. Files never leave your server. The scan runs in short steps and picks up where it stopped. It stops for good after 50,000 files, 1 GiB, or 300 seconds of work.

= Login and accounts =

All of these are off until you turn them on. Most are under **Log In & Register**. The hidden field and the breached-password check are turned on from Recommendations.

* Limit repeated sign-in attempts per address (record only, or limit).
* Turn off password sign-in through xmlrpc.php. Pingbacks are separate.
* Sign out signed-in users after 15, 30 or 60 minutes without activity.
* Hold new registrations until an administrator approves them.
* Email a six-digit sign-in code. A code expires after 10 minutes and stops working after five wrong tries.
* Ask a simple sum on the login form. This slows down basic bots. It isn't a CAPTCHA.
* Add a hidden field to the login form. Simple bots fill it in and get refused. People never see it, and there is nothing to tick.
* Check new and reset passwords against public breach data, and block administrators whose password shows up there (see External services).
* Password rules, session lists, and an email to an administrator when they sign in (at most once an hour).

You need HTTPS and your password to end sessions or change some Traffic settings.

If you get locked out, run `wp amazing-security login disable` from WP-CLI on the server. It turns off every sign-in check above. Accounts waiting for approval stay waiting.

= Traffic =

Hostname, browser and referrer block lists, a live request log, hotlink protection, comment and registration limits, REST rate controls, manual network rules, a security headers check, and trusted proxy settings. Each blocking control stays off until you save it, and each can be turned off from WP-CLI. `wp amazing-security traffic disable` turns off the block lists, live log, hotlink protection, precise blocks and comment checks. `bots disable`, `rest-rates disable`, `network disable` and `proxies disable` cover the rest.

The security headers check reads your homepage's response headers and lists the missing ones. It doesn't add headers.

The REST request watch is on from the start. It only records matches, on your server, and doesn't block requests. Set `AMSEC_DISABLE_FIREWALL` to `true` in `wp-config.php` to stop it.

= Notifications =

Optional emails for changed files, suspicious PHP matches, and high-severity plugin vulnerabilities, plus a weekly digest. They use your site's WordPress mail and go to the admin email. Both are off by default.

= AI assistant access (MCP) =

Off by default. On WordPress 6.9 or newer, with the official MCP Adapter plugin installed, an administrator can let an AI assistant list findings, run the local hardening checks, and propose a sign-in limit change. A proposal changes nothing until an administrator approves it in wp-admin.

= What this plugin doesn't do =

* It doesn't have a maintained malware signature feed. Patterns update with plugin releases.
* It doesn't change plugin, theme or core files. When a file differs from its release, reinstall that plugin or theme from Plugins or Appearance, or reinstall WordPress from Dashboard > Updates.
* Scheduled scans run on WP-Cron, which needs site traffic. A quiet site may run them late.

== External services ==

The plugin contacts these services only for the features listed below. It never sends file contents, passwords, or personal data, and AmazingPlugins doesn't receive any of it.

**WordPress.org (api.wordpress.org, downloads.wordpress.org)**
Used by the integrity scan, which runs when you press Scan and then once a day on WP-Cron. It sends the WordPress version and locale and the installed plugin and theme slugs and versions, then downloads published checksums and theme release ZIPs. The Directory status screen also asks api.wordpress.org/plugins/info about installed plugin slugs when you click to look them up.
[Terms](https://wordpress.org/about/domains/) · [Privacy policy](https://wordpress.org/about/privacy/)

**WPVulnerability (www.wpvulnerability.net)**
Used only after an administrator turns on vulnerability checks. It sends the WordPress core version and installed plugin and theme slugs. The provider can see your server's IP address. You can turn lookups off at any time.
[License and terms](https://www.wpvulnerability.com/license/) · [Privacy policy](https://www.wpvulnerability.com/privacy/)

**CISA Known Exploited Vulnerabilities catalog (www.cisa.gov)**
Used only after an administrator turns on vulnerability checks and then the CISA list. During a vulnerability check, at most once a week, the site downloads the public list of security holes attackers are using. Nothing about your site is sent. CISA can see your server's IP address. Only the CVE IDs are kept, and turning the list off deletes them.
[About the catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [Privacy policy](https://www.cisa.gov/privacy-policy)

**Have I Been Pwned, Pwned Passwords (api.pwnedpasswords.com)**
Used only after an administrator turns on breached-password checks. It runs when an administrator signs in and when anyone sets or resets a password. It sends the first 5 characters of the password's SHA-1 hash, never the password or the full hash. The match is checked on your server.
[Terms](https://haveibeenpwned.com/API/v3#AcceptableUse) · [Privacy policy](https://haveibeenpwned.com/Privacy)

**Your own site**
Each scan requests your own homepage once to read its response headers, the same way WordPress Site Health checks your site. The request stays on your site and no other service gets it. You can turn it off under Settings → Scan options.

== Installation ==

1. In wp-admin, go to Plugins, Add New, Upload Plugin, and upload the ZIP. Or search for "AmazingPlugins Security Scanner".
2. Activate the plugin and open **Security Scanner** in the admin menu.
3. Press **Scan**. Then go through Recommendations to choose which protections to turn on.

== Frequently Asked Questions ==

= Does a finished scan mean the site is clean? =

No. A pass means that check didn't find what it looks for. Run the scan again after you change files or settings.

= Does this plugin send my site's data somewhere? =

Local checks stay on your server. See External services for the few lookups that leave it, and when they happen.

= What happens when I delete the plugin? =

By default, your settings are kept in case you reinstall. To remove everything, tick **Erase all AmazingPlugins Security Scanner settings, logs and scan results when the plugin is deleted** under Log In & Register before you delete the plugin.

= I'm locked out. What do I do? =

Run `wp amazing-security login disable` on the server. Other controls have their own commands, such as `wp amazing-security traffic disable` and `wp amazing-security network disable`.

== Credits ==

* Fraunces and Inter fonts, bundled under the SIL Open Font License 1.1 (see assets/fonts/).
* Vulnerability data from WPVulnerability, credited to its original sources.

== Changelog ==

= 0.1.3 =
* Renamed to AmazingPlugins Security Scanner (slug amazingplugins-security-scanner).

= 0.1.2 =
* Renamed to Amazing Security Scanner.
* Removed the file repair and recovery tools that replaced, moved or chmodded site files. Scans still report changed files.
* Theme release ZIPs are now downloaded with WordPress's download_url().

= 0.1.1 =
* Removed the unused passkey code and the bundled WebAuthn library. Passkey status for other plugins is still reported.

= 0.1.0 =
* First release: local hardening scan, file integrity and pattern scans, reviewed file repair, opt-in vulnerability lookups, login and traffic protection, and email notifications.
