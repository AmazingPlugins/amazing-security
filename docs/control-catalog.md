# Local control catalog

These five checks read local WordPress state only. Their source is the [WordPress hardening guide](https://developer.wordpress.org/advanced-administration/security/hardening/). A pass means the specific value was observed at scan time, not that the site is secure.

| ID | Method | Unknown condition | Owner action |
| --- | --- | --- | --- |
| `core-updates` | Read cached core update response. | Cache unavailable or malformed. | Review Dashboard > Updates. |
| `debug-display` | Read `WP_DEBUG_DISPLAY` with `WP_DEBUG`. | Display setting unavailable. | Disable public debug display in configuration. |
| `file-editor` | Read `DISALLOW_FILE_EDIT`. | Setting cannot be inspected. | Consider enabling this configuration guard. Other controls may also restrict the editor. |
| `https-admin` | Check administrator URL scheme. | URL scheme unavailable. | Configure HTTPS and test admin login. |
| `default-admin-login` | Inspect at most 500 administrator logins for `admin`. | Query invalid or over 500 users. | Review privileged accounts. |

The update result depends on the last WordPress update cache refresh. HTTPS checks the configured admin URL, not an external TLS handshake or enforcement on every request. The account check does not assess password strength or 2FA and reports unknown if no administrators can be found.

## Release file integrity

An administrator can request a checksum comparison for WordPress core and plugins with a supported WordPress.org checksum manifest. The core package locale comes from the installed package, not the site's selected language. The plugin fetches manifests over HTTPS from `api.wordpress.org` and `downloads.wordpress.org` and hashes local files in bounded chunks. It does not upload file contents.

A changed file or missing core PHP file is `warn`. A missing plugin file, missing optional core file, unreadable path, or symlink is `inconclusive`. A package without a usable official manifest is `unknown`. An interrupted or capped scan is `partial`. Matching files count toward coverage; the scanner does not inspect unlisted extra files. A checksum match does not mean the site is malware-free.

Each request compares up to 250 files and reads up to 32 MiB within a cooperative five-second budget. The whole scan stops at 5,000 files, 128 MiB, or 30 seconds of accumulated work. At most 250 file findings are stored. The last completed integrity report stays visible if a later run is partial.

## Installed software and published vulnerabilities

An administrator can list up to 1,000 installed core, plugin, and theme identities. A WordPress.org update offer is not proof that the installed files came from that package: a custom plugin can use the same directory. Plugin and theme identities therefore stay `unknown` in this preview until a separate release-provenance check is built. Custom update URIs and ambiguous versions also stay `unknown`. The inventory does not send site data to a service in this preview.

After administrator opt-in, direct WPVulnerability lookups check installed component versions. Exact package identity is proven only where the local release-file check supports it. A version match without package proof is possible affected; an unverified no-match stays unknown. Stale or unavailable provider data cannot clear an earlier affected finding. The disconnected signed-snapshot verifier remains in the codebase for possible future use; it is not the source of direct lookup findings.

## Login protection

All login controls start off. Observe mode counts failures without denying login. Block mode denies an address after five failed interactive password or second-factor attempts in a 15-minute window, for 15 minutes. It reads `REMOTE_ADDR`, ignores forwarded headers, and stores a keyed address hash. Counters stop affecting decisions after 24 hours. WP-Cron removes expired rows when the site receives traffic; a failed login or dashboard view also cleans them. Turning protection off deletes all counters. A missing address or unavailable/full counter store fails open and reports unknown coverage. Password reset remains available. A shared network can cause a false lockout.

Administrator TOTP requires HTTPS and OpenSSL for enrollment. A six-digit code uses a 30-second step with one adjacent step of clock tolerance; a successful step cannot be reused. Ten single-use recovery codes are shown once. Seeds are encrypted locally and recovery codes are hashed. WordPress and WooCommerce login forms include the factor field. Other interactive forms without it deny enrolled administrators. WP-CLI recovery can disable rate blocking or one administrator's TOTP requirement without decrypting the seed.

The optional XML-RPC switch uses WordPress's `xmlrpc_enabled` filter to disable authenticated methods. Pingbacks and other unauthenticated XML-RPC methods remain available.
