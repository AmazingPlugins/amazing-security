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

An administrator can list up to 1,000 installed core, plugin, and theme identities. A plugin or theme is eligible for a no-match result only when a local WordPress update record links its slug to an official `downloads.wordpress.org` package. Custom update URIs and ambiguous versions stay `unknown`. The inventory does not send site data to a service in this preview.

The snapshot verifier accepts only a signed, complete, current record set bound to the exact inventory. It rejects tampering, replay, stale dates, unsupported schemas, oversized payloads, and wrong-inventory snapshots. No live signing key or feed connection ships in this preview, so normal scans show **Feed not connected** and `unknown` coverage. A future service plan must define feed licensing, key rotation, consent, and deletion before the report can make current vulnerability findings. No no-match result means the site is vulnerability-free.
