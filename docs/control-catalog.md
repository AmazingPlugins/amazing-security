# Local control catalog

These five checks read local WordPress state only. Their source is the [WordPress hardening guide](https://developer.wordpress.org/advanced-administration/security/hardening/). A pass means the specific value was observed at scan time, not that the site is secure.

| ID | Method | Unknown condition | Owner action |
| --- | --- | --- | --- |
| `core-updates` | Read cached core update response. | Cache unavailable or malformed. | Review Dashboard > Updates. |
| `debug-display` | Read `WP_DEBUG_DISPLAY` with `WP_DEBUG`. | Display setting unavailable. | Disable public debug display in configuration. |
| `file-editor` | Read `DISALLOW_FILE_EDIT`. | Setting cannot be inspected. | Consider disabling the built-in file editor. |
| `https-admin` | Check administrator URL scheme. | URL scheme unavailable. | Configure HTTPS and test admin login. |
| `default-admin-login` | Inspect at most 500 administrator logins for `admin`. | Query invalid or over 500 users. | Review privileged accounts. |

The update result depends on the last WordPress update cache refresh. HTTPS checks the configured admin URL, not an external TLS handshake. The account check does not assess password strength or 2FA.
