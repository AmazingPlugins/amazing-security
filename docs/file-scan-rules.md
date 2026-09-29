# Bundled local code checks

Version `2026.09.29.1` ships with Amazing Security. The rules run on the site when an administrator starts a scan. They do not update between plugin releases and cannot confirm that a file is malware-free.

| Rule | What it looks for | Common false positive |
| --- | --- | --- |
| AS-PHP-001 | `eval` called on the result of `base64_decode` | Demonstration or compatibility code that intentionally evaluates encoded PHP. |
| AS-PHP-002 | Request input passed directly to a command function such as `system` or `shell_exec` | A controlled maintenance endpoint with its own strict authorization and validation. |
| AS-PHP-003 | Remote content fetched with `file_get_contents` and passed to PHP `include` or `require` | A developer tool that intentionally loads remote PHP. |

The matcher tokenizes PHP and ignores comments, documentation strings, and ordinary encoding calls. A hit is labeled **suspected code**. Review the named relative path and line with a trusted developer before taking action. The scanner stores the rule ID, version, path, and line, not source snippets or matched content.
