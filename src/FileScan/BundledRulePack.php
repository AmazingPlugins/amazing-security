<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

defined( 'ABSPATH' ) || exit;

final class BundledRulePack {
	public function version(): string {
		return '2026.10.19.1';
	}

	public function rules(): array {
		return array(
			'AS-PHP-001' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\beval\s*\(\s*base64_decode\s*\(/i',
				'summary' => 'Decoded input is evaluated as PHP code.',
			),
			'AS-PHP-002' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\b(?:system|exec|shell_exec|passthru|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[/i',
				'summary' => 'Request input is passed directly to a command function.',
			),
			'AS-PHP-003' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\b(?:include|require)(?:_once)?\s*\(?\s*file_get_contents\s*\(\s*\x01URL\x02/i',
				'summary' => 'A remote response supplies the path used by include or require.',
			),
			'AS-PHP-004' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\beval\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[/i',
				'summary' => 'Request input is directly evaluated as PHP code.',
			),
			'AS-PHP-005' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST)\s*\[/i',
				'summary' => 'Request input directly selects a PHP file to load.',
			),
			'AS-PHP-006' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\beval\s*\(\s*gzinflate\s*\(\s*base64_decode\s*\(/i',
				'summary' => 'Compressed, decoded input is evaluated as PHP code.',
			),
			'AS-PHP-007' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\beval\s*\(\s*\$_COOKIE\s*\[/i',
				'summary' => 'Cookie input is directly evaluated as PHP code.',
			),
			'AS-PHP-008' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\bheader\s*\(\s*\x01LOCATION\x02\s*\.\s*\$_(?:GET|POST|REQUEST)\s*\[/i',
				'summary' => 'Request input is used directly in a Location header.',
			),
			'AS-PHP-009' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\b(?:echo|print)\s*\x01HIDDEN_EXTERNAL_LINK\x02/i',
				'summary' => 'PHP emits a hidden link to an external site.',
			),
			'AS-PHP-010' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
				'summary' => 'Request or cookie data is passed directly to PHP unserialize.',
			),
			'AS-PHP-011' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\bcall_user_func\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
				'summary' => 'Request or cookie data directly selects a PHP callback.',
			),
			'AS-PHP-012' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\bwp_redirect\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[/i',
				'summary' => 'Request input is passed directly to wp_redirect.',
			),
			'AS-PHP-013' => array(
				'pattern' => '/\x01INDIRECT_REDIRECT\x02/',
				'summary' => 'Request input is assigned to a variable immediately passed to wp_redirect.',
			),
			'AS-PHP-014' => array(
				'pattern' => '/\x01INDIRECT_COMMAND\x02/',
				'summary' => 'A literal-selected command function receives request input.',
			),
			'AS-PHP-015' => array(
				'pattern' => '/\x01INLINE_HIDDEN_LINK\x02/',
				'summary' => 'Inline HTML contains a hidden link to an external site.',
			),
			'AS-PHP-016' => array(
				'pattern' => '/\x01INDIRECT_EVAL\x02/',
				'summary' => 'Request or cookie data is assigned to a variable immediately evaluated as PHP code.',
			),
			'AS-PHP-017' => array(
				'pattern' => '/\x01REQUEST_CALLBACK\x02/',
				'summary' => 'Request or cookie data selects a variable callback immediately invoked.',
			),
			'AS-PHP-018' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\bassert\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
				'summary' => 'Request or cookie data is passed directly to assert. A second variable between the request and assert is not matched.',
			),
			'AS-PHP-019' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\beval\s*\(\s*str_rot13\s*\(/i',
				'summary' => 'Rotated text is evaluated as PHP code. Other encodings are not matched.',
			),
			'AS-PHP-020' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\bfile_put_contents\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[/i',
				'summary' => 'Request input directly selects a file to write. A second variable between the request and the write is not matched.',
			),
			'AS-PHP-021' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
				'summary' => 'Request or cookie data is expanded into variables. A second variable between the request and extract is not matched.',
			),
			'AS-PHP-022' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\bparse_str\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
				'summary' => 'Request or cookie data is parsed into variables. A second variable between the request and parse_str is not matched.',
			),
			'AS-PHP-023' => array(
				'pattern' => '/\x01INDIRECT_ASSERT\x02/',
				'summary' => 'A variable holding assert is called with request data within six assignments. A seventh assignment is not matched.',
			),
			'AS-PHP-024' => array(
				'pattern' => '/\x01INDIRECT_EXTRACT\x02/',
				'summary' => 'Request data reaches extract through up to six variables. A seventh assignment is not matched.',
			),
			'AS-PHP-025' => array(
				'pattern' => '/\x01INDIRECT_PARSE\x02/',
				'summary' => 'Request data reaches parse_str through up to six variables. A seventh assignment is not matched.',
			),
			'AS-PHP-026' => array(
				'pattern' => '/\x01INDIRECT_WRITE\x02/',
				'summary' => 'Request data reaches file_put_contents through up to six variables. A seventh assignment is not matched.',
			),
			'AS-PHP-027' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\bcreate_function\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)\s*\[|S\s*,\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[)|\x01INDIRECT_CREATE\x02/i',
				'summary' => 'Request data is passed to create_function directly or through three variables. A fourth copied variable is not matched.',
			),
			'AS-PHP-028' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\bpreg_replace\s*\(\s*\x01PREG_E\x02|\x01INDIRECT_PREG_E\x02/i',
				'summary' => 'A preg_replace pattern uses the old e modifier, including two variables that hold that pattern. A third copied variable is not matched.',
			),
			'AS-PHP-029' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\bmove_uploaded_file\s*\([^;]{0,240}S\s*\.\s*NON_GLOBAL_NAME\s*\.\s*S\s*\)/i',
				'summary' => 'move_uploaded_file builds its destination from two string literals around a name in the same call. A single destination string is not matched.',
			),
			'AS-PHP-030' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\bfile_put_contents\s*\(\s*(?:NON_GLOBAL_NAME\s*\.\s*)?S\s*,\s*\$_(?:POST|REQUEST)\s*\[/i',
				'summary' => 'file_put_contents writes a string path using $_POST or $_REQUEST in the same statement. $_GET, and a request value used only in another statement, are not matched.',
			),
			'AS-PHP-031' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\b(?:shell_exec|passthru)\s*\(\s*S(?:\s*\.\s*S)*\s*\.\s*\$_(?:GET|POST|REQUEST)\s*\[/i',
				'summary' => 'shell_exec or passthru concatenates a string literal in front of a request variable in the same statement. A request variable passed alone is a different rule, and exec is not matched.',
			),
			'AS-PHP-032' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\bcopy\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[\s*S\s*\]\s*,\s*S/i',
				'summary' => 'copy reads a request value and writes a string path in the same call. A variable destination, a joined path, and $_COOKIE are not matched.',
			),
			'AS-PHP-033' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\bfopen\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[/i',
				'summary' => 'fopen is called with a request value in the same statement. A variable path and $_COOKIE are not matched.',
			),
			'AS-PHP-034' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\bheader\s*\(\s*\x01REFRESH\x02\s*\.\s*\$_(?:GET|POST|REQUEST)\s*\[/i',
				'summary' => 'A Refresh header sends the browser to a request value in the same statement. A fixed URL and a variable destination are not matched.',
			),
			'AS-PHP-035' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\breadfile\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[/i',
				'summary' => 'readfile is called with a request value in the same statement. A variable path and $_COOKIE are not matched.',
			),
			'AS-PHP-036' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\beval\s*\(\s*wp_remote_retrieve_body\s*\(/i',
				'summary' => 'eval runs the body of an HTTP response in the same statement. One assignment then eval is AS-PHP-038. One copy then eval is AS-PHP-040. Two copies then eval is AS-PHP-042.',
			),
			'AS-PHP-037' => array(
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\b(?:include|require)(?:_once)?\s*\(?\s*\x01DATA_URI\x02/i',
				'summary' => 'include or require loads a data:// stream in the same statement. One assignment then include is AS-PHP-039. One copy then include is AS-PHP-041. Two copies then include is AS-PHP-043. A string that is only echoed is not matched.',
			),
			'AS-PHP-038' => array(
				'pattern' => '/\x01INDIRECT_HTTP_BODY_EVAL\x02/',
				'summary' => 'An HTTP response body is stored in one variable and then evaluated. One copied variable then eval is AS-PHP-040. Two copies then eval is AS-PHP-042. A fourth hop is not matched.',
			),
			'AS-PHP-039' => array(
				'pattern' => '/\x01INDIRECT_DATA_URI\x02/',
				'summary' => 'A data:// string is stored in one variable and then loaded with include or require. One copied variable then include is AS-PHP-041. Two copies then include is AS-PHP-043. A fourth hop is not matched.',
			),
			'AS-PHP-040' => array(
				'pattern' => '/\x01INDIRECT_HTTP_BODY_EVAL_COPY\x02/',
				'summary' => 'An HTTP response body is copied once and then evaluated. Two copies then eval is AS-PHP-042. A fourth hop is not matched.',
			),
			'AS-PHP-041' => array(
				'pattern' => '/\x01INDIRECT_DATA_URI_COPY\x02/',
				'summary' => 'A data:// string is copied once and then loaded with include or require. Two copies then include is AS-PHP-043. A fourth hop is not matched.',
			),
			'AS-PHP-042' => array(
				'pattern' => '/\x01INDIRECT_HTTP_BODY_EVAL_COPY2\x02/',
				'summary' => 'An HTTP response body is copied twice and then evaluated. A fourth hop is not matched.',
			),
			'AS-PHP-043' => array(
				'pattern' => '/\x01INDIRECT_DATA_URI_COPY2\x02/',
				'summary' => 'A data:// string is copied twice and then loaded with include or require. A fourth hop is not matched.',
			),
			'AS-MAL-001' => array(
				'summary' => 'Decoded or decompressed text is run as PHP with eval or assert.',
			),
			'AS-MAL-002' => array(
				'summary' => 'A command or eval call receives request or HTTP header data in the same statement.',
			),
			'AS-MAL-003' => array(
				'summary' => 'A backtick shell command contains request data.',
			),
			'AS-MAL-004' => array(
				'summary' => 'Request data is passed where a function expects a callback.',
			),
			'AS-MAL-005' => array(
				'summary' => 'A request value is called as a function.',
			),
			'AS-MAL-006' => array(
				'summary' => 'eval runs the result of a variable function call.',
			),
			'AS-MAL-007' => array(
				'summary' => 'The file contains the name or marker of a known web shell.',
			),
			'AS-MAL-008' => array(
				'summary' => 'A dangerous function name is hidden by splitting, reversing or rot13.',
			),
			'AS-MAL-009' => array(
				'summary' => 'A very long encoded string sits in a file that also decodes text.',
			),
			'AS-MAL-010' => array(
				'summary' => 'An upload is saved under the file name the visitor sent.',
			),
			'AS-MAL-011' => array(
				'summary' => 'A standalone upload form that uses no WordPress functions.',
			),
			'AS-MAL-012' => array(
				'summary' => 'A standalone mailer that sends mail from request data without WordPress.',
			),
			'AS-MAL-013' => array(
				'summary' => 'The file writes over itself.',
			),
			'AS-MAL-014' => array(
				'summary' => 'Text is built by combining many string pieces with ^, | or &, a common obfuscation.',
			),
			'AS-MAL-015' => array(
				'summary' => 'A function name is assembled one character at a time from another string.',
			),
			'AS-MAL-016' => array(
				'summary' => 'The file calls four or more different command functions.',
			),
			'AS-MAL-017' => array(
				'summary' => 'A database query is taken straight from request data.',
			),
			'AS-MAL-018' => array(
				'summary' => 'include or require loads an image, text file or hex-escaped path.',
			),
			'AS-MAL-019' => array(
				'summary' => 'The file tries to undo disable_functions or safe_mode.',
			),
			'AS-MAL-020' => array(
				'summary' => 'A variable filled from request data is run as a command or as PHP.',
			),
		);
	}
}
