<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

final class BundledRulePack {
	public function version(): string {
		return '2026.10.03.3';
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
		);
	}
}
