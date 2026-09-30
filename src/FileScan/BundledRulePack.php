<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

final class BundledRulePack {
	public function version(): string {
		return '2026.09.30.1';
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
		);
	}
}
