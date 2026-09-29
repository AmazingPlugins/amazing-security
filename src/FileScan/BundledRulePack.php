<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

final class BundledRulePack {
	public function version(): string {
		return '2026.09.29.2';
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
				'pattern' => '/(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)\b(?:include|require)(?:_once)?\s*\(?\s*file_get_contents\s*\(\s*URL\b/i',
				'summary' => 'Remote content is loaded for PHP execution.',
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
		);
	}
}
