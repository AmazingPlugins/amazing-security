<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\FileScan;

use AmazingPlugins\Security\FileScan\BundledRulePack;
use AmazingPlugins\Security\FileScan\RuleMatcher;
use PHPUnit\Framework\TestCase;

final class RuleMatcherTest extends TestCase {
	public function test_suspicious_constructs_have_stable_ids_and_no_snippets(): void {
		$matcher = new RuleMatcher( new BundledRulePack() );
		$cases = array(
			'AS-PHP-001' => 'obfuscated-eval.txt',
			'AS-PHP-002' => 'request-command.txt',
			'AS-PHP-003' => 'remote-include.txt',
			'AS-PHP-004' => 'request-eval.txt',
			'AS-PHP-005' => 'request-include.txt',
			'AS-PHP-006' => 'compressed-eval.txt',
			'AS-PHP-007' => 'cookie-eval.txt',
			'AS-PHP-008' => 'request-location-header.txt',
			'AS-PHP-009' => 'hidden-external-link.txt',
		);
		foreach ( $cases as $id => $filename ) {
			$code = file_get_contents( dirname( __DIR__, 2 ) . '/Fixtures/FileScan/' . $filename );
			$hits = $matcher->match( $code, 'plugins/demo/loader.php' );
			self::assertSame( array( $id ), array_column( $hits, 'ruleId' ) );
			self::assertSame( 'plugins/demo/loader.php', $hits[0]->relativePath );
			self::assertStringNotContainsString( 'ZWNobyAxOw==', json_encode( $hits ) );
			self::assertStringNotContainsString( 'bad.example', json_encode( $hits ) );
		}
	}

	public function test_comments_strings_and_common_encoding_do_not_trigger(): void {
		$matcher = new RuleMatcher( new BundledRulePack() );
		$benign = array(
			file_get_contents( dirname( __DIR__, 2 ) . '/Fixtures/FileScan/benign-comments.txt' ),
			'<?php $docs = "system(\\$_POST[cmd])";',
			file_get_contents( dirname( __DIR__, 2 ) . '/Fixtures/FileScan/benign-encoding.txt' ),
			file_get_contents( dirname( __DIR__, 2 ) . '/Fixtures/FileScan/benign-remote-data.txt' ),
			file_get_contents( dirname( __DIR__, 2 ) . '/Fixtures/FileScan/benign-request-routing.txt' ),
			file_get_contents( dirname( __DIR__, 2 ) . '/Fixtures/FileScan/benign-redirects-and-links.txt' ),
		);
		foreach ( $benign as $code ) {
			self::assertSame( array(), $matcher->match( $code, 'demo.php' ) );
		}
	}
}
