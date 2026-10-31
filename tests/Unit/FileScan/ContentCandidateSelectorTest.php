<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\FileScan;

use AmazingPlugins\Security\FileScan\ContentCandidateSelector;
use AmazingPlugins\Security\FileScan\FileScanTarget;
use AmazingPlugins\Security\Integrity\Manifest;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class ContentCandidateSelectorTest extends TestCase {
	public function test_skips_only_fresh_exact_release_match_for_php_like_file(): void {
		$manifest = new Manifest( 'plugin', 'demo:1.0', 'https://wordpress.org/', new DateTimeImmutable(), 'sha256', array( 'known.php' => array( hash( 'sha256', 'known' ) ) ) );
		$target   = new FileScanTarget( 'demo:1.0', 'plugin', '/tmp/demo', $manifest );
		$selector = new ContentCandidateSelector();
		self::assertFalse( $selector->eligible( $target, 'known.php', hash( 'sha256', 'known' ) ) );
		self::assertTrue( $selector->eligible( $target, 'known.php', hash( 'sha256', 'changed' ) ) );
		self::assertTrue( $selector->eligible( $target, 'unknown.phtml', null ) );
		self::assertTrue( $selector->eligible( $target, 'shell.php7', null ) );
		self::assertFalse( $selector->eligible( $target, 'style.css', null ) );
	}

	public function test_unverified_and_stale_release_stay_eligible(): void {
		$selector = new ContentCandidateSelector();
		self::assertTrue( $selector->eligible( new FileScanTarget( 'custom', 'theme', '/tmp/custom' ), 'code.php', hash( 'sha256', 'known' ) ) );
		$old = new Manifest( 'theme', 'demo:1', 'https://wordpress.org/', new DateTimeImmutable( '-2 days' ), 'sha256', array( 'code.php' => array( hash( 'sha256', 'known' ) ) ) );
		self::assertTrue( $selector->eligible( new FileScanTarget( 'demo:1', 'theme', '/tmp/demo', $old ), 'code.php', hash( 'sha256', 'known' ) ) );
		self::assertFalse( $selector->eligible( new FileScanTarget( 'demo', 'core', '/tmp/demo' ), 'wp-admin/known.php', null ) );
		self::assertTrue( $selector->eligible( new FileScanTarget( 'demo', 'core', '/tmp/demo' ), 'wp-admin/extra.php', null, true ) );
	}
}
