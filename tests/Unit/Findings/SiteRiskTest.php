<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Findings;

use AmazingPlugins\Security\Admin\SiteRiskCard;
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\SiteRisk;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class SiteRiskTest extends TestCase {
	private const OFF = array( 'off', 'off', 'off' );

	private static function finding( string $id, array $evidence, string $state = 'warn' ): CheckResult {
		return new CheckResult( $id, $state, 'Summary', 'https://developer.wordpress.org/', new DateTimeImmutable( '2026-01-01T00:00:00Z' ), 'medium', 'complete', $evidence );
	}

	private static function package( string $risk, bool $exploited = false ): CheckResult {
		return self::finding( 'vulnerability', array( 'risk' => $risk ) + ( $exploited ? array( 'exploited' => true ) : array() ) );
	}

	/** @return array{0: string, 1: string} Status and reason for one area. */
	private static function verdict( string $area, array $findings, ?array $packages = null, array $bots = self::OFF, int $age = 0 ): array {
		foreach ( SiteRisk::rows( $findings, $packages, $bots, $age ) as $row ) {
			if ( $area === $row['area'] ) {
				return array( $row['status'], $row['reason'] );
			}
		}
		self::fail( 'Missing area ' . $area );
	}

	public function test_rows_cover_every_area_in_order(): void {
		self::assertSame( array( 'plugins', 'files', 'bots', 'ai', 'signin' ), array_column( SiteRisk::rows( array(), null, self::OFF, 0 ), 'area' ) );
	}

	public function test_plugins(): void {
		$on = array( self::finding( 'known-holes', array( 'enabled' => 'yes' ) ) );
		self::assertSame( array( 'risk', 'exploited' ), self::verdict( 'plugins', $on, array( self::package( 'low' ), self::package( 'high', true ) ) ) );
		self::assertSame( array( 'risk', 'open-hole' ), self::verdict( 'plugins', $on, array( self::package( 'watch' ), self::package( 'high' ) ) ) );
		self::assertSame( array( 'check', 'watch' ), self::verdict( 'plugins', $on, array( self::package( 'low' ), self::package( 'watch' ) ) ) );
		self::assertSame( array( 'check', 'no-report' ), self::verdict( 'plugins', $on, null ) );
		self::assertSame( array( 'check', 'off' ), self::verdict( 'plugins', array( self::finding( 'known-holes', array( 'enabled' => 'no' ) ) ), null ) );
		self::assertSame( array( 'good', 'clear' ), self::verdict( 'plugins', $on, array( self::package( 'low' ) ) ) );
	}

	public function test_files(): void {
		$clean = self::finding( 'local-code', array( 'stored' => 'clean' ), 'pass' );
		self::assertSame( array( 'risk', 'malware' ), self::verdict( 'files', array( self::finding( 'local-code', array( 'stored' => 'found' ) ) ) ) );
		self::assertSame( array( 'risk', 'malware' ), self::verdict( 'files', array( $clean, self::finding( 'suspicious-files', array( 'stored' => 'found' ) ) ) ) );
		self::assertSame( array( 'risk', 'uploads-php' ), self::verdict( 'files', array( $clean, self::finding( 'uploads-php-files', array( 'kind' => 'present' ) ) ) ) );
		self::assertSame( array( 'risk', 'core-changed' ), self::verdict( 'files', array( $clean, self::finding( 'release-files', array( 'stored' => 'found' ) ) ) ) );
		self::assertSame( array( 'check', 'not-run' ), self::verdict( 'files', array( self::finding( 'local-code', array( 'stored' => 'running' ) ) ) ) );
		self::assertSame( array( 'check', 'stale' ), self::verdict( 'files', array( $clean ), null, self::OFF, 8 * 86400 ) );
		self::assertSame( array( 'good', 'clear' ), self::verdict( 'files', array( $clean ), null, self::OFF, 86400 ) );
	}

	public function test_bots(): void {
		self::assertSame( array( 'risk', 'all-off' ), self::verdict( 'bots', array() ) );
		self::assertSame( array( 'check', 'watch-only' ), self::verdict( 'bots', array(), null, array( 'observe', 'off', 'watch' ) ) );
		self::assertSame( array( 'good', 'on' ), self::verdict( 'bots', array(), null, array( 'off', 'block', 'watch' ) ) );
	}

	public function test_ai(): void {
		$https   = self::finding( 'https-admin', array(), 'pass' );
		$plain   = self::finding( 'https-admin', array() );
		$on      = self::finding( 'ai-readiness', array( 'assistant' => 'on', 'guide' => 'present' ) );
		$set     = self::finding( 'ai-readers', array( 'ai_crawlers' => 'limited' ) );
		self::assertSame( array( 'risk', 'assistant-plain' ), self::verdict( 'ai', array( $plain, $on, $set ) ) );
		self::assertSame( array( 'check', 'crawlers' ), self::verdict( 'ai', array( $https, $on, self::finding( 'ai-readers', array( 'ai_crawlers' => 'allowed' ) ) ) ) );
		self::assertSame( array( 'check', 'no-guide' ), self::verdict( 'ai', array( $https, self::finding( 'ai-readiness', array( 'assistant' => 'off', 'guide' => 'absent' ) ), $set ) ) );
		self::assertSame( array( 'check', 'unknown' ), self::verdict( 'ai', array( $https, $set ) ) );
		self::assertSame( array( 'good', 'ready' ), self::verdict( 'ai', array( $https, $on, $set ) ) );
	}

	public function test_sign_in(): void {
		self::assertSame( array( 'risk', 'off' ), self::verdict( 'signin', array( self::finding( 'login-rate-mode', array( 'mode' => 'off' ) ) ) ) );
		self::assertSame( array( 'check', 'watch' ), self::verdict( 'signin', array( self::finding( 'login-rate-mode', array( 'mode' => 'observe' ) ) ) ) );
		self::assertSame( array( 'good', 'on' ), self::verdict( 'signin', array( self::finding( 'login-rate-mode', array( 'mode' => 'block' ) ) ) ) );
		self::assertSame( array( 'check', 'unknown' ), self::verdict( 'signin', array() ) );
	}

	public function test_card_shows_status_as_text_with_a_link_and_skips_unknown_rows(): void {
		$html = SiteRiskCard::render(
			array(
				array( 'area' => 'bots', 'status' => 'risk', 'reason' => 'all-off' ),
				array( 'area' => 'signin', 'status' => 'good', 'reason' => 'on' ),
				array( 'area' => 'nope', 'status' => 'good', 'reason' => 'on' ),
			)
		);
		self::assertStringContainsString( '<h2 id="amsec-risk-title">', $html );
		self::assertStringContainsString( '<span class="amsec-pill is-risk">Risk</span>', $html );
		self::assertStringContainsString( '<span class="amsec-pill is-on">Good</span>', $html );
		self::assertStringContainsString( 'page=amsec-traffic-guard', $html );
		self::assertSame( 2, substr_count( $html, '<li ' ) );
	}
}
