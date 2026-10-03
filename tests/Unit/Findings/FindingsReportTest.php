<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Findings;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\FindingsReport;
use AmazingPlugins\Security\Scan\ScanRun;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class FindingsReportTest extends TestCase {
	public function test_report_omits_evidence_and_redacts_paths_and_mail(): void {
		$run = new ScanRun(
			new DateTimeImmutable( '2026-10-01T00:00:00Z' ),
			new DateTimeImmutable( '2026-10-01T00:01:00Z' ),
			array(
				new CheckResult(
					'file-modes',
					'warn',
					'Review /var/www/html/wp-config.php and owner@example.com.',
					'https://developer.wordpress.org/advanced-administration/security/hardening/',
					new DateTimeImmutable( '2026-10-01T00:01:00Z' ),
					'medium',
					'complete',
					array( 'path' => '/var/www/html/wp-config.php', 'token' => 'secret-session' )
				),
			),
			false
		);
		$text = FindingsReport::text( $run );
		self::assertStringContainsString( 'not a compliance report', $text );
		self::assertStringContainsString( 'No password or login attempt was sent.', $text );
		self::assertStringContainsString( 'does not show that the site is clean', $text );
		self::assertStringContainsString( 'file-modes: Needs attention', $text );
		self::assertStringContainsString( '[path]', $text );
		self::assertStringContainsString( '[email]', $text );
		self::assertStringNotContainsString( '/var/www', $text );
		self::assertStringNotContainsString( 'owner@example.com', $text );
		self::assertStringNotContainsString( 'secret-session', $text );
		self::assertStringNotContainsString( 'safe', $text );
		self::assertStringContainsString( 'No completed local check is stored.', FindingsReport::text( null ) );
	}
}
