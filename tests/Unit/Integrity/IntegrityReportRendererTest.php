<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Integrity;

use AmazingPlugins\Security\Admin\IntegrityReportRenderer;
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Integrity\IntegrityCursor;
use AmazingPlugins\Security\Integrity\IntegrityStep;
use AmazingPlugins\Security\Scan\ScanRun;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class IntegrityReportRendererTest extends TestCase {
	public function test_partial_report_escapes_remote_package_and_preserves_prior_time(): void {
		$finding = new CheckResult( 'integrity-package', 'unknown', 'Could not verify', 'https://wordpress.org/plugins/', new DateTimeImmutable( '2026-09-28T00:00:00Z' ), 'low', 'unavailable', array( 'package' => '<script>alert(1)</script>', 'reason' => 'unsupported' ) );
		$cursor = new IntegrityCursor( 'scan-1', findings: array( $finding ), startedAt: new DateTimeImmutable( '2026-09-28T00:00:00Z' ), partial: true );
		$cursor->packages['core:6.6:en_US'] = array( 'total' => 3000, 'checked' => 250, 'matched' => 250, 'warn' => 0, 'inconclusive' => 0, 'source_url' => 'https://api.wordpress.org/', 'fetched_at' => '2026-09-28T00:00:00+00:00' );
		$html = ( new IntegrityReportRenderer() )->render( null, new IntegrityStep( $cursor, true ) );
		self::assertStringContainsString( '&lt;script&gt;', $html );
		self::assertStringNotContainsString( '<script>', $html );
		self::assertStringContainsString( 'Partial', $html );
		self::assertStringContainsString( '250 of 3000', $html );
		$completed = new ScanRun( new DateTimeImmutable( '2026-09-27T00:00:00Z' ), new DateTimeImmutable( '2026-09-27T00:01:00Z' ), array( $finding ), false );
		$both = ( new IntegrityReportRenderer() )->render( $completed, new IntegrityStep( $cursor, true ) );
		self::assertStringContainsString( 'aria-label="Completed integrity findings"', $both );
		self::assertStringContainsString( 'aria-label="Current integrity findings"', $both );
	}
}
