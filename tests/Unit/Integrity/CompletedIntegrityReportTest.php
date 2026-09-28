<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Integrity;

use AmazingPlugins\Security\Integrity\CompletedIntegrityReport;
use AmazingPlugins\Security\Integrity\IntegrityCursor;
use PHPUnit\Framework\TestCase;

final class CompletedIntegrityReportTest extends TestCase {
	public function test_clean_completion_reports_coverage_counts_without_safety_claim(): void {
		$cursor = new IntegrityCursor( 'scan-1', processed: 12, matched: 12 );
		$run = ( new CompletedIntegrityReport() )->fromCursor( $cursor );
		self::assertSame( 'pass', $run->results[0]->state );
		self::assertSame( 12, $run->results[0]->evidence['matched'] );
		self::assertStringNotContainsString( 'malware-free', $run->results[0]->summary );
		self::assertSame( 'inconclusive', ( new CompletedIntegrityReport() )->fromCursor( new IntegrityCursor( 'scan-2', processed: 12, matched: 11 ) )->results[0]->state );
		$cursor->packages['core:6.6:en_US'] = array( 'total' => 12, 'checked' => 12, 'matched' => 12, 'warn' => 0, 'inconclusive' => 0, 'source_url' => 'https://api.wordpress.org/', 'fetched_at' => '2026-09-28T00:00:00+00:00' );
		self::assertSame( 'pass', ( new CompletedIntegrityReport() )->fromCursor( $cursor )->results[0]->state );
		self::assertSame( 'core:6.6:en_US', ( new CompletedIntegrityReport() )->fromCursor( $cursor )->results[0]->evidence['package'] );
	}
}
