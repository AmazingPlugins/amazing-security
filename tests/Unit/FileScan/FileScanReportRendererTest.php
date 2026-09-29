<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\FileScan;

use AmazingPlugins\Security\Admin\FileScanReportRenderer;
use AmazingPlugins\Security\FileScan\FileScanCursor;
use AmazingPlugins\Security\FileScan\FileScanReport;
use AmazingPlugins\Security\FileScan\FileScanStep;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class FileScanReportRendererTest extends TestCase {
	public function test_empty_state_invites_manual_scan_without_all_clear(): void {
		$html = ( new FileScanReportRenderer() )->render( null, null, array() );
		self::assertStringContainsString( 'No file scan has run', $html );
		self::assertStringContainsString( 'days old', $html );
		self::assertStringNotContainsString( 'malware-free', $html );
	}

	public function test_only_current_findings_offer_review_notes_during_a_scan(): void {
		$id = str_repeat( 'a', 32 );
		$cursor = new FileScanCursor( 'scan-2' );
		$cursor->findings[] = array( 'id' => $id, 'kind' => 'suspected', 'path' => 'demo.php', 'summary' => 'Suspected code' );
		$report = new FileScanReport( 'scan-1', 'warn', new DateTimeImmutable(), false, 1, 1, 0, 0, 0, 0, 1, 0, $cursor->findings );
		$html = ( new FileScanReportRenderer( 'https://example.test/wp-admin/admin-post.php', 'nonce' ) )->render( $report, new FileScanStep( $cursor, false ), array() );
		preg_match_all( '/id="(amsec-note-[^"]+)"/', $html, $matches );
		self::assertCount( 1, $matches[1] );
		self::assertStringContainsString( 'Last completed scan', $html );
	}

	public function test_package_gap_names_the_package_and_reason(): void {
		$cursor = new FileScanCursor( 'scan-3' );
		$cursor->findings[] = array( 'id' => str_repeat( 'c', 32 ), 'kind' => 'package', 'package' => 'example:1.2', 'path' => '', 'reason' => 'custom_theme', 'summary' => 'Published release could not be verified.' );
		$html = ( new FileScanReportRenderer() )->render( null, new FileScanStep( $cursor, true ), array() );
		self::assertStringContainsString( 'Release unavailable', $html );
		self::assertStringContainsString( 'example:1.2', $html );
		self::assertStringContainsString( 'custom_theme', $html );
		self::assertStringNotContainsString( '<code></code>', $html );
	}

	public function test_partial_report_escapes_findings_and_keeps_previous_warning_date(): void {
		$cursor = new FileScanCursor( 'scan-2' );
		$cursor->processed = 250;
		$cursor->partial = true;
		$cursor->findings[] = array( 'id' => 'abc', 'state' => 'warn', 'kind' => 'suspected', 'package' => 'demo', 'path' => '<script>alert(1)</script>.php', 'rule_id' => 'AS-PHP-001', 'version' => '2026.09.29.1', 'line' => 2, 'summary' => 'Suspected code', 'reason' => '', 'tested_at' => '2026-09-29T00:00:00+00:00' );
		$old = new FileScanReport( 'scan-1', 'warn', new DateTimeImmutable( '2026-09-28T00:00:00Z' ), false, 3, 100, 0, 0, 1, 1, 1, 0, $cursor->findings );
		$html = ( new FileScanReportRenderer() )->render( $old, new FileScanStep( $cursor, false ), array( $old ) );
		self::assertStringContainsString( 'Partial coverage', $html );
		self::assertStringContainsString( '250 files', $html );
		self::assertStringContainsString( '&lt;script&gt;', $html );
		self::assertStringNotContainsString( '<script>', $html );
		self::assertStringContainsString( '2026-09-28', $html );
		self::assertStringContainsString( 'Suspected code', $html );
	}
}
