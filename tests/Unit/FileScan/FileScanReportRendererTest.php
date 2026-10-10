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
    public function test_suspicious_finding_has_rule_guidance_and_safe_next_steps(): void {
        $cursor = new FileScanCursor( 'guidance' );
        $cursor->findings[] = array( 'kind' => 'suspected', 'rule_id' => 'AS-PHP-012', 'path' => 'plugin.php', 'summary' => 'Request redirect' );
        $html = ( new FileScanReportRenderer() )->render( null, new FileScanStep( $cursor, false ), array() );
        self::assertStringContainsString( 'Why this needs review', $html );
        self::assertStringContainsString( 'wp_safe_redirect', $html );
        self::assertStringContainsString( 'Back up the site', $html );
        self::assertStringContainsString( 'Do not delete a file based only on this match', $html );
        self::assertStringNotContainsString( 'three suspicious', ( new FileScanReportRenderer() )->render( null, null, array() ) );
    }

	public function test_empty_state_invites_manual_scan_without_all_clear(): void {
		$html = ( new FileScanReportRenderer() )->render( null, null, array() );
		self::assertStringContainsString( 'No file scan has run', $html );
		self::assertMatchesRegularExpression( '/\d+ days? old/', $html );
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
		self::assertStringContainsString( 'Last finished scan', $html );
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

	public function test_historical_warning_shows_evidence_and_later_status(): void {
		$id = str_repeat( 'd', 32 );
		$old = new FileScanReport( 'old', 'warn', new DateTimeImmutable( '2026-09-28T00:00:00Z' ), false, 1, 10, 0, 0, 0, 0, 1, 0, array( array( 'id' => $id, 'state' => 'warn', 'kind' => 'suspected', 'package' => 'plugin-one:1.0', 'path' => 'includes/loader.php', 'rule_id' => 'AS-PHP-001', 'tested_at' => '2026-09-28T00:00:00+00:00', 'summary' => 'Suspected code' ) ) );
		$new = new FileScanReport( 'new', 'inconclusive', new DateTimeImmutable( '2026-09-29T00:00:00Z' ), true, 1, 10, 1, 0, 0, 0, 0, 0, array() );
		$html = ( new FileScanReportRenderer() )->render( $new, null, array( $old ) );
		self::assertStringContainsString( 'Partial coverage', $html );
		self::assertStringContainsString( 'plugin-one:1.0', $html );
		self::assertStringContainsString( 'includes/loader.php', $html );
		self::assertStringContainsString( 'AS-PHP-001', $html );
		self::assertStringContainsString( '2026-09-28T00:00:00+00:00', $html );
		self::assertStringContainsString( 'Current status unknown; latest scan was partial', $html );
	}

	public function test_every_retained_warning_is_reviewable(): void {
		$history = array();
		for ( $reportIndex = 0; $reportIndex < 6; ++$reportIndex ) {
			$findings = array();
			for ( $findingIndex = 0; $findingIndex < 4; ++$findingIndex ) {
				$findings[] = array( 'id' => substr( hash( 'sha256', $reportIndex . ':' . $findingIndex ), 0, 32 ), 'state' => 'warn', 'kind' => 'suspected', 'package' => 'plugin-' . $reportIndex, 'path' => 'path-' . $findingIndex . '.php', 'rule_id' => 'AS-PHP-001', 'tested_at' => '2026-09-28T00:00:00+00:00' );
			}
			$history[] = new FileScanReport( 'old-' . $reportIndex, 'warn', new DateTimeImmutable( '2026-09-28T00:00:00Z' ), false, 4, 40, 0, 0, 0, 0, 4, 0, $findings );
		}
		$latest = new FileScanReport( 'latest', 'pass', new DateTimeImmutable( '2026-09-29T00:00:00Z' ), false, 1, 10, 0, 0, 0, 0, 1, 0, array() );
		$html = ( new FileScanReportRenderer() )->render( $latest, null, $history );
		self::assertStringContainsString( 'plugin-0', $html );
		self::assertStringContainsString( 'path-3.php', $html );
		self::assertStringContainsString( 'Not reported in the last complete scan', $html );
	}

	public function test_newer_history_never_uses_an_older_complete_scan_as_comparison(): void {
		$old = new FileScanReport( 'old', 'pass', new DateTimeImmutable( '2026-09-28T00:00:00Z' ), false, 1, 10, 0, 0, 0, 0, 1, 0, array() );
		$newerWarning = new FileScanReport( 'newer', 'warn', new DateTimeImmutable( '2026-09-29T00:00:00Z' ), false, 1, 10, 0, 0, 0, 0, 1, 0, array( array( 'id' => str_repeat( 'f', 32 ), 'state' => 'warn', 'kind' => 'suspected', 'path' => 'loader.php' ) ) );
		$html = ( new FileScanReportRenderer() )->render( $old, null, array( $newerWarning ) );
		self::assertStringContainsString( 'No later complete comparison available', $html );
		self::assertStringNotContainsString( 'Not reported in the last complete scan', $html );
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
		self::assertStringContainsString( 'demo', $html );
	}
}
