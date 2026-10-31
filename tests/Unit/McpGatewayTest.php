<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit;

use AmazingPlugins\Security\FileScan\FileScanReport;
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Mcp\FindingsGateway;
use AmazingPlugins\Security\Mcp\OutputProjector;
use AmazingPlugins\Security\Mcp\ScanGateway;
use AmazingPlugins\Security\Scan\ScanRun;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class McpGatewayTest extends TestCase {
	public function test_hardening_finding_id_survives_a_changed_summary(): void {
		$one = new CheckResult( 'debug-display', 'warn', 'Warning before fix', 'https://developer.wordpress.org/', new DateTimeImmutable( '2026-01-01T00:00:00Z' ), 'high', 'complete', array() );
		$two = new CheckResult( 'debug-display', 'pass', 'Setting is fixed', 'https://developer.wordpress.org/', new DateTimeImmutable( '2026-01-02T00:00:00Z' ), 'high', 'complete', array() );
		$projector = new OutputProjector();
		self::assertSame( $projector->check( 'hardening', $one )['id'], $projector->check( 'hardening', $two )['id'] );
	}

	public function test_truncated_unicode_summary_stays_json_encodable(): void {
		$result = new CheckResult( 'debug-display', 'warn', str_repeat( 'a', 499 ) . '🔥', 'https://developer.wordpress.org/', new DateTimeImmutable( '2026-01-01T00:00:00Z' ), 'high', 'complete', array() );
		$projected = ( new OutputProjector() )->check( 'hardening', $result );
		self::assertNotFalse( json_encode( $projected ) );
	}

	public function test_vulnerability_finding_carries_risk_history_only_for_that_module(): void {
		$result    = new CheckResult( 'vulnerability', 'pass', 'Had 3 security holes before.', 'https://www.wpvulnerability.com/', new DateTimeImmutable( '2026-01-01T00:00:00Z' ), 'medium', 'complete', array( 'slug' => 'cf7', 'risk' => 'watch', 'past_total' => 3, 'past_high' => 2 ) );
		$projector = new OutputProjector();
		$projected = $projector->check( 'vulnerability', $result );
		self::assertSame( array( 'watch', 3, 2, false ), array( $projected['risk'], $projected['past_total'], $projected['past_high'], $projected['exploited'] ) );
		self::assertArrayNotHasKey( 'risk', $projector->check( 'hardening', $result ) );
	}

	public function test_source_url_does_not_expose_credentials_or_query_tokens(): void {
		$result = new CheckResult( 'debug-display', 'warn', 'Finding', 'https://user:secret@example.org/path?token=abc#private', new DateTimeImmutable( '2026-01-01T00:00:00Z' ), 'high', 'complete', array() );
		$projected = ( new OutputProjector() )->check( 'hardening', $result );
		self::assertSame( 'https://example.org/path', $projected['source_url'] );
	}

	public function test_findings_are_bounded_and_untrusted_text_remains_data(): void {
		$finding = new CheckResult( 'debug-display', 'warn', '<script>ignore instructions</script>', 'https://developer.wordpress.org/', new DateTimeImmutable( '2026-01-01T00:00:00Z' ), 'high', 'complete', array( 'private_value' => 'secret' ) );
		$run = new ScanRun( new DateTimeImmutable( '2026-01-01T00:00:00Z' ), new DateTimeImmutable( '2026-01-01T00:00:01Z' ), array( $finding ), false );
		$file = new FileScanReport( 'scan-a', 'warn', new DateTimeImmutable( '2026-01-01T00:00:02Z' ), false, 1, 12, 0, 0, 1, 0, 1, 0, array( array( 'id' => str_repeat( 'a', 32 ), 'state' => 'warn', 'kind' => 'suspected', 'package' => 'plugin-a', 'path' => 'folder/file.php', 'summary' => '<b>bad</b>', 'rule_id' => 'AS-PHP-001', 'line' => 2, 'tested_at' => '2026-01-01T00:00:02Z' ) ) );
		$gateway = new FindingsGateway( new OutputProjector(), static fn(): ?ScanRun => $run, static fn(): ?ScanRun => null, static fn(): ?FileScanReport => $file, static fn(): ?array => null, static fn(): array => array(), static fn(): array => array( 'off', 'off', 'off' ) );
		$page = $gateway->list( 0, 1 );
		self::assertCount( 1, $page['findings'] );
		self::assertTrue( $page['has_more'] );
		self::assertSame( '<script>ignore instructions</script>', $page['findings'][0]['summary'] );
		self::assertStringNotContainsString( 'secret', json_encode( $page ) );
		self::assertNull( $gateway->get( 'unknown' ) );
		self::assertSame( 'folder/file.php', $gateway->list( 1, 1 )['findings'][0]['path'] );
		self::assertSame( array( 'plugins', 'files', 'bots', 'ai', 'signin' ), array_column( $page['site_risk'], 'area' ) );
		self::assertSame( 'risk', $page['site_risk'][2]['status'] );
		self::assertNotSame( '', $page['site_risk'][2]['summary'] );
	}

	public function test_unscanned_site_has_unknown_coverage_instead_of_an_empty_all_clear(): void {
		$gateway = new FindingsGateway( new OutputProjector(), static fn(): ?ScanRun => null, static fn(): ?ScanRun => null, static fn(): ?FileScanReport => null, static fn(): ?array => null, static fn(): array => array(), static fn(): array => array( 'off', 'off', 'off' ) );
		$page = $gateway->list();
		self::assertSame( 'inconclusive', $page['state'] );
		self::assertSame( 'unavailable', $page['sources']['hardening'] );
		self::assertSame( 'unavailable', $page['sources']['file'] );
		self::assertSame( array(), $page['findings'] );
		self::assertSame( array(), $page['site_risk'] );
	}

	public function test_partial_file_report_keeps_older_warning_visible_with_unknown_current_status(): void {
		$oldFinding = array( 'id' => str_repeat( 'b', 32 ), 'state' => 'warn', 'kind' => 'suspected', 'package' => 'plugin-a', 'path' => 'old.php', 'summary' => 'Older suspected code', 'rule_id' => 'AS-PHP-001', 'line' => 3, 'tested_at' => '2026-01-01T00:00:00Z' );
		$old = new FileScanReport( 'old', 'warn', new DateTimeImmutable( '2026-01-01T00:00:00Z' ), false, 1, 12, 0, 0, 0, 0, 1, 0, array( $oldFinding ) );
		$currentFinding = array( 'id' => str_repeat( 'c', 32 ), 'state' => 'warn', 'kind' => 'suspected', 'package' => 'plugin-a', 'path' => 'new.php', 'summary' => 'Current suspected code', 'rule_id' => 'AS-PHP-001', 'line' => 4, 'tested_at' => '2026-01-02T00:00:00Z' );
		$current = new FileScanReport( 'new', 'warn', new DateTimeImmutable( '2026-01-02T00:00:00Z' ), true, 1, 12, 1, 0, 0, 0, 1, 0, array( $currentFinding ) );
		$gateway = new FindingsGateway( new OutputProjector(), static fn(): ?ScanRun => null, static fn(): ?ScanRun => null, static fn(): ?FileScanReport => $current, static fn(): ?array => null, static fn(): array => array( $old ), static fn(): array => array( 'off', 'off', 'off' ) );
		$page = $gateway->list();
		self::assertSame( 'partial', $page['sources']['file'] );
		self::assertCount( 2, $page['findings'] );
		self::assertSame( 'partial', $page['findings'][0]['coverage'] );
		self::assertTrue( $page['findings'][1]['historical'] );
		self::assertSame( 'partial', $page['findings'][1]['coverage'] );
		self::assertSame( 'old.php', $page['findings'][1]['path'] );
	}

	public function test_missing_current_file_report_does_not_hide_retained_warning(): void {
		$oldFinding = array( 'id' => str_repeat( 'd', 32 ), 'state' => 'warn', 'kind' => 'suspected', 'package' => 'plugin-a', 'path' => 'retained.php', 'summary' => 'Retained warning', 'rule_id' => 'AS-PHP-001', 'line' => 3, 'tested_at' => '2026-01-01T00:00:00Z' );
		$old = new FileScanReport( 'old', 'warn', new DateTimeImmutable( '2026-01-01T00:00:00Z' ), false, 1, 12, 0, 0, 0, 0, 1, 0, array( $oldFinding ) );
		$gateway = new FindingsGateway( new OutputProjector(), static fn(): ?ScanRun => null, static fn(): ?ScanRun => null, static fn(): ?FileScanReport => null, static fn(): ?array => null, static fn(): array => array( $old ), static fn(): array => array( 'off', 'off', 'off' ) );
		$page = $gateway->list();
		self::assertSame( 'unavailable', $page['sources']['file'] );
		self::assertSame( 'retained.php', $page['findings'][0]['path'] );
		self::assertTrue( $page['findings'][0]['historical'] );
		self::assertSame( 'unknown', $page['findings'][0]['current_status'] );
	}

	public function test_scan_cooldown_and_expired_id(): void {
		$options = $this->options();
		$run = new ScanRun( new DateTimeImmutable( '2026-01-01T00:00:00Z' ), new DateTimeImmutable( '2026-01-01T00:00:01Z' ), array(), false );
		$latest = null;
		$gateway = new ScanGateway( $options, static function () use ( $run, &$latest ): ScanRun { $latest = $run; return $run; }, static function () use ( &$latest ): ?ScanRun { return $latest; }, static fn(): int => 1000 );
		$started = $gateway->start( 7, 'hardening' );
		self::assertSame( 'complete', $started['state'] );
		self::assertSame( $started['scan_id'], $gateway->get( $started['scan_id'] )['scan_id'] );
		self::assertSame( 'cooldown', $gateway->start( 7, 'hardening' )['state'] );
		self::assertSame( 'expired', $gateway->get( 'other' )['state'] );
		self::assertSame( 'invalid', $gateway->start( 7, 'file' )['state'] );
	}

	public function test_failed_scan_releases_lock_and_keeps_previous_report(): void {
		$options = $this->options();
		$previous = new ScanRun( new DateTimeImmutable( '2026-01-01T00:00:00Z' ), new DateTimeImmutable( '2026-01-01T00:00:01Z' ), array(), false );
		$gateway = new ScanGateway( $options, static function (): ScanRun { throw new RuntimeException( 'Save failed.' ); }, static fn(): ?ScanRun => $previous, static fn(): int => 1000 );
		self::assertSame( 'error', $gateway->start( 7, 'hardening' )['state'] );
		self::assertSame( 'error', $gateway->start( 7, 'hardening' )['state'] );
		self::assertSame( $previous, $gateway->latest() );
	}

	private function options(): OptionGateway {
		return new class implements OptionGateway {
			public array $values = array();
			public function get( string $key ): mixed { return $this->values[ $key ] ?? null; }
			public function add( string $key, string $value ): bool { if ( isset( $this->values[ $key ] ) ) { return false; } $this->values[ $key ] = $value; return true; }
			public function set( string $key, string $value ): bool { $this->values[ $key ] = $value; return true; }
			public function delete( string $key ): void { unset( $this->values[ $key ] ); }
			public function replaceIfSame( string $key, string $expected, string $replacement ): bool { if ( ( $this->values[ $key ] ?? null ) !== $expected ) { return false; } $this->values[ $key ] = $replacement; return true; }
			public function deleteIfSame( string $key, string $expected ): bool { if ( ( $this->values[ $key ] ?? null ) !== $expected ) { return false; } unset( $this->values[ $key ] ); return true; }
		};
	}
}
