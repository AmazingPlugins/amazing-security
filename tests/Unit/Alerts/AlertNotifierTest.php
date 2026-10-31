<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Alerts;

use AmazingPlugins\Security\Alerts\AlertDelivery;
use AmazingPlugins\Security\Alerts\AlertNotifier;
use AmazingPlugins\Security\Alerts\AlertPolicy;
use AmazingPlugins\Security\FileScan\FileScanReport;
use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Scan\ScanRun;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Vulnerabilities\VulnerabilityReport;

final class AlertNotifierTest extends TestCase {
	public function test_confirmed_serious_vulnerability_alerts_survive_partial_scans_without_repeats(): void {
		$options                                 = $this->options();
		$options->values['amsec_alerts_enabled'] = '1';
		$messages                                = array();
		$notifier                                = new AlertNotifier(
			new AlertPolicy(),
			new AlertDelivery(
				$options,
				static function ( $to, $subject, $body ) use ( &$messages ): bool {
					$messages[] = $body;
					return true;
				},
				'owner@example.test',
				'https://example.test/report'
			)
		);
		$finding                                 = static fn ( string $id, string $severity, string $coverage = 'complete' ): CheckResult => new CheckResult( 'vulnerability', 'warn', 'Untrusted issue title', 'https://www.wpvulnerability.com/', new DateTimeImmutable(), 'medium', $coverage, array( 'severity' => $severity ), $id );
		$high                                    = $finding( 'high-finding', 'high' );
		$critical                                = $finding( 'critical-finding', 'critical' );
		self::assertSame( 'accepted', $notifier->vulnerabilities( new VulnerabilityReport( array( $high, $finding( 'possible', 'critical', 'partial' ), $finding( 'medium', 'medium' ) ), true, 'Partial' ), 1000 ) );
		self::assertSame( 'accepted', $notifier->vulnerabilities( new VulnerabilityReport( array( $critical ), true, 'Partial' ), 1001 ) );
		self::assertSame( 'none', $notifier->vulnerabilities( new VulnerabilityReport( array( $high, $critical ), false, 'Complete' ), 1002 ) );
		self::assertCount( 2, $messages );
		self::assertStringContainsString( 'high-finding', $messages[0] );
		self::assertStringNotContainsString( 'Untrusted issue title', implode( '', $messages ) );
		self::assertStringNotContainsString( 'possible', implode( '', $messages ) );
		self::assertSame( 'none', $notifier->vulnerabilities( new VulnerabilityReport( array(), false, 'Complete' ), 1003 ) );
		self::assertSame( 'accepted', $notifier->vulnerabilities( new VulnerabilityReport( array( $high ), false, 'Complete' ), 1004 ) );
		$options->values['amsec_alerts_enabled'] = '0';
		self::assertSame( 'off', $notifier->vulnerabilities( new VulnerabilityReport( array( $critical ), false, 'Complete' ), 1005 ) );
	}

	public function test_partial_reports_send_confirmed_findings_and_keep_earlier_ones(): void {
		$options                                 = $this->options();
		$options->values['amsec_alerts_enabled'] = '1';
		$messages                                = array();
		$notifier                                = new AlertNotifier(
			new AlertPolicy(),
			new AlertDelivery(
				$options,
				static function ( string $to, string $subject, string $body ) use ( &$messages ): bool {
					$messages[] = $body;
					return true;
				},
				'owner@example.test',
				'https://example.test/report'
			)
		);
		$now                                     = new DateTimeImmutable( '@1000' );
		$hit                                     = static fn( string $c, string $rule ): array => array(
			'id'      => str_repeat( $c, 32 ),
			'kind'    => 'suspected',
			'rule_id' => $rule,
			'state'   => 'warn',
		);
		self::assertSame( 'none', $notifier->files( new FileScanReport( 'scan-1', 'inconclusive', $now, true, 0, 0, 0, 0, 0, 0, 0, 0, array() ), 1000 ) );
		self::assertSame( 'accepted', $notifier->files( new FileScanReport( 'scan-2', 'warn', $now, true, 1, 10, 1, 0, 1, 0, 1, 0, array( $hit( 'a', 'AS-MAL-001' ) ) ), 1001 ) );
		self::assertStringContainsString( str_repeat( 'a', 32 ), $messages[0] );
		// A later partial run that didn't reach that file neither re-sends nor clears it.
		self::assertSame( 'none', $notifier->files( new FileScanReport( 'scan-3', 'warn', $now, true, 1, 10, 1, 0, 1, 0, 1, 0, array() ), 1002 ) );
		self::assertCount( 1, $messages );
		self::assertSame( 'accepted', $notifier->files( new FileScanReport( 'scan-4', 'warn', $now, true, 1, 10, 1, 0, 1, 0, 1, 0, array( $hit( 'a', 'AS-MAL-001' ), $hit( 'b', 'AS-PHP-020' ) ) ), 1003 ) );
		self::assertStringNotContainsString( str_repeat( 'a', 32 ), $messages[1] );
	}

	private function options(): OptionGateway {
		return new class() implements OptionGateway {
			public array $values = array();
			public function get( string $key ): mixed {
				return $this->values[ $key ] ?? null; }
			public function add( string $key, string $value ): bool {
				$this->values[ $key ] = $value;
				return true; }
			public function set( string $key, string $value ): bool {
				$this->values[ $key ] = $value;
				return true; }
			public function delete( string $key ): void {
				unset( $this->values[ $key ] ); }
			public function replaceIfSame( string $key, string $expected, string $replacement ): bool {
				$this->values[ $key ] = $replacement;
				return true; }
			public function deleteIfSame( string $key, string $expected ): bool {
				unset( $this->values[ $key ] );
				return true; }
		};
	}
}
