<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Alerts;

use AmazingPlugins\Security\Alerts\AlertPolicy;
use AmazingPlugins\Security\FileScan\FileScanReport;
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Scan\ScanRun;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class AlertPolicyTest extends TestCase {
	public function test_only_complete_eligible_integrity_findings_alert(): void {
		$policy = new AlertPolicy();
		$now = new DateTimeImmutable( '@1000' );
		$changed = new CheckResult( 'integrity-file', 'warn', 'Release file differs.', 'https://wordpress.org/', $now, 'high', 'complete', array(), 'changed-file' );
		$unknown = new CheckResult( 'integrity-file', 'inconclusive', 'Unknown.', 'https://wordpress.org/', $now, 'low', 'partial', array(), 'unknown-file' );
		$run = new ScanRun( $now, $now, array( $changed, $unknown ), false );
		self::assertSame( array( 'changed-file' ), $policy->fromIntegrity( $run ) );
		self::assertSame( array(), $policy->fromIntegrity( new ScanRun( $now, $now, array( $changed ), true ) ) );
	}

	public function test_only_complete_suspicious_php_findings_alert(): void {
		$policy = new AlertPolicy();
		$now = new DateTimeImmutable( '@1000' );
		$findings = array(
			array( 'id' => str_repeat( 'a', 32 ), 'kind' => 'suspected', 'rule_id' => 'AS-PHP-004', 'state' => 'warn' ),
			array( 'id' => str_repeat( 'b', 32 ), 'kind' => 'extra', 'rule_id' => '', 'state' => 'warn' ),
		);
		$report = new FileScanReport( 'scan-1', 'warn', $now, false, 2, 100, 0, 0, 1, 0, 1, 0, $findings );
		self::assertSame( array( str_repeat( 'a', 32 ) ), $policy->fromFiles( $report ) );
		$partial = new FileScanReport( 'scan-2', 'warn', $now, true, 2, 100, 1, 0, 1, 0, 1, 0, $findings );
		self::assertSame( array(), $policy->fromFiles( $partial ) );
	}
}
