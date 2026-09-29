<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Alerts;

use AmazingPlugins\Security\FileScan\FileScanReport;
use AmazingPlugins\Security\Scan\ScanRun;
use AmazingPlugins\Security\Vulnerabilities\VulnerabilityReport;

final class AlertPolicy {
	public function fromVulnerabilities( VulnerabilityReport $report ): array {
		$ids = array();
		foreach ( $report->results as $finding ) {
			if ( 'vulnerability' === $finding->checkId && 'warn' === $finding->state && 'complete' === $finding->coverage && in_array( $finding->evidence['severity'] ?? null, array( 'high', 'critical' ), true ) && null !== $finding->findingId ) {
				$ids[] = $finding->findingId;
			}
		}
		return array_values( array_unique( $ids ) );
	}

	public function fromIntegrity( ScanRun $run ): array {
		if ( $run->partial ) {
			return array();
		}
		$ids = array();
		foreach ( $run->results as $result ) {
			if ( 'integrity-file' === $result->checkId && 'warn' === $result->state && 'complete' === $result->coverage && null !== $result->findingId ) {
				$ids[] = $result->findingId;
			}
		}
		return array_values( array_unique( $ids ) );
	}

	public function fromFiles( FileScanReport $report ): array {
		if ( $report->partial ) {
			return array();
		}
		$ids = array();
		foreach ( $report->findings as $finding ) {
			$id   = $finding['id'] ?? null;
			$rule = $finding['rule_id'] ?? null;
			if ( 'suspected' === ( $finding['kind'] ?? null ) && 'warn' === ( $finding['state'] ?? null ) && is_string( $id ) && preg_match( '/^[a-f0-9]{32}$/D', $id ) && in_array( $rule, array( 'AS-PHP-001', 'AS-PHP-002', 'AS-PHP-003', 'AS-PHP-004', 'AS-PHP-005', 'AS-PHP-006', 'AS-PHP-007', 'AS-PHP-008', 'AS-PHP-009' ), true ) ) {
				$ids[] = $id;
			}
		}
		return array_values( array_unique( $ids ) );
	}
}
