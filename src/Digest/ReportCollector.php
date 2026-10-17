<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Digest;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\FindingsRepository;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Integrity\WordPressIntegrityStore;
use AmazingPlugins\Security\FileScan\WordPressFileScanStore;
use AmazingPlugins\Security\Vulnerabilities\WordPressVulnerabilityReportStore;

final class ReportCollector {
	public function collect(): array {
		$options = new WordPressOptions();
		$sources = array();
		foreach ( DigestSummary::SOURCES as $kind ) {
			try {
				$running = false;
				$step    = null;
				if ( 'hardening' === $kind ) {
					$report = ( new FindingsRepository() )->latest();
				} elseif ( 'integrity' === $kind ) {
					$store   = new WordPressIntegrityStore( $options );
					$report  = $store->latestCompleted();
					$step    = $store->latestProgress();
					$running = null !== $step;
				} elseif ( 'files' === $kind ) {
					$store   = new WordPressFileScanStore( $options );
					$report  = $store->latestCompleted();
					$step    = $store->latestProgress();
					$running = null !== $step;
				} else {
					$report = ( new WordPressVulnerabilityReportStore( $options ) )->current();
				}
				$rawRows = null === $report ? array() : ( 'files' === $kind ? $report->findings : $report->results );
				if ( null !== $step ) {
					$rawRows = array_merge( $step->cursor->findings, $rawRows ); }
				$partial = null === $report || $report->partial || $running || count( $rawRows ) > 250;
				$rows    = array();
				$at      = null === $report || 'vulnerabilities' === $kind ? 0 : $report->finishedAt->getTimestamp();
				foreach ( array_slice( $rawRows, 0, 250 ) as $result ) {
					$row    = is_array( $result ) ? $result : $result->toArray();
					$id     = $row['id'] ?? $row['finding_id'] ?? $row['check_id'] ?? '';
					$rows[] = array(
						'id'       => $id,
						'state'    => $row['state'] ?? 'unknown',
						'coverage' => $row['coverage'] ?? 'complete',
					);
					if ( 'vulnerabilities' === $kind ) {
						$checked = is_string( $row['tested_at'] ?? null ) ? strtotime( $row['tested_at'] ) : false;
						$at      = false === $checked ? 0 : ( 0 === $at ? $checked : min( $at, $checked ) );
					}
				}
				$sources[ $kind ] = array(
					'at'      => $at,
					'partial' => $partial,
					'running' => $running,
					'rows'    => $rows,
					'unknown' => 'files' === $kind ? max( $report?->unknown ?? 0, $step?->cursor->unknown ?? 0 ) : 0,
				);
			} catch ( \Throwable ) {
				$sources[ $kind ] = array();
			}
		}
		return $sources;
	}
}
