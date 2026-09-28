<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\ScanRun;
use DateTimeImmutable;

final class CompletedIntegrityReport {
	public function fromCursor( IntegrityCursor $cursor ): ScanRun {
		$now     = new DateTimeImmutable();
		$results = $cursor->findings;
		foreach ( $cursor->packages as $package => $counts ) {
			$state     = $counts['warn'] > 0 ? State::WARN : ( $counts['inconclusive'] > 0 || $counts['checked'] < $counts['total'] ? State::INCONCLUSIVE : State::PASS );
			$results[] = new CheckResult(
				'integrity-package',
				$state,
				$counts['matched'] . ' of ' . $counts['total'] . ' published files matched. Manifest fetched ' . $counts['fetched_at'] . '.',
				$counts['source_url'],
				$now,
				'high',
				'complete',
				array(
					'package'             => $package,
					'matched'             => $counts['matched'],
					'compared'            => $counts['checked'],
					'total'               => $counts['total'],
					'manifest_fetched_at' => $counts['fetched_at'],
				),
				substr( hash( 'sha256', 'package:' . $package ), 0, 32 )
			);
		}
		$results[] = new CheckResult(
			'integrity-coverage',
			$cursor->matched === $cursor->processed ? State::PASS : State::INCONCLUSIVE,
			$cursor->matched . ' of ' . $cursor->processed . ' compared release files matched their published checksums. Unlisted extra files were not inspected.',
			'https://wordpress.org/plugins/',
			$now,
			'high',
			'complete',
			array(
				'matched'  => $cursor->matched,
				'compared' => $cursor->processed,
			)
		);
		return new ScanRun( $cursor->startedAt ?? $now, $now, $results, false );
	}
}
