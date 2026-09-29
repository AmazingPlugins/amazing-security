<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Repair;

use AmazingPlugins\Security\Integrity\WordPressOrgManifestProvider;
use AmazingPlugins\Security\Scan\ScanRun;

final class RepairCandidate {
	private function __construct( public readonly string $findingId, public readonly string $slug, public readonly string $version, public readonly string $relativePath, public readonly string $observedSha256 ) {}

	public static function fromReport( ScanRun $report, string $findingId ): ?self {
		return self::fromFindings( $report->results, $findingId );
	}

	public static function fromFindings( array $findings, string $findingId ): ?self {
		if ( ! preg_match( '/^[a-f0-9]{32}$/D', $findingId ) ) {
			return null;
		}
		foreach ( $findings as $finding ) {
			if ( $findingId !== $finding->findingId || 'integrity-file' !== $finding->checkId || 'warn' !== $finding->state || 'complete' !== $finding->coverage ) {
				continue;
			}
			$evidence = $finding->evidence;
			if ( 'plugin' !== ( $evidence['package_type'] ?? null ) || 'ok' !== ( $evidence['reason'] ?? null ) ) {
				return null;
			}
			$package = $evidence['package'] ?? null;
			$path    = $evidence['path'] ?? null;
			$sha256  = $evidence['observed_sha256'] ?? null;
			if ( ! is_string( $package ) || ! preg_match( '/^([a-z0-9]+(?:-[a-z0-9]+)*):([0-9]+(?:\.[0-9A-Za-z-]+)*)$/D', $package, $match ) || ! is_string( $path ) || ! WordPressOrgManifestProvider::safePath( $path ) || ! is_string( $sha256 ) || ! preg_match( '/^[a-f0-9]{64}$/D', $sha256 ) ) {
				return null;
			}
			return new self( $findingId, $match[1], $match[2], $path, $sha256 );
		}
		return null;
	}
}
