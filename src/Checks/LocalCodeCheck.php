<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\LocalCodeScan;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\SecurityCheck;
use Closure;
use DateTimeImmutable;
use DateTimeZone;

/** Reports the local malware scan. Files stay on this server. */
final class LocalCodeCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/security/hardening/';
	private readonly Closure $read;

	public function __construct( ?callable $read = null ) {
		$this->read = Closure::fromCallable( $read ?? array( LocalCodeScan::class, 'snapshot' ) );
	}

	public function id(): string {
		return 'local-code';
	}

	public function run( ScanContext $context ): array {
		unset( $context );
		$snapshot = ( $this->read )();
		$stored   = is_array( $snapshot ) && is_string( $snapshot['stored'] ?? null ) ? $snapshot['stored'] : 'unknown';
		$found    = is_array( $snapshot ) && is_int( $snapshot['found'] ?? null ) ? $snapshot['found'] : 0;
		$scanned  = is_array( $snapshot ) && is_int( $snapshot['scanned'] ?? null ) ? $snapshot['scanned'] : 0;
		$matches  = is_array( $snapshot ) && is_string( $snapshot['matches'] ?? null ) ? $snapshot['matches'] : '';
		$state    = match ( $stored ) {
			'found' => State::CRITICAL,
			'clean' => State::PASS,
			'none' => State::WARN,
			default => State::UNKNOWN,
		};
		/* translators: %s: number of files checked. */
		$files   = sprintf( _n( '%s file', '%s files', $scanned, 'amsec-security-scanner' ), (string) $scanned );
		$summary = match ( $stored ) {
			'none' => __( 'Plugins, themes, uploads, mu-plugins and loose PHP files in the site root have not been checked for malware yet. Run the scan on this page. Files stay on this server.', 'amsec-security-scanner' ),
			/* translators: %s: number of files checked, for example 12 files. */
			'running' => sprintf( __( 'The malware scan has checked %s so far and keeps going in the background. Open this page again in a minute.', 'amsec-security-scanner' ), $files ),
			/* translators: %s: number of files checked, for example 12 files. */
			'partial' => sprintf( __( 'The malware scan checked %s and stopped before every file was read. Scan again to finish it.', 'amsec-security-scanner' ), $files ),
			/* translators: %s: number of files checked, for example 12 files. */
			'found' => sprintf( __( 'The malware scan checked %s and found code shaped like malware.', 'amsec-security-scanner' ), $files ) . ' ' . ( '' !== $matches ? $matches . '. ' : '' ) . __( 'Open the findings and check each file.', 'amsec-security-scanner' ),
			/* translators: %s: number of files checked, for example 12 files. */
			'clean' => sprintf( __( 'The malware scan checked %s and found no known malware shapes. That does not prove the site is clean.', 'amsec-security-scanner' ), $files ),
			default => __( 'The malware scan result could not be read. Scan again.', 'amsec-security-scanner' ),
		};
		return array(
			new CheckResult(
				$this->id(),
				$state,
				$summary,
				self::SOURCE,
				new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ),
				'medium',
				State::UNKNOWN === $state ? 'unavailable' : 'complete',
				array(
					'stored'      => $stored,
					'found_count' => $found,
					'scanned'     => $scanned,
					'matches'     => $matches,
				)
			),
		);
	}
}
