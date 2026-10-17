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

/** Reports the local pattern scan. It does not contact WordPress.org. */
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
			'found' => State::WARN,
			'clean' => State::PASS,
			'none' => State::WARN,
			default => State::UNKNOWN,
		};
		$files   = $scanned . ' files';
		$summary = match ( $stored ) {
			'none' => __( 'Plugin and theme PHP has not been scanned with the local patterns. Run local checks on this page. This scan does not contact WordPress.org.', 'amazing-security' ),
			'running' => sprintf( /* translators: %s: number of files read, for example 12 files. */ __( 'The local code scan has read %s and is still working. Run local checks again to continue it. This scan does not contact WordPress.org.', 'amazing-security' ), $files ),
			'partial' => sprintf( /* translators: %s: number of files read, for example 12 files. */ __( 'The local code scan read %s and stopped before every file was read. Run local checks again. This scan does not contact WordPress.org.', 'amazing-security' ), $files ),
			'found' => sprintf( /* translators: %s: number of files read, for example 12 files. */ __( 'The local code scan read %s.', 'amazing-security' ), $files ) . ' ' . ( '' !== $matches ? $matches . '. ' : '' ) . __( 'This scan does not contact WordPress.org and does not prove the site is clean.', 'amazing-security' ),
			'clean' => sprintf( /* translators: %s: number of files read, for example 12 files. */ __( 'The local code scan read %s and finished without a pattern match. This scan does not contact WordPress.org and does not prove the site is clean.', 'amazing-security' ), $files ),
			default => __( 'The local code scan could not be read. This scan does not contact WordPress.org.', 'amazing-security' ),
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
