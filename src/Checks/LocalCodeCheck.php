<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

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
			'none' => 'Plugin and theme PHP has not been scanned with the local patterns. Run local checks on this page. This scan does not contact WordPress.org.',
			'running' => 'The local code scan has read ' . $files . ' and is still working. Run local checks again to continue it. This scan does not contact WordPress.org.',
			'partial' => 'The local code scan read ' . $files . ' and stopped before every file was read. Run local checks again. This scan does not contact WordPress.org.',
			'found' => 'The local code scan read ' . $files . '. ' . ( '' !== $matches ? $matches . '. ' : '' ) . 'This scan does not contact WordPress.org and does not prove the site is clean.',
			'clean' => 'The local code scan read ' . $files . ' and finished without a pattern match. This scan does not contact WordPress.org and does not prove the site is clean.',
			default => 'The local code scan could not be read. This scan does not contact WordPress.org.',
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
