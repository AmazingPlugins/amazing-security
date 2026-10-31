<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Firewall\RestRatePolicy;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\SecurityCheck;
use Closure;
use DateTimeImmutable;
use DateTimeZone;
use Throwable;

/** Reports the REST rate policy. It does not change that policy. */
final class RestRateCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/security/hardening/';
	private readonly Closure $read;

	public function __construct( callable $read ) {
		$this->read = Closure::fromCallable( $read );
	}

	public function id(): string {
		return 'rest-rates';
	}

	public function run( ScanContext $context ): array {
		try {
			$raw = ( $this->read )();
		} catch ( Throwable ) {
			$raw = 'unavailable';
		}
		$policy = ( new RestRatePolicy() )->read( $raw );
		$mode   = is_array( $policy ) && is_string( $policy['mode'] ?? null ) ? $policy['mode'] : 'unknown';
		$state  = match ( $mode ) {
			'off', 'observe' => State::WARN,
			'block' => State::PASS,
			default => State::UNKNOWN,
		};
		$summary = match ( $mode ) {
			'off' => __( 'REST user and comment limits are off.', 'amsec-security-scanner' ),
			'observe' => __( 'REST user and comment limits are recording only.', 'amsec-security-scanner' ),
			'block' => __( 'REST user and comment limits can reject excess unauthenticated requests.', 'amsec-security-scanner' ),
			default => __( 'The REST rate policy could not be read.', 'amsec-security-scanner' ),
		};
		return array(
			new CheckResult(
				$this->id(),
				$state,
				$summary . ' This check does not change that policy.',
				self::SOURCE,
				new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ),
				State::UNKNOWN === $state ? 'low' : 'medium',
				State::UNKNOWN === $state ? 'unavailable' : 'complete',
				array( 'mode' => $mode )
			),
		);
	}
}
