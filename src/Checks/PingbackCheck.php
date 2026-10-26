<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\SecurityCheck;
use Closure;
use DateTimeImmutable;
use DateTimeZone;
use Throwable;

/** Suggests turning pingbacks off. It does not change the setting or authenticated XML-RPC. */
final class PingbackCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/security/hardening/';
	private readonly Closure $readStatus;

	public function __construct( callable $readStatus ) {
		$this->readStatus = Closure::fromCallable( $readStatus );
	}

	public function id(): string {
		return 'pingbacks';
	}

	public function run( ScanContext $context ): array {
		try {
			$status = ( $this->readStatus )();
		} catch ( Throwable ) {
			$status = null;
		}
		$known = is_string( $status ) && in_array( $status, array( 'open', 'closed' ), true ) ? $status : '';
		$state = match ( $known ) {
			'open' => State::WARN,
			'closed' => State::PASS,
			default => State::UNKNOWN,
		};
		$summary = match ( $known ) {
			'open' => __( 'New posts can accept pingbacks. You can turn them off under Settings, then Discussion. This check leaves the setting as it is. Sign-in over XML-RPC is unchanged.', 'amazing-security-scanner' ),
			'closed' => __( 'New posts do not accept pingbacks.', 'amazing-security-scanner' ),
			default => __( 'The pingback setting could not be read.', 'amazing-security-scanner' ),
		};
		return array(
			new CheckResult(
				$this->id(),
				$state,
				$summary,
				self::SOURCE,
				new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ),
				State::UNKNOWN === $state ? 'low' : 'medium',
				State::UNKNOWN === $state ? 'unavailable' : 'complete',
				array( 'status' => '' !== $known ? $known : 'unknown' )
			),
		);
	}
}
