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

final class LoginRateModeCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/security/brute-force/';
	private readonly Closure $readMode;

	public function __construct( callable $readMode ) {
		$this->readMode = Closure::fromCallable( $readMode );
	}

	public function id(): string {
		return 'login-rate-mode';
	}

	public function run( ScanContext $context ): array {
		try {
			$raw = ( $this->readMode )();
		} catch ( Throwable ) {
			$raw = 'unavailable';
		}
		$mode = null === $raw ? 'off' : $raw;
		if ( ! is_string( $mode ) || ! in_array( $mode, array( 'off', 'observe', 'block' ), true ) ) {
			$mode = 'unavailable';
		}
		$state = match ( $mode ) {
			'block' => State::PASS,
			'off', 'observe' => State::WARN,
			default => State::UNKNOWN,
		};
		$summary = match ( $mode ) {
			'off' => __( 'Login monitoring is off. Turn on observe mode so repeated failures are recorded before anyone is blocked.', 'amazing-security' ),
			'observe' => __( 'Repeated login failures are recorded and not blocked yet. Read that record before you turn blocking on.', 'amazing-security' ),
			'block' => __( 'Repeated login failures are limited. A shared network can still block a real sign-in.', 'amazing-security' ),
			default => __( 'The login monitoring setting could not be read.', 'amazing-security' ),
		};
		return array(
			new CheckResult(
				$this->id(),
				$state,
				$summary,
				self::SOURCE,
				new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ),
				State::UNKNOWN === $state ? 'low' : 'high',
				State::UNKNOWN === $state ? 'unavailable' : 'complete',
				array( 'mode' => $mode ),
			),
		);
	}
}
