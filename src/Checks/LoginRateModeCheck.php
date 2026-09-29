<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

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
			'off' => 'Amazing Security login attempt monitoring is off. You can enable observe mode before choosing to block repeated failures.',
			'observe' => 'Amazing Security records repeated login failures but does not block them. Review the observed traffic before enabling blocking.',
			'block' => 'Amazing Security limits repeated login failures. Shared addresses can still affect legitimate sign-ins.',
			default => 'The login attempt setting could not be read.',
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
