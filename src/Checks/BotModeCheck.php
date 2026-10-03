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

/** Reports the native bot-control mode. It does not change that setting. */
final class BotModeCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/security/hardening/';
	private readonly Closure $read;

	public function __construct( callable $read ) {
		$this->read = Closure::fromCallable( $read );
	}

	public function id(): string {
		return 'bot-controls';
	}

	public function run( ScanContext $context ): array {
		try {
			$raw = ( $this->read )();
		} catch ( Throwable ) {
			$raw = 'unavailable';
		}
		$mode  = is_string( $raw ) && in_array( $raw, array( 'off', 'observe', 'block' ), true ) ? $raw : ( null === $raw || false === $raw || '' === $raw ? 'off' : 'unknown' );
		$state = match ( $mode ) {
			'off', 'observe' => State::WARN,
			'block' => State::PASS,
			default => State::UNKNOWN,
		};
		$summary = match ( $mode ) {
			'off' => 'Native comment and registration controls are off.',
			'observe' => 'Native comment and registration controls are recording only.',
			'block' => 'Native comment and registration controls can reject excess unauthenticated requests.',
			default => 'The bot control mode could not be read.',
		};
		return array(
			new CheckResult(
				$this->id(),
				$state,
				$summary . ' This check does not change that setting.',
				self::SOURCE,
				new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ),
				State::UNKNOWN === $state ? 'low' : 'medium',
				State::UNKNOWN === $state ? 'unavailable' : 'complete',
				array( 'mode' => $mode )
			),
		);
	}
}
