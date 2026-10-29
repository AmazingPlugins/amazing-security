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
			'off' => __( 'Native comment and registration controls are off.', 'amazingplugins-security-scanner' ),
			'observe' => __( 'Native comment and registration controls are recording only.', 'amazingplugins-security-scanner' ),
			'block' => __( 'Native comment and registration controls can reject excess unauthenticated requests.', 'amazingplugins-security-scanner' ),
			default => __( 'The bot control mode could not be read.', 'amazingplugins-security-scanner' ),
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
