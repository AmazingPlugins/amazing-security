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

/** Reports whether authenticated XML-RPC methods are turned off. It does not change that setting. */
final class XmlRpcAuthCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/security/hardening/';
	private readonly Closure $read;

	public function __construct( callable $read ) {
		$this->read = Closure::fromCallable( $read );
	}

	public function id(): string {
		return 'xmlrpc-auth';
	}

	public function run( ScanContext $context ): array {
		try {
			$raw = ( $this->read )();
		} catch ( Throwable ) {
			$raw = 'unavailable';
		}
		$auth  = self::auth( $raw );
		$state = match ( $auth ) {
			'open' => State::WARN,
			'closed' => State::PASS,
			default => State::UNKNOWN,
		};
		$summary = match ( $auth ) {
			'open' => __( 'Sign-in over XML-RPC is still allowed. A script can try passwords there without the login form. This check does not turn that off.', 'amazing-security-scanner' ),
			'closed' => __( 'Sign-in over XML-RPC is turned off. Pingbacks stay a separate setting.', 'amazing-security-scanner' ),
			default => __( 'The XML-RPC sign-in setting could not be read.', 'amazing-security-scanner' ),
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
				array( 'auth' => $auth )
			),
		);
	}

	private static function auth( mixed $raw ): string {
		if ( null === $raw || false === $raw || '' === $raw || '0' === $raw || 0 === $raw ) {
			return 'open';
		}
		return true === $raw || 1 === $raw || '1' === $raw ? 'closed' : 'unknown';
	}
}
