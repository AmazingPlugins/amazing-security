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

/** Reports when core background updates are turned off. It does not turn them on. */
final class BackgroundUpdatesCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/security/hardening/';
	private readonly Closure $readKind;

	public function __construct( ?callable $readKind = null ) {
		$this->readKind = Closure::fromCallable( $readKind ?? array( self::class, 'wordpressKind' ) );
	}

	public function id(): string {
		return 'background-updates';
	}

	public static function decide( string $kind ): string {
		return match ( $kind ) {
			'off' => 'warn',
			'on' => 'pass',
			default => 'unknown',
		};
	}

	public static function wordpressKind(): string {
		if ( ! defined( 'ABSPATH' ) ) {
			return 'unknown';
		}
		if ( defined( 'AUTOMATIC_UPDATER_DISABLED' ) && true === AUTOMATIC_UPDATER_DISABLED ) {
			return 'off';
		}
		if ( defined( 'DISALLOW_FILE_MODS' ) && true === DISALLOW_FILE_MODS ) {
			return 'off';
		}
		if ( ! defined( 'WP_AUTO_UPDATE_CORE' ) ) {
			return 'on';
		}
		if ( false === WP_AUTO_UPDATE_CORE ) {
			return 'off';
		}
		if ( true === WP_AUTO_UPDATE_CORE || 'minor' === WP_AUTO_UPDATE_CORE ) {
			return 'on';
		}
		return 'unknown';
	}

	public function run( ScanContext $context ): array {
		unset( $context );
		$kind    = (string) ( $this->readKind )();
		$state   = self::decide( $kind );
		$summary = match ( $state ) {
			'warn' => __( 'WordPress background updates are turned off. This check does not turn them on.', 'amazing-security' ),
			'pass' => __( 'WordPress background updates are not turned off. This check does not turn them on.', 'amazing-security' ),
			default => __( 'WordPress background updates could not be read. This check does not turn them on.', 'amazing-security' ),
		};
		return array(
			new CheckResult( $this->id(), 'warn' === $state ? State::WARN : ( 'pass' === $state ? State::PASS : State::UNKNOWN ), $summary, self::SOURCE, new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ), 'low', 'unknown' === $state ? 'unavailable' : 'complete', array( 'kind' => $kind ) ),
		);
	}
}
