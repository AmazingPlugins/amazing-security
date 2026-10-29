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

/** Reports plugin or theme updates already stored by WordPress. It does not install them or contact WordPress.org. */
final class PackageUpdateCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/security/hardening/';
	private readonly Closure $readKind;

	public function __construct( private readonly string $checkId, ?callable $readKind = null ) {
		$this->readKind = Closure::fromCallable( $readKind ?? static fn(): string => self::wordpressKind( $checkId ) );
	}

	public function id(): string {
		return $this->checkId;
	}

	public static function decide( string $kind ): string {
		return match ( $kind ) {
			'waiting' => 'warn',
			'current' => 'pass',
			default => 'unknown',
		};
	}

	public static function wordpressKind( string $checkId ): string {
		$transient = get_site_transient( 'plugin-updates' === $checkId ? 'update_plugins' : 'update_themes' );
		if ( ! is_object( $transient ) || ! isset( $transient->response, $transient->checked ) || ! is_array( $transient->response ) || ! is_array( $transient->checked ) ) {
			return 'unknown';
		}
		return array() === $transient->response ? 'current' : 'waiting';
	}

	public function run( ScanContext $context ): array {
		unset( $context );
		$kind    = (string) ( $this->readKind )();
		$state   = self::decide( $kind );
		$plugins = 'plugin-updates' === $this->checkId;
		$summary = match ( $state ) {
			'warn' => $plugins
				? __( 'Plugin updates are waiting. Open Dashboard, then Updates. This check does not install them and does not contact WordPress.org.', 'amazingplugins-security-scanner' )
				: __( 'Theme updates are waiting. Open Dashboard, then Updates. This check does not install them and does not contact WordPress.org.', 'amazingplugins-security-scanner' ),
			'pass' => $plugins
				? __( 'WordPress does not report a plugin update waiting. This check does not install updates and does not contact WordPress.org.', 'amazingplugins-security-scanner' )
				: __( 'WordPress does not report a theme update waiting. This check does not install updates and does not contact WordPress.org.', 'amazingplugins-security-scanner' ),
			default => $plugins
				? __( 'Plugin update status could not be read. This check does not install updates and does not contact WordPress.org.', 'amazingplugins-security-scanner' )
				: __( 'Theme update status could not be read. This check does not install updates and does not contact WordPress.org.', 'amazingplugins-security-scanner' ),
		};
		return array(
			new CheckResult( $this->id(), 'warn' === $state ? State::WARN : ( 'pass' === $state ? State::PASS : State::UNKNOWN ), $summary, self::SOURCE, new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ), 'unknown' === $state ? 'low' : 'medium', 'unknown' === $state ? 'unavailable' : 'complete', array( 'kind' => $kind ) ),
		);
	}
}
