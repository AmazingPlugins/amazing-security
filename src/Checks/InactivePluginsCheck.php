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

/** Reports installed plugins that are not active. It does not deactivate or delete them. */
final class InactivePluginsCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/security/hardening/';
	private readonly Closure $readKind;

	public function __construct( ?callable $readKind = null ) {
		$this->readKind = Closure::fromCallable( $readKind ?? array( self::class, 'wordpressKind' ) );
	}

	public function id(): string {
		return 'inactive-plugins';
	}

	public static function decide( string $kind ): string {
		$kind = explode( ':', $kind, 2 )[0];
		return match ( $kind ) {
			'inactive' => 'warn',
			'active' => 'pass',
			default => 'unknown',
		};
	}

	public static function count( string $kind ): int {
		if ( 1 !== preg_match( '/^inactive:(\d+)$/D', $kind, $matches ) ) {
			return 0;
		}
		return min( 999, (int) $matches[1] );
	}

	public static function wordpressKind(): string {
		if ( ! function_exists( 'get_plugins' ) && defined( 'ABSPATH' ) ) {
			$plugin_file = ABSPATH . 'wp-admin/includes/plugin.php';
			if ( is_file( $plugin_file ) ) {
				require_once $plugin_file;
			}
		}
		if ( ! function_exists( 'get_plugins' ) || ! function_exists( 'is_plugin_active' ) ) {
			return 'unknown';
		}
		$plugins = get_plugins();
		if ( ! is_array( $plugins ) ) {
			return 'unknown';
		}
		$inactive = 0;
		foreach ( array_keys( $plugins ) as $file ) {
			if ( ! is_string( $file ) || ! is_plugin_active( $file ) ) {
				++$inactive;
			}
		}
		return $inactive > 0 ? 'inactive:' . $inactive : 'active';
	}

	public function run( ScanContext $context ): array {
		unset( $context );
		$kind    = (string) ( $this->readKind )();
		$state   = self::decide( $kind );
		$count   = self::count( $kind );
		$summary = match ( $state ) {
			'warn' => ( $count > 0 ? $count . ' inactive ' . ( 1 === $count ? 'plugin is' : 'plugins are' ) . ' installed. ' : 'Inactive plugins are installed. ' ) . 'Open Plugins to review them. This check does not deactivate or delete them.',
			'pass' => 'Every installed plugin is active. This check does not deactivate or delete plugins.',
			default => 'Inactive plugins could not be listed. This check does not deactivate or delete plugins.',
		};
		return array(
			new CheckResult( $this->id(), 'warn' === $state ? State::WARN : ( 'pass' === $state ? State::PASS : State::UNKNOWN ), $summary, self::SOURCE, new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ), 'low', 'unknown' === $state ? 'unavailable' : 'complete', array( 'kind' => $kind ) ),
		);
	}
}
