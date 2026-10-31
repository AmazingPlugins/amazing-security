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

/** Reports installed themes that are not the active theme or its parent. It does not switch or delete them. */
final class InactiveThemesCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/security/hardening/';
	private readonly Closure $readKind;

	public function __construct( ?callable $readKind = null ) {
		$this->readKind = Closure::fromCallable( $readKind ?? array( self::class, 'wordpressKind' ) );
	}

	public function id(): string {
		return 'inactive-themes';
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
		if ( ! function_exists( 'wp_get_themes' ) || ! function_exists( 'get_stylesheet' ) || ! function_exists( 'get_template' ) ) {
			return 'unknown';
		}
		$themes = wp_get_themes();
		if ( ! is_array( $themes ) ) {
			return 'unknown';
		}
		$used     = array( get_stylesheet(), get_template() );
		$inactive = 0;
		foreach ( array_keys( $themes ) as $slug ) {
			if ( ! is_string( $slug ) || ! in_array( $slug, $used, true ) ) {
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
			'warn' => ( $count > 0 ? sprintf( /* translators: %d: number of inactive themes. */ _n( '%d inactive theme is installed.', '%d inactive themes are installed.', $count, 'amsec-security-scanner' ), $count ) . ' ' : __( 'Inactive themes are installed.', 'amsec-security-scanner' ) . ' ' ) . __( 'Open Appearance, then Themes, to review them. This check does not switch or delete them.', 'amsec-security-scanner' ),
			'pass' => __( 'Every installed theme is in use. This check does not switch or delete themes.', 'amsec-security-scanner' ),
			default => __( 'Inactive themes could not be listed. This check does not switch or delete themes.', 'amsec-security-scanner' ),
		};
		return array(
			new CheckResult( $this->id(), 'warn' === $state ? State::WARN : ( 'pass' === $state ? State::PASS : State::UNKNOWN ), $summary, self::SOURCE, new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ), 'low', 'unknown' === $state ? 'unavailable' : 'complete', array( 'kind' => $kind ) ),
		);
	}
}
