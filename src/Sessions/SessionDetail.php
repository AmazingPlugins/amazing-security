<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Sessions;

defined( 'ABSPATH' ) || exit;

/** Readable browser, computer, and network labels from a WordPress session. */
final class SessionDetail {
	public static function browser( string $agent ): string {
		$checks = array(
			'Edg/'            => 'Edge',
			'OPR/'            => 'Opera',
			'Opera'           => 'Opera',
			'HeadlessChrome/' => 'Chrome',
			'Chrome/'         => 'Chrome',
			'Firefox/'        => 'Firefox',
			'Safari/'         => 'Safari',
			'curl/'           => 'curl',
			'Wget/'           => 'Wget',
			'WP-CLI'          => 'WP-CLI',
			'python-requests' => 'Python',
			'Python-urllib'   => 'Python',
			'Go-http-client'  => 'Go',
			'WordPress/'      => 'WordPress',
		);
		foreach ( $checks as $needle => $name ) {
			if ( str_contains( $agent, $needle ) ) {
				return $name;
			}
		}
		return '' === $agent ? '' : __( 'Unknown browser', 'amazingplugins-security-scanner' );
	}

	public static function computer( string $agent ): string {
		$checks = array(
			'iPhone'   => 'iPhone',
			'iPad'     => 'iPad',
			'Android'  => 'Android',
			'Mac OS X' => 'Mac',
			'Windows'  => 'Windows',
			'CrOS'     => 'Chromebook',
			'Linux'    => 'Linux',
		);
		foreach ( $checks as $needle => $name ) {
			if ( str_contains( $agent, $needle ) ) {
				return $name;
			}
		}
		if ( str_contains( $agent, 'curl/' ) || str_contains( $agent, 'Wget/' ) || str_contains( $agent, 'WP-CLI' ) || str_contains( $agent, 'python-requests' ) || str_contains( $agent, 'Go-http-client' ) ) {
			return __( 'Command line', 'amazingplugins-security-scanner' );
		}
		return '' === $agent ? '' : __( 'Unknown computer', 'amazingplugins-security-scanner' );
	}

	public static function icon( string $computer ): string {
		$icons = array(
			'iPhone'                                 => 'dashicons-smartphone',
			'Android'                                => 'dashicons-smartphone',
			'iPad'                                   => 'dashicons-tablet',
			__( 'Command line', 'amazingplugins-security-scanner' ) => 'dashicons-editor-code',
		);
		return $icons[ $computer ] ?? 'dashicons-desktop';
	}

	public static function place( string $ip ): string {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return '';
		}
		$public = filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
		if ( false !== $public ) {
			return $ip;
		}
		if ( '::1' === $ip || str_starts_with( $ip, '127.' ) ) {
			return __( 'This computer', 'amazingplugins-security-scanner' );
		}
		return __( 'This network', 'amazingplugins-security-scanner' );
	}
}
