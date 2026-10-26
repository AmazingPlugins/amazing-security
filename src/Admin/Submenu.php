<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

/** Scan stays first. Recommendations, Log In & Register, Traffic, Files, and Records stay beside it. */
final class Submenu {
	public const PARENT = 'amazing-security';

	/**
	 * Side-menu slugs after Scan.
	 *
	 * @return list<string>
	 */
	public static function visible(): array {
		return array(
			'amsec-recommendations',
			'amsec-accounts',
			'amsec-traffic-guard',
			'amsec-files',
			'amsec-records',
			'amsec-settings',
			'amsec-assistant',
		);
	}

	/**
	 * @param list<string> $registered Menu slugs currently under the parent.
	 * @return list<string>
	 */
	public static function hidden( array $registered ): array {
		$keep = array_fill_keys( array_merge( array( self::PARENT ), self::visible() ), true );
		$hide = array();
		foreach ( $registered as $slug ) {
			if ( ! isset( $keep[ $slug ] ) ) {
				$hide[] = $slug;
			}
		}
		return $hide;
	}

	public static function trim(): void {
		global $submenu;
		$items = $submenu[ self::PARENT ] ?? null;
		if ( ! is_array( $items ) ) {
			return;
		}
		$by_slug = array();
		foreach ( $items as $item ) {
			if ( ! is_array( $item ) || ! isset( $item[2] ) || ! is_string( $item[2] ) || isset( $by_slug[ $item[2] ] ) ) {
				continue;
			}
			$by_slug[ $item[2] ] = $item;
		}
		$ordered = array();
		if ( isset( $by_slug[ self::PARENT ] ) ) {
			$scan      = $by_slug[ self::PARENT ];
			$scan[0]   = __( 'Scan', 'amazing-security-scanner' );
			$ordered[] = $scan;
		}
		$shown = array_fill_keys( self::visible(), true );
		foreach ( self::visible() as $slug ) {
			if ( ! isset( $by_slug[ $slug ] ) ) {
				continue;
			}
			$item   = $by_slug[ $slug ];
			$labels = array(
				'amsec-recommendations' => __( 'Recommendations', 'amazing-security-scanner' ),
				'amsec-accounts'        => __( 'Log In & Register', 'amazing-security-scanner' ),
				'amsec-traffic-guard'   => __( 'Traffic', 'amazing-security-scanner' ),
				'amsec-files'           => __( 'Files', 'amazing-security-scanner' ),
				'amsec-records'         => __( 'Records', 'amazing-security-scanner' ),
				'amsec-settings'        => __( 'Settings', 'amazing-security-scanner' ),
				'amsec-assistant'       => __( 'AI & MCP', 'amazing-security-scanner' ),
			);
			if ( isset( $labels[ $slug ] ) ) {
				$item[0] = $labels[ $slug ];
			}
			$ordered[] = $item;
		}
		foreach ( $by_slug as $slug => $item ) {
			if ( self::PARENT === $slug || isset( $shown[ $slug ] ) ) {
				continue;
			}
			$item[4]   = 'amsec-menu-hidden';
			$ordered[] = $item;
		}
		if ( array() !== $ordered ) {
			// Scan stays first so the Amazing Security Scanner menu opens it. Hidden rows stay registered.
			$submenu[ self::PARENT ] = $ordered; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		}
		add_action( 'admin_enqueue_scripts', array( self::class, 'hide' ) );
	}

	public static function hide(): void {
		// Core's admin-menu stylesheet loads on every admin screen, like the menu itself.
		wp_add_inline_style( 'admin-menu', '#adminmenu .amsec-menu-hidden{display:none}' );
	}
}
