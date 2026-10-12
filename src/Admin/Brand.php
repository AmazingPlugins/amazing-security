<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

/** Landing-page frame for Amazing Security screens. */
final class Brand {
	public const DOCS = 'https://amazingplugins.com/plugins/amazing-security/';

	public const GUIDE = 'https://amazingplugins.com/wordpress-security/';

	public static function boot(): void {
		add_filter( 'admin_body_class', array( self::class, 'bodyClass' ) );
		add_action( 'admin_enqueue_scripts', array( self::class, 'assets' ) );
		add_action( 'all_admin_notices', array( self::class, 'bar' ), 1000 );
	}

	public static function bodyClass( string $classes ): string {
		return self::onScreen() ? $classes . ' amsec-app' : $classes;
	}

	public static function assets(): void {
		if ( ! self::onScreen() ) {
			return;
		}
		wp_enqueue_style( 'amazing-security-admin', plugins_url( 'assets/admin.css', AMAZING_SECURITY_FILE ), array(), AMAZING_SECURITY_VERSION );
		$page = self::page();
		if ( in_array( $page, array( 'amsec-accounts', 'amsec-traffic-guard' ), true ) ) {
			wp_enqueue_script( 'amazing-security-tabs', plugins_url( 'assets/admin-tabs.js', AMAZING_SECURITY_FILE ), array(), AMAZING_SECURITY_VERSION, true );
		}
		if ( 'amazing-security' !== $page ) {
			return;
		}
		wp_enqueue_script( 'amazing-security-scan', plugins_url( 'assets/admin-scan.js', AMAZING_SECURITY_FILE ), array(), AMAZING_SECURITY_VERSION, true );
		wp_localize_script( 'amazing-security-scan', 'amsecScan', array( 'error' => __( 'Scan could not be saved.', 'amazing-security' ) ) );
	}

	public static function bar(): void {
		if ( ! self::onScreen() ) {
			return;
		}
		$logo    = plugins_url( 'assets/logo-shield.svg', AMAZING_SECURITY_FILE );
		$docs    = plugins_url( 'assets/icon-docs.svg', AMAZING_SECURITY_FILE );
		$guide   = plugins_url( 'assets/icon-guide.svg', AMAZING_SECURITY_FILE );
		$headers = get_file_data( AMAZING_SECURITY_FILE, array( 'Version' => 'Version' ) );
		$version = is_string( $headers['Version'] ?? null ) ? $headers['Version'] : '';
		// WordPress moves other plugins' notices below this marker, so they appear above our bar and not inside it. Our own messages use the inline class and stay in place.
		echo '<hr class="wp-header-end">';
		echo '<div class="amsec-brand"><div class="amsec-brand-mark">';
		echo '<img src="' . esc_url( $logo ) . '" alt="' . esc_attr__( 'Amazing Security', 'amazing-security' ) . '" width="44" height="44">';
		echo '<div class="amsec-brand-title"><p class="amsec-brand-name">' . esc_html__( 'Amazing Security', 'amazing-security' ) . '</p>';
		if ( 1 === preg_match( '/^\d+\.\d+\.\d+$/', $version ) ) {
			echo '<p class="amsec-brand-version">' . esc_html( $version ) . '</p>';
		}
		echo '</div></div>';
		echo '<p class="amsec-brand-links"><a href="' . esc_url( self::DOCS ) . '" target="_blank" rel="noopener noreferrer">';
		echo '<img src="' . esc_url( $docs . '?ver=' . AMAZING_SECURITY_VERSION ) . '" alt="" width="22" height="22">' . esc_html__( 'Docs', 'amazing-security' ) . '</a>';
		echo '<a href="' . esc_url( self::GUIDE ) . '" target="_blank" rel="noopener noreferrer">';
		echo '<img src="' . esc_url( $guide . '?ver=' . AMAZING_SECURITY_VERSION ) . '" alt="" width="22" height="22">' . esc_html__( 'Security guide', 'amazing-security' ) . '</a></p></div>';
		if ( 'amazing-security' === self::page() ) {
			return;
		}
		$title = function_exists( 'get_admin_page_title' ) ? get_admin_page_title() : '';
		if ( ! is_string( $title ) || '' === $title ) {
			return;
		}
		echo '<div class="amsec-rescan-bar amsec-page-bar"><div class="amsec-rescan-row"><h1>' . esc_html( $title ) . '</h1></div></div>';
	}

	public static function onScreen(): bool {
		$page = self::page();
		return 'amazing-security' === $page || str_starts_with( $page, 'amsec-' );
	}

	private static function page(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only admin screen slug.
		$raw = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
		return is_string( $raw ) ? $raw : '';
	}
}
