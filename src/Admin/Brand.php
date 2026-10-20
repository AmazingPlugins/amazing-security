<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

/** Landing-page frame for Amazing Security screens. */
final class Brand {
	public const DOCS = 'https://amazingplugins.com/plugins/amazing-security/';

	public const GUIDE = 'https://amazingplugins.com/wordpress-security/';

	public static function boot(): void {
		add_filter( 'admin_body_class', array( self::class, 'bodyClass' ) );
		add_action( 'admin_enqueue_scripts', array( self::class, 'assets' ) );
		add_action( 'all_admin_notices', array( self::class, 'bar' ), 1000 );
		add_action( 'all_admin_notices', array( self::class, 'savedNotice' ) );
		add_filter( 'removable_query_args', array( self::class, 'removableArgs' ) );
	}

	/** Marks a settings redirect so the next screen confirms the save. */
	public static function saved( string $url ): string {
		return add_query_arg( 'amsec_saved', '1', $url );
	}

	public static function savedNotice(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only flash flag after a nonce-checked save.
		if ( self::onScreen() && isset( $_GET['amsec_saved'] ) && '1' === $_GET['amsec_saved'] ) {
			echo '<div class="notice notice-success is-dismissible" role="status"><p>' . esc_html__( 'Settings saved.', 'amazing-security' ) . '</p></div>';
		}
	}

	/**
	 * @param array<int, string> $args
	 * @return array<int, string>
	 */
	public static function removableArgs( array $args ): array {
		$args[] = 'amsec_saved';
		return $args;
	}

	public static function bodyClass( string $classes ): string {
		return self::onScreen() ? $classes . ' amsec-app' : $classes;
	}

	public static function assets(): void {
		if ( ! self::onScreen() ) {
			return;
		}
		wp_enqueue_style( 'amazing-security-admin', plugins_url( 'assets/admin.css', AMAZING_SECURITY_FILE ), array(), '0.1.62' );
		$page = self::page();
		if ( in_array( $page, array( 'amsec-accounts', 'amsec-traffic-guard' ), true ) ) {
			wp_enqueue_script( 'amazing-security-tabs', plugins_url( 'assets/admin-tabs.js', AMAZING_SECURITY_FILE ), array(), '0.1.1', true );
		}
		if ( 'amazing-security' !== $page ) {
			return;
		}
		wp_enqueue_script( 'amazing-security-scan', plugins_url( 'assets/admin-scan.js', AMAZING_SECURITY_FILE ), array(), '0.1.16', true );
		wp_localize_script(
			'amazing-security-scan',
			'amsecScan',
			array(
				'error'   => __( 'Scan could not be saved.', 'amazing-security' ),
				// Every check the scan runs, in order; the progress list ticks each one off.
				'checks'  => array(
					__( 'Admin pages use HTTPS', 'amazing-security' ),
					__( 'Update settings', 'amazing-security' ),
					__( 'Administrator accounts', 'amazing-security' ),
					__( 'Errors shown to visitors', 'amazing-security' ),
					__( 'Built-in file editor', 'amazing-security' ),
					__( 'Sign-in attempt limits', 'amazing-security' ),
					__( 'Folder permissions', 'amazing-security' ),
					__( 'File modes on key files', 'amazing-security' ),
					__( 'PHP running in uploads', 'amazing-security' ),
					__( 'Pingbacks', 'amazing-security' ),
					__( 'XML-RPC sign-in', 'amazing-security' ),
					__( 'Authenticator app sign-in', 'amazing-security' ),
					__( 'Passkeys', 'amazing-security' ),
					__( 'Login bot trap', 'amazing-security' ),
					__( 'Breached password check', 'amazing-security' ),
					__( 'Sign-in error hints', 'amazing-security' ),
					__( 'Author archive pages', 'amazing-security' ),
					__( 'Public REST user list', 'amazing-security' ),
					__( 'WordPress version tag', 'amazing-security' ),
					__( 'Discovery links in the page head', 'amazing-security' ),
					__( 'readme.html', 'amazing-security' ),
					__( 'license.txt', 'amazing-security' ),
					__( 'debug.log', 'amazing-security' ),
					__( 'wp-config-sample.php', 'amazing-security' ),
					__( 'error_log files', 'amazing-security' ),
					__( 'Backup copies of wp-config.php', 'amazing-security' ),
					__( 'PHP version', 'amazing-security' ),
					__( 'Background updates', 'amazing-security' ),
					__( 'Plugin updates', 'amazing-security' ),
					__( 'Theme updates', 'amazing-security' ),
					__( 'Inactive plugins', 'amazing-security' ),
					__( 'Inactive themes', 'amazing-security' ),
					__( 'PHP files in uploads', 'amazing-security' ),
					__( 'Files exposed in the site root', 'amazing-security' ),
					__( 'Bot protection mode', 'amazing-security' ),
					__( 'REST rate limits', 'amazing-security' ),
					__( 'REST request watch', 'amazing-security' ),
					__( 'Finding emails', 'amazing-security' ),
					__( 'Weekly digest', 'amazing-security' ),
					__( 'Traffic history', 'amazing-security' ),
					__( 'Network controls', 'amazing-security' ),
					__( 'Trusted proxies', 'amazing-security' ),
					__( 'Security activity log', 'amazing-security' ),
					__( 'Account sessions', 'amazing-security' ),
					__( 'Code baselines', 'amazing-security' ),
					__( 'Daily checks', 'amazing-security' ),
					__( 'Daily file checks', 'amazing-security' ),
					__( 'Rule review', 'amazing-security' ),
					__( 'AI crawler access', 'amazing-security' ),
					__( 'AI readiness', 'amazing-security' ),
					__( 'Known security holes', 'amazing-security' ),
					__( 'Release file integrity', 'amazing-security' ),
					__( 'Closed plugins', 'amazing-security' ),
					__( 'Public content', 'amazing-security' ),
					__( 'Local plugin code', 'amazing-security' ),
					__( 'Suspicious files', 'amazing-security' ),
					__( 'Local file inventory', 'amazing-security' ),
					__( 'Security headers follow-up', 'amazing-security' ),
				),
				'headers' => __( 'Homepage response headers', 'amazing-security' ),
				'saving'  => __( 'Saving the results', 'amazing-security' ),
				/* translators: 1: current step number, 2: total number of steps. */
				'step'    => __( 'Step %1$s of %2$s', 'amazing-security' ),
				'minMs'   => 36000,
			)
		);
	}

	public static function bar(): void {
		if ( ! self::onScreen() ) {
			return;
		}
		// WordPress moves notices to just after this marker, which keeps them above the plugin header.
		echo '<hr class="wp-header-end">';
		$logo    = plugins_url( 'assets/logo.png', AMAZING_SECURITY_FILE );
		$docs    = plugins_url( 'assets/icon-docs.svg', AMAZING_SECURITY_FILE );
		$guide   = plugins_url( 'assets/icon-guide.svg', AMAZING_SECURITY_FILE );
		$headers = get_file_data( AMAZING_SECURITY_FILE, array( 'Version' => 'Version' ) );
		$version = is_string( $headers['Version'] ?? null ) ? $headers['Version'] : '';
		echo '<div class="amsec-brand"><div class="amsec-brand-mark">';
		echo '<img src="' . esc_url( $logo ) . '" alt="' . esc_attr__( 'AmazingPlugins', 'amazing-security' ) . '" width="44" height="44">';
		echo '<div class="amsec-brand-title"><p class="amsec-brand-name">' . esc_html__( 'Amazing Security', 'amazing-security' ) . '</p>';
		if ( 1 === preg_match( '/^\d+\.\d+\.\d+$/', $version ) ) {
			echo '<p class="amsec-brand-version">' . esc_html( $version ) . '</p>';
		}
		echo '</div></div>';
		echo '<p class="amsec-brand-links"><a href="' . esc_url( self::DOCS ) . '" target="_blank" rel="noopener noreferrer">';
		echo '<img src="' . esc_url( $docs . '?ver=0.1.18' ) . '" alt="" width="22" height="22">' . esc_html__( 'Docs', 'amazing-security' ) . '</a>';
		echo '<a href="' . esc_url( self::GUIDE ) . '" target="_blank" rel="noopener noreferrer">';
		echo '<img src="' . esc_url( $guide . '?ver=0.1.18' ) . '" alt="" width="22" height="22">' . esc_html__( 'Security guide', 'amazing-security' ) . '</a></p></div>';
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
