<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Detect;

defined( 'ABSPATH' ) || exit;

final class Module {
	public const OPTION = 'ironlatch_precise_block';

	public const QUERY_BUDGET = 2048;

	public const VALUE_NEEDLE = 'ironlatch_webshell_marker_<?php';

	public const PROBE_KEY = 'ironlatch_block_probe';

	public static function boot(): void {
		add_action( 'init', array( self::class, 'inspect' ) );
		add_action( 'admin_menu', array( self::class, 'menu' ) );
		add_action( 'admin_post_ironlatch_precise_block', array( self::class, 'save' ) );
	}

	public static function inspect(): void {
		if ( self::constantDisables() ) {
			return;
		}
		$option = get_option( self::OPTION, '0' );
		$option = is_scalar( $option ) ? (string) $option : '0';
		if ( '1' !== $option ) {
			return;
		}
		// Public request: no nonce is possible, and nothing read here is stored or printed.
		$pairs = array();
		if ( isset( $_GET[ self::PROBE_KEY ] ) && is_string( $_GET[ self::PROBE_KEY ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$pairs[ self::PROBE_KEY ] = sanitize_text_field( wp_unslash( $_GET[ self::PROBE_KEY ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}
		$used = 0;
		foreach ( array_keys( $_GET ) as $i => $name ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( $used >= self::QUERY_BUDGET ) {
				break;
			}
			if ( ! is_string( $name ) || ! isset( $_GET[ $name ] ) || ! is_string( $_GET[ $name ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				continue;
			}
			// The marker holds "<", which sanitize_text_field would strip as a tag. Escape it first and restore it after.
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Public request with no nonce; sanitized in this expression.
			$value             = sanitize_text_field( str_replace( '<', '&lt;', wp_unslash( $_GET[ $name ] ) ) );
			$used             += strlen( $value );
			$pairs[ 'q' . $i ] = str_replace( '&lt;', '<', $value );
		}
		if ( ! self::shouldBlock( $pairs, '1', false ) ) {
			return;
		}
		wp_die( esc_html__( 'This request was refused.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
	}

	public static function menu(): void {
		add_submenu_page(
			'ironlatch-security-scanner',
			__( 'Precise blocks', 'ironlatch-security-scanner' ),
			__( 'Precise blocks', 'ironlatch-security-scanner' ),
			'manage_options',
			'ironlatch-precise-block',
			array( self::class, 'render' )
		);
	}

	public static function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$option  = get_option( self::OPTION, '0' );
		$enabled = '1' === ( is_scalar( $option ) ? (string) $option : '0' );
		echo '<div class="wrap ironlatch-security-scanner-admin"><h1>' . esc_html__( 'Precise blocks', 'ironlatch-security-scanner' ) . '</h1>';
		echo '<p>' . esc_html__( 'Off until you turn it on. A query is rejected only for two exact test markers. SQL keywords and ../ are left alone.', 'ironlatch-security-scanner' ) . '</p>';
		echo '<p>' . esc_html__( 'Set IRONLATCH_DISABLE_PRECISE_BLOCK to true and this check stops.', 'ironlatch-security-scanner' ) . '</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="ironlatch_precise_block">';
		wp_nonce_field( 'ironlatch_precise_block' );
		echo '<p><label><input type="radio" name="ironlatch_precise_block" value="0"' . checked( ! $enabled, true, false ) . '> ' . esc_html__( 'Off', 'ironlatch-security-scanner' ) . '</label></p>';
		echo '<p><label><input type="radio" name="ironlatch_precise_block" value="1"' . checked( $enabled, true, false ) . '> ' . esc_html__( 'On', 'ironlatch-security-scanner' ) . '</label></p>';
		submit_button( __( 'Save precise blocks', 'ironlatch-security-scanner' ) );
		echo '</form></div>';
	}

	public static function save(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'ironlatch_precise_block' );
		$raw = isset( $_POST['ironlatch_precise_block'] ) && is_string( $_POST['ironlatch_precise_block'] ) ? sanitize_text_field( wp_unslash( $_POST['ironlatch_precise_block'] ) ) : '0';
		update_option( self::OPTION, '1' === $raw ? '1' : '0', false );
		wp_safe_redirect( \AmazingPlugins\Security\Admin\Brand::saved( admin_url( 'admin.php?page=ironlatch-traffic-guard#precise' ) ) );
		exit;
	}

	public static function constantDisables(): bool {
		return defined( 'IRONLATCH_DISABLE_PRECISE_BLOCK' ) && true === IRONLATCH_DISABLE_PRECISE_BLOCK;
	}

	/**
	 * Decide from an already unslashed query. No WordPress calls.
	 *
	 * @param array<mixed> $query
	 */
	public static function shouldBlock( array $query, string $option, bool $disabled ): bool {
		if ( $disabled || '1' !== $option ) {
			return false;
		}
		$remaining = self::QUERY_BUDGET;
		foreach ( $query as $key => $value ) {
			if ( $remaining <= 0 ) {
				break;
			}
			if ( ! is_string( $key ) || ! is_string( $value ) ) {
				continue;
			}
			$key_bytes = strlen( $key );
			if ( $key_bytes > $remaining ) {
				break;
			}
			$remaining -= $key_bytes;
			if ( self::PROBE_KEY === $key ) {
				return true;
			}
			$value_bytes = strlen( $value );
			$slice       = $value_bytes > $remaining ? substr( $value, 0, $remaining ) : $value;
			$remaining  -= strlen( $slice );
			if ( str_contains( $slice, self::VALUE_NEEDLE ) ) {
				return true;
			}
			if ( strlen( $slice ) < $value_bytes ) {
				break;
			}
		}
		return false;
	}
}
