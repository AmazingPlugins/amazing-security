<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Detect;

defined( 'ABSPATH' ) || exit;

final class Module {
	public const OPTION = 'amsec_precise_block';

	public const QUERY_BUDGET = 2048;

	public const VALUE_NEEDLE = 'amsec_webshell_marker_<?php';

	public const PROBE_KEY = 'amsec_block_probe';

	public static function boot(): void {
		add_action( 'init', array( self::class, 'inspect' ) );
		add_action( 'admin_menu', array( self::class, 'menu' ) );
		add_action( 'admin_post_amsec_precise_block', array( self::class, 'save' ) );
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
		$query = $_GET; // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Public query marker check. Values are bounded and not stored or printed.
		if ( ! is_array( $query ) || ! self::shouldBlock( self::queryStrings( $query ), '1', false ) ) {
			return;
		}
		wp_die( esc_html__( 'This request was refused.', 'amazingplugins-security-scanner' ), '', array( 'response' => 403 ) );
	}

	public static function menu(): void {
		add_submenu_page(
			'amazing-security',
			__( 'Precise blocks', 'amazingplugins-security-scanner' ),
			__( 'Precise blocks', 'amazingplugins-security-scanner' ),
			'manage_options',
			'amsec-precise-block',
			array( self::class, 'render' )
		);
	}

	public static function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazingplugins-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$option  = get_option( self::OPTION, '0' );
		$enabled = '1' === ( is_scalar( $option ) ? (string) $option : '0' );
		echo '<div class="wrap amazing-security-admin"><h1>' . esc_html__( 'Precise blocks', 'amazingplugins-security-scanner' ) . '</h1>';
		echo '<p>' . esc_html__( 'Off until you turn it on. A query is rejected only for two exact test markers. SQL keywords and ../ are left alone.', 'amazingplugins-security-scanner' ) . '</p>';
		echo '<p>' . esc_html__( 'Set AMSEC_DISABLE_PRECISE_BLOCK to true and this check stops.', 'amazingplugins-security-scanner' ) . '</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="amsec_precise_block">';
		wp_nonce_field( 'amsec_precise_block' );
		echo '<p><label><input type="radio" name="amsec_precise_block" value="0"' . checked( ! $enabled, true, false ) . '> ' . esc_html__( 'Off', 'amazingplugins-security-scanner' ) . '</label></p>';
		echo '<p><label><input type="radio" name="amsec_precise_block" value="1"' . checked( $enabled, true, false ) . '> ' . esc_html__( 'On', 'amazingplugins-security-scanner' ) . '</label></p>';
		submit_button( __( 'Save precise blocks', 'amazingplugins-security-scanner' ) );
		echo '</form></div>';
	}

	public static function save(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazingplugins-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_precise_block' );
		$posted = isset( $_POST['amsec_precise_block'] ) ? sanitize_text_field( wp_unslash( $_POST['amsec_precise_block'] ) ) : '0'; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce checked above.
		$raw    = is_string( $posted ) ? $posted : '0';
		update_option( self::OPTION, '1' === $raw ? '1' : '0', false );
		wp_safe_redirect( \AmazingPlugins\Security\Admin\Brand::saved( admin_url( 'admin.php?page=amsec-traffic-guard#precise' ) ) );
		exit;
	}

	public static function constantDisables(): bool {
		return defined( 'AMSEC_DISABLE_PRECISE_BLOCK' ) && true === AMSEC_DISABLE_PRECISE_BLOCK;
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

	/**
	 * String keys and values only, after unslashing.
	 *
	 * @param array<mixed> $query
	 * @return array<string, string>
	 */
	private static function queryStrings( array $query ): array {
		$pairs = array();
		foreach ( $query as $key => $value ) {
			if ( ! is_string( $key ) || ! is_string( $value ) ) {
				continue;
			}
			$pairs[ wp_unslash( $key ) ] = wp_unslash( $value );
		}
		return $pairs;
	}
}
