<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

/** Status-only Verification tab. Enrollment lives in a dedicated 2FA plugin. */
final class RequiredTotpPage {
	public function register(): void {
		// Hidden submenu retired; Verification lives on Log In & Register.
	}

	public function notice(): void {
		// No required-policy notices while Amazing Security does not own TOTP.
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		$factor = AuthFactorDetector::fromWordPress()->totp( get_current_user_id() );
		$url    = self::directoryUrl( (string) ( $factor['suggest_slug'] ?? 'two-factor' ) );
		echo '<div class="wrap amazing-security-admin">';
		echo '<p>' . esc_html__( 'Amazing Security reports whether an authenticator-app plugin is present. It does not enroll devices or store backup codes.', 'amazing-security' ) . '</p>';
		echo wp_kses( AuthFactorPanel::html( __( 'Authenticator app (TOTP)', 'amazing-security' ), $factor, $url, 'totp' ), \AmazingPlugins\Security\Admin\AdminHtml::allowed() );
		echo '</div>';
	}

	public function profile( \WP_User $user ): void {
		unset( $user );
		// Profile enroll form retired.
	}

	public static function directoryUrl( string $slug ): string {
		$safe = preg_replace( '/[^a-z0-9\-]+/', '', strtolower( $slug ) );
		$slug = is_string( $safe ) && '' !== $safe ? $safe : 'two-factor';
		if ( self::installed( $slug ) && current_user_can( 'activate_plugins' ) ) {
			// Already on disk, so send people to activate it rather than install it again.
			return self_admin_url( 'plugins.php?plugin_status=inactive&s=' . rawurlencode( str_replace( '-', ' ', $slug ) ) );
		}
		if ( current_user_can( 'install_plugins' ) ) {
			// Plugins > Add New search, so people pick and install it themselves. Quoted so the exact plugin ranks first.
			return self_admin_url( 'plugin-install.php?s=' . rawurlencode( '"' . str_replace( '-', ' ', $slug ) . '"' ) . '&tab=search&type=term' );
		}
		return 'https://wordpress.org/plugins/' . rawurlencode( $slug ) . '/';
	}

	public static function installed( string $slug ): bool {
		return defined( 'WP_PLUGIN_DIR' ) && 1 === preg_match( '/^[a-z0-9-]+$/D', $slug ) && is_dir( WP_PLUGIN_DIR . '/' . $slug );
	}
}
