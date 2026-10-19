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
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- AuthFactorPanel escapes output.
		echo AuthFactorPanel::html( __( 'Authenticator app (TOTP)', 'amazing-security' ), $factor, $url, 'totp' );
		echo '</div>';
	}

	public function profile( \WP_User $user ): void {
		unset( $user );
		// Profile enroll form retired.
	}

	public static function directoryUrl( string $slug ): string {
		$safe = preg_replace( '/[^a-z0-9\-]+/', '', strtolower( $slug ) );
		$slug = is_string( $safe ) && '' !== $safe ? $safe : 'two-factor';
		if ( current_user_can( 'install_plugins' ) ) {
			// Plugins > Add New search, so people pick and install it themselves. Quoted so the exact plugin ranks first.
			return self_admin_url( 'plugin-install.php?s=' . rawurlencode( '"' . str_replace( '-', ' ', $slug ) . '"' ) . '&tab=search&type=term' );
		}
		return 'https://wordpress.org/plugins/' . rawurlencode( $slug ) . '/';
	}
}
