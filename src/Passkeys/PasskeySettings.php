<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Passkeys;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Activity\ActivityHooks;
use AmazingPlugins\Security\Activity\ActivityRepository;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Login\AuthFactorDetector;
use AmazingPlugins\Security\Login\AuthFactorPanel;
use AmazingPlugins\Security\Login\RequiredTotpPage;
use AmazingPlugins\Security\Proxy\FreshSecurityOptions;

final class PasskeySettings {
	private function service(): PasskeySettingsService {
		return new PasskeySettingsService( new FreshSecurityOptions( $GLOBALS['wpdb'], new WordPressOptions() ) );
	}

	public function register(): void {
		// Empty menu title keeps a bookmarkable page without a visible submenu label.
		add_submenu_page( 'amazing-security', __( 'Passkeys', 'amazing-security' ), '', 'manage_options', 'amsec-passkeys', array( $this, 'render' ) );
	}

	public function handle(): void {
		wp_die( esc_html__( 'Amazing Security no longer enables passkeys. Use a dedicated passkey plugin.', 'amazing-security' ), '', array( 'response' => 410 ) );
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		$factor = AuthFactorDetector::fromWordPress()->passkeys( get_current_user_id() );
		$url    = RequiredTotpPage::directoryUrl( (string) ( $factor['suggest_slug'] ?? 'two-factor' ) );
		echo '<div class="wrap amazing-security-admin"><h1>' . esc_html__( 'Passkeys', 'amazing-security' ) . '</h1>';
		echo '<p><a href="' . esc_url( admin_url( 'admin.php?page=amsec-accounts#passkeys' ) ) . '">' . esc_html__( 'Back to Log In & Register', 'amazing-security' ) . '</a></p>';
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- AuthFactorPanel escapes output.
		echo AuthFactorPanel::html( __( 'Passkeys', 'amazing-security' ), $factor, $url, 'passkeys' );
		echo '<details><summary>' . esc_html__( 'Host cleanup for old Amazing Security passkey data', 'amazing-security' ) . '</summary>';
		echo '<p><code>wp amazing-security passkeys disable</code><br><code>wp amazing-security passkeys revoke USER_ID</code></p></details></div>';
	}

	public function recoveryDisable( array $args, array $assoc ): void {
		if ( array() !== $args || array() !== $assoc ) {
			\WP_CLI::error( 'This command accepts no arguments.' );
		}
		if ( ! $this->service()->disable() ) {
			\WP_CLI::error( 'Passkeys could not be disabled.' );
		}
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', 0, 'passkeys-off' );
		\WP_CLI::success( 'Passkey sign-in and enrollment are off. Saved credentials are retained.' );
	}

	public function recoveryRevoke( array $args, array $assoc ): void {
		if ( count( $args ) !== 1 || array() !== $assoc || ! ctype_digit( (string) $args[0] ) || (int) $args[0] < 1 || ! get_userdata( (int) $args[0] ) ) {
			\WP_CLI::error( 'Pass one existing user ID.' );
		}
		if ( ! ( new PasskeyRepository( $GLOBALS['wpdb'] ) )->revokeUser( (int) $args[0] ) ) {
			\WP_CLI::error( 'Passkeys could not be revoked.' );
		}
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', (int) $args[0], 'passkeys-revoked' );
		\WP_CLI::success( 'Saved passkeys and pending enrollments removed for the selected account.' );
	}
}
