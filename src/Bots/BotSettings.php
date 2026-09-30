<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Bots;

use AmazingPlugins\Security\Activity\ActivityHooks;
use AmazingPlugins\Security\Activity\ActivityRepository;
use AmazingPlugins\Security\Admin\FixApprovalAction;
use AmazingPlugins\Security\Sessions\SessionPolicy;

final class BotSettings {
	public function register(): void {
		add_submenu_page( 'amazing-security', 'Native bot controls', 'Bot controls', 'manage_options', 'amsec-bots', array( $this, 'render' ) );
	}

	public function handle(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified before changing settings.
		$post   = wp_unslash( $_POST );
		$method = is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		$auth   = wp_parse_auth_cookie( '', is_ssl() ? 'secure_auth' : 'auth' );
		$mode   = is_string( $post['mode'] ?? null ) ? $post['mode'] : '';
		if ( ! SessionPolicy::allowed( 'post' === $method, current_user_can( 'manage_options' ), in_array( $mode, array( 'off', 'observe', 'block' ), true ), FixApprovalAction::cookieAuthenticated() && SessionPolicy::matchingTokens( is_array( $auth ) ? (string) $auth['token'] : '', wp_get_session_token() ), is_ssl(), '1' === ( $post['confirm'] ?? null ) ) ) {
			wp_die( esc_html__( 'Secure administrator approval and acknowledgement are required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_bot_settings' );
		$password = is_string( $post['password'] ?? null ) && strlen( $post['password'] ) <= 1024 ? $post['password'] : '';
		$user     = wp_get_current_user();
		if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			wp_die( esc_html__( 'Password confirmation failed.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		update_option( 'amsec_bot_mode', $mode, false );
		if ( get_option( 'amsec_bot_mode', 'off' ) !== $mode ) {
			wp_die( esc_html__( 'The setting change could not be verified.', 'amazing-security' ), '', array( 'response' => 409 ) );
		}
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'bot_policy_changed', 0, $mode );
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-bots' ) );
		exit;
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		$mode      = ( new BotHooks() )->mode();
		$available = ( new BotCounterStore( $GLOBALS['wpdb'] ) )->available();
		echo '<div class="wrap"><h1>Native comment and registration controls</h1><p>Off by default. Observe records request counters without rejecting submissions. Block rejects filled/malformed hidden fields or excess unauthenticated native requests: twenty comments per five minutes and five registrations per fifteen minutes. Missing trap fields remain accepted for legacy forms.</p><p>These controls apply to native wp-comments-post.php and wp-login.php registration. Logged-in users, WooCommerce registration/checkout, Contact Form 7 and custom/API forms are outside this scope. The host-provided PHP REMOTE_ADDR is salted into an opaque key. Forwarded headers are ignored by default. Optional approved trusted-proxy settings require a host-confirmed direct peer; Apache or a proxy may already have rewritten the address. Verify host proxy trust before relying on rate accuracy. Proxies and shared networks can group visitors, so test observe mode before blocking.</p><p>Counters have a 10,000-key admission budget. Hourly cleanup deletes up to 1,000 records older than one day. Missing/full storage or invalid addresses skip rate enforcement; the hidden-field check remains independent. No raw addresses, usernames or submission contents are stored. Host recovery: <code>wp amazing-security bots disable</code>.</p><p>Mode: ' . esc_html( $mode ) . '. Rate storage/admission: ' . ( $available ? 'available' : 'unavailable' ) . '.</p>';
		if ( ! is_ssl() ) {
			echo '<p>Use HTTPS to approve a setting change.</p></div>';
			return;
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_bot_settings"><label>Mode <select name="mode">';
		foreach ( array( 'off', 'observe', 'block' ) as $value ) {
			echo '<option value="' . esc_attr( $value ) . '"' . selected( $mode, $value, false ) . '>' . esc_html( ucfirst( $value ) ) . '</option>';
		}
		echo '</select></label>';
		wp_nonce_field( 'amsec_bot_settings' );
		echo '<p><label>Your password <input type="password" name="password" autocomplete="current-password" required maxlength="1024"></label></p><p><label><input type="checkbox" name="confirm" value="1" required> I understand that blocking can reject legitimate visitors behind shared addresses or autofilled forms.</label></p>';
		submit_button( 'Approve mode', 'secondary' );
		echo '</form></div>';
	}

	public function recovery( array $args, array $assoc ): void {
		if ( array() !== $args || array() !== $assoc ) {
			\WP_CLI::error( 'This command accepts no arguments.' );
		}
		update_option( 'amsec_bot_mode', 'off', false );
		if ( 'off' !== get_option( 'amsec_bot_mode', 'off' ) ) {
			\WP_CLI::error( 'Bot controls could not be disabled.' );
		}
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'bot_policy_changed', 0, 'off' );
		\WP_CLI::success( 'Native bot controls are off.' );
	}
}
