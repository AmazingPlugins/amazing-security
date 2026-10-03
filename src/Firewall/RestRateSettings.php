<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Firewall;

use AmazingPlugins\Security\Admin\FixApprovalAction;
use AmazingPlugins\Security\Sessions\SessionPolicy;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Bots\BotCounterStore;
use AmazingPlugins\Security\Activity\{ActivityHooks, ActivityRepository};
final class RestRateSettings {
	private function service(): RestRateSettingsService {
		return new RestRateSettingsService( new WordPressOptions() );}
	public function register(): void {
		$hook = add_submenu_page( 'amazing-security', __( 'REST rate controls', 'amazing-security' ), __( 'REST rate controls', 'amazing-security' ), 'manage_options', 'amsec-rest-rates', array( $this, 'render' ) );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $current ) use ( $hook ): void {
				if ( $current === $hook ) {
					wp_enqueue_style( 'amazing-security-admin', plugins_url( 'assets/admin.css', AMAZING_SECURITY_FILE ), array(), '0.1.0' );
				}}
		);}
	public function handle(): void {
	 // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Exact policy nonce and authenticated approval checked before mutation.
		$post       = wp_unslash( $_POST );
		$method     = is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		$auth       = wp_parse_auth_cookie( '', is_ssl() ? 'secure_auth' : 'auth' );
		$mode       = is_string( $post['mode'] ?? null ) ? $post['mode'] : '';
		$exemptions = is_array( $post['exemptions'] ?? null ) ? $post['exemptions'] : array();
		$s          = $this->service();
		$state      = $s->status();
		$fp         = $s->fingerprint();
		if ( ! SessionPolicy::allowed( 'post' === $method, current_user_can( 'manage_options' ), empty( $state['invalid'] ) && ( ! isset( $post['exemptions'] ) || is_array( $post['exemptions'] ) ) && in_array( $mode, array( 'off', 'observe', 'block' ), true ) && is_string( $post['fingerprint'] ?? null ) && $post['fingerprint'] === $fp, FixApprovalAction::cookieAuthenticated() && SessionPolicy::matchingTokens( is_array( $auth ) ? (string) $auth['token'] : '', wp_get_session_token() ), is_ssl(), '1' === ( $post['confirm'] ?? null ) ) ) {
			wp_die( esc_html__( 'Secure administrator approval of the current policy is required.', 'amazing-security' ), '', array( 'response' => 403 ) );}
		check_admin_referer( 'amsec_rest_rates_' . $fp );
		$password = is_string( $post['password'] ?? null ) && strlen( $post['password'] ) <= 1024 ? $post['password'] : '';
		$user     = wp_get_current_user();
		if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			wp_die( esc_html__( 'Password confirmation failed.', 'amazing-security' ), '', array( 'response' => 403 ) );}
		if ( 'saved' !== $s->apply( $fp, $mode, $exemptions ) ) {
			wp_die( esc_html__( 'Policy changed or could not be saved. Review and approve the current policy.', 'amazing-security' ), '', array( 'response' => 409 ) );}
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', 0, 'rest-rate-' . $mode );
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-rest-rates' ) );
		exit;
	}
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}$s        = $this->service();
		$state     = $s->status();
		$fp        = $s->fingerprint();
		$available = ( new BotCounterStore( $GLOBALS['wpdb'] ) )->available();
		echo '<div class="wrap amazing-security-admin"><header class="amsec-header"><div><h1>REST rate controls</h1><p>Optional controls for two native anonymous endpoints.</p></div></header><section class="amsec-overview"><h2>Observe before blocking</h2><p>Off by default. Observe is the learning mode: it records counters without rejecting requests and never automatically enables blocking. Block rejects excess anonymous GET requests to native users endpoints (60 per five minutes) or POST requests to the native comments collection (20 per five minutes). Each approved policy edit starts a new counter namespace.</p><p>Authenticated requests, other methods, custom routes, WooCommerce and Contact Form 7 routes are excluded. Query-pattern observations remain separate and never block. These controls are not a complete attack-rule firewall.</p><p>The host-provided PHP REMOTE_ADDR becomes a salted opaque key; forwarded headers are ignored by default. Optional approved trusted-proxy settings require a host-confirmed direct peer; Apache or a proxy may already have rewritten that value. Verify host proxy trust before relying on rate accuracy. Proxies and shared networks can group visitors. Missing/full/busy storage or invalid addresses skip rate enforcement. The shared bot-counter store admits at most 10,000 keys, with hourly bounded cleanup of records older than one day. Raw addresses, request contents and URLs are not stored.</p><p>Host recovery: <code>wp amazing-security rest-rates disable</code>. The <code>AMSEC_DISABLE_FIREWALL</code> constant bypasses rate controls and query observations.</p></section>';
		if ( ! empty( $state['invalid'] ) ) {
			echo '<div class="notice notice-error"><p>Policy is invalid and enforcement is unavailable. Use host recovery to set an explicit off policy.</p></div></div>';
			return;}
		echo '<section class="amsec-file-scan"><h2>Current policy</h2><p>Mode: ' . esc_html( $state['mode'] ) . '. Counter storage: ' . esc_html( $available ? 'available' : 'unavailable' ) . '.</p>';
		if ( ! is_ssl() ) {
			echo '<p>Use HTTPS to approve policy changes.</p></section></div>';
			return;}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_rest_rate_settings"><input type="hidden" name="fingerprint" value="' . esc_attr( $fp ) . '"><p><label>Mode <select name="mode">';
		foreach ( array( 'off', 'observe', 'block' ) as $mode ) {
			echo '<option value="' . esc_attr( $mode ) . '"' . selected( $state['mode'], $mode, false ) . '>' . esc_html( ucfirst( $mode ) ) . '</option>';
		}echo '</select></label></p><fieldset><legend>Exempt an endpoint from counting and enforcement</legend>';
		foreach ( RestRatePolicy::IDS as $id ) {
			echo '<p><label><input type="checkbox" name="exemptions[]" value="' . esc_attr( $id ) . '"' . checked( in_array( $id, $state['exemptions'], true ), true, false ) . '> ' . esc_html( 'users-read' === $id ? 'Native users GET collection/items' : 'Native comments POST collection' ) . '</label></p>';
		}echo '</fieldset>';
		wp_nonce_field( 'amsec_rest_rates_' . $fp );
		echo '<p><label>Your password <input type="password" name="password" autocomplete="current-password" maxlength="1024" required></label></p><p><label><input type="checkbox" name="confirm" value="1" required> I understand that blocking may reject legitimate requests behind shared addresses. I have tested observe mode and integration compatibility.</label></p>';
		submit_button( __( 'Approve current policy', 'amazing-security' ), 'secondary' );
		echo '</form></section></div>';
	}
	public function recovery( array $args, array $assoc ): void {
		if ( array() !== $args || array() !== $assoc ) {
			\WP_CLI::error( 'This command accepts no arguments.' );
		}if ( ! $this->service()->disable() ) {
			\WP_CLI::error( 'REST rates could not be disabled.' );
		}( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', 0, 'rest-rate-off' );
		\WP_CLI::success( 'REST rate controls are off.' );}
}
