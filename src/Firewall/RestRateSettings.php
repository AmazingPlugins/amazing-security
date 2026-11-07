<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Firewall;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Admin\FixApprovalAction;
use AmazingPlugins\Security\Sessions\SessionPolicy;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Bots\BotCounterStore;
use AmazingPlugins\Security\Activity\{ActivityHooks, ActivityRepository};
use AmazingPlugins\Security\Request\PostedPassword;
final class RestRateSettings {
	private function service(): RestRateSettingsService {
		return new RestRateSettingsService( new WordPressOptions() );}
	public function register(): void {
		$hook = add_submenu_page( 'ironlatch-security-scanner', __( 'REST rate controls', 'ironlatch-security-scanner' ), __( 'REST rate controls', 'ironlatch-security-scanner' ), 'manage_options', 'ironlatch-rest-rates', array( $this, 'render' ) );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $current ) use ( $hook ): void {
				if ( $current === $hook ) {
					wp_enqueue_style( 'ironlatch-security-scanner-admin', plugins_url( 'assets/admin.css', IRONLATCH_SECURITY_SCANNER_FILE ), array(), '0.1.0' );
				}}
		);}
	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Secure administrator approval of the current policy is required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );}
		$s  = $this->service();
		$fp = $s->fingerprint();
		check_admin_referer( 'ironlatch_rest_rates_' . $fp );
		$state         = $s->status();
		$method        = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		$auth          = wp_parse_auth_cookie( '', is_ssl() ? 'secure_auth' : 'auth' );
		$mode          = isset( $_POST['mode'] ) && is_string( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : '';
		$exemptions_ok = ! isset( $_POST['exemptions'] ) || is_array( $_POST['exemptions'] );
		$exemptions    = isset( $_POST['exemptions'] ) && is_array( $_POST['exemptions'] ) ? array_values( array_filter( map_deep( wp_unslash( $_POST['exemptions'] ), 'sanitize_key' ), 'is_string' ) ) : array();
		$posted_fp     = isset( $_POST['fingerprint'] ) && is_string( $_POST['fingerprint'] ) ? sanitize_key( wp_unslash( $_POST['fingerprint'] ) ) : '';
		$confirmed     = isset( $_POST['confirm'] ) && is_string( $_POST['confirm'] ) ? sanitize_text_field( wp_unslash( $_POST['confirm'] ) ) : '';
		if ( ! SessionPolicy::allowed( 'post' === $method, current_user_can( 'manage_options' ), empty( $state['invalid'] ) && $exemptions_ok && in_array( $mode, array( 'off', 'observe', 'block' ), true ) && $posted_fp === $fp, FixApprovalAction::cookieAuthenticated() && SessionPolicy::matchingTokens( is_array( $auth ) ? (string) $auth['token'] : '', wp_get_session_token() ), is_ssl(), '1' === $confirmed ) ) {
			wp_die( esc_html__( 'Secure administrator approval of the current policy is required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );}
		// Passwords are compared as typed; sanitizing would change them.
		$password = PostedPassword::read( 'password' ) ?? '';
		$user     = wp_get_current_user();
		if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			wp_die( esc_html__( 'Password confirmation failed.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );}
		if ( 'saved' !== $s->apply( $fp, $mode, $exemptions ) ) {
			wp_die( esc_html__( 'Policy changed or could not be saved. Review and approve the current policy.', 'ironlatch-security-scanner' ), '', array( 'response' => 409 ) );}
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', 0, 'rest-rate-' . $mode );
		wp_safe_redirect( admin_url( 'admin.php?page=ironlatch-traffic-guard#rest' ) );
		exit;
	}
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}$s        = $this->service();
		$state     = $s->status();
		$fp        = $s->fingerprint();
		$available = ( new BotCounterStore( $GLOBALS['wpdb'] ) )->available();
		echo '<div class="wrap ironlatch-security-scanner-admin"><header class="ironlatch-header"><div><h1>' . esc_html__( 'REST rate controls', 'ironlatch-security-scanner' ) . '</h1><p>' . esc_html__( 'Optional controls for two native anonymous endpoints.', 'ironlatch-security-scanner' ) . '</p></div></header><section class="ironlatch-overview"><h2>' . esc_html__( 'Observe before blocking', 'ironlatch-security-scanner' ) . '</h2><p>' . esc_html__( 'Off by default. Observe is the learning mode: it records counters without rejecting requests and never automatically enables blocking. Block rejects excess anonymous GET requests to native users endpoints (60 per five minutes) or POST requests to the native comments collection (20 per five minutes). Each approved policy edit starts a new counter namespace.', 'ironlatch-security-scanner' ) . '</p><details class="ironlatch-more"><summary>' . esc_html__( 'How it works', 'ironlatch-security-scanner' ) . '</summary><p>' . esc_html__( 'Authenticated requests, other methods, custom routes, WooCommerce and Contact Form 7 routes are excluded. Query-pattern observations remain separate and never block. These controls are not a complete attack-rule firewall.', 'ironlatch-security-scanner' ) . '</p><p>' . esc_html__( 'The host-provided PHP REMOTE_ADDR becomes a salted opaque key; forwarded headers are ignored by default. Optional approved trusted-proxy settings require a host-confirmed direct peer; Apache or a proxy may already have rewritten that value. Verify host proxy trust before relying on rate accuracy. Proxies and shared networks can group visitors. Missing/full/busy storage or invalid addresses skip rate enforcement. The shared bot-counter store admits at most 10,000 keys, with hourly bounded cleanup of records older than one day. Raw addresses, request contents and URLs are not stored.', 'ironlatch-security-scanner' ) . '</p><p>' .
			/* translators: %1$s and %2$s are inline code snippets (a WP-CLI command or a constant name); keep them unchanged. */
			sprintf( esc_html__( 'Host recovery: %1$s. The %2$s constant bypasses rate controls and query observations.', 'ironlatch-security-scanner' ), '<code>wp ironlatch-security-scanner rest-rates disable</code>', '<code>IRONLATCH_DISABLE_FIREWALL</code>' ) . '</p></details></section>';
		if ( ! empty( $state['invalid'] ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Policy is invalid and enforcement is unavailable. Use host recovery to set an explicit off policy.', 'ironlatch-security-scanner' ) . '</p></div></div>';
			return;}
		echo '<section class="ironlatch-file-scan"><h2>' . esc_html__( 'Current policy', 'ironlatch-security-scanner' ) . '</h2><p>' .
			/* translators: 1: mode slug; 2: counter storage state, available or unavailable. */
			sprintf( esc_html__( 'Mode: %1$s. Counter storage: %2$s.', 'ironlatch-security-scanner' ), esc_html( $state['mode'] ), esc_html( $available ? __( 'available', 'ironlatch-security-scanner' ) : __( 'unavailable', 'ironlatch-security-scanner' ) ) ) . '</p>';
		if ( ! is_ssl() ) {
			echo '<p>' . esc_html__( 'Use HTTPS to approve policy changes.', 'ironlatch-security-scanner' ) . '</p></section></div>';
			return;}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="ironlatch_rest_rate_settings"><input type="hidden" name="fingerprint" value="' . esc_attr( $fp ) . '"><p><label>' . esc_html__( 'Mode', 'ironlatch-security-scanner' ) . ' <select name="mode">';
		foreach ( array(
			'off'     => __( 'Off', 'ironlatch-security-scanner' ),
			'observe' => __( 'Observe', 'ironlatch-security-scanner' ),
			'block'   => __( 'Block', 'ironlatch-security-scanner' ),
		) as $mode => $label ) {
			echo '<option value="' . esc_attr( $mode ) . '"' . selected( $state['mode'], $mode, false ) . '>' . esc_html( $label ) . '</option>';
		}echo '</select></label></p><fieldset><legend>' . esc_html__( 'Exempt an endpoint from counting and enforcement', 'ironlatch-security-scanner' ) . '</legend>';
		foreach ( RestRatePolicy::IDS as $id ) {
			echo '<p><label><input type="checkbox" name="exemptions[]" value="' . esc_attr( $id ) . '"' . checked( in_array( $id, $state['exemptions'], true ), true, false ) . '> ' . esc_html( 'users-read' === $id ? __( 'Native users GET collection/items', 'ironlatch-security-scanner' ) : __( 'Native comments POST collection', 'ironlatch-security-scanner' ) ) . '</label></p>';
		}echo '</fieldset>';
		wp_nonce_field( 'ironlatch_rest_rates_' . $fp );
		echo '<p><label>' . esc_html__( 'Your password', 'ironlatch-security-scanner' ) . ' <input type="password" name="password" autocomplete="current-password" maxlength="1024" required></label></p><p><label><input type="checkbox" name="confirm" value="1" required> ' . esc_html__( 'I understand that blocking may reject legitimate requests behind shared addresses. I have tested observe mode and integration compatibility.', 'ironlatch-security-scanner' ) . '</label></p>';
		submit_button( __( 'Approve current policy', 'ironlatch-security-scanner' ), 'secondary' );
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
