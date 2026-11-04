<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Network;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Admin\FixApprovalAction;
use AmazingPlugins\Security\Sessions\SessionPolicy;
use AmazingPlugins\Security\Activity\{ActivityHooks, ActivityRepository};
final class NetworkSettings {
	private function service(): NetworkSettingsService {
		return new NetworkSettingsService( new \AmazingPlugins\Security\Proxy\FreshSecurityOptions( $GLOBALS['wpdb'], new WordPressOptions() ) );}
	public function register(): void {
		$hook = add_submenu_page( 'ironlatch-security-scanner', __( 'Manual network controls', 'ironlatch-security-scanner' ), __( 'Network controls', 'ironlatch-security-scanner' ), 'manage_options', 'ironlatch-network', array( $this, 'render' ) );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $current ) use ( $hook ): void {
				if ( $current === $hook ) {
					wp_enqueue_style( 'ironlatch-security-scanner-admin', plugins_url( 'assets/admin.css', IRONLATCH_SECURITY_SCANNER_FILE ), array(), '0.1.0' );
				}}
		);}
	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Secure administrator approval of the current network policy is required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );}
		$s  = $this->service();
		$fp = $s->fingerprint();
		check_admin_referer( 'ironlatch_network_' . $fp );
		$state  = $s->status();
		$method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		$auth   = wp_parse_auth_cookie( '', is_ssl() ? 'secure_auth' : 'auth' );
		$mode   = isset( $_POST['mode'] ) && is_string( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : '';
		$rules  = isset( $_POST['rules'] ) && is_string( $_POST['rules'] ) ? sanitize_textarea_field( wp_unslash( $_POST['rules'] ) ) : null;
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Unslashed here and sanitized per item in the callback.
		$methods   = isset( $_POST['methods'] ) && is_array( $_POST['methods'] ) ? array_map( static fn( mixed $m ): string => is_string( $m ) ? sanitize_text_field( $m ) : '', wp_unslash( $_POST['methods'] ) ) : null;
		$posted_fp = isset( $_POST['fingerprint'] ) && is_string( $_POST['fingerprint'] ) ? sanitize_key( wp_unslash( $_POST['fingerprint'] ) ) : '';
		$confirmed = isset( $_POST['confirm'] ) && is_string( $_POST['confirm'] ) ? sanitize_text_field( wp_unslash( $_POST['confirm'] ) ) : '';
		if ( ! SessionPolicy::allowed( 'post' === $method, current_user_can( 'manage_options' ), empty( $state['invalid'] ) && in_array( $mode, array( 'off', 'observe', 'block' ), true ) && null !== $rules && strlen( $rules ) <= 4096 && null !== $methods && $posted_fp === $fp, FixApprovalAction::cookieAuthenticated() && SessionPolicy::matchingTokens( is_array( $auth ) ? (string) $auth['token'] : '', wp_get_session_token() ), is_ssl(), '1' === $confirmed ) ) {
			wp_die( esc_html__( 'Secure administrator approval of the current network policy is required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );}
		// Passwords are compared as typed; sanitizing would change them.
		$password = isset( $_POST['password'] ) && is_string( $_POST['password'] ) ? wp_unslash( $_POST['password'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Compared as typed; sanitizing would change the password.
		$password = strlen( $password ) <= 1024 ? $password : '';
		$user     = wp_get_current_user();
		if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			wp_die( esc_html__( 'Password confirmation failed.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );}
		$lines  = preg_split( '/\r?\n/', $rules );
		$lines  = is_array( $lines ) ? array_values( array_filter( array_map( 'trim', $lines ), static fn( string $line ): bool=>'' !== $line ) ) : array();
		$result = ( new \AmazingPlugins\Security\Proxy\SecurityApprovalLock( $GLOBALS['wpdb'] ) )->run(
			function () use ( $s, $fp, $mode, $lines, $methods ): string {
				$options  = new \AmazingPlugins\Security\Proxy\FreshSecurityOptions( $GLOBALS['wpdb'], new WordPressOptions() );
				$operator = ( new \AmazingPlugins\Security\Proxy\WordPressClientAddress() )->address( \AmazingPlugins\Security\Proxy\WordPressClientAddress::request(), $options ) ?? '';
				return $s->apply( $fp, $mode, $lines, $methods, $operator );
			}
		);
		if ( 'saved' !== $result ) {
			wp_die( esc_html__( 'Policy changed, invalid rules or self-lockout risk. Review the current policy and your host address before approving.', 'ironlatch-security-scanner' ), '', array( 'response' => 409 ) );}
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', 0, 'network-' . $mode );
		wp_safe_redirect( \AmazingPlugins\Security\Admin\Brand::saved( admin_url( 'admin.php?page=ironlatch-traffic-guard#network' ) ) );
		exit;
	}
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}$s     = $this->service();
		$state  = $s->status();
		$fp     = $s->fingerprint();
		$metric = ( new NetworkObservation( new WordPressOptions() ) )->status();
		echo '<div class="wrap ironlatch-security-scanner-admin"><header class="ironlatch-header"><div><h1>' . esc_html__( 'Manual network controls', 'ironlatch-security-scanner' ) . '</h1><p>' . esc_html__( 'Approve explicit network rules without changing host infrastructure.', 'ironlatch-security-scanner' ) . '</p></div></header><section class="ironlatch-overview"><h2>' . esc_html__( 'PHP requests only', 'ironlatch-security-scanner' ) . '</h2><p>' . esc_html__( 'Off by default. Observe records an approximate redacted match count without denying traffic. Block denies matching IPv4/IPv6 CIDRs for selected methods on requests reaching WordPress PHP. Static assets, cached pages or CDN responses that bypass PHP are outside this scope. This is not a server firewall or automatic ban service.', 'ironlatch-security-scanner' ) . '</p><details class="ironlatch-more"><summary>' . esc_html__( 'How it works', 'ironlatch-security-scanner' ) . '</summary><p>' . esc_html__( 'CLI, cron and administrators already identified by WordPress at the check point are exempt. Authentication handled later in an API request may still be denied. By default use the host-provided PHP REMOTE_ADDR; optional approved trusted-proxy settings can resolve a reported client only with host-confirmed direct peer configuration. The host may already have rewritten the address. Verify proxy trust before enforcing. Shared networks can group legitimate visitors.', 'ironlatch-security-scanner' ) . '</p><p>' .
			/* translators: %1$s and %2$s are inline code snippets (a WP-CLI command or a constant name); keep them unchanged. */
			sprintf( esc_html__( 'Approval refuses a block policy covering your current resolved address to reduce self-lockout. A later network change can still lock you out. Recovery: %1$s, or bypass with %2$s. Recovery clears this feature’s advisory count.', 'ironlatch-security-scanner' ), '<code>wp ironlatch-security-scanner network disable</code>', '<code>IRONLATCH_DISABLE_FIREWALL</code>' ) . '</p><p>' . esc_html__( 'Configured CIDRs are stored as explicit policy. Visitor addresses, URLs, content and usernames are not collected by the match counter. Counts can miss concurrent or failed writes and cap at one million; they never decide enforcement.', 'ironlatch-security-scanner' ) . '</p></details></section>';
		if ( ! empty( $state['invalid'] ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Network policy is invalid; enforcement is unavailable. Use host recovery to set an explicit off policy.', 'ironlatch-security-scanner' ) . '</p></div></div>';
			return;}
		echo '<section class="ironlatch-file-scan"><h2>' . esc_html__( 'Current policy', 'ironlatch-security-scanner' ) . '</h2><p>' .
			/* translators: %s: current mode slug, for example off, observe or block. */
			sprintf( esc_html__( 'Mode: %s.', 'ironlatch-security-scanner' ), esc_html( $state['mode'] ) ) . '</p>';
		if ( ! empty( $metric['invalid'] ) ) {
			echo '<p>' . esc_html__( 'Observed match count is unavailable.', 'ironlatch-security-scanner' ) . '</p>';
		} elseif ( $metric['revision'] === $state['revision'] ) {
			echo '<p>' .
				/* translators: %s: approximate match count for this policy revision. */
				sprintf( esc_html__( 'Approximate matches for this policy revision: %s.', 'ironlatch-security-scanner' ), esc_html( (string) $metric['count'] ) ) . '</p>';
		} else {
			echo '<p>' . esc_html__( 'No advisory count for this policy revision; earlier counts are historical.', 'ironlatch-security-scanner' ) . '</p>';}
		echo array() === $state['cidrs'] ? '<p>' . esc_html__( 'Configured networks: none.', 'ironlatch-security-scanner' ) . '</p>' : '<p>' . esc_html__( 'Configured networks:', 'ironlatch-security-scanner' ) . '</p><pre>' . esc_html( implode( "\n", $state['cidrs'] ) ) . '</pre>';
		if ( ! is_ssl() ) {
			echo '<p>' . esc_html__( 'Use HTTPS to approve changes.', 'ironlatch-security-scanner' ) . '</p></section></div>';
			return;}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="ironlatch_network_settings"><input type="hidden" name="fingerprint" value="' . esc_attr( $fp ) . '"><p><label>' . esc_html__( 'Mode', 'ironlatch-security-scanner' ) . ' <select name="mode">';
		foreach ( array(
			'off'     => __( 'Off', 'ironlatch-security-scanner' ),
			'observe' => __( 'Observe', 'ironlatch-security-scanner' ),
			'block'   => __( 'Block', 'ironlatch-security-scanner' ),
		) as $mode => $label ) {
			echo '<option value="' . esc_attr( $mode ) . '"' . selected( $state['mode'], $mode, false ) . '>' . esc_html( $label ) . '</option>';
		}echo '</select></label></p><p><label>' . esc_html__( 'Networks to deny (one IP or CIDR per line, up to 50)', 'ironlatch-security-scanner' ) . '<br><textarea name="rules" rows="6" class="large-text code" maxlength="4096">' . esc_html( implode( "\n", $state['cidrs'] ) ) . '</textarea></label></p><fieldset><legend>' . esc_html__( 'Methods: choose all, or selected methods', 'ironlatch-security-scanner' ) . '</legend>';
		foreach ( array_merge( array( '*' ), NetworkPolicy::METHODS ) as $method ) {
			echo '<label style="margin-right:1rem"><input type="checkbox" name="methods[]" value="' . esc_attr( $method ) . '"' . checked( in_array( $method, $state['methods'], true ), true, false ) . '> ' . esc_html( '*' === $method ? __( 'All methods', 'ironlatch-security-scanner' ) : $method ) . '</label>';
		}echo '</fieldset>';
		wp_nonce_field( 'ironlatch_network_' . $fp );
		echo '<p><label>' . esc_html__( 'Your password', 'ironlatch-security-scanner' ) . ' <input type="password" name="password" autocomplete="current-password" maxlength="1024" required></label></p><p><label><input type="checkbox" name="confirm" value="1" required> ' . esc_html__( 'I have reviewed proxy trust, shared-network and API effects, tested observe mode, and know the host recovery command.', 'ironlatch-security-scanner' ) . '</label></p>';
		submit_button( __( 'Approve current network policy', 'ironlatch-security-scanner' ), 'secondary' );
		echo '</form></section></div>';
	}
	public function recovery( array $args, array $assoc ): void {
		if ( array() !== $args || array() !== $assoc ) {
			\WP_CLI::error( 'This command accepts no arguments.' );
		}if ( ! $this->service()->disable() ) {
			\WP_CLI::error( 'Network controls could not be disabled.' );
		}( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', 0, 'network-off' );
		\WP_CLI::success( 'Network controls are off; advisory match count reset.' );}
}
