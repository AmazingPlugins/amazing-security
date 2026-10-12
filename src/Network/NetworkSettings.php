<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Network;

use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Admin\FixApprovalAction;
use AmazingPlugins\Security\Sessions\SessionPolicy;
use AmazingPlugins\Security\Activity\{ActivityHooks, ActivityRepository};
final class NetworkSettings {
	private function service(): NetworkSettingsService {
		return new NetworkSettingsService( new \AmazingPlugins\Security\Proxy\FreshSecurityOptions( $GLOBALS['wpdb'], new WordPressOptions() ) );}
	public function register(): void {
		$hook = add_submenu_page( 'amazing-security', __( 'Manual network controls', 'amazing-security' ), __( 'Network controls', 'amazing-security' ), 'manage_options', 'amsec-network', array( $this, 'render' ) );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $current ) use ( $hook ): void {
				if ( $current === $hook ) {
					wp_enqueue_style( 'amazing-security-admin', plugins_url( 'assets/admin.css', AMAZING_SECURITY_FILE ), array(), '0.1.0' );
				}}
		);}
	public function handle(): void {
	 // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Exact policy nonce and session approval checked before mutation.
		$post    = wp_unslash( $_POST );
		$method  = is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		$auth    = wp_parse_auth_cookie( '', is_ssl() ? 'secure_auth' : 'auth' );
		$mode    = is_string( $post['mode'] ?? null ) ? $post['mode'] : '';
		$rules   = is_string( $post['rules'] ?? null ) ? $post['rules'] : null;
		$methods = is_array( $post['methods'] ?? null ) ? $post['methods'] : null;
		$s       = $this->service();
		$state   = $s->status();
		$fp      = $s->fingerprint();
		if ( ! SessionPolicy::allowed( 'post' === $method, current_user_can( 'manage_options' ), empty( $state['invalid'] ) && in_array( $mode, array( 'off', 'observe', 'block' ), true ) && null !== $rules && strlen( $rules ) <= 4096 && null !== $methods && is_string( $post['fingerprint'] ?? null ) && $post['fingerprint'] === $fp, FixApprovalAction::cookieAuthenticated() && SessionPolicy::matchingTokens( is_array( $auth ) ? (string) $auth['token'] : '', wp_get_session_token() ), is_ssl(), '1' === ( $post['confirm'] ?? null ) ) ) {
			wp_die( esc_html__( 'Secure administrator approval of the current network policy is required.', 'amazing-security' ), '', array( 'response' => 403 ) );}
		check_admin_referer( 'amsec_network_' . $fp );
		$password = is_string( $post['password'] ?? null ) && strlen( $post['password'] ) <= 1024 ? $post['password'] : '';
		$user     = wp_get_current_user();
		if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			wp_die( esc_html__( 'Password confirmation failed.', 'amazing-security' ), '', array( 'response' => 403 ) );}
		$lines  = preg_split( '/\r?\n/', $rules );
		$lines  = is_array( $lines ) ? array_values( array_filter( array_map( 'trim', $lines ), static fn( string $line ): bool=>'' !== $line ) ) : array();
		$result = ( new \AmazingPlugins\Security\Proxy\SecurityApprovalLock( $GLOBALS['wpdb'] ) )->run(
			function () use ( $s, $fp, $mode, $lines, $methods ): string {
				$options  = new \AmazingPlugins\Security\Proxy\FreshSecurityOptions( $GLOBALS['wpdb'], new WordPressOptions() );
				$operator = ( new \AmazingPlugins\Security\Proxy\WordPressClientAddress() )->address( $_SERVER, $options ) ?? '';
				return $s->apply( $fp, $mode, $lines, $methods, $operator );
			}
		);
		if ( 'saved' !== $result ) {
			wp_die( esc_html__( 'Policy changed, invalid rules or self-lockout risk. Review the current policy and your host address before approving.', 'amazing-security' ), '', array( 'response' => 409 ) );}
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', 0, 'network-' . $mode );
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-network' ) );
		exit;
	}
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}$s     = $this->service();
		$state  = $s->status();
		$fp     = $s->fingerprint();
		$metric = ( new NetworkObservation( new WordPressOptions() ) )->status();
		echo '<div class="wrap amazing-security-admin"><header class="amsec-header"><div><h1>Manual network controls</h1><p>Approve explicit network rules without changing host infrastructure.</p></div></header><section class="amsec-overview"><h2>PHP requests only</h2><p>Off by default. Observe records an approximate redacted match count without denying traffic. Block denies matching IPv4/IPv6 CIDRs for selected methods on requests reaching WordPress PHP. Static assets, cached pages or CDN responses that bypass PHP are outside this scope. This is not a server firewall or automatic ban service.</p><p>CLI, cron and administrators already identified by WordPress at the check point are exempt. Authentication handled later in an API request may still be denied. By default use the host-provided PHP REMOTE_ADDR; optional approved trusted-proxy settings can resolve a reported client only with host-confirmed direct peer configuration. The host may already have rewritten the address. Verify proxy trust before enforcing. Shared networks can group legitimate visitors.</p><p>Approval refuses a block policy covering your current resolved address to reduce self-lockout. A later network change can still lock you out. Recovery: <code>wp amazing-security network disable</code>, or bypass with <code>AMSEC_DISABLE_FIREWALL</code>. Recovery clears this feature’s advisory count.</p><p>Configured CIDRs are stored as explicit policy. Visitor addresses, URLs, content and usernames are not collected by the match counter. Counts can miss concurrent or failed writes and cap at one million; they never decide enforcement.</p></section>';
		if ( ! empty( $state['invalid'] ) ) {
			echo '<div class="notice inline notice-error"><p>Network policy is invalid; enforcement is unavailable. Use host recovery to set an explicit off policy.</p></div></div>';
			return;}
		echo '<section class="amsec-file-scan"><h2>Current policy</h2><p>Mode: ' . esc_html( $state['mode'] ) . '.</p>';
		if ( ! empty( $metric['invalid'] ) ) {
			echo '<p>Observed match count is unavailable.</p>';
		} elseif ( $metric['revision'] === $state['revision'] ) {
			echo '<p>Approximate matches for this policy revision: ' . esc_html( (string) $metric['count'] ) . '.</p>';
		} else {
			echo '<p>No advisory count for this policy revision; earlier counts are historical.</p>';}
		echo '<p>Configured networks:</p><pre>' . esc_html( implode( "\n", $state['cidrs'] ) ) . '</pre>';
		if ( ! is_ssl() ) {
			echo '<p>Use HTTPS to approve changes.</p></section></div>';
			return;}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_network_settings"><input type="hidden" name="fingerprint" value="' . esc_attr( $fp ) . '"><p><label>Mode <select name="mode">';
		foreach ( array( 'off', 'observe', 'block' ) as $mode ) {
			echo '<option value="' . esc_attr( $mode ) . '"' . selected( $state['mode'], $mode, false ) . '>' . esc_html( ucfirst( $mode ) ) . '</option>';
		}echo '</select></label></p><p><label>Networks to deny (one IP or CIDR per line, up to 50)<br><textarea name="rules" rows="6" class="large-text code" maxlength="4096">' . esc_html( implode( "\n", $state['cidrs'] ) ) . '</textarea></label></p><fieldset><legend>Methods: choose all, or selected methods</legend>';
		foreach ( array_merge( array( '*' ), NetworkPolicy::METHODS ) as $method ) {
			echo '<label style="margin-right:1rem"><input type="checkbox" name="methods[]" value="' . esc_attr( $method ) . '"' . checked( in_array( $method, $state['methods'], true ), true, false ) . '> ' . esc_html( '*' === $method ? 'All methods' : $method ) . '</label>';
		}echo '</fieldset>';
		wp_nonce_field( 'amsec_network_' . $fp );
		echo '<p><label>Your password <input type="password" name="password" autocomplete="current-password" maxlength="1024" required></label></p><p><label><input type="checkbox" name="confirm" value="1" required> I have reviewed proxy trust, shared-network and API effects, tested observe mode, and know the host recovery command.</label></p>';
		submit_button( __( 'Approve current network policy', 'amazing-security' ), 'secondary' );
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
