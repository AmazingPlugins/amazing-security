<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Proxy;

use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Admin\FixApprovalAction;
use AmazingPlugins\Security\Sessions\SessionPolicy;
use AmazingPlugins\Security\Activity\{ActivityHooks, ActivityRepository};
final class ProxySettings {
	private function service(): ProxySettingsService {
		return new ProxySettingsService( new FreshSecurityOptions( $GLOBALS['wpdb'], new WordPressOptions() ) ); }
	public function register(): void {
		$hook = add_submenu_page( 'amazing-security', 'Trusted proxy addresses', 'Trusted proxies', 'manage_options', 'amsec-proxies', array( $this, 'render' ) );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $current ) use ( $hook ): void {
				if ( $current === $hook ) {
					wp_enqueue_style( 'amazing-security-admin', plugins_url( 'assets/admin.css', AMAZING_SECURITY_FILE ), array(), '0.1.0' );
				} }
		);
	}
	public function handle(): void {
	 // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Exact policy nonce and matched session checked before mutation.
		$post    = wp_unslash( $_POST );
		$method  = is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		$auth    = wp_parse_auth_cookie( '', is_ssl() ? 'secure_auth' : 'auth' );
		$mode    = is_string( $post['mode'] ?? null ) ? $post['mode'] : '';
		$rules   = is_string( $post['rules'] ?? null ) ? $post['rules'] : null;
		$service = $this->service();
		$state   = $service->status();
		$fp      = $service->fingerprint();
		if ( ! SessionPolicy::allowed( 'post' === $method, current_user_can( 'manage_options' ), empty( $state['invalid'] ) && in_array( $mode, array( 'off', 'xff', 'single' ), true ) && null !== $rules && strlen( $rules ) <= 4096 && is_string( $post['fingerprint'] ?? null ) && $post['fingerprint'] === $fp, FixApprovalAction::cookieAuthenticated() && SessionPolicy::matchingTokens( is_array( $auth ) ? (string) $auth['token'] : '', wp_get_session_token() ), is_ssl(), '1' === ( $post['confirm'] ?? null ) ) ) {
			wp_die( esc_html__( 'Secure administrator approval of the current proxy policy is required.', 'amazing-security' ), '', array( 'response' => 403 ) ); }
		check_admin_referer( 'amsec_proxy_' . $fp );
		$password = is_string( $post['password'] ?? null ) && strlen( $post['password'] ) <= 1024 ? $post['password'] : '';
		$user     = wp_get_current_user();
		if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			wp_die( esc_html__( 'Password confirmation failed.', 'amazing-security' ), '', array( 'response' => 403 ) ); }
		$lines  = preg_split( '/\r?\n/', $rules );
		$lines  = is_array( $lines ) ? array_values( array_filter( array_map( 'trim', $lines ), static fn( string $line ): bool=>'' !== $line ) ) : array();
		$result = ( new SecurityApprovalLock( $GLOBALS['wpdb'] ) )->run( fn(): string=>$service->apply( $fp, $mode, $lines, $_SERVER, WordPressClientAddress::peerConfirmed() ) );
		if ( 'saved' !== $result ) {
			wp_die( esc_html__( 'Proxy policy changed, approval is busy, host peer is unverified, rules are invalid or the operator cannot be resolved safely. Review host trust and network self-lockout before approving.', 'amazing-security' ), '', array( 'response' => 409 ) ); }
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', 0, 'proxy-' . $mode );
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-proxies' ) );
		exit;
	}
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) ); }
		echo '<div class="wrap amazing-security-admin"><header class="amsec-header"><div><h1>Trusted proxy addresses</h1><p>Explicit address interpretation for verified host configurations.</p></div></header><section class="amsec-overview"><h2>Start with a host-confirmed direct peer</h2><p>Off by default. Login, native bot and REST counters and manual network controls normally use the host-provided PHP address. Optional header modes require the host to set <code>AMSEC_DIRECT_PEER_CONFIRMED</code> to the boolean true after verifying that REMOTE_ADDR is the unmodified connection peer. This plugin cannot reverse Apache/CDN address rewriting or prove host configuration.</p><p>Configure only the actual trusted upstream CIDRs. Origin access and header overwrite/append rules must be secured by the host. Trusted upstreams control the address they report; a header name alone does not identify a provider. No provider ranges are downloaded or inferred. Global /0 trust is refused. IPv4 and IPv6 are supported, including mapped-address normalization.</p><p>X-Forwarded-For walks a validated chain from right to left and stops at the first untrusted address. CF-Connecting-IP accepts one validated address from a configured trusted peer. Other headers are ignored. Untrusted direct peers cannot supply either header. Missing, oversized, malformed or all-trusted chains resolve unknown; address-dependent checks then skip enforcement. Hidden-field checks remain independent. No raw visitor headers or addresses are logged.</p><p>Changing this policy starts a new rate-counter namespace. Approval refuses a resolved operator covered by an existing network block. Shared proxies and later network changes can still affect access; test observe mode and recovery first. Recovery: <code>wp amazing-security proxies disable</code>, or <code>AMSEC_DISABLE_PROXY_HEADERS</code>. These restore host-provided semantics, which can group visitors at a proxy.</p></section>';
		try {
			$service = $this->service();
			$state   = $service->status();
			$fp      = $service->fingerprint(); } catch ( \Throwable ) {
					echo '<section class="amsec-file-scan"><p>Proxy policy storage is unavailable. No verified configuration can be shown.</p></section></div>';
					return; }
			if ( ! empty( $state['invalid'] ) ) {
				echo '<section class="amsec-file-scan"><p>Proxy policy is invalid; address resolution is unknown. Use host recovery to set an explicit off policy.</p></section></div>';
				return; }
			$confirmed = WordPressClientAddress::peerConfirmed();
			echo '<section class="amsec-file-scan"><h2>Current trust policy</h2><p>Mode: ' . esc_html( $state['mode'] ) . '.</p><p>Host attestation: ' . esc_html( $confirmed ? 'present; operator must verify its correctness' : 'absent; header modes cannot be enabled' ) . '.</p><p>Configured trusted networks:</p><pre>' . esc_html( implode( "\n", $state['cidrs'] ) ) . '</pre>';
			if ( ! is_ssl() ) {
				echo '<p>Use HTTPS to approve changes.</p></section></div>';
				return; }
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_proxy_settings"><input type="hidden" name="fingerprint" value="' . esc_attr( $fp ) . '"><p><label>Header interpretation <select name="mode">';
			foreach ( array(
				'off'    => 'Off: host-provided address',
				'xff'    => 'X-Forwarded-For: trusted chain',
				'single' => 'CF-Connecting-IP: one trusted sender',
			) as $mode => $label ) {
				echo '<option value="' . esc_attr( $mode ) . '"' . selected( $state['mode'], $mode, false ) . '>' . esc_html( $label ) . '</option>'; }
			echo '</select></label></p><p><label>Trusted proxy networks (one IP/CIDR per line, up to 50)<br><textarea name="rules" rows="6" class="large-text code" maxlength="4096">' . esc_html( implode( "\n", $state['cidrs'] ) ) . '</textarea></label></p>';
			wp_nonce_field( 'amsec_proxy_' . $fp );
			echo '<p><label>Your password <input type="password" name="password" autocomplete="current-password" maxlength="1024" required></label></p><p><label><input type="checkbox" name="confirm" value="1" required> The host verified socket-peer origin, upstream ranges and header behavior. I reviewed shared-network and self-lockout effects and know the recovery command.</label></p>';
			submit_button( 'Approve current proxy policy', 'secondary' );
			echo '</form></section></div>';
	}
	public function recovery( array $args, array $assoc ): void {
		if ( array() !== $args || array() !== $assoc ) {
			\WP_CLI::error( 'This command accepts no arguments.' ); }
		if ( ! $this->service()->disable() ) {
			\WP_CLI::error( 'Proxy header interpretation could not be disabled.' ); }
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', 0, 'proxy-off' );
		\WP_CLI::success( 'Proxy headers are off. Host-provided address behavior remains subject to host configuration.' );
	}
}
