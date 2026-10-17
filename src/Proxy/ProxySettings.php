<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Proxy;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Admin\FixApprovalAction;
use AmazingPlugins\Security\Sessions\SessionPolicy;
use AmazingPlugins\Security\Activity\{ActivityHooks, ActivityRepository};
final class ProxySettings {
	private function service(): ProxySettingsService {
		return new ProxySettingsService( new FreshSecurityOptions( $GLOBALS['wpdb'], new WordPressOptions() ) ); }
	public function register(): void {
		$hook = add_submenu_page( 'amazing-security', __( 'Trusted proxy addresses', 'amazing-security' ), __( 'Trusted proxies', 'amazing-security' ), 'manage_options', 'amsec-proxies', array( $this, 'render' ) );
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
		wp_safe_redirect( \AmazingPlugins\Security\Admin\Brand::saved( admin_url( 'admin.php?page=amsec-traffic-guard#proxies' ) ) );
		exit;
	}
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) ); }
		echo '<div class="wrap amazing-security-admin"><header class="amsec-header"><div><h1>' . esc_html__( 'Trusted proxy addresses', 'amazing-security' ) . '</h1><p>' . esc_html__( 'Explicit address interpretation for verified host configurations.', 'amazing-security' ) . '</p></div></header><section class="amsec-overview"><h2>' . esc_html__( 'Start with a host-confirmed direct peer', 'amazing-security' ) . '</h2><p>' .
			/* translators: %1$s is an inline code snippet (a WP-CLI command or a constant name); keep it unchanged. */
			sprintf( esc_html__( 'Off by default. Login, native bot and REST counters and manual network controls normally use the host-provided PHP address. Optional header modes require the host to set %1$s to the boolean true after verifying that REMOTE_ADDR is the unmodified connection peer. This plugin cannot reverse Apache/CDN address rewriting or prove host configuration.', 'amazing-security' ), '<code>AMSEC_DIRECT_PEER_CONFIRMED</code>' ) . '</p><p>' . esc_html__( 'Configure only the actual trusted upstream CIDRs. Origin access and header overwrite/append rules must be secured by the host. Trusted upstreams control the address they report; a header name alone does not identify a provider. No provider ranges are downloaded or inferred. Global /0 trust is refused. IPv4 and IPv6 are supported, including mapped-address normalization.', 'amazing-security' ) . '</p><p>' . esc_html__( 'X-Forwarded-For walks a validated chain from right to left and stops at the first untrusted address. CF-Connecting-IP accepts one validated address from a configured trusted peer. Other headers are ignored. Untrusted direct peers cannot supply either header. Missing, oversized, malformed or all-trusted chains resolve unknown; address-dependent checks then skip enforcement. Hidden-field checks remain independent. No raw visitor headers or addresses are logged.', 'amazing-security' ) . '</p><p>' . sprintf( esc_html__( 'Changing this policy starts a new rate-counter namespace. Approval refuses a resolved operator covered by an existing network block. Shared proxies and later network changes can still affect access; test observe mode and recovery first. Recovery: %1$s, or %2$s. These restore host-provided semantics, which can group visitors at a proxy.', 'amazing-security' ), '<code>wp amazing-security proxies disable</code>', '<code>AMSEC_DISABLE_PROXY_HEADERS</code>' ) . '</p></section>';
		try {
			$service = $this->service();
			$state   = $service->status();
			$fp      = $service->fingerprint(); } catch ( \Throwable ) {
					echo '<section class="amsec-file-scan"><p>' . esc_html__( 'Proxy policy storage is unavailable. No verified configuration can be shown.', 'amazing-security' ) . '</p></section></div>';
					return; }
			if ( ! empty( $state['invalid'] ) ) {
				echo '<section class="amsec-file-scan"><p>' . esc_html__( 'Proxy policy is invalid; address resolution is unknown. Use host recovery to set an explicit off policy.', 'amazing-security' ) . '</p></section></div>';
				return; }
			$confirmed = WordPressClientAddress::peerConfirmed();
			echo '<section class="amsec-file-scan"><h2>' . esc_html__( 'Current trust policy', 'amazing-security' ) . '</h2><p>' .
				/* translators: %s: current mode slug, for example off, observe or block. */
				sprintf( esc_html__( 'Mode: %s.', 'amazing-security' ), esc_html( $state['mode'] ) ) . '</p><p>' . sprintf( esc_html__( 'Host attestation: %s.', 'amazing-security' ), esc_html( $confirmed ? __( 'present; operator must verify its correctness', 'amazing-security' ) : __( 'absent; header modes cannot be enabled', 'amazing-security' ) ) ) . '</p><p>' . esc_html__( 'Configured trusted networks:', 'amazing-security' ) . '</p><pre>' . esc_html( implode( "\n", $state['cidrs'] ) ) . '</pre>';
			if ( ! is_ssl() ) {
				echo '<p>' . esc_html__( 'Use HTTPS to approve changes.', 'amazing-security' ) . '</p></section></div>';
				return; }
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_proxy_settings"><input type="hidden" name="fingerprint" value="' . esc_attr( $fp ) . '"><p><label>' . esc_html__( 'Header interpretation', 'amazing-security' ) . ' <select name="mode">';
			foreach ( array(
				'off'    => __( 'Off: host-provided address', 'amazing-security' ),
				'xff'    => __( 'X-Forwarded-For: trusted chain', 'amazing-security' ),
				'single' => __( 'CF-Connecting-IP: one trusted sender', 'amazing-security' ),
			) as $mode => $label ) {
				echo '<option value="' . esc_attr( $mode ) . '"' . selected( $state['mode'], $mode, false ) . '>' . esc_html( $label ) . '</option>'; }
			echo '</select></label></p><p><label>' . esc_html__( 'Trusted proxy networks (one IP/CIDR per line, up to 50)', 'amazing-security' ) . '<br><textarea name="rules" rows="6" class="large-text code" maxlength="4096">' . esc_html( implode( "\n", $state['cidrs'] ) ) . '</textarea></label></p>';
			wp_nonce_field( 'amsec_proxy_' . $fp );
			echo '<p><label>' . esc_html__( 'Your password', 'amazing-security' ) . ' <input type="password" name="password" autocomplete="current-password" maxlength="1024" required></label></p><p><label><input type="checkbox" name="confirm" value="1" required> ' . esc_html__( 'The host verified socket-peer origin, upstream ranges and header behavior. I reviewed shared-network and self-lockout effects and know the recovery command.', 'amazing-security' ) . '</label></p>';
			submit_button( __( 'Approve current proxy policy', 'amazing-security' ), 'secondary' );
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
