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
		$hook = add_submenu_page( 'ironlatch-security-scanner', __( 'Trusted proxy addresses', 'ironlatch-security-scanner' ), __( 'Trusted proxies', 'ironlatch-security-scanner' ), 'manage_options', 'ironlatch-proxies', array( $this, 'render' ) );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $current ) use ( $hook ): void {
				if ( $current === $hook ) {
					wp_enqueue_style( 'ironlatch-security-scanner-admin', plugins_url( 'assets/admin.css', IRONLATCH_SECURITY_SCANNER_FILE ), array(), '0.1.0' );
				} }
		);
	}
	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Secure administrator approval of the current proxy policy is required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) ); }
		$service = $this->service();
		$fp      = $service->fingerprint();
		check_admin_referer( 'ironlatch_proxy_' . $fp );
		$state     = $service->status();
		$method    = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		$auth      = wp_parse_auth_cookie( '', is_ssl() ? 'secure_auth' : 'auth' );
		$mode      = isset( $_POST['mode'] ) && is_string( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : '';
		$rules     = isset( $_POST['rules'] ) && is_string( $_POST['rules'] ) ? sanitize_textarea_field( wp_unslash( $_POST['rules'] ) ) : null;
		$posted_fp = isset( $_POST['fingerprint'] ) && is_string( $_POST['fingerprint'] ) ? sanitize_key( wp_unslash( $_POST['fingerprint'] ) ) : '';
		$confirmed = isset( $_POST['confirm'] ) && is_string( $_POST['confirm'] ) ? sanitize_text_field( wp_unslash( $_POST['confirm'] ) ) : '';
		if ( ! SessionPolicy::allowed( 'post' === $method, current_user_can( 'manage_options' ), empty( $state['invalid'] ) && in_array( $mode, array( 'off', 'xff', 'single' ), true ) && null !== $rules && strlen( $rules ) <= 4096 && $posted_fp === $fp, FixApprovalAction::cookieAuthenticated() && SessionPolicy::matchingTokens( is_array( $auth ) ? (string) $auth['token'] : '', wp_get_session_token() ), is_ssl(), '1' === $confirmed ) ) {
			wp_die( esc_html__( 'Secure administrator approval of the current proxy policy is required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) ); }
		// Passwords are compared as typed; sanitizing would change them.
		$password = isset( $_POST['password'] ) && is_string( $_POST['password'] ) ? wp_unslash( $_POST['password'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Compared as typed; sanitizing would change the password.
		$password = strlen( $password ) <= 1024 ? $password : '';
		$user     = wp_get_current_user();
		if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			wp_die( esc_html__( 'Password confirmation failed.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) ); }
		$lines  = preg_split( '/\r?\n/', $rules );
		$lines  = is_array( $lines ) ? array_values( array_filter( array_map( 'trim', $lines ), static fn( string $line ): bool=>'' !== $line ) ) : array();
		$result = ( new SecurityApprovalLock( $GLOBALS['wpdb'] ) )->run( fn(): string=>$service->apply( $fp, $mode, $lines, WordPressClientAddress::request(), WordPressClientAddress::peerConfirmed() ) );
		if ( 'saved' !== $result ) {
			wp_die( esc_html__( 'Proxy policy changed, approval is busy, host peer is unverified, rules are invalid or the operator cannot be resolved safely. Review host trust and network self-lockout before approving.', 'ironlatch-security-scanner' ), '', array( 'response' => 409 ) ); }
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', 0, 'proxy-' . $mode );
		wp_safe_redirect( \AmazingPlugins\Security\Admin\Brand::saved( admin_url( 'admin.php?page=ironlatch-traffic-guard#proxies' ) ) );
		exit;
	}
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) ); }
		echo '<div class="wrap ironlatch-security-scanner-admin"><header class="ironlatch-header"><div><h1>' . esc_html__( 'Trusted proxy addresses', 'ironlatch-security-scanner' ) . '</h1><p>' . esc_html__( 'Explicit address interpretation for verified host configurations.', 'ironlatch-security-scanner' ) . '</p></div></header><section class="ironlatch-overview"><h2>' . esc_html__( 'Start with a host-confirmed direct peer', 'ironlatch-security-scanner' ) . '</h2><p>' .
			/* translators: %1$s is an inline code snippet (a WP-CLI command or a constant name); keep it unchanged. */
			sprintf( esc_html__( 'Off by default. Login, native bot and REST counters and manual network controls normally use the host-provided PHP address. Optional header modes require the host to set %1$s to the boolean true after verifying that REMOTE_ADDR is the unmodified connection peer. This plugin cannot reverse Apache/CDN address rewriting or prove host configuration.', 'ironlatch-security-scanner' ), '<code>IRONLATCH_DIRECT_PEER_CONFIRMED</code>' ) . '</p><details class="ironlatch-more"><summary>' . esc_html__( 'How it works', 'ironlatch-security-scanner' ) . '</summary><p>' . esc_html__( 'Configure only the actual trusted upstream CIDRs. Origin access and header overwrite/append rules must be secured by the host. Trusted upstreams control the address they report; a header name alone does not identify a provider. No provider ranges are downloaded or inferred. Global /0 trust is refused. IPv4 and IPv6 are supported, including mapped-address normalization.', 'ironlatch-security-scanner' ) . '</p><p>' . esc_html__( 'X-Forwarded-For walks a validated chain from right to left and stops at the first untrusted address. CF-Connecting-IP accepts one validated address from a configured trusted peer. Other headers are ignored. Untrusted direct peers cannot supply either header. Missing, oversized, malformed or all-trusted chains resolve unknown; address-dependent checks then skip enforcement. Hidden-field checks remain independent. No raw visitor headers or addresses are logged.', 'ironlatch-security-scanner' ) . '</p><p>' . sprintf( esc_html__( 'Changing this policy starts a new rate-counter namespace. Approval refuses a resolved operator covered by an existing network block. Shared proxies and later network changes can still affect access; test observe mode and recovery first. Recovery: %1$s, or %2$s. These restore host-provided semantics, which can group visitors at a proxy.', 'ironlatch-security-scanner' ), '<code>wp ironlatch-security-scanner proxies disable</code>', '<code>IRONLATCH_DISABLE_PROXY_HEADERS</code>' ) . '</p></details></section>';
		try {
			$service = $this->service();
			$state   = $service->status();
			$fp      = $service->fingerprint(); } catch ( \Throwable ) {
					echo '<section class="ironlatch-file-scan"><p>' . esc_html__( 'Proxy policy storage is unavailable. No verified configuration can be shown.', 'ironlatch-security-scanner' ) . '</p></section></div>';
					return; }
			if ( ! empty( $state['invalid'] ) ) {
				echo '<section class="ironlatch-file-scan"><p>' . esc_html__( 'Proxy policy is invalid; address resolution is unknown. Use host recovery to set an explicit off policy.', 'ironlatch-security-scanner' ) . '</p></section></div>';
				return; }
			$confirmed = WordPressClientAddress::peerConfirmed();
			echo '<section class="ironlatch-file-scan"><h2>' . esc_html__( 'Current trust policy', 'ironlatch-security-scanner' ) . '</h2><p>' .
				/* translators: %s: current mode slug, for example off, observe or block. */
				sprintf( esc_html__( 'Mode: %s.', 'ironlatch-security-scanner' ), esc_html( $state['mode'] ) ) . '</p><p>' . sprintf( esc_html__( 'Host attestation: %s.', 'ironlatch-security-scanner' ), esc_html( $confirmed ? __( 'present; operator must verify its correctness', 'ironlatch-security-scanner' ) : __( 'absent; header modes cannot be enabled', 'ironlatch-security-scanner' ) ) ) . '</p><p>' . esc_html__( 'Configured trusted networks:', 'ironlatch-security-scanner' ) . '</p><pre>' . esc_html( implode( "\n", $state['cidrs'] ) ) . '</pre>';
			if ( ! is_ssl() ) {
				echo '<p>' . esc_html__( 'Use HTTPS to approve changes.', 'ironlatch-security-scanner' ) . '</p></section></div>';
				return; }
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="ironlatch_proxy_settings"><input type="hidden" name="fingerprint" value="' . esc_attr( $fp ) . '"><p><label>' . esc_html__( 'Header interpretation', 'ironlatch-security-scanner' ) . ' <select name="mode">';
			foreach ( array(
				'off'    => __( 'Off: host-provided address', 'ironlatch-security-scanner' ),
				'xff'    => __( 'X-Forwarded-For: trusted chain', 'ironlatch-security-scanner' ),
				'single' => __( 'CF-Connecting-IP: one trusted sender', 'ironlatch-security-scanner' ),
			) as $mode => $label ) {
				echo '<option value="' . esc_attr( $mode ) . '"' . selected( $state['mode'], $mode, false ) . '>' . esc_html( $label ) . '</option>'; }
			echo '</select></label></p><p><label>' . esc_html__( 'Trusted proxy networks (one IP/CIDR per line, up to 50)', 'ironlatch-security-scanner' ) . '<br><textarea name="rules" rows="6" class="large-text code" maxlength="4096">' . esc_html( implode( "\n", $state['cidrs'] ) ) . '</textarea></label></p>';
			wp_nonce_field( 'ironlatch_proxy_' . $fp );
			echo '<p><label>' . esc_html__( 'Your password', 'ironlatch-security-scanner' ) . ' <input type="password" name="password" autocomplete="current-password" maxlength="1024" required></label></p><p><label><input type="checkbox" name="confirm" value="1" required> ' . esc_html__( 'The host verified socket-peer origin, upstream ranges and header behavior. I reviewed shared-network and self-lockout effects and know the recovery command.', 'ironlatch-security-scanner' ) . '</label></p>';
			submit_button( __( 'Approve current proxy policy', 'ironlatch-security-scanner' ), 'secondary' );
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
