<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Digest;

use AmazingPlugins\Security\Admin\FixApprovalAction;
use AmazingPlugins\Security\Sessions\SessionPolicy;

final class DigestSettings {
	public function register(): void {
		add_submenu_page( 'amazing-security', __( 'Weekly security digest', 'amazing-security' ), __( 'Weekly digest', 'amazing-security' ), 'manage_options', 'amsec-digest', array( $this, 'render' ) );
	}

	public function handle(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified before changing settings.
		$post   = wp_unslash( $_POST );
		$method = is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		$auth   = wp_parse_auth_cookie( '', is_ssl() ? 'secure_auth' : 'auth' );
		$mode   = is_string( $post['mode'] ?? null ) ? $post['mode'] : '';
		if ( ! SessionPolicy::allowed( 'post' === $method, current_user_can( 'manage_options' ), in_array( $mode, array( 'off', 'on' ), true ), FixApprovalAction::cookieAuthenticated() && SessionPolicy::matchingTokens( is_array( $auth ) ? (string) $auth['token'] : '', wp_get_session_token() ), is_ssl(), '1' === ( $post['confirm'] ?? null ) ) ) {
			wp_die( esc_html__( 'Secure administrator approval and acknowledgement are required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_digest_settings' );
		$password = is_string( $post['password'] ?? null ) && strlen( $post['password'] ) <= 1024 ? $post['password'] : '';
		$user     = wp_get_current_user();
		if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			wp_die( esc_html__( 'Password confirmation failed.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		update_option( 'amsec_digest_enabled', 'on' === $mode ? '1' : '0', false );
		if ( get_option( 'amsec_digest_enabled', '0' ) !== ( 'on' === $mode ? '1' : '0' ) ) {
			wp_die( esc_html__( 'The setting change could not be verified.', 'amazing-security' ), '', array( 'response' => 409 ) );
		}
		( new DigestHooks() )->ensure();
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-digest' ) );
		exit;
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		$mode    = '1' === get_option( 'amsec_digest_enabled' ) ? 'on' : 'off';
		$status  = ( new DigestHooks() )->delivery()->status();
		$last    = $status['last_attempt'] ?? array();
		$pending = $status['pending'] ?? null;
		$state   = ! empty( $status['invalid'] ) ? 'invalid: no mail will be sent' : ( 'sending' === ( $pending['status'] ?? '' ) ? 'uncertain: previous in-flight attempt will not be resent' : ( ( $pending['attempts'] ?? 0 ) >= 3 ? 'exhausted: three failed attempts' : ( $last['status'] ?? 'none' ) ) );
		echo '<div class="wrap amazing-security-admin"><h1>Weekly security digest</h1><p>Off by default. Sends a summary through this site’s WordPress mail transport to the current administrator email. The first interval is due seven days after enabling; an hourly WP-Cron check sends it when the site receives traffic. A quiet site can delay delivery.</p><p>The digest reports counts from stored hardening, integrity, file and vulnerability scans and recorded account/role changes and blocked login requests. It does not start scans. Missing, stale, partial and unknown coverage is stated explicitly. Initial findings are an initial snapshot; later new counts compare with the last accepted digest. Incomplete scans retain earlier identities. No finding details, account identities, addresses, file paths, credentials or review notes are included.</p><p>Failed calls retry after one hour, up to three attempts. An interrupted or unrecorded result is uncertain and is not automatically resent. Accepted means WordPress’s mail transport accepted the message; it does not confirm inbox delivery. The next weekly interval supersedes an older failed queue.</p><p>Mode: ' . esc_html( $mode ) . '. Last mail state: ' . esc_html( $state ) . '.</p>';
		echo '<p><a href="' . esc_url( admin_url( 'admin.php?page=amsec-settings#amsec-notifications' ) ) . '">' . esc_html__( 'Notification settings (finding emails, test email, account-change email)', 'amazing-security' ) . '</a></p>';
		if ( is_int( $status['next_due'] ?? null ) ) {
			echo '<p>Next interval due UTC: ' . esc_html( gmdate( 'Y-m-d H:i:s', $status['next_due'] ) ) . '.</p>';
		}
		if ( ! is_ssl() ) {
			echo '<p>Use HTTPS to approve a setting change.</p>';
			echo '</div>';
			return;
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_digest_settings"><label>Mode <select name="mode">';
		foreach ( array( 'off', 'on' ) as $value ) {
			echo '<option value="' . esc_attr( $value ) . '"' . selected( $mode, $value, false ) . '>' . esc_html( ucfirst( $value ) ) . '</option>';
		}
		echo '</select></label>';
		wp_nonce_field( 'amsec_digest_settings' );
		echo '<p><label>Your password <input type="password" name="password" autocomplete="current-password" required maxlength="1024"></label></p><p><label><input type="checkbox" name="confirm" value="1" required> I understand that this summary is emailed to the current WordPress administrator email and does not establish a clean-site verdict.</label></p>';
		submit_button( __( 'Approve digest setting', 'amazing-security' ), 'secondary' );
		echo '</form></div>';
	}
}
