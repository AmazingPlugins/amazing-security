<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

use AmazingPlugins\Security\Admin\FixApprovalAction;
use AmazingPlugins\Security\Sessions\SessionPolicy;
use AmazingPlugins\Security\Activity\ActivityHooks;
use AmazingPlugins\Security\Activity\ActivityRepository;

final class RequiredTotpAction {
	public function handle(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified before writes or factor consumption.
		$post   = wp_unslash( $_POST );
		$method = is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		$auth   = wp_parse_auth_cookie( '', is_ssl() ? 'secure_auth' : 'auth' );
		$id     = is_scalar( $post['user_id'] ?? null ) ? absint( $post['user_id'] ) : 0;
		$mode   = is_string( $post['mode'] ?? null ) ? $post['mode'] : '';
		if ( ! SessionPolicy::allowed( 'post' === $method, current_user_can( 'manage_options' ), $id > 0 && current_user_can( 'edit_user', $id ), FixApprovalAction::cookieAuthenticated() && SessionPolicy::matchingTokens( is_array( $auth ) ? (string) $auth['token'] : '', wp_get_session_token() ), is_ssl(), '1' === ( $post['confirm'] ?? null ) ) || ! in_array( $mode, array( 'enable', 'disable', 'grace' ), true ) ) {
			$this->refuse();
		}
		check_admin_referer( 'amsec_totp_policy_' . $mode . '_' . $id );
		$user     = wp_get_current_user();
		$password = is_string( $post['password'] ?? null ) && strlen( $post['password'] ) <= 1024 ? $post['password'] : '';
		$factor   = is_string( $post['factor'] ?? null ) && strlen( $post['factor'] ) <= 64 ? sanitize_text_field( $post['factor'] ) : '';
		if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) || ! get_userdata( $id ) || ( 'grace' === $mode ? $id === $user->ID || ! user_can( $id, 'manage_options' ) : $id !== $user->ID ) ) {
			$this->refuse();
		}
		try {
			$policy = new RequiredTotpPolicy();
			if ( 'enable' === $mode && null !== $policy->generation() ) {
				$this->refuse();
			}
			$store      = new WordPressTotpStore( $GLOBALS['wpdb'] );
			$enrollment = new TotpEnrollment( $store, new WordPressPendingEnrollmentStore(), new SecretCipher( wp_salt( 'auth' ) ), new Totp(), new RecoveryCodes() );
			if ( ! $store->isEnrolled( $user->ID ) || ! $enrollment->verifyFactor( $user->ID, $factor ) ) {
				$this->refuse();
			}
			if ( 'grace' === $mode ) {
				$policy->grantGrace( $id );
			} else {
				$policy->setEnabled( 'enable' === $mode );
			}
		} catch ( \Throwable ) {
			wp_die( esc_html__( 'The policy change could not be verified. Review its current state before retrying.', 'amazing-security' ), '', array( 'response' => 409 ) );
		}
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'grace' === $mode ? 'totp_grace_granted' : 'totp_policy_changed', $id, $mode );
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-required-totp' ) );
		exit;
	}

	private function refuse(): void {
		wp_die( esc_html__( 'An enrolled administrator must approve this action with a secure session, password and current verification factor.', 'amazing-security' ), '', array( 'response' => 403 ) );
	}
}
