<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Incident;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Access;
use AmazingPlugins\Security\Sessions\SessionPolicy;
use AmazingPlugins\Security\Sessions\SessionAction;

use AmazingPlugins\Security\Activity\ActivityHooks;
use AmazingPlugins\Security\Activity\ActivityRepository;
use AmazingPlugins\Security\Admin\FixApprovalAction;

final class IncidentAction {
	public function handle(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Read only to name the nonce action; verified below.
		$id = isset( $_POST['user_id'] ) && is_scalar( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : 0;
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'A secure administrator session and explicit confirmation are required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'ironlatch_incident_reset_' . $id );
		$method    = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		$confirmed = isset( $_POST['confirm'] ) && is_string( $_POST['confirm'] ) ? sanitize_text_field( wp_unslash( $_POST['confirm'] ) ) : '';
		$auth      = wp_parse_auth_cookie( '', is_ssl() ? 'secure_auth' : 'auth' );
		$viewer    = get_current_user_id();
		$allowed   = Access::otherAccount( current_user_can( 'manage_options' ), $viewer, $id ) && current_user_can( 'edit_user', $id );
		if ( ! SessionPolicy::allowed( 'post' === $method, current_user_can( 'manage_options' ), $allowed, FixApprovalAction::cookieAuthenticated() && SessionPolicy::matchingTokens( is_array( $auth ) ? (string) $auth['token'] : '', wp_get_session_token() ), is_ssl(), '1' === $confirmed ) ) {
			wp_die( esc_html__( 'A secure administrator session and explicit confirmation are required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		// Passwords are compared as typed; sanitizing would change them.
		$password = isset( $_POST['password'] ) && is_string( $_POST['password'] ) ? wp_unslash( $_POST['password'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Compared as typed; sanitizing would change the password.
		$password = strlen( $password ) <= 1024 ? $password : '';
		$user     = wp_get_current_user();
		if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			wp_die( esc_html__( 'Password confirmation failed.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		if ( ! get_userdata( $id ) ) {
			wp_die( esc_html__( 'The selected account no longer exists.', 'ironlatch-security-scanner' ), '', array( 'response' => 409 ) );
		}
		try {
			( new ResetRequirement() )->requireReset( $id );
			( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'password_reset_required', $id );
			( new SessionAction() )->revoke( $id, $user->ID, wp_get_session_token() );
		} catch ( \Throwable ) {
			wp_die( esc_html__( 'The action could not be verified. A reset requirement may already be stored. Review the account and sessions; use WP-CLI recovery if needed.', 'ironlatch-security-scanner' ), '', array( 'response' => 409 ) );
		}
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'sessions_revoked', $id );
		wp_safe_redirect( admin_url( 'admin.php?page=ironlatch-incident&user_id=' . $id . '&revoked=1' ) );
		exit;
	}
}
