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
		// Nonce is verified before any mutation.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$post    = wp_unslash( $_POST );
		$method  = is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		$auth    = wp_parse_auth_cookie( '', is_ssl() ? 'secure_auth' : 'auth' );
		$id      = is_scalar( $post['user_id'] ?? null ) ? absint( $post['user_id'] ) : 0;
		$viewer  = get_current_user_id();
		$allowed = Access::otherAccount( current_user_can( 'manage_options' ), $viewer, $id ) && current_user_can( 'edit_user', $id );
		if ( ! SessionPolicy::allowed( 'post' === $method, current_user_can( 'manage_options' ), $allowed, FixApprovalAction::cookieAuthenticated() && SessionPolicy::matchingTokens( is_array( $auth ) ? (string) $auth['token'] : '', wp_get_session_token() ), is_ssl(), '1' === ( $post['confirm'] ?? null ) ) ) {
			wp_die( esc_html__( 'A secure administrator session and explicit confirmation are required.', 'amazingplugins-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_incident_reset_' . $id );
		$password = is_string( $post['password'] ?? null ) && strlen( $post['password'] ) <= 1024 ? $post['password'] : '';
		$user     = wp_get_current_user();
		if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			wp_die( esc_html__( 'Password confirmation failed.', 'amazingplugins-security-scanner' ), '', array( 'response' => 403 ) );
		}
		if ( ! get_userdata( $id ) ) {
			wp_die( esc_html__( 'The selected account no longer exists.', 'amazingplugins-security-scanner' ), '', array( 'response' => 409 ) );
		}
		try {
			( new ResetRequirement() )->requireReset( $id );
			( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'password_reset_required', $id );
			( new SessionAction() )->revoke( $id, $user->ID, wp_get_session_token() );
		} catch ( \Throwable ) {
			wp_die( esc_html__( 'The action could not be verified. A reset requirement may already be stored. Review the account and sessions; use WP-CLI recovery if needed.', 'amazingplugins-security-scanner' ), '', array( 'response' => 409 ) );
		}
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'sessions_revoked', $id );
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-incident&user_id=' . $id . '&revoked=1' ) );
		exit;
	}
}
