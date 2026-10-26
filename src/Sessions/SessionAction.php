<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Sessions;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Activity\ActivityHooks;
use AmazingPlugins\Security\Activity\ActivityRepository;
use AmazingPlugins\Security\Admin\FixApprovalAction;

final class SessionAction {
	public function handle(): void {
		// Nonce is verified before any mutation.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$post   = wp_unslash( $_POST );
		$method = is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		$auth   = wp_parse_auth_cookie( '', is_ssl() ? 'secure_auth' : 'auth' );
		$id     = is_scalar( $post['user_id'] ?? null ) ? absint( $post['user_id'] ) : 0;
		if ( ! SessionPolicy::allowed( 'post' === $method, current_user_can( 'manage_options' ), $id > 0 && current_user_can( 'edit_user', $id ), FixApprovalAction::cookieAuthenticated() && SessionPolicy::matchingTokens( is_array( $auth ) ? (string) $auth['token'] : '', wp_get_session_token() ), is_ssl(), '1' === ( $post['confirm'] ?? null ) ) ) {
			wp_die( esc_html__( 'A secure administrator session and explicit confirmation are required.', 'amazing-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_sessions_revoke_' . $id );
		$password = is_string( $post['password'] ?? null ) && strlen( $post['password'] ) <= 1024 ? $post['password'] : '';
		$user     = wp_get_current_user();
		if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			wp_die( esc_html__( 'Password confirmation failed.', 'amazing-security-scanner' ), '', array( 'response' => 403 ) );
		}
		if ( ! get_userdata( $id ) ) {
			wp_die( esc_html__( 'The selected account no longer exists.', 'amazing-security-scanner' ), '', array( 'response' => 409 ) );
		}
		$operation = isset( $post['operation'] ) && is_string( $post['operation'] ) ? sanitize_key( $post['operation'] ) : '';
		if ( 'revoke-application-password' === $operation ) {
			$this->revokeApplicationPassword( $id, $post );
		}
		try {
			$this->revoke( $id, $user->ID, wp_get_session_token() );
		} catch ( \Throwable ) {
			wp_die( esc_html__( 'Session revocation could not be verified. Review the current sessions.', 'amazing-security-scanner' ), '', array( 'response' => 409 ) );
		}
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'sessions_revoked', $id );
		wp_safe_redirect( self::back( $id, 'revoked' ) );
		exit;
	}

	private function revokeApplicationPassword( int $id, array $post ): void {
		$uuid   = isset( $post['uuid'] ) && is_string( $post['uuid'] ) ? strtolower( $post['uuid'] ) : '';
		$stored = class_exists( \WP_Application_Passwords::class ) ? \WP_Application_Passwords::get_user_application_passwords( $id ) : array();
		$match  = ApplicationPasswordList::selected( ApplicationPasswordList::rows( is_array( $stored ) ? $stored : array() ), $uuid );
		if ( '' === $match || ! \WP_Application_Passwords::delete_application_password( $id, $match ) ) {
			wp_die( esc_html__( 'That application password was not revoked.', 'amazing-security-scanner' ), '', array( 'response' => 409 ) );
		}
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', $id, 'application-password' );
		wp_safe_redirect( self::back( $id, 'app-revoked' ) );
		exit;
	}

	public function revoke( int $target, int $actor, string $token ): void {
		if ( $actor <= 0 || $target <= 0 || ! \WP_Session_Tokens::get_instance( $actor )->verify( $token ) ) {
			throw new \RuntimeException( 'Approving session unavailable.' );
		}
		$manager = \WP_Session_Tokens::get_instance( $target );
		if ( $target === $actor ) {
			$manager->destroy_others( $token );
			if ( ! $manager->verify( $token ) || count( $manager->get_all() ) !== 1 ) {
				throw new \RuntimeException( 'Session revocation could not be verified.' );
			}
		} else {
			$manager->destroy_all();
			if ( array() !== $manager->get_all() ) {
				throw new \RuntimeException( 'Session revocation could not be verified.' );
			}
		}
	}

	/** Administrators land on the Sessions tab; other users keep their own sessions page. */
	private static function back( int $id, string $flag ): string {
		$page = current_user_can( 'manage_options' ) ? 'amsec-accounts' : 'amsec-sessions';
		return admin_url( 'admin.php?page=' . $page . '&user_id=' . $id . '&' . $flag . '=1#sessions' );
	}
}
