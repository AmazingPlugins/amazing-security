<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Baseline;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Activity\ActivityHooks;
use AmazingPlugins\Security\Activity\ActivityRepository;
use AmazingPlugins\Security\Admin\FixApprovalAction;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Sessions\SessionPolicy;

final class BaselineAction {
	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'A secure administrator session and exact baseline request are required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Read only to name the nonce action; verified right after.
		$mode  = isset( $_POST['mode'] ) && is_string( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : '';
		$token = isset( $_POST['token'] ) && is_string( $_POST['token'] ) ? sanitize_key( wp_unslash( $_POST['token'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		check_admin_referer( 'preview' === $mode ? 'ironlatch_baseline_preview' : 'ironlatch_baseline_approve_' . $token );
		$method    = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		$auth      = wp_parse_auth_cookie( '', is_ssl() ? 'secure_auth' : 'auth' );
		$target    = isset( $_POST['target'] ) && is_string( $_POST['target'] ) ? sanitize_text_field( wp_unslash( $_POST['target'] ) ) : '';
		$key       = strlen( $target ) <= 256 ? $target : '';
		$confirmed = isset( $_POST['confirm'] ) && is_string( $_POST['confirm'] ) ? sanitize_text_field( wp_unslash( $_POST['confirm'] ) ) : '';
		if ( ! SessionPolicy::allowed( 'post' === $method, current_user_can( 'manage_options' ), '' !== $key, FixApprovalAction::cookieAuthenticated() && SessionPolicy::matchingTokens( is_array( $auth ) ? (string) $auth['token'] : '', wp_get_session_token() ), is_ssl(), 'preview' === $mode || '1' === $confirmed ) || ! in_array( $mode, array( 'preview', 'approve' ), true ) || ( 'approve' === $mode && ! preg_match( '/^[a-f0-9]{32}$/D', $token ) ) ) {
			wp_die( esc_html__( 'A secure administrator session and exact baseline request are required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		if ( 'approve' === $mode ) {
			// Passwords are compared as typed; sanitizing would change them.
			$password = isset( $_POST['password'] ) && is_string( $_POST['password'] ) ? wp_unslash( $_POST['password'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Compared as typed; sanitizing would change the password.
			$password = strlen( $password ) <= 1024 ? $password : '';
			$user     = wp_get_current_user();
			if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
				wp_die( esc_html__( 'Password confirmation failed.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
			}
		}
		try {
			$target  = ( new TargetResolver() )->resolve( $key );
			$service = new BaselineService( new BaselineRepository( new WordPressOptions() ) );
			if ( 'preview' === $mode ) {
				$service->preview( $target, get_current_user_id() );
			} else {
				$service->approve( $target, get_current_user_id(), $token );
			}
		} catch ( \Throwable ) {
			wp_die( esc_html__( 'Baseline work is incomplete, expired or changed. No baseline approval was verified. Review the target and preview again.', 'ironlatch-security-scanner' ), '', array( 'response' => 409 ) );
		}
		if ( 'approve' === $mode ) {
			( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'baseline_approved', 0, $target->kind );
		}
		wp_safe_redirect( admin_url( 'admin.php?page=ironlatch-baselines' ) );
		exit;
	}
}
