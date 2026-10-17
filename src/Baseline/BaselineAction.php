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
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified before storing previews or baselines.
		$post   = wp_unslash( $_POST );
		$method = is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		$auth   = wp_parse_auth_cookie( '', is_ssl() ? 'secure_auth' : 'auth' );
		$mode   = is_string( $post['mode'] ?? null ) ? $post['mode'] : '';
		$key    = is_string( $post['target'] ?? null ) && strlen( $post['target'] ) <= 256 ? $post['target'] : '';
		$token  = is_string( $post['token'] ?? null ) ? $post['token'] : '';
		if ( ! SessionPolicy::allowed( 'post' === $method, current_user_can( 'manage_options' ), '' !== $key, FixApprovalAction::cookieAuthenticated() && SessionPolicy::matchingTokens( is_array( $auth ) ? (string) $auth['token'] : '', wp_get_session_token() ), is_ssl(), 'preview' === $mode || '1' === ( $post['confirm'] ?? null ) ) || ! in_array( $mode, array( 'preview', 'approve' ), true ) || ( 'approve' === $mode && ! preg_match( '/^[a-f0-9]{32}$/D', $token ) ) ) {
			wp_die( esc_html__( 'A secure administrator session and exact baseline request are required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'preview' === $mode ? 'amsec_baseline_preview' : 'amsec_baseline_approve_' . $token );
		if ( 'approve' === $mode ) {
			$password = is_string( $post['password'] ?? null ) && strlen( $post['password'] ) <= 1024 ? $post['password'] : '';
			$user     = wp_get_current_user();
			if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
				wp_die( esc_html__( 'Password confirmation failed.', 'amazing-security' ), '', array( 'response' => 403 ) );
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
			wp_die( esc_html__( 'Baseline work is incomplete, expired or changed. No baseline approval was verified. Review the target and preview again.', 'amazing-security' ), '', array( 'response' => 409 ) );
		}
		if ( 'approve' === $mode ) {
			( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'baseline_approved', 0, $target->kind );
		}
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-baselines' ) );
		exit;
	}
}
