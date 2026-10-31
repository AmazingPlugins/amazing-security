<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Fixes\FixProposal;
use AmazingPlugins\Security\Fixes\WordPressFixRepository;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Mcp\McpPreferences;
use AmazingPlugins\Security\Scan\LocalHardeningScanService;
use Throwable;

final class FixApprovalAction {
	public function handle(): void {
		$method = is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'post' !== $method || ! current_user_can( 'manage_options' ) || ! self::cookieAuthenticated() ) {
			wp_die( esc_html__( 'A current administrator session is required.', 'amsec-security-scanner' ), '', array( 'response' => 403 ) );
		}
		// The nonce is verified below before these fields affect a write.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$post = wp_unslash( $_POST );
		$id   = is_string( $post['proposal_id'] ?? null ) ? $post['proposal_id'] : '';
		if ( ! preg_match( '/^[a-f0-9]{32}$/D', $id ) || '1' !== ( $post['confirm'] ?? null ) ) {
			wp_die( esc_html__( 'Invalid proposal request.', 'amsec-security-scanner' ), '', array( 'response' => 400 ) );
		}
		check_admin_referer( 'amsec_fix_approve_' . $id );
		if ( ! ( new McpPreferences( new WordPressOptions() ) )->enabled() ) {
			wp_die( esc_html__( 'AI assistant access is off.', 'amsec-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$repository = new WordPressFixRepository( $GLOBALS['wpdb'] );
		try {
			$proposal = $repository->get( $id );
		} catch ( Throwable ) {
			$proposal = null;
		}
		if ( null === $proposal || 'pending' !== $proposal->status || $proposal->isExpired( time() ) ) {
			wp_die( esc_html__( 'This proposal is no longer available.', 'amsec-security-scanner' ), '', array( 'response' => 409 ) );
		}
		$password      = is_string( $post['password'] ?? null ) && strlen( $post['password'] ) <= 1024 ? $post['password'] : '';
		$checkPassword = static function ( string $value ): bool {
			$user = wp_get_current_user();
			return wp_check_password( $value, $user->user_pass, $user->ID );
		};
		if ( ! self::passwordConfirmed( $proposal, is_ssl(), $password, $checkPassword ) ) {
			wp_die( esc_html__( 'Password confirmation or HTTPS is required.', 'amsec-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$result = $repository->apply( $id, get_current_user_id(), time() );
		if ( 'applied' !== $result ) {
			wp_die( esc_html__( 'The setting was not changed. Review the current proposal state.', 'amsec-security-scanner' ), '', array( 'response' => 409 ) );
		}
		$verification = 'verified';
		try {
			( new LocalHardeningScanService() )->run();
		} catch ( Throwable ) {
			$verification = 'pending';
		}
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-fix-review&proposal=' . $id . '&verification=' . $verification ) );
		exit;
	}

	public static function cookieAuthenticated(): bool {
		$scheme = is_ssl() ? 'secure_auth' : 'auth';
		$userId = wp_validate_auth_cookie( '', $scheme );
		return is_int( $userId ) && 0 < $userId && get_current_user_id() === $userId && '' !== wp_get_session_token();
	}

	public static function passwordConfirmed( FixProposal $proposal, bool $secure, string $password, callable $check ): bool {
		if ( 'block' !== $proposal->afterMode ) {
			return true;
		}
		return $secure && '' !== $password && $check( $password );
	}
}
