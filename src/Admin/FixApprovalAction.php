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
use AmazingPlugins\Security\Request\PostedPassword;

final class FixApprovalAction {
	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'A current administrator session is required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Read only to name the nonce action; verified on the next line.
		$id = isset( $_POST['proposal_id'] ) && is_string( $_POST['proposal_id'] ) ? sanitize_key( wp_unslash( $_POST['proposal_id'] ) ) : '';
		check_admin_referer( 'ironlatch_fix_approve_' . $id );
		$method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'post' !== $method || ! self::cookieAuthenticated() ) {
			wp_die( esc_html__( 'A current administrator session is required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$confirmed = isset( $_POST['confirm'] ) && is_string( $_POST['confirm'] ) ? sanitize_text_field( wp_unslash( $_POST['confirm'] ) ) : '';
		if ( ! preg_match( '/^[a-f0-9]{32}$/D', $id ) || '1' !== $confirmed ) {
			wp_die( esc_html__( 'Invalid proposal request.', 'ironlatch-security-scanner' ), '', array( 'response' => 400 ) );
		}
		if ( ! ( new McpPreferences( new WordPressOptions() ) )->enabled() ) {
			wp_die( esc_html__( 'AI agent access is off.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$repository = new WordPressFixRepository( $GLOBALS['wpdb'] );
		try {
			$proposal = $repository->get( $id );
		} catch ( Throwable ) {
			$proposal = null;
		}
		if ( null === $proposal || 'pending' !== $proposal->status || $proposal->isExpired( time() ) ) {
			wp_die( esc_html__( 'This proposal is no longer available.', 'ironlatch-security-scanner' ), '', array( 'response' => 409 ) );
		}
		// Passwords are compared as typed; sanitizing would change them.
		$password      = PostedPassword::read( 'password' ) ?? '';
		$checkPassword = static function ( string $value ): bool {
			$user = wp_get_current_user();
			return wp_check_password( $value, $user->user_pass, $user->ID );
		};
		if ( ! self::passwordConfirmed( $proposal, is_ssl(), $password, $checkPassword ) ) {
			wp_die( esc_html__( 'Password confirmation or HTTPS is required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$result = $repository->apply( $id, get_current_user_id(), time() );
		if ( 'applied' !== $result ) {
			wp_die( esc_html__( 'The setting was not changed. Review the current proposal state.', 'ironlatch-security-scanner' ), '', array( 'response' => 409 ) );
		}
		$verification = 'verified';
		try {
			( new LocalHardeningScanService() )->run();
		} catch ( Throwable ) {
			$verification = 'pending';
		}
		wp_safe_redirect( admin_url( 'admin.php?page=ironlatch-fix-review&proposal=' . $id . '&verification=' . $verification ) );
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
