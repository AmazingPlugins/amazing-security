<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

use AmazingPlugins\Security\Fixes\WordPressFixRepository;
use AmazingPlugins\Security\Scan\LocalHardeningScanService;
use Throwable;

final class FixRollbackAction {
	public function handle(): void {
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) || ! current_user_can( 'manage_options' ) || ! FixApprovalAction::cookieAuthenticated() ) {
			wp_die( esc_html__( 'A current administrator session is required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		// The nonce is verified below before these fields affect a write.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$post = wp_unslash( $_POST );
		$id   = is_string( $post['proposal_id'] ?? null ) ? $post['proposal_id'] : '';
		if ( ! preg_match( '/^[a-f0-9]{32}$/D', $id ) || '1' !== ( $post['confirm'] ?? null ) ) {
			wp_die( esc_html__( 'Invalid rollback request.', 'amazing-security' ), '', array( 'response' => 400 ) );
		}
		check_admin_referer( 'amsec_fix_rollback_' . $id );
		$repository = new WordPressFixRepository( $GLOBALS['wpdb'] );
		if ( 'rolled_back' !== $repository->rollback( $id, get_current_user_id(), time() ) ) {
			wp_die( esc_html__( 'The previous setting could not be restored.', 'amazing-security' ), '', array( 'response' => 409 ) );
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
}
