<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Fixes\WordPressFixRepository;
use AmazingPlugins\Security\Scan\LocalHardeningScanService;
use Throwable;

final class FixRollbackAction {
	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'A current administrator session is required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Read only to name the nonce action; verified on the next line.
		$id = isset( $_POST['proposal_id'] ) && is_string( $_POST['proposal_id'] ) ? sanitize_key( wp_unslash( $_POST['proposal_id'] ) ) : '';
		check_admin_referer( 'ironlatch_fix_rollback_' . $id );
		$method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'post' !== $method || ! FixApprovalAction::cookieAuthenticated() ) {
			wp_die( esc_html__( 'A current administrator session is required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$confirmed = isset( $_POST['confirm'] ) && is_string( $_POST['confirm'] ) ? sanitize_text_field( wp_unslash( $_POST['confirm'] ) ) : '';
		if ( ! preg_match( '/^[a-f0-9]{32}$/D', $id ) || '1' !== $confirmed ) {
			wp_die( esc_html__( 'Invalid rollback request.', 'ironlatch-security-scanner' ), '', array( 'response' => 400 ) );
		}
		$repository = new WordPressFixRepository( $GLOBALS['wpdb'] );
		if ( 'rolled_back' !== $repository->rollback( $id, get_current_user_id(), time() ) ) {
			wp_die( esc_html__( 'The previous setting could not be restored.', 'ironlatch-security-scanner' ), '', array( 'response' => 409 ) );
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
}
