<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

use AmazingPlugins\Security\Repair\WordPressPluginRepair;

final class RepairAction {
	public function apply(): void {
		$id = $this->authorize( 'apply' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in authorize.
		$post   = wp_unslash( $_POST );
		$before = is_string( $post['before_sha256'] ?? null ) ? $post['before_sha256'] : '';
		$after  = is_string( $post['after_sha256'] ?? null ) ? $post['after_sha256'] : '';
		if ( '1' !== ( $post['confirm'] ?? null ) || ! preg_match( '/^[a-f0-9]{64}$/D', $before ) || ! preg_match( '/^[a-f0-9]{64}$/D', $after ) ) {
			$this->fail();
		}
		$repair  = new WordPressPluginRepair();
		$preview = $repair->preview( $id );
		if ( null === $preview || null === $repair->apply( $preview, $before, $after ) ) {
			$this->fail();
		}
		$this->redirect( $id );
	}

	public function rollback(): void {
		$id = $this->authorize( 'rollback' );
		if ( ! ( new WordPressPluginRepair() )->rollback( $id ) ) {
			$this->fail();
		}
		$this->redirect( $id );
	}

	public function retire(): void {
		$id = $this->authorize( 'retire' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in authorize.
		$post = wp_unslash( $_POST );
		if ( '1' !== ( $post['confirm'] ?? null ) || ! ( new WordPressPluginRepair() )->retire( $id ) ) {
			$this->fail();
		}
		$this->redirect( $id );
	}

	private function authorize( string $action ): string {
		if ( ! current_user_can( 'manage_options' ) || ! FixApprovalAction::cookieAuthenticated() ) {
			wp_die( esc_html__( 'A current administrator session is required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Dynamic nonce action needs the validated ID first.
		$id = isset( $_POST['finding_id'] ) && is_string( $_POST['finding_id'] ) ? sanitize_text_field( wp_unslash( $_POST['finding_id'] ) ) : '';
		if ( ! preg_match( '/^[a-f0-9]{32}$/D', $id ) ) {
			$this->fail();
		}
		check_admin_referer( 'amsec_repair_' . $action . '_' . $id );
		return $id;
	}

	private function fail(): never {
		wp_die( esc_html__( 'Repair could not be confirmed. Check the repair review page before trying again; the file or backup may need recovery.', 'amazing-security' ), '', array( 'response' => 409 ) );
	}

	private function redirect( string $id ): never {
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-repair&finding=' . rawurlencode( $id ) ) );
		exit;
	}
}
