<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

use AmazingPlugins\Security\Findings\FindingsRepository;

final class AdminPage {
	public function register(): void {
		$hook = add_menu_page( 'Amazing Security', 'Amazing Security', 'manage_options', 'amazing-security', array( $this, 'render' ), 'dashicons-shield-alt', 81 );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $current_hook ) use ( $hook ): void {
				if ( $hook === $current_hook ) {
					wp_enqueue_style( 'amazing-security-admin', plugins_url( 'assets/admin.css', AMAZING_SECURITY_FILE ), array(), '0.1.0' );
				}
			}
		);
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to view this report.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		$run = ( new FindingsRepository() )->latest();
		echo '<div class="wrap"><h1>Amazing Security</h1><p>Private preview: five read-only WordPress hardening checks. This report is not a complete security assessment.</p>';
		// This flag selects a static message and does not change state or enter output.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['amazing_security_error'] ) ) {
			echo '<div class="notice notice-error"><p>Scan could not be saved. The previous report is still shown.</p></div>';
		}
		echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_scan">';
		wp_nonce_field( 'amazing_security_scan' );
		submit_button( 'Run local checks' );
		echo '</form>';
		// ReportRenderer escapes every dynamic value before constructing markup.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo $run ? ( new ReportRenderer() )->render( $run ) : '<p>No scan has run yet.</p>';
		echo '</div>';
	}
}
