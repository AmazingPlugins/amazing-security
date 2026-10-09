<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

/** Old address. The screen list moved into the side menu. */
final class ReviewPage {
	public function register(): void {
		$hook = add_submenu_page(
			Submenu::PARENT,
			__( 'Review', 'amazing-security' ),
			__( 'Review', 'amazing-security' ),
			'manage_options',
			'amsec-review',
			array( $this, 'render' )
		);
		if ( is_string( $hook ) ) {
			add_action( 'load-' . $hook, array( $this, 'redirect' ) );
		}
	}

	public function redirect(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-files' ) );
		exit;
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap amazing-security-admin"><h1>' . esc_html__( 'Files', 'amazing-security' ) . '</h1>';
		echo '<p><a href="' . esc_url( admin_url( 'admin.php?page=amsec-files' ) ) . '">' . esc_html__( 'Open Files', 'amazing-security' ) . '</a></p></div>';
	}
}
