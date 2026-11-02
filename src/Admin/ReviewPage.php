<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

/** Old address. The screen list moved into the side menu. */
final class ReviewPage {
	public function register(): void {
		$hook = add_submenu_page(
			Submenu::PARENT,
			__( 'Review', 'ironlatch-security-scanner' ),
			__( 'Review', 'ironlatch-security-scanner' ),
			'manage_options',
			'ironlatch-review',
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
		wp_safe_redirect( admin_url( 'admin.php?page=ironlatch-files' ) );
		exit;
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap ironlatch-security-scanner-admin"><h1>' . esc_html__( 'Files', 'ironlatch-security-scanner' ) . '</h1>';
		echo '<p><a href="' . esc_url( admin_url( 'admin.php?page=ironlatch-files' ) ) . '">' . esc_html__( 'Open Files', 'ironlatch-security-scanner' ) . '</a></p></div>';
	}
}
