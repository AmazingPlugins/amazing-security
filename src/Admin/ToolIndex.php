<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

/** Old address. File settings now live on Files. */
final class ToolIndex {
	public function register(): void {
		$hook = add_submenu_page(
			Submenu::PARENT,
			__( 'Advanced', 'amazing-security-scanner' ),
			__( 'Advanced', 'amazing-security-scanner' ),
			'manage_options',
			'amsec-tools',
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
		wp_safe_redirect( SettingList::page( 'amsec-files' ) );
		exit;
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security-scanner' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap amazing-security-admin"><h1>' . esc_html__( 'Files', 'amazing-security-scanner' ) . '</h1>';
		echo '<p><a href="' . esc_url( SettingList::page( 'amsec-files' ) ) . '">' . esc_html__( 'Open Files', 'amazing-security-scanner' ) . '</a></p></div>';
	}
}
