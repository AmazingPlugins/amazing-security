<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

/** Settings → Scan options. */
final class ScanOptions {
	public const HEADERS = 'ironlatch_scan_headers';

	/** On unless turned off: the request goes only to this site's own homepage, like a Site Health loopback. */
	public static function headers(): bool {
		return '0' !== (string) get_option( self::HEADERS, '1' );
	}

	public static function form(): void {
		echo '<section class="ironlatch-alert-settings" id="ironlatch-scan-options" aria-labelledby="ironlatch-scan-options-title">';
		echo '<h2 id="ironlatch-scan-options-title">' . esc_html__( 'Scan options', 'ironlatch-security-scanner' ) . '</h2>';
		if ( isset( $_GET['ironlatch_saved'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only flash after saving.
			echo '<div class="notice notice-success inline"><p>' . esc_html__( 'Scan options saved.', 'ironlatch-security-scanner' ) . '</p></div>';
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="ironlatch_scan_options">';
		wp_nonce_field( 'ironlatch_scan_options' );
		echo '<p><label><input type="checkbox" name="ironlatch_scan_headers" value="1"' . checked( self::headers(), true, false ) . '> ' . esc_html__( 'Check security headers during each scan', 'ironlatch-security-scanner' ) . '</label></p>';
		echo '<p class="ironlatch-muted">' . esc_html__( 'The scan opens your homepage once, the way a visitor would, and looks at the security headers your server sends back. They tell browsers things like "don\'t show this site inside another site". The request goes only to your own site and nothing is sent anywhere else. Turn this off if your host blocks a site from calling itself.', 'ironlatch-security-scanner' ) . '</p>';
		submit_button( __( 'Save scan options', 'ironlatch-security-scanner' ), 'secondary' );
		echo '</form></section>';
	}

	public static function save(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'ironlatch_scan_options' );
		update_option( self::HEADERS, isset( $_POST['ironlatch_scan_headers'] ) ? '1' : '0', false );
		wp_safe_redirect( admin_url( 'admin.php?page=ironlatch-settings&ironlatch_saved=1#ironlatch-scan-options' ) );
		exit;
	}
}
