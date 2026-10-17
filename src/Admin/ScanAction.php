<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Headers\WordPressHeaderService;
use AmazingPlugins\Security\Scan\LocalHardeningScanService;
use Throwable;

final class ScanAction {
	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to run a scan.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amazing_security_scan' );
		try {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- The scan nonce was checked above. The checkbox only allows this site's homepage request.
			$consent = isset( $_POST['amsec_header_consent'] ) && '1' === sanitize_text_field( wp_unslash( $_POST['amsec_header_consent'] ) );
			if ( $consent ) {
				try {
					$headers = ( new WordPressHeaderService() )->create();
					$headers->check( $headers->fingerprint(), time() );
				} catch ( Throwable $headerError ) {
					$headerState = $headerError->getMessage();
				}
			}
			( new LocalHardeningScanService() )->run();
			$url = admin_url( 'admin.php?page=amazing-security' . ( isset( $headerState ) ? '&amazing_security_header_error=1' : '' ) );
		} catch ( Throwable $error ) {
			$url = admin_url( 'admin.php?page=amazing-security&amazing_security_error=1' );
		}
		wp_safe_redirect( $url );
		exit;
	}
}
