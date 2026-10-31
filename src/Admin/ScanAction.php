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
			wp_die( esc_html__( 'You are not allowed to run a scan.', 'amsec-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_security_scanner_scan' );
		try {
			if ( ScanOptions::headers() ) {
				try {
					$headers = ( new WordPressHeaderService() )->create();
					$headers->check( $headers->fingerprint(), time() );
				} catch ( Throwable $headerError ) {
					$headerState = $headerError->getMessage();
				}
			}
			( new LocalHardeningScanService() )->run();
			$url = admin_url( 'admin.php?page=amsec-security-scanner' . ( isset( $headerState ) ? '&amsec_security_scanner_header_error=1' : '' ) );
		} catch ( Throwable $error ) {
			$url = admin_url( 'admin.php?page=amsec-security-scanner&amsec_security_scanner_error=1' );
		}
		wp_safe_redirect( $url );
		exit;
	}
}
