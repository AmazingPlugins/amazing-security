<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

use AmazingPlugins\Security\Scan\LocalHardeningScanService;
use Throwable;

final class ScanAction {
	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to run a scan.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amazing_security_scan' );
		try {
			( new LocalHardeningScanService() )->run();
			$url = admin_url( 'admin.php?page=amazing-security' );
		} catch ( Throwable $error ) {
			$url = admin_url( 'admin.php?page=amazing-security&amazing_security_error=1' );
		}
		wp_safe_redirect( $url );
		exit;
	}
}
