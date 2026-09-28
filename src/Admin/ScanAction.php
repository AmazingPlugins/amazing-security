<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

use AmazingPlugins\Security\Checks\AdminAccountsCheck;
use AmazingPlugins\Security\Checks\DebugDisplayCheck;
use AmazingPlugins\Security\Checks\FileEditorCheck;
use AmazingPlugins\Security\Checks\HttpsAdminCheck;
use AmazingPlugins\Security\Checks\UpdatePostureCheck;
use AmazingPlugins\Security\Checks\WordPressValues;
use AmazingPlugins\Security\Findings\FindingsRepository;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\ScanCoordinator;
use Throwable;

final class ScanAction {
	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to run a scan.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amazing_security_scan' );
		$values = new WordPressValues();
		$checks = array( new UpdatePostureCheck( $values ), new DebugDisplayCheck( $values ), new FileEditorCheck( $values ), new HttpsAdminCheck( $values ), new AdminAccountsCheck( $values ) );
		try {
			$run = ( new ScanCoordinator() )->run( $checks, new ScanContext() );
			( new FindingsRepository() )->save( $run );
			$url = admin_url( 'admin.php?page=amazing-security' );
		} catch ( Throwable $error ) {
			$url = admin_url( 'admin.php?page=amazing-security&amazing_security_error=1' );
		}
		wp_safe_redirect( $url );
		exit;
	}
}
