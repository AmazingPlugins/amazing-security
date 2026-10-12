<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

use AmazingPlugins\Security\Schedule\DailyReleaseCheck;

final class DailyReleaseCheckAction {
	public function save(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You cannot change the daily checks.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_daily_release_check' );
		// Nonce verified above.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$value = isset( $_POST['enabled'] ) && is_string( $_POST['enabled'] ) ? wp_unslash( $_POST['enabled'] ) : '';
		if ( ! in_array( $value, array( '0', '1' ), true ) ) {
			wp_die( esc_html__( 'The setting could not be saved.', 'amazing-security' ), '', array( 'response' => 400 ) );
		}
		update_option( DailyReleaseCheck::OPTION, $value, false );
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-schedule#amsec-schedule' ) );
		exit;
	}
}
