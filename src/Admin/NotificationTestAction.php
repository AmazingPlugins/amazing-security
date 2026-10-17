<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Alerts\MailStatus;

final class NotificationTestAction {
	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_notification_test' );
		$mail = MailStatus::assess();
		if ( ! $mail['configured'] ) {
			wp_safe_redirect( admin_url( 'admin.php?page=amsec-settings&amsec_mail=unconfigured#amsec-notifications' ) );
			exit;
		}
		$accepted = false;
		if ( function_exists( 'wp_mail' ) ) {
			$body     = "Amazing Security test notification.\n\nThis confirms WordPress mail accepted a message for the administrator address. It does not prove inbox delivery.\n\nDashboard:\n" . admin_url( 'admin.php?page=amazing-security' );
			$accepted = (bool) wp_mail( $mail['email'], 'Amazing Security: test notification', $body );
		}
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-settings&amsec_mail=' . ( $accepted ? 'accepted' : 'failed' ) . '#amsec-notifications' ) );
		exit;
	}
}
