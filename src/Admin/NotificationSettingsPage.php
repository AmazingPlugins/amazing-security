<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Alerts\AlertDelivery;
use AmazingPlugins\Security\Alerts\AlertSettingsRenderer;
use AmazingPlugins\Security\Alerts\MailStatus;
use AmazingPlugins\Security\Free\Notices\Module as EventMail;
use AmazingPlugins\Security\Free\Notices\Notice;
use AmazingPlugins\Security\Integrity\WordPressOptions;

/** Settings → Notifications. Administrators only. Uses WordPress mail to admin_email. */
final class NotificationSettingsPage {
	public function register(): void {
		add_submenu_page(
			Submenu::PARENT,
			__( 'Settings', 'amazing-security' ),
			__( 'Settings', 'amazing-security' ),
			'manage_options',
			'amsec-settings',
			array( $this, 'render' )
		);
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		$options = new WordPressOptions();
		$mail    = MailStatus::assess();
		$alerts  = ( new AlertDelivery( $options, static fn (): bool => false, '', '' ) )->status();
		$digest  = '1' === get_option( 'amsec_digest_enabled', '0' );
		$events  = '1' === Notice::flag( get_option( Notice::OPTION, '0' ) );
		$notice  = isset( $_GET['amsec_mail'] ) ? sanitize_key( wp_unslash( $_GET['amsec_mail'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only flash after test mail.

		echo '<div class="wrap amazing-security-admin">';
		echo '<header class="amsec-header"><div><h1>' . esc_html__( 'Settings', 'amazing-security' ) . '</h1>';
		echo '<p>' . esc_html__( 'Administrators configure notifications here. Messages use this site’s WordPress mail and go to the WordPress admin email.', 'amazing-security' ) . '</p></div></header>';

		echo '<section class="amsec-overview" id="amsec-notifications" aria-labelledby="amsec-notifications-title">';
		echo '<h2 id="amsec-notifications-title">' . esc_html__( 'Notification settings', 'amazing-security' ) . '</h2>';
		echo '<p>' . esc_html__( 'Off by default. Only administrators can change these. Amazing Security does not add its own mail host; it uses whatever WordPress already uses for password resets.', 'amazing-security' ) . '</p>';

		if ( 'accepted' === $notice ) {
			echo '<div class="notice notice-success"><p>' . esc_html__( 'Test message was accepted by WordPress mail. That does not confirm it arrived in the inbox.', 'amazing-security' ) . '</p></div>';
		} elseif ( 'failed' === $notice ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Test message was not accepted. Check the site mail setup, then try again.', 'amazing-security' ) . '</p></div>';
		} elseif ( 'unconfigured' === $notice ) {
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'WordPress admin email is not configured. Fix it under Settings → General first.', 'amazing-security' ) . '</p></div>';
		}

		echo '<div class="amsec-login-panel">';
		echo '<h3>' . esc_html__( 'Administrator email', 'amazing-security' ) . '</h3>';
		if ( $mail['configured'] ) {
			echo '<p><strong>' . esc_html( $mail['email'] ) . '</strong></p>';
			echo '<p class="amsec-muted">' . esc_html( $mail['summary'] ) . '</p>';
			echo '<p><a href="' . esc_url( admin_url( 'options-general.php' ) ) . '">' . esc_html__( 'Change admin email in WordPress', 'amazing-security' ) . '</a></p>';
		} else {
			echo '<p class="notice notice-warning inline">' . esc_html__( 'Email is not configured.', 'amazing-security' ) . '</p>';
			echo '<p>' . esc_html( $mail['summary'] ) . '</p>';
			echo '<p><a class="button" href="' . esc_url( admin_url( 'options-general.php' ) ) . '">' . esc_html__( 'Open WordPress General settings', 'amazing-security' ) . '</a></p>';
		}

		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="amsec_notification_test">';
		wp_nonce_field( 'amsec_notification_test' );
		echo '<p><button type="submit" class="button"' . ( $mail['configured'] ? '' : ' disabled' ) . '>' . esc_html__( 'Send test email', 'amazing-security' ) . '</button></p>';
		echo '</form>';
		echo '</div>';

		$alertHtml = ( new AlertSettingsRenderer() )->render(
			'1' === $options->get( 'amsec_alerts_enabled' ),
			$alerts,
			admin_url( 'admin-post.php' ),
			wp_create_nonce( 'amsec_alert_settings' ),
			$mail
		);
		// AlertSettingsRenderer escapes dynamic values before constructing markup.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo $alertHtml;

		echo '<section class="amsec-alert-settings" aria-labelledby="amsec-digest-notify">';
		echo '<h2 id="amsec-digest-notify">' . esc_html__( 'Weekly digest', 'amazing-security' ) . '</h2>';
		echo '<p>' . esc_html( $digest ? __( 'On. A weekly count summary can be emailed to the admin address.', 'amazing-security' ) : __( 'Off. Turn it on from the weekly digest screen when you want that summary.', 'amazing-security' ) ) . '</p>';
		echo '<p><a class="button" href="' . esc_url( admin_url( 'admin.php?page=amsec-digest' ) ) . '">' . esc_html__( 'Open weekly digest settings', 'amazing-security' ) . '</a></p>';
		echo '</section>';

		echo '<section class="amsec-alert-settings" aria-labelledby="amsec-event-mail">';
		EventMail::form();
		echo '<p class="amsec-muted">' . esc_html(
			$events
				? __( 'Account-change email is on.', 'amazing-security' )
				: __( 'Account-change email is off.', 'amazing-security' )
		) . '</p>';
		echo '</section>';

		echo '</section></div>';
	}
}
