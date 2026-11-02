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
			__( 'Settings', 'ironlatch-security-scanner' ),
			__( 'Settings', 'ironlatch-security-scanner' ),
			'manage_options',
			'ironlatch-settings',
			array( $this, 'render' )
		);
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$options = new WordPressOptions();
		$mail    = MailStatus::assess();
		$alerts  = ( new AlertDelivery( $options, static fn (): bool => false, '', '' ) )->status();
		$digest  = '1' === get_option( 'ironlatch_digest_enabled', '0' );
		$events  = '1' === Notice::flag( get_option( Notice::OPTION, '0' ) );
		$notice  = isset( $_GET['ironlatch_mail'] ) ? sanitize_key( wp_unslash( $_GET['ironlatch_mail'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only flash after test mail.

		echo '<div class="wrap ironlatch-security-scanner-admin">';
		echo '<header class="ironlatch-header"><div><h1>' . esc_html__( 'Settings', 'ironlatch-security-scanner' ) . '</h1>';
		echo '<p>' . esc_html__( 'Administrators configure notifications here. Messages use this site’s WordPress mail and go to the WordPress admin email.', 'ironlatch-security-scanner' ) . '</p></div></header>';

		echo '<section class="ironlatch-overview" id="ironlatch-notifications" aria-labelledby="ironlatch-notifications-title">';
		echo '<h2 id="ironlatch-notifications-title">' . esc_html__( 'Notification settings', 'ironlatch-security-scanner' ) . '</h2>';
		echo '<p>' . esc_html__( 'Off by default. Only administrators can change these. Ironlatch Security Scanner does not add its own mail host; it uses whatever WordPress already uses for password resets.', 'ironlatch-security-scanner' ) . '</p>';

		if ( 'accepted' === $notice ) {
			echo '<div class="notice notice-success"><p>' . esc_html__( 'Test message was accepted by WordPress mail. That does not confirm it arrived in the inbox.', 'ironlatch-security-scanner' ) . '</p></div>';
		} elseif ( 'failed' === $notice ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Test message was not accepted. Check the site mail setup, then try again.', 'ironlatch-security-scanner' ) . '</p></div>';
		} elseif ( 'unconfigured' === $notice ) {
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'WordPress admin email is not configured. Fix it under Settings → General first.', 'ironlatch-security-scanner' ) . '</p></div>';
		}

		echo '<div class="ironlatch-login-panel">';
		echo '<h3>' . esc_html__( 'Administrator email', 'ironlatch-security-scanner' ) . '</h3>';
		if ( $mail['configured'] ) {
			echo '<p><strong>' . esc_html( $mail['email'] ) . '</strong></p>';
			echo '<p class="ironlatch-muted">' . esc_html( $mail['summary'] ) . '</p>';
			echo '<p><a href="' . esc_url( admin_url( 'options-general.php' ) ) . '">' . esc_html__( 'Change admin email in WordPress', 'ironlatch-security-scanner' ) . '</a></p>';
		} else {
			echo '<p class="notice notice-warning inline">' . esc_html__( 'Email is not configured.', 'ironlatch-security-scanner' ) . '</p>';
			echo '<p>' . esc_html( $mail['summary'] ) . '</p>';
			echo '<p><a class="button" href="' . esc_url( admin_url( 'options-general.php' ) ) . '">' . esc_html__( 'Open WordPress General settings', 'ironlatch-security-scanner' ) . '</a></p>';
		}

		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="ironlatch_notification_test">';
		wp_nonce_field( 'ironlatch_notification_test' );
		echo '<p><button type="submit" class="button"' . ( $mail['configured'] ? '' : ' disabled' ) . '>' . esc_html__( 'Send test email', 'ironlatch-security-scanner' ) . '</button></p>';
		echo '</form>';
		echo '</div>';

		$alertHtml = ( new AlertSettingsRenderer() )->render(
			'1' === $options->get( 'ironlatch_alerts_enabled' ),
			$alerts,
			admin_url( 'admin-post.php' ),
			wp_create_nonce( 'ironlatch_alert_settings' ),
			$mail
		);
		// AlertSettingsRenderer escapes dynamic values before constructing markup.
		echo wp_kses( $alertHtml, AdminHtml::allowed() );

		echo '<section class="ironlatch-alert-settings" aria-labelledby="ironlatch-digest-notify">';
		echo '<h2 id="ironlatch-digest-notify">' . esc_html__( 'Weekly digest', 'ironlatch-security-scanner' ) . '</h2>';
		echo '<p>' . esc_html( $digest ? __( 'On. A weekly count summary can be emailed to the admin address.', 'ironlatch-security-scanner' ) : __( 'Off. Turn it on from the weekly digest screen when you want that summary.', 'ironlatch-security-scanner' ) ) . '</p>';
		echo '<p><a class="button" href="' . esc_url( admin_url( 'admin.php?page=ironlatch-digest' ) ) . '">' . esc_html__( 'Open weekly digest settings', 'ironlatch-security-scanner' ) . '</a></p>';
		echo '</section>';

		echo '<section class="ironlatch-alert-settings" aria-labelledby="ironlatch-event-mail">';
		EventMail::form();
		echo '<p class="ironlatch-muted">' . esc_html(
			$events
				? __( 'Account-change email is on.', 'ironlatch-security-scanner' )
				: __( 'Account-change email is off.', 'ironlatch-security-scanner' )
		) . '</p>';
		echo '</section>';

		echo '</section>';
		ScanOptions::form();
		echo '</div>';
	}
}
