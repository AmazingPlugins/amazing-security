<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

/** Record settings. Each row opens that screen. */
final class RecordsPage {
	public function register(): void {
		add_submenu_page(
			Submenu::PARENT,
			__( 'Records', 'amsec-security-scanner' ),
			__( 'Records', 'amsec-security-scanner' ),
			'manage_options',
			'amsec-records',
			array( $this, 'render' )
		);
	}

	public function render(): void {
		SettingList::render(
			__( 'Records', 'amsec-security-scanner' ),
			__( 'Activity is first. Each row opens on its own screen.', 'amsec-security-scanner' ),
			array(
				array(
					'label' => __( 'Activity', 'amsec-security-scanner' ),
					'note'  => __( 'Off until you turn recording on. It can store sign-ins, user changes, and plugin changes.', 'amsec-security-scanner' ),
					'url'   => SettingList::page( 'amsec-activity' ),
				),
				array(
					'label' => __( 'Settings', 'amsec-security-scanner' ),
					'note'  => __( 'Notification settings: finding emails, test email, and account-change email. Uses WordPress mail to the admin address.', 'amsec-security-scanner' ),
					'url'   => SettingList::page( 'amsec-settings' ),
				),
				array(
					'label' => __( 'Weekly digest', 'amsec-security-scanner' ),
					'note'  => __( 'Off until you turn the email on. It sends a count summary once a week.', 'amsec-security-scanner' ),
					'url'   => SettingList::page( 'amsec-digest' ),
				),
				array(
					'label' => __( 'Daily checks', 'amsec-security-scanner' ),
					'note'  => __( 'Shows whether the local cycle is waiting. Opening it does not start a check.', 'amsec-security-scanner' ),
					'url'   => SettingList::page( 'amsec-schedule' ),
				),
				array(
					'label' => __( 'Incident response', 'amsec-security-scanner' ),
					'note'  => __( 'Review administrators, end other sessions, then require a new password.', 'amsec-security-scanner' ),
					'url'   => SettingList::page( 'amsec-incident' ),
				),
				array(
					'label' => __( 'Site review', 'amsec-security-scanner' ),
					'note'  => __( 'Shows which protections are on. Each one stays off until you turn it on.', 'amsec-security-scanner' ),
					'url'   => SettingList::page( 'amsec-guide' ),
				),
				array(
					'label' => __( 'Saved change', 'amsec-security-scanner' ),
					'note'  => __( 'Opens one saved proposal. This screen stays empty until a proposal exists.', 'amsec-security-scanner' ),
					'url'   => SettingList::page( 'amsec-fix-review' ),
				),
			)
		);
	}
}
