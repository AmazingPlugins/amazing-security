<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

/** Record settings. Each row opens that screen. */
final class RecordsPage {
	public function register(): void {
		add_submenu_page(
			Submenu::PARENT,
			__( 'Records', 'amazing-security' ),
			__( 'Records', 'amazing-security' ),
			'manage_options',
			'amsec-records',
			array( $this, 'render' )
		);
	}

	public function render(): void {
		SettingList::render(
			__( 'Records', 'amazing-security' ),
			__( 'Activity is first. Each row opens on its own screen.', 'amazing-security' ),
			array(
				array(
					'label' => __( 'Activity', 'amazing-security' ),
					'note'  => __( 'Off until you turn recording on. It can store sign-ins, user changes, and plugin changes.', 'amazing-security' ),
					'url'   => SettingList::page( 'amsec-activity' ),
				),
				array(
					'label' => __( 'Settings', 'amazing-security' ),
					'note'  => __( 'Notification settings: finding emails, test email, and account-change email. Uses WordPress mail to the admin address.', 'amazing-security' ),
					'url'   => SettingList::page( 'amsec-settings' ),
				),
				array(
					'label' => __( 'Weekly digest', 'amazing-security' ),
					'note'  => __( 'Off until you turn the email on. It sends a count summary once a week.', 'amazing-security' ),
					'url'   => SettingList::page( 'amsec-digest' ),
				),
				array(
					'label' => __( 'Daily checks', 'amazing-security' ),
					'note'  => __( 'Shows whether the local cycle is waiting. Opening it does not start a check.', 'amazing-security' ),
					'url'   => SettingList::page( 'amsec-schedule' ),
				),
				array(
					'label' => __( 'Incident response', 'amazing-security' ),
					'note'  => __( 'Review administrators, end other sessions, then require a new password.', 'amazing-security' ),
					'url'   => SettingList::page( 'amsec-incident' ),
				),
				array(
					'label' => __( 'Site review', 'amazing-security' ),
					'note'  => __( 'Shows which protections are on. Each one stays off until you turn it on.', 'amazing-security' ),
					'url'   => SettingList::page( 'amsec-guide' ),
				),
				array(
					'label' => __( 'Saved change', 'amazing-security' ),
					'note'  => __( 'Opens one saved proposal. This screen stays empty until a proposal exists.', 'amazing-security' ),
					'url'   => SettingList::page( 'amsec-fix-review' ),
				),
			)
		);
	}
}
