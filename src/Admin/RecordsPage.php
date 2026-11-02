<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

/** Record settings. Each row opens that screen. */
final class RecordsPage {
	public function register(): void {
		add_submenu_page(
			Submenu::PARENT,
			__( 'Records', 'ironlatch-security-scanner' ),
			__( 'Records', 'ironlatch-security-scanner' ),
			'manage_options',
			'ironlatch-records',
			array( $this, 'render' )
		);
	}

	public function render(): void {
		SettingList::render(
			__( 'Records', 'ironlatch-security-scanner' ),
			__( 'Activity is first. Each row opens on its own screen.', 'ironlatch-security-scanner' ),
			array(
				array(
					'label' => __( 'Activity', 'ironlatch-security-scanner' ),
					'note'  => __( 'Off until you turn recording on. It can store sign-ins, user changes, and plugin changes.', 'ironlatch-security-scanner' ),
					'url'   => SettingList::page( 'ironlatch-activity' ),
				),
				array(
					'label' => __( 'Settings', 'ironlatch-security-scanner' ),
					'note'  => __( 'Notification settings: finding emails, test email, and account-change email. Uses WordPress mail to the admin address.', 'ironlatch-security-scanner' ),
					'url'   => SettingList::page( 'ironlatch-settings' ),
				),
				array(
					'label' => __( 'Weekly digest', 'ironlatch-security-scanner' ),
					'note'  => __( 'Off until you turn the email on. It sends a count summary once a week.', 'ironlatch-security-scanner' ),
					'url'   => SettingList::page( 'ironlatch-digest' ),
				),
				array(
					'label' => __( 'Daily checks', 'ironlatch-security-scanner' ),
					'note'  => __( 'Shows whether the local cycle is waiting. Opening it does not start a check.', 'ironlatch-security-scanner' ),
					'url'   => SettingList::page( 'ironlatch-schedule' ),
				),
				array(
					'label' => __( 'Incident response', 'ironlatch-security-scanner' ),
					'note'  => __( 'Review administrators, end other sessions, then require a new password.', 'ironlatch-security-scanner' ),
					'url'   => SettingList::page( 'ironlatch-incident' ),
				),
				array(
					'label' => __( 'Site review', 'ironlatch-security-scanner' ),
					'note'  => __( 'Shows which protections are on. Each one stays off until you turn it on.', 'ironlatch-security-scanner' ),
					'url'   => SettingList::page( 'ironlatch-guide' ),
				),
				array(
					'label' => __( 'Saved change', 'ironlatch-security-scanner' ),
					'note'  => __( 'Opens one saved proposal. This screen stays empty until a proposal exists.', 'ironlatch-security-scanner' ),
					'url'   => SettingList::page( 'ironlatch-fix-review' ),
				),
			)
		);
	}
}
