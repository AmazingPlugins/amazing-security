<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

/** File settings. Each row opens that screen. */
final class FilesPage {
	public function register(): void {
		add_submenu_page(
			Submenu::PARENT,
			__( 'Files', 'ironlatch-security-scanner' ),
			__( 'Files', 'ironlatch-security-scanner' ),
			'manage_options',
			'ironlatch-files',
			array( $this, 'render' )
		);
	}

	public function render(): void {
		SettingList::render(
			__( 'Files', 'ironlatch-security-scanner' ),
			__( 'The first rows are the ones to open first. Each row opens on its own screen.', 'ironlatch-security-scanner' ),
			array(
				array(
					'label' => __( 'PHP in uploads', 'ironlatch-security-scanner' ),
					'note'  => __( 'Shows an Apache rule for the uploads folder. Nothing is written until you confirm it.', 'ironlatch-security-scanner' ),
					'url'   => SettingList::page( 'ironlatch-uploads' ),
				),
				array(
					'label' => __( 'Content scan', 'ironlatch-security-scanner' ),
					'note'  => __( 'Looks through public posts and comments for hidden links and redirects.', 'ironlatch-security-scanner' ),
					'url'   => SettingList::page( 'ironlatch-content' ),
				),
				array(
					'label' => __( 'Integrity and file scan', 'ironlatch-security-scanner' ),
					'note'  => __( 'Compares release files and reviews unfamiliar PHP.', 'ironlatch-security-scanner' ),
					'url'   => SettingList::page( 'ironlatch-file-checks' ),
				),
				array(
					'label' => __( 'Published vulnerabilities', 'ironlatch-security-scanner' ),
					'note'  => __( 'Stays off until you allow this site to ask about installed versions.', 'ironlatch-security-scanner' ),
					'url'   => SettingList::page( 'ironlatch-vulnerabilities' ),
				),
				array(
					'label' => __( 'Code baselines', 'ironlatch-security-scanner' ),
					'note'  => __( 'Saves a reference for a plugin or theme you choose.', 'ironlatch-security-scanner' ),
					'url'   => SettingList::page( 'ironlatch-baselines' ),
				),
				array(
					'label' => __( 'Local inventory', 'ironlatch-security-scanner' ),
					'note'  => __( 'Lists filenames that may need a host check. It does not open the files.', 'ironlatch-security-scanner' ),
					'url'   => SettingList::page( 'ironlatch-exposure' ),
				),
				array(
					'label' => __( 'Directory status', 'ironlatch-security-scanner' ),
					'note'  => __( 'Asks WordPress.org about a plugin slug after you agree.', 'ironlatch-security-scanner' ),
					'url'   => SettingList::page( 'ironlatch-repository' ),
				),
				array(
					'label' => __( 'Rule information', 'ironlatch-security-scanner' ),
					'note'  => __( 'Versions of the patterns shipped with this plugin.', 'ironlatch-security-scanner' ),
					'url'   => SettingList::page( 'ironlatch-rules' ),
				),
				array(
					'label' => __( 'Recovery', 'ironlatch-security-scanner' ),
					'note'  => __( 'Directory modes and a database SQL download.', 'ironlatch-security-scanner' ),
					'url'   => SettingList::page( 'ironlatch-recovery' ),
				),
			)
		);
	}
}
