<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

/** File settings. Each row opens that screen. */
final class FilesPage {
	public function register(): void {
		add_submenu_page(
			Submenu::PARENT,
			__( 'Files', 'amsec-security-scanner' ),
			__( 'Files', 'amsec-security-scanner' ),
			'manage_options',
			'amsec-files',
			array( $this, 'render' )
		);
	}

	public function render(): void {
		SettingList::render(
			__( 'Files', 'amsec-security-scanner' ),
			__( 'The first rows are the ones to open first. Each row opens on its own screen.', 'amsec-security-scanner' ),
			array(
				array(
					'label' => __( 'PHP in uploads', 'amsec-security-scanner' ),
					'note'  => __( 'Shows an Apache rule for the uploads folder. Nothing is written until you confirm it.', 'amsec-security-scanner' ),
					'url'   => SettingList::page( 'amsec-uploads' ),
				),
				array(
					'label' => __( 'Content scan', 'amsec-security-scanner' ),
					'note'  => __( 'Looks through public posts and comments for hidden links and redirects.', 'amsec-security-scanner' ),
					'url'   => SettingList::page( 'amsec-content' ),
				),
				array(
					'label' => __( 'Integrity and file scan', 'amsec-security-scanner' ),
					'note'  => __( 'Compares release files and reviews unfamiliar PHP.', 'amsec-security-scanner' ),
					'url'   => SettingList::page( 'amsec-file-checks' ),
				),
				array(
					'label' => __( 'Published vulnerabilities', 'amsec-security-scanner' ),
					'note'  => __( 'Stays off until you allow this site to ask about installed versions.', 'amsec-security-scanner' ),
					'url'   => SettingList::page( 'amsec-vulnerabilities' ),
				),
				array(
					'label' => __( 'Code baselines', 'amsec-security-scanner' ),
					'note'  => __( 'Saves a reference for a plugin or theme you choose.', 'amsec-security-scanner' ),
					'url'   => SettingList::page( 'amsec-baselines' ),
				),
				array(
					'label' => __( 'Local inventory', 'amsec-security-scanner' ),
					'note'  => __( 'Lists filenames that may need a host check. It does not open the files.', 'amsec-security-scanner' ),
					'url'   => SettingList::page( 'amsec-exposure' ),
				),
				array(
					'label' => __( 'Directory status', 'amsec-security-scanner' ),
					'note'  => __( 'Asks WordPress.org about a plugin slug after you agree.', 'amsec-security-scanner' ),
					'url'   => SettingList::page( 'amsec-repository' ),
				),
				array(
					'label' => __( 'Rule information', 'amsec-security-scanner' ),
					'note'  => __( 'Versions of the patterns shipped with this plugin.', 'amsec-security-scanner' ),
					'url'   => SettingList::page( 'amsec-rules' ),
				),
				array(
					'label' => __( 'Recovery', 'amsec-security-scanner' ),
					'note'  => __( 'Directory modes and a database SQL download.', 'amsec-security-scanner' ),
					'url'   => SettingList::page( 'amsec-recovery' ),
				),
			)
		);
	}
}
