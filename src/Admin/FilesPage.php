<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

/** File settings. Each row opens that screen. */
final class FilesPage {
	public function register(): void {
		add_submenu_page(
			Submenu::PARENT,
			__( 'Files', 'amazingplugins-security-scanner' ),
			__( 'Files', 'amazingplugins-security-scanner' ),
			'manage_options',
			'amsec-files',
			array( $this, 'render' )
		);
	}

	public function render(): void {
		SettingList::render(
			__( 'Files', 'amazingplugins-security-scanner' ),
			__( 'The first rows are the ones to open first. Each row opens on its own screen.', 'amazingplugins-security-scanner' ),
			array(
				array(
					'label' => __( 'PHP in uploads', 'amazingplugins-security-scanner' ),
					'note'  => __( 'Shows an Apache rule for the uploads folder. Nothing is written until you confirm it.', 'amazingplugins-security-scanner' ),
					'url'   => SettingList::page( 'amsec-uploads' ),
				),
				array(
					'label' => __( 'Content scan', 'amazingplugins-security-scanner' ),
					'note'  => __( 'Looks through public posts and comments for hidden links and redirects.', 'amazingplugins-security-scanner' ),
					'url'   => SettingList::page( 'amsec-content' ),
				),
				array(
					'label' => __( 'Integrity and file scan', 'amazingplugins-security-scanner' ),
					'note'  => __( 'Compares release files and reviews unfamiliar PHP.', 'amazingplugins-security-scanner' ),
					'url'   => SettingList::page( 'amsec-file-checks' ),
				),
				array(
					'label' => __( 'Published vulnerabilities', 'amazingplugins-security-scanner' ),
					'note'  => __( 'Stays off until you allow this site to ask about installed versions.', 'amazingplugins-security-scanner' ),
					'url'   => SettingList::page( 'amsec-vulnerabilities' ),
				),
				array(
					'label' => __( 'Code baselines', 'amazingplugins-security-scanner' ),
					'note'  => __( 'Saves a reference for a plugin or theme you choose.', 'amazingplugins-security-scanner' ),
					'url'   => SettingList::page( 'amsec-baselines' ),
				),
				array(
					'label' => __( 'Local inventory', 'amazingplugins-security-scanner' ),
					'note'  => __( 'Lists filenames that may need a host check. It does not open the files.', 'amazingplugins-security-scanner' ),
					'url'   => SettingList::page( 'amsec-exposure' ),
				),
				array(
					'label' => __( 'Directory status', 'amazingplugins-security-scanner' ),
					'note'  => __( 'Asks WordPress.org about a plugin slug after you agree.', 'amazingplugins-security-scanner' ),
					'url'   => SettingList::page( 'amsec-repository' ),
				),
				array(
					'label' => __( 'Rule information', 'amazingplugins-security-scanner' ),
					'note'  => __( 'Versions of the patterns shipped with this plugin.', 'amazingplugins-security-scanner' ),
					'url'   => SettingList::page( 'amsec-rules' ),
				),
				array(
					'label' => __( 'Recovery', 'amazingplugins-security-scanner' ),
					'note'  => __( 'Directory modes and a database SQL download.', 'amazingplugins-security-scanner' ),
					'url'   => SettingList::page( 'amsec-recovery' ),
				),
			)
		);
	}
}
