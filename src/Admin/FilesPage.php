<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

/** File settings. Each row opens that screen. */
final class FilesPage {
	public function register(): void {
		add_submenu_page(
			Submenu::PARENT,
			__( 'Files', 'amazing-security' ),
			__( 'Files', 'amazing-security' ),
			'manage_options',
			'amsec-files',
			array( $this, 'render' )
		);
	}

	public function render(): void {
		SettingList::render(
			__( 'Files', 'amazing-security' ),
			__( 'The first rows are the ones to open first. Each row opens on its own screen.', 'amazing-security' ),
			array(
				array(
					'label' => __( 'PHP in uploads', 'amazing-security' ),
					'note'  => __( 'Shows an Apache rule for the uploads folder. Nothing is written until you confirm it.', 'amazing-security' ),
					'url'   => SettingList::page( 'amsec-uploads' ),
				),
				array(
					'label' => __( 'Content scan', 'amazing-security' ),
					'note'  => __( 'Looks through public posts and comments for hidden links and redirects.', 'amazing-security' ),
					'url'   => SettingList::page( 'amsec-content' ),
				),
				array(
					'label' => __( 'Integrity and file scan', 'amazing-security' ),
					'note'  => __( 'Compares release files and reviews unfamiliar PHP.', 'amazing-security' ),
					'url'   => SettingList::page( 'amsec-file-checks' ),
				),
				array(
					'label' => __( 'Published vulnerabilities', 'amazing-security' ),
					'note'  => __( 'Stays off until you allow this site to ask about installed versions.', 'amazing-security' ),
					'url'   => SettingList::page( 'amsec-vulnerabilities' ),
				),
				array(
					'label' => __( 'File repair', 'amazing-security' ),
					'note'  => __( 'WordPress / plugin / theme files only. Replaces one supported release file after you approve the exact change.', 'amazing-security' ),
					'url'   => SettingList::page( 'amsec-repair' ),
				),
				array(
					'label' => __( 'Code baselines', 'amazing-security' ),
					'note'  => __( 'Saves a reference for a plugin or theme you choose.', 'amazing-security' ),
					'url'   => SettingList::page( 'amsec-baselines' ),
				),
				array(
					'label' => __( 'Local inventory', 'amazing-security' ),
					'note'  => __( 'Lists filenames that may need a host check. It does not open the files.', 'amazing-security' ),
					'url'   => SettingList::page( 'amsec-exposure' ),
				),
				array(
					'label' => __( 'Directory status', 'amazing-security' ),
					'note'  => __( 'Asks WordPress.org about a plugin slug after you agree.', 'amazing-security' ),
					'url'   => SettingList::page( 'amsec-repository' ),
				),
				array(
					'label' => __( 'Rule information', 'amazing-security' ),
					'note'  => __( 'Versions of the patterns shipped with this plugin.', 'amazing-security' ),
					'url'   => SettingList::page( 'amsec-rules' ),
				),
				array(
					'label' => __( 'Recovery', 'amazing-security' ),
					'note'  => __( 'Soft WordPress recovery tools (modes, SQL download, approved file moves). Each one waits for its own form.', 'amazing-security' ),
					'url'   => SettingList::page( 'amsec-recovery' ),
				),
			)
		);
	}
}
