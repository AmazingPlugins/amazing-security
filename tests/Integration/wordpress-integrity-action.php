<?php

// Run with AMSEC_CASE=editor|forged|start|resume and WP-CLI eval-file.
use AmazingPlugins\Security\Admin\IntegrityScanAction;
use AmazingPlugins\Security\Integrity\WordPressIntegrityStore;
use AmazingPlugins\Security\Integrity\WordPressOptions;

$case = getenv( 'AMSEC_CASE' );
if ( 'editor' === $case ) {
	$editor = get_user_by( 'login', 'amsec_fixture_editor' );
	if ( ! $editor ) {
		$id = wp_insert_user(
			array(
				'user_login' => 'amsec_fixture_editor',
				'user_pass'  => wp_generate_password( 32 ),
				'user_email' => 'amsec-editor@example.invalid',
				'role'       => 'editor',
			)
		);
		if ( is_wp_error( $id ) ) {
			throw new RuntimeException( 'Could not create editor fixture.' );
		}
		$editor = get_user_by( 'id', $id );
	}
	wp_set_current_user( $editor->ID );
} else {
	wp_set_current_user( 1 );
}

if ( 'resume' === $case ) {
	$progress = ( new WordPressIntegrityStore( new WordPressOptions() ) )->latestProgress();
	if ( null === $progress || $progress->finished ) {
		throw new RuntimeException( 'No resumable scan.' );
	}
	$_POST['scan_id']     = $progress->cursor->scanId;
	$_POST['_wpnonce']    = wp_create_nonce( 'amsec_security_scanner_integrity_resume' );
	$_REQUEST['_wpnonce'] = $_POST['_wpnonce'];
	( new IntegrityScanAction() )->resume();
}

$_POST['_wpnonce']    = 'forged' === $case ? 'invalid' : wp_create_nonce( 'amsec_security_scanner_integrity_start' );
$_REQUEST['_wpnonce'] = $_POST['_wpnonce'];
( new IntegrityScanAction() )->start();
