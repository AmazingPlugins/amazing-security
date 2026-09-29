<?php

// Run with AMSEC_CASE=editor|forged|changed|long|valid on a disposable site with current file-scan findings.
use AmazingPlugins\Security\Admin\FileScanReviewAction;
use AmazingPlugins\Security\FileScan\WordPressFileScanStore;
use AmazingPlugins\Security\Integrity\WordPressOptions;

$case = getenv( 'AMSEC_CASE' );
$store = new WordPressFileScanStore( new WordPressOptions() );
$progress = $store->latestProgress();
if ( null === $progress || array() === $progress->cursor->findings ) {
	throw new RuntimeException( 'No current findings for note fixture.' );
}
$id = $progress->cursor->findings[0]['id'];
if ( 'editor' === $case ) {
	$editor = get_user_by( 'login', 'amsec_file_fixture_editor' );
	wp_set_current_user( $editor->ID );
} else {
	wp_set_current_user( 1 );
}
$_POST['finding_id'] = 'changed' === $case ? str_repeat( 'b', 32 ) : $id;
$_POST['note'] = 'long' === $case ? str_repeat( 'x', 501 ) : 'Reviewed locally.';
$_POST['_wpnonce'] = 'forged' === $case ? 'invalid' : wp_create_nonce( 'amsec_file_scan_note' );
$_REQUEST['_wpnonce'] = $_POST['_wpnonce'];
( new FileScanReviewAction() )->note();
