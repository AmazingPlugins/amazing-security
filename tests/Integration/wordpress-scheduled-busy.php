<?php

// Run with wp eval-file on a disposable site after a scheduled integrity step has begun.
use AmazingPlugins\Security\Admin\IntegrityScanAction;
use AmazingPlugins\Security\Integrity\IntegrityCursor;
use AmazingPlugins\Security\Integrity\WordPressIntegrityStore;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Schedule\SuiteCycle;

$options = new WordPressOptions();
$options->delete( 'amsec_suite_cycle' );
$cycle = new SuiteCycle( $options );
if ( ! $cycle->start( time() ) ) {
	throw new RuntimeException( 'Could not start scheduled suite.' );
}
$options->delete( 'amazing_security_integrity_active' );
$store = new WordPressIntegrityStore( $options );
$id = wp_generate_uuid4();
if ( ! $store->begin( $id, new IntegrityCursor( $id ) ) ) {
	throw new RuntimeException( 'Could not create an unfinished integrity scan.' );
}
$progress = $store->latestProgress();
if ( null === $progress || $progress->finished ) {
	throw new RuntimeException( 'Expected unfinished integrity progress.' );
}
wp_clear_scheduled_hook( 'amsec_file_tick' );
$lock = 'amazing_security_integrity_worker_lock';
$options->set( $lock, json_encode( array( 'scan_id' => 'other-worker', 'expires' => time() + 60 ) ) );
try {
	( new IntegrityScanAction() )->scheduled();
	if ( false !== wp_next_scheduled( 'amsec_file_tick' ) ) {
		throw new RuntimeException( 'File scan started while integrity worker was busy.' );
	}
	if ( false === wp_next_scheduled( 'amsec_integrity_tick' ) ) {
		throw new RuntimeException( 'Busy integrity worker has no retry.' );
	}
} finally {
	$options->delete( $lock );
}
echo 'Busy integrity worker did not advance the scheduled suite.';
