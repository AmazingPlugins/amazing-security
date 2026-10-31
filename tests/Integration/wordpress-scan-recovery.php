<?php
// Run only through wp eval-file on a disposable WordPress site.
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Integrity\WordPressIntegrityStore;
use AmazingPlugins\Security\Integrity\IntegrityCursor;
use AmazingPlugins\Security\FileScan\WordPressFileScanStore;
use AmazingPlugins\Security\FileScan\FileScanCursor;
use AmazingPlugins\Security\Schedule\SuiteCycle;
use AmazingPlugins\Security\Schedule\LocalSchedule;
use AmazingPlugins\Security\Admin\IntegrityScanAction;

$keys = array( 'cron', 'amsec_local_schedule_state', 'amsec_suite_cycle', 'amsec_security_scanner_integrity_active', 'amsec_security_scanner_file_scan_active', 'amsec_security_scanner_integrity_worker_lock' );
$saved = array();
foreach ( $keys as $key ) { $saved[$key] = get_option( $key, null ); }
$assert = static function ( bool $pass, string $message ): void { if ( ! $pass ) { throw new RuntimeException( $message ); } };
$options = new WordPressOptions();
try {
	delete_option( 'amsec_local_schedule_state' );
	wp_clear_scheduled_hook( 'amsec_local_daily_scan' );
	wp_schedule_single_event( time() - 7200, 'amsec_local_daily_scan' );
	$assert( 'missed' === ( new LocalSchedule( $options ) )->status( time() )['state'], 'Overdue first event was not reported missed.' );

	foreach ( array( array( 'amsec_security_scanner_integrity_active', new WordPressIntegrityStore( $options ), new IntegrityCursor( 'expired-test' ) ), array( 'amsec_security_scanner_file_scan_active', new WordPressFileScanStore( $options ), new FileScanCursor( 'expired-test' ) ) ) as [ $key, $store, $cursor ] ) {
		delete_option( $key );
		$assert( $store->begin( 'expired-test', $cursor ), 'Could not begin scan.' );
		$active = json_decode( get_option( $key ), true );
		$active['expires'] = time() - 1;
		update_option( $key, wp_json_encode( $active ), false );
		$progress = $store->latestProgress();
		$assert( null !== $progress && $progress->finished && $progress->cursor->partial, 'Expired cursor claimed full coverage.' );
	}

	delete_option( 'amsec_suite_cycle' );
	$cycle = new SuiteCycle( $options );
	$assert( $cycle->start( time() - 700 ) && $cycle->claim( 'integrity', time() - 700 ), 'Could not prepare interrupted lease.' );
	wp_clear_scheduled_hook( 'amsec_integrity_tick' );
	do_action( 'init' );
	do_action( 'init' );
	$count = 0;
	foreach ( _get_cron_array() as $hooks ) { $count += count( $hooks['amsec_integrity_tick'] ?? array() ); }
	$assert( 1 === $count, 'Interrupted lease did not recover to exactly one event.' );

	delete_option( 'amsec_security_scanner_integrity_active' );
	$store = new WordPressIntegrityStore( $options );
	$assert( $store->begin( 'manual-worker', new IntegrityCursor( 'manual-worker' ) ), 'Manual fixture did not start.' );
	$assert( ! $store->begin( 'second-worker', new IntegrityCursor( 'second-worker' ) ), 'Concurrent manual start replaced active scan.' );
	update_option( 'amsec_security_scanner_integrity_worker_lock', wp_json_encode( array( 'scan_id' => 'manual-worker', 'expires' => time() + 60 ) ), false );
	wp_clear_scheduled_hook( 'amsec_file_tick' );
	( new IntegrityScanAction() )->scheduled();
	$assert( 'integrity' === $cycle->status( time() )['stage'] && false === wp_next_scheduled( 'amsec_file_tick' ), 'Busy manual worker advanced scheduled stage.' );
	$assert( false !== wp_next_scheduled( 'amsec_integrity_tick' ), 'Busy manual worker lost scheduled retry.' );

	delete_option( 'amsec_suite_cycle' );
	$assert( $cycle->start( time() - 86401 ), 'Could not prepare stale cycle.' );
	$assert( 'partial' === $cycle->status( time() )['state'] && ! $cycle->claim( 'integrity', time() ), 'Stale suite kept running.' );
	echo 'Missed cron, expired cursors, interrupted leases, manual overlap, and stale suite checks passed.';
} finally {
	foreach ( $saved as $key => $value ) { if ( null === $value ) { delete_option( $key ); } else { update_option( $key, $value, false ); } }
}
