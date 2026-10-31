<?php

// Run with wp eval-file on a disposable WordPress site.
use AmazingPlugins\Security\Alerts\WordPressAlertNotifier;
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Scan\ScanRun;

$mailCount = 0;
$capture = static function ( mixed $result, array $args ) use ( &$mailCount ): bool {
	++$mailCount;
	if ( ! str_contains( $args['message'], 'Finding IDs:' ) || ! str_contains( $args['message'], 'AmSec Security Scanner dashboard' ) ) {
		throw new RuntimeException( 'Alert body omitted the review path.' );
	}
	return 1 < $mailCount;
};
add_filter( 'pre_wp_mail', $capture, 10, 2 );
$previousState = get_option( 'amsec_alert_state', null );
$previousEnabled = get_option( 'amsec_alerts_enabled', null );
update_option( 'amsec_alerts_enabled', '1', false );
delete_option( 'amsec_alert_state' );
$now = new DateTimeImmutable();
$id = bin2hex( random_bytes( 16 ) );
$finding = new CheckResult( 'integrity-file', 'warn', 'Release file differs.', 'https://wordpress.org/', $now, 'high', 'complete', array(), $id );
$run = new ScanRun( $now, $now, array( $finding ), false );
try {
	$notifier = ( new WordPressAlertNotifier() )->create();
	if ( 'failed' !== $notifier->integrity( $run, time() ) ) {
		throw new RuntimeException( 'Initial mail failure was not recorded.' );
	}
	$delivery = ( new WordPressAlertNotifier() )->delivery();
	if ( array( $id ) !== $delivery->status()['pending'] || false === wp_next_scheduled( 'amsec_alert_retry' ) ) {
		throw new RuntimeException( 'Failed mail was not queued for retry.' );
	}
	if ( 'accepted' !== $delivery->retry( time() + 1 ) || 'none' !== $notifier->integrity( $run, time() + 2 ) || 2 !== $mailCount ) {
		throw new RuntimeException( 'Alert retry or deduplication failed.' );
	}
} finally {
	remove_filter( 'pre_wp_mail', $capture, 10 );
	wp_clear_scheduled_hook( 'amsec_alert_retry' );
	if ( null === $previousState ) { delete_option( 'amsec_alert_state' ); } else { update_option( 'amsec_alert_state', $previousState, false ); }
	if ( null === $previousEnabled ) { delete_option( 'amsec_alerts_enabled' ); } else { update_option( 'amsec_alerts_enabled', $previousEnabled, false ); }
}
echo 'Failed finding email retried and was accepted; duplicate was suppressed.';
