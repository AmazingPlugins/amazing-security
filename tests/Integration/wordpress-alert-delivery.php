<?php

// Run with wp eval-file on a disposable WordPress site.
use AmazingPlugins\Security\Alerts\WordPressAlertNotifier;
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Scan\ScanRun;

$mailCount = 0;
$capture = static function ( mixed $result, array $args ) use ( &$mailCount ): bool {
	++$mailCount;
	if ( ! str_contains( $args['message'], 'Finding IDs:' ) || ! str_contains( $args['message'], 'Amazing Security dashboard' ) ) {
		throw new RuntimeException( 'Alert body omitted the review path.' );
	}
	return true;
};
add_filter( 'pre_wp_mail', $capture, 10, 2 );
$now = new DateTimeImmutable();
$id = bin2hex( random_bytes( 16 ) );
$finding = new CheckResult( 'integrity-file', 'warn', 'Release file differs.', 'https://wordpress.org/', $now, 'high', 'complete', array(), $id );
$run = new ScanRun( $now, $now, array( $finding ), false );
try {
	$notifier = ( new WordPressAlertNotifier() )->create();
	if ( 'accepted' !== $notifier->integrity( $run, time() ) || 'none' !== $notifier->integrity( $run, time() ) || 1 !== $mailCount ) {
		throw new RuntimeException( 'Alert delivery or deduplication failed.' );
	}
} finally {
	remove_filter( 'pre_wp_mail', $capture, 10 );
}
echo 'One finding email was accepted; duplicate was suppressed.';
