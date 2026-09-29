<?php

// Execute with WP-CLI eval-file or after wp-load.php on a disposable WordPress site.
use AmazingPlugins\Security\FileScan\FileScanCursor;
use AmazingPlugins\Security\FileScan\FileScanReport;
use AmazingPlugins\Security\FileScan\FileScanRunner;
use AmazingPlugins\Security\FileScan\FileScanStep;
use AmazingPlugins\Security\FileScan\FileScanTarget;
use AmazingPlugins\Security\FileScan\WordPressFileScanStore;
use AmazingPlugins\Security\Integrity\Manifest;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Scan\ScanContext;

$root = sys_get_temp_dir() . '/amsec-file-fixture-' . bin2hex( random_bytes( 4 ) );
mkdir( $root );
file_put_contents( $root . '/known.php', '<?php echo 1;' );
file_put_contents( $root . '/extra.php', '<?php eval(base64_decode("ZWNobyAxOw=="));' );
$manifest = new Manifest( 'plugin', 'fixture:1', 'https://wordpress.org/', new DateTimeImmutable(), 'sha256', array( 'known.php' => array( hash( 'sha256', '<?php echo 1;' ) ) ) );
$target = new FileScanTarget( 'fixture:1', 'plugin', $root, $manifest );
$store = new WordPressFileScanStore( new WordPressOptions() );
$cursor = new FileScanCursor( 'fixture-1' );
$step = ( new FileScanRunner() )->step( array( $target ), $cursor, new ScanContext( null, 1 ) );
if ( $step->finished || 1 !== $cursor->processed ) {
	throw new RuntimeException( 'First file scan step was not bounded.' );
}
if ( ! $store->begin( 'fixture-1', $cursor ) ) {
	throw new RuntimeException( 'Could not begin file scan.' );
}
$store->saveProgress( 'fixture-1', $step );
$second = ( new FileScanRunner() )->step( array( $target ), $cursor, new ScanContext() );
$store->saveProgress( 'fixture-1', $second );
if ( ! $second->finished || $second->cursor->partial || 'warn' !== $second->cursor->state() ) {
	throw new RuntimeException( 'Suspicious extra file was not reported after resume.' );
}
$store->complete( 'fixture-1', FileScanReport::fromCursor( $cursor ) );
if ( 'warn' !== $store->latestCompleted()->state || 'warn' !== $store->historicalWarnings()[0]->state ) {
	throw new RuntimeException( 'Completed warning or history was not saved.' );
}
$raw = get_option( 'amazing_security_file_scan_completed' );
if ( str_contains( $raw, 'ZWNobyAxOw==' ) || str_contains( $raw, $root ) || isset( wp_load_alloptions()['amazing_security_file_scan_completed'] ) ) {
	throw new RuntimeException( 'Stored report contains content, absolute paths, or autoloaded data.' );
}
$partial = new FileScanCursor( 'fixture-2' );
$partial->partial = true;
$partial->finished = true;
if ( ! $store->begin( 'fixture-2', $partial ) ) {
	throw new RuntimeException( 'Could not begin later partial scan.' );
}
$store->saveProgress( 'fixture-2', new FileScanStep( $partial, true ) );
if ( 'warn' !== $store->latestCompleted()->state ) {
	throw new RuntimeException( 'Partial scan erased prior warning.' );
}
delete_option( 'amazing_security_file_scan_active' );
delete_option( 'amazing_security_file_scan_completed' );
delete_option( 'amazing_security_file_scan_history' );
unlink( $root . '/known.php' );
unlink( $root . '/extra.php' );
rmdir( $root );
echo 'File scan: PHP ' . PHP_VERSION . ', bounded resume, suspected rule, nonautoloaded report, and prior warning passed.' . PHP_EOL;
