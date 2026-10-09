<?php

// Run after wp-load.php on a disposable WordPress site.
use AmazingPlugins\Security\Admin\AdminPage;
use AmazingPlugins\Security\FileScan\FileScanCursor;
use AmazingPlugins\Security\FileScan\FileScanReport;

require_once ABSPATH . 'wp-admin/includes/template.php';
wp_set_current_user( 1 );
$key = 'amazing_security_file_scan_active';
$previous = get_option( $key, null );
$completedKey = 'amazing_security_file_scan_completed';
$previousCompleted = get_option( $completedKey, null );
$cursor = new FileScanCursor( 'attention-fixture' );
$cursor->findings[] = array( 'id' => str_repeat( 'a', 32 ), 'state' => 'warn', 'kind' => 'suspected', 'package' => 'fixture', 'path' => 'demo/loader.php', 'rule_id' => 'AS-PHP-001', 'version' => '2026.09.29.1', 'line' => 1, 'summary' => 'Decoded input is evaluated as PHP code.', 'reason' => '', 'tested_at' => gmdate( 'c' ) );
update_option( $key, wp_json_encode( array( 'scan_id' => 'attention-fixture', 'expires' => time() + 600, 'cursor' => $cursor->toArray(), 'finished' => false ) ), false );
ob_start();
( new AdminPage() )->renderSection( 'files' );
$html = ob_get_clean();
if ( ! str_contains( $html, 'id="amsec-file-scan"' ) || ! str_contains( $html, 'demo/loader.php' ) ) {
	throw new RuntimeException( 'File finding was absent from the security overview.' );
}
$cursor->findings = array();
$cursor->partial = true;
update_option( $key, wp_json_encode( array( 'scan_id' => 'attention-fixture', 'expires' => time() + 600, 'cursor' => $cursor->toArray(), 'finished' => false ) ), false );
$prior = new FileScanReport( 'prior-fixture', 'warn', new DateTimeImmutable( '2026-09-28T00:00:00Z' ), false, 1, 10, 0, 0, 0, 0, 1, 0, array( array( 'id' => str_repeat( 'b', 32 ), 'state' => 'warn', 'kind' => 'suspected', 'path' => 'prior/loader.php', 'summary' => 'Prior finding.' ) ) );
update_option( $completedKey, wp_json_encode( $prior->toArray() ), false );
ob_start();
( new AdminPage() )->renderSection( 'files' );
$html = ob_get_clean();
$preserved = str_contains( $html, 'prior/loader.php' ) && str_contains( $html, '<strong>Partial coverage</strong>' );
if ( null === $previous ) {
	delete_option( $key );
} else {
	update_option( $key, $previous, false );
}
if ( null === $previousCompleted ) {
	delete_option( $completedKey );
} else {
	update_option( $completedKey, $previousCompleted, false );
}
if ( ! $preserved ) {
	throw new RuntimeException( 'Partial scan hid a prior warning or displayed a stale state.' );
}
$historyKey = 'amazing_security_file_scan_history';
$previousHistory = get_option( $historyKey, null );
$partial = new FileScanReport( 'partial-fixture', 'inconclusive', new DateTimeImmutable( '2026-09-29T00:00:00Z' ), true, 2, 20, 1, 0, 0, 0, 1, 0, array() );
delete_option( $key );
update_option( $completedKey, wp_json_encode( $partial->toArray() ), false );
update_option( $historyKey, wp_json_encode( array( $prior->toArray() ) ), false );
ob_start();
( new AdminPage() )->renderSection( 'files' );
$html = ob_get_clean();
$preserved = str_contains( $html, 'prior/loader.php' ) && str_contains( $html, '<strong>Partial coverage</strong>' );
if ( null === $previous ) {
	delete_option( $key );
} else {
	update_option( $key, $previous, false );
}
if ( null === $previousCompleted ) {
	delete_option( $completedKey );
} else {
	update_option( $completedKey, $previousCompleted, false );
}
if ( null === $previousHistory ) {
	delete_option( $historyKey );
} else {
	update_option( $historyKey, $previousHistory, false );
}
if ( ! $preserved ) {
	throw new RuntimeException( 'A finished partial scan hid the prior warning.' );
}
echo 'File attention: suspected file appears in security overview.' . PHP_EOL;
