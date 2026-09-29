<?php

// Run only with wp eval-file on a disposable WordPress site. It alters an inactive repository plugin file and restores it.
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Integrity\IntegrityCursor;
use AmazingPlugins\Security\Integrity\IntegrityStep;
use AmazingPlugins\Security\Integrity\WordPressIntegrityStore;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Repair\WordPressPluginRepair;

require_once ABSPATH . 'wp-admin/includes/plugin.php';
$path = WP_PLUGIN_DIR . '/akismet/akismet.php';
$akismetVersion = get_plugin_data( $path, false, false )['Version'];
$original = file_get_contents( $path );
if ( false === $original ) {
	throw new RuntimeException( 'Disposable Akismet fixture missing.' );
}
$options = new WordPressOptions();
$oldActive = $options->get( 'amazing_security_integrity_active' );
$id = bin2hex( random_bytes( 16 ) );
$scanId = wp_generate_uuid4();
$receiptOption = 'amsec_repair_' . substr( hash( 'sha256', $id ), 0, 32 );
try {
	file_put_contents( $path, $original . "\n/* disposable repair test */\n" );
	$observed = hash_file( 'sha256', $path );
	$options->delete( 'amazing_security_integrity_active' );
	$store = new WordPressIntegrityStore( $options );
	$cursor = new IntegrityCursor( $scanId );
	$cursor->findings[] = new CheckResult( 'integrity-file', 'warn', 'Release file differs.', 'https://downloads.wordpress.org/plugin-checksums/akismet/' . $akismetVersion . '.json', new DateTimeImmutable(), 'high', 'complete', array( 'package_type' => 'plugin', 'package' => 'akismet:' . $akismetVersion, 'path' => 'akismet.php', 'reason' => 'ok', 'observed_sha256' => $observed ), $id );
	if ( ! $store->begin( $scanId, $cursor ) ) {
		throw new RuntimeException( 'Could not create disposable finding.' );
	}
	$store->saveProgress( $scanId, new IntegrityStep( $cursor, true ) );
	$repair = new WordPressPluginRepair();
	$preview = $repair->preview( $id );
	if ( null === $preview ) {
		throw new RuntimeException( 'Trusted repair preview unavailable.' );
	}
	if ( hash( 'sha256', $original ) !== $preview->replacement->sha256 ) {
		throw new RuntimeException( 'Release archive did not match disposable fixture.' );
	}
	$receipt = $repair->apply( $preview, $observed, $preview->replacement->sha256 );
	if ( null === $receipt || $preview->replacement->sha256 !== hash_file( 'sha256', $path ) || null === $repair->receipt( $id ) ) {
		throw new RuntimeException( 'Verified repair did not apply.' );
	}
	file_put_contents( $path, $original . "\n/* second disposable change */\n" );
	if ( $repair->canRollback( $id ) || $repair->rollback( $id ) ) {
		throw new RuntimeException( 'Rollback accepted a changed replacement.' );
	}
	sleep( 1 );
	$secondScanId = wp_generate_uuid4();
	$secondCursor = new IntegrityCursor( $secondScanId );
	$secondHash = hash_file( 'sha256', $path );
	$secondCursor->findings[] = new CheckResult( 'integrity-file', 'warn', 'Release file differs.', 'https://downloads.wordpress.org/plugin-checksums/akismet/' . $akismetVersion . '.json', new DateTimeImmutable(), 'high', 'complete', array( 'package_type' => 'plugin', 'package' => 'akismet:' . $akismetVersion, 'path' => 'akismet.php', 'reason' => 'ok', 'observed_sha256' => $secondHash ), $id );
	if ( ! $store->begin( $secondScanId, $secondCursor ) ) {
		throw new RuntimeException( 'Could not save second scan.' );
	}
	$store->saveProgress( $secondScanId, new IntegrityStep( $secondCursor, true ) );
	if ( ! $repair->retire( $id ) ) {
		throw new RuntimeException( 'Could not retire obsolete backup after fresh scan.' );
	}
	$secondPreview = $repair->preview( $id );
	if ( null === $secondPreview || null === $repair->apply( $secondPreview, $secondHash, $secondPreview->replacement->sha256 ) ) {
		throw new RuntimeException( 'Could not repair second changed file.' );
	}
	if ( ! $repair->rollback( $id ) || $secondHash !== hash_file( 'sha256', $path ) ) {
		throw new RuntimeException( 'Verified rollback did not restore second changed bytes.' );
	}
	echo 'Exact plugin repair, changed-file refusal, fresh-scan retirement, and rollback passed.';
} finally {
	file_put_contents( $path, $original );
	$options->delete( 'amazing_security_integrity_active' );
	if ( is_string( $oldActive ) ) {
		$options->add( 'amazing_security_integrity_active', $oldActive );
	}
	$options->delete( $receiptOption );
}
