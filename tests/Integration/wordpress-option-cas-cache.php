<?php
// Disposable Docker WordPress only. Reproduces a second writer changing a cached option.
if ( ! defined( 'WP_CLI' ) || ! WP_CLI || 'amsec-next-db' !== DB_HOST || ! in_array( DB_NAME, array( 'wordpress', 'wordpress69' ), true ) ) {
	exit( 1 ); }
use AmazingPlugins\Security\Integrity\WordPressOptions;
global $wpdb;
$key     = 'amsec_test_cas_' . bin2hex( random_bytes( 8 ) );
$options = new WordPressOptions();
try {
	if ( ! $options->add( $key, 'first' ) || 'first' !== $options->get( $key ) ) {
		throw new RuntimeException( 'Fixture setup failed.' ); }
	// A competing request updates storage without touching this process's local object cache.
	$wpdb->update( $wpdb->options, array( 'option_value' => 'second' ), array( 'option_name' => $key ) );
	if ( $options->replaceIfSame( $key, 'first', 'mine' ) ) {
		throw new RuntimeException( 'Stale CAS incorrectly succeeded.' ); }
	if ( 'second' !== $options->get( $key ) ) {
		throw new RuntimeException( 'Failed CAS retained stale cache; retry cannot observe competing writer.' ); }
	if ( ! $options->replaceIfSame( $key, 'second', 'mine' ) || 'mine' !== $options->get( $key ) ) {
		throw new RuntimeException( 'Fresh retry did not succeed.' ); }
	$wpdb->update( $wpdb->options, array( 'option_value' => 'last' ), array( 'option_name' => $key ) );
	if ( $options->deleteIfSame( $key, 'mine' ) || 'last' !== $options->get( $key ) ) {
		throw new RuntimeException( 'Failed guarded delete retained stale cache.' ); }
	if ( ! $options->deleteIfSame( $key, 'last' ) || null !== $options->get( $key ) ) {
		throw new RuntimeException( 'Guarded deletion failed.' ); }
	$wpdb->insert(
		$wpdb->options,
		array(
			'option_name'  => $key,
			'option_value' => 'rival',
			'autoload'     => 'no',
		)
	);
	if ( $options->add( $key, 'mine' ) || 'rival' !== $options->get( $key ) ) {
		throw new RuntimeException( 'Failed add retained cached absence.' ); }
	echo 'Failed CAS refreshes cache; guarded retry sees competing writer and succeeds.' . PHP_EOL;
} finally {
	delete_option( $key ); }
