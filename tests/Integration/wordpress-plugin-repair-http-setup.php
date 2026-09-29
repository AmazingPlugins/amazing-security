<?php

// Test-only wp eval-file fixture for a disposable site.
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Integrity\IntegrityCursor;
use AmazingPlugins\Security\Integrity\IntegrityStep;
use AmazingPlugins\Security\Integrity\WordPressIntegrityStore;
use AmazingPlugins\Security\Integrity\WordPressOptions;

require_once ABSPATH . 'wp-admin/includes/plugin.php';
$id = getenv( 'AMSEC_TEST_ID' );
$login = getenv( 'AMSEC_TEST_LOGIN' );
$password = getenv( 'AMSEC_TEST_PASSWORD' );
if ( ! is_string( $id ) || ! preg_match( '/^[a-f0-9]{32}$/D', $id ) || ! is_string( $login ) || ! is_string( $password ) ) {
	throw new RuntimeException( 'Missing test fixture inputs.' );
}
$user = wp_create_user( $login, $password, $login . '@example.test' );
if ( is_wp_error( $user ) ) {
	throw new RuntimeException( 'Could not create disposable admin.' );
}
( new WP_User( $user ) )->set_role( 'administrator' );
$path = WP_PLUGIN_DIR . '/akismet/akismet.php';
$akismetVersion = get_plugin_data( $path, false, false )['Version'];
$original = file_get_contents( $path );
if ( false === $original ) {
	throw new RuntimeException( 'Akismet test file missing.' );
}
file_put_contents( $path, $original . "\n/* disposable repair HTTP test */\n" );
$options = new WordPressOptions();
$options->delete( 'amazing_security_integrity_active' );
$scanId = wp_generate_uuid4();
$cursor = new IntegrityCursor( $scanId );
$cursor->findings[] = new CheckResult( 'integrity-file', 'warn', 'Release file differs.', 'https://downloads.wordpress.org/plugin-checksums/akismet/' . $akismetVersion . '.json', new DateTimeImmutable(), 'high', 'complete', array( 'package_type' => 'plugin', 'package' => 'akismet:' . $akismetVersion, 'path' => 'akismet.php', 'reason' => 'ok', 'observed_sha256' => hash_file( 'sha256', $path ) ), $id );
$store = new WordPressIntegrityStore( $options );
if ( ! $store->begin( $scanId, $cursor ) ) {
	throw new RuntimeException( 'Could not create repair finding.' );
}
$store->saveProgress( $scanId, new IntegrityStep( $cursor, true ) );
echo 'Fixture ready.';
