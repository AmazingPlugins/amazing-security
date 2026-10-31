<?php

// Execute with WP-CLI eval-file against a disposable WordPress site.
use AmazingPlugins\Security\Admin\AdminPage;
use AmazingPlugins\Security\Integrity\FileReader;
use AmazingPlugins\Security\Integrity\IntegrityBudget;
use AmazingPlugins\Security\Integrity\IntegrityCursor;
use AmazingPlugins\Security\Integrity\IntegrityRunner;
use AmazingPlugins\Security\Integrity\IntegrityTarget;
use AmazingPlugins\Security\Integrity\WordPressHttpClient;
use AmazingPlugins\Security\Integrity\WordPressIntegrityStore;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Integrity\WordPressOrgManifestProvider;
use AmazingPlugins\Security\Scan\ScanContext;

if ( false !== get_option( 'amsec_security_scanner_integrity_active', false ) || false !== get_option( 'amsec_security_scanner_integrity_completed', false ) ) {
	throw new RuntimeException( 'Activation performed an integrity scan.' );
}

$outbound      = 0;
$countRequests = static function ( $preempt ) use ( &$outbound ) {
	++$outbound;
	return $preempt;
};
add_filter( 'pre_http_request', $countRequests );
wp_set_current_user( 1 );
ob_start();
( new AdminPage() )->render();
$html = ob_get_clean();
remove_filter( 'pre_http_request', $countRequests );
if ( 0 !== $outbound || ! str_contains( $html, 'Run integrity scan' ) ) {
	throw new RuntimeException( 'Viewing admin page contacted a remote host or omitted scan control.' );
}

global $wp_version, $wp_local_package;
$locale   = isset( $wp_local_package ) && $wp_local_package ? $wp_local_package : 'en_US';
$provider = new WordPressOrgManifestProvider( new WordPressHttpClient() );
$core     = $provider->core( (string) $wp_version, $locale );
if ( null === $core->manifest || ! isset( $core->manifest->files['wp-includes/version.php'] ) ) {
	throw new RuntimeException( 'Core manifest unavailable: ' . $core->reason );
}
$reader = new FileReader();
$match  = $reader->hash( ABSPATH, 'wp-includes/version.php', 'md5', new IntegrityBudget() );
if ( 'ok' !== $match->state || ! in_array( $match->digest, $core->manifest->files['wp-includes/version.php'], true ) ) {
	throw new RuntimeException( 'Clean core file did not match manifest.' );
}
$runner = new IntegrityRunner( $reader );
$step   = $runner->step( array( new IntegrityTarget( $core->manifest, ABSPATH ) ), new IntegrityCursor( 'fixture' ), new ScanContext( null, 5 ) );
if ( $step->finished || 5 !== $step->cursor->processed || 0 === $step->cursor->matched ) {
	throw new RuntimeException( 'Expected bounded partial step over clean core files.' );
}
$store = new WordPressIntegrityStore( new WordPressOptions() );
if ( ! $store->begin( 'fixture', $step->cursor ) ) {
	throw new RuntimeException( 'Could not start integrity store.' );
}
$store->saveProgress( 'fixture', $step );
if ( null === $store->latestProgress() || null !== $store->latestCompleted() ) {
	throw new RuntimeException( 'Partial scan replaced completed report.' );
}

echo 'Integrity smoke: PHP ' . PHP_VERSION . ', core ' . $wp_version . ', clean file, bounded cursor, quiet admin view, and separate progress passed.' . PHP_EOL;
