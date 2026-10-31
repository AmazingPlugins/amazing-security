<?php

// Run with WP-CLI eval-file or after wp-load.php on a disposable site.
use AmazingPlugins\Security\Integrity\FileReader;
use AmazingPlugins\Security\Integrity\HttpClient;
use AmazingPlugins\Security\Integrity\HttpResult;
use AmazingPlugins\Security\Integrity\IntegrityCursor;
use AmazingPlugins\Security\Integrity\IntegrityRunner;
use AmazingPlugins\Security\Integrity\IntegrityTarget;
use AmazingPlugins\Security\Integrity\Manifest;
use AmazingPlugins\Security\Integrity\TargetDiscovery;
use AmazingPlugins\Security\Integrity\WordPressOrgManifestProvider;
use AmazingPlugins\Security\Scan\ScanContext;

$root = sys_get_temp_dir() . '/amsec-cases-' . bin2hex( random_bytes( 4 ) );
mkdir( $root );
file_put_contents( $root . '/clean.php', 'clean' );
file_put_contents( $root . '/changed.php', 'changed' );
symlink( '/etc/passwd', $root . '/link.php' );
$manifest = new Manifest( 'core', 'fixture:en_US', 'https://api.wordpress.org/core/checksums/1.0/', new DateTimeImmutable(), 'md5', array( 'clean.php' => array( md5( 'clean' ) ), 'changed.php' => array( md5( 'original' ) ), 'missing.php' => array( md5( 'missing' ) ), 'link.php' => array( md5( 'target' ) ) ) );
$runner = new IntegrityRunner( new FileReader() );
$target = new IntegrityTarget( $manifest, $root );
$first = $runner->step( array( $target ), new IntegrityCursor( 'fixture-cases' ), new ScanContext( null, 2 ) );
$second = $runner->step( array( $target ), $first->cursor, new ScanContext() );
if ( $first->finished || ! $second->finished || 1 !== $second->cursor->matched || 3 !== count( $second->cursor->findings ) ) {
	throw new RuntimeException( 'Clean, changed, missing, symlink or resume result differed.' );
}
if ( str_contains( wp_json_encode( $second->cursor->toArray() ), $root ) ) {
	throw new RuntimeException( 'Stored cursor contains an absolute path.' );
}
$client = new class implements HttpClient {
	public function get( string $url, int $maxBytes ): HttpResult { return new HttpResult( 404, '' ); }
};
$provider = new WordPressOrgManifestProvider( $client );
if ( 'unavailable' !== $provider->plugin( 'unsupported-example', '1.0' )->reason ) {
	throw new RuntimeException( 'Unavailable manifest did not produce an unknown state.' );
}
$discovery = ( new TargetDiscovery( $provider ) )->discover( '6.6', 'en_US', $root, array( array( 'slug' => 'premium-example', 'version' => '1.0', 'root' => $root, 'update_uri' => 'https://vendor.example/' ) ) );
if ( 2 !== count( $discovery->findings ) || ! $discovery->partial ) {
	throw new RuntimeException( 'Premium package or unavailable core appeared verified.' );
}
unlink( $root . '/clean.php' );
unlink( $root . '/changed.php' );
unlink( $root . '/link.php' );
rmdir( $root );
echo 'Integrity cases: PHP ' . PHP_VERSION . ', changed, missing, symlink, unavailable, premium, and resume passed.' . PHP_EOL;
