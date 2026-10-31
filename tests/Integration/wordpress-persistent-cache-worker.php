<?php
// Disposable Redis test only. Invoked by wordpress-persistent-cache-lock.sh in independent processes.
if ( ! defined( 'WP_CLI' ) || ! WP_CLI || DB_HOST !== 'amsec-next-db' || DB_NAME !== 'wordpress' || ! wp_using_ext_object_cache() ) { throw new RuntimeException( 'Expected disposable WordPress with persistent cache.' ); }
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Integrity\WorkerLock;
$id = getenv( 'AMSEC_CACHE_TEST_ID' );
$mode = getenv( 'AMSEC_CACHE_TEST_MODE' );
if ( ! is_string( $id ) || ! preg_match( '/^[a-f0-9]{16}$/D', $id ) ) { throw new RuntimeException( 'Invalid fixture identity.' ); }
$key = 'amsec_cache_test_' . $id;
$directory = WP_CONTENT_DIR . '/amsec-cache-test-' . $id;
$options = new WordPressOptions();
if ( 'seed' === $mode ) {
    if ( ! wp_cache_set( $key, 'persisted', 'amsec-integration', 120 ) ) { throw new RuntimeException( 'Could not seed persistent cache.' ); }
    return;
}
if ( 'read' === $mode ) {
    if ( 'persisted' !== wp_cache_get( $key, 'amsec-integration' ) ) { throw new RuntimeException( 'Cache value did not survive independent process.' ); }
    wp_cache_delete( $key, 'amsec-integration' );
    echo 'Persistent cache survives independent process.' . PHP_EOL;
    return;
}
$lock = new WorkerLock( $options, $key );
if ( 'after' === $mode ) {
    if ( ! $lock->acquire( 'after-release' ) ) { throw new RuntimeException( 'Released lease remained unavailable.' ); }
    $lock->release();
    echo 'A later independent worker acquires and releases the lease.' . PHP_EOL;
    return;
}
if ( ! in_array( $mode, array( 'a', 'b' ), true ) || ! is_dir( $directory ) || is_link( $directory ) ) { throw new RuntimeException( 'Invalid worker mode or barrier.' ); }
$options->get( $key ); // Both workers cache absence before racing to insert the lease.
if ( false === file_put_contents( $directory . '/ready-' . $mode, 'ready' ) ) { throw new RuntimeException( 'Could not signal readiness.' ); }
$wait = static function ( string $path ): void {
    $deadline = microtime( true ) + 20;
    while ( ! is_file( $path ) && microtime( true ) < $deadline ) { clearstatcache( true, $path ); usleep( 10000 ); }
    if ( ! is_file( $path ) ) { throw new RuntimeException( 'Barrier timed out.' ); }
};
$acquired = false;
try {
    $wait( $directory . '/go' );
    $acquired = $lock->acquire( 'worker-' . $mode );
    if ( false === file_put_contents( $directory . '/result-' . $mode, $acquired ? '1' : '0' ) ) { throw new RuntimeException( 'Could not record lock result.' ); }
    if ( $acquired ) { $wait( $directory . '/release' ); }
} finally { if ( $acquired ) { $lock->release(); } }
