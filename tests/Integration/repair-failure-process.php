<?php
// Standalone PHP harness. Pass installed plugin path and mode; full modes require a 64 KiB tmpfs at /amsec-full.
spl_autoload_register( static function ( string $class ): void {
	$prefix = 'AmazingPlugins\\Security\\';
	if ( str_starts_with( $class, $prefix ) ) { require $GLOBALS['argv'][1] . '/src/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php'; }
} );
use AmazingPlugins\Security\Repair\AtomicPluginRepair;
use AmazingPlugins\Security\Repair\RepairBytes;
use AmazingPlugins\Security\Repair\RepairReceipt;

$mode = $argv[2];
if ( 'child' === $mode ) {
	$base = $argv[3];
	$repair = new AtomicPluginRepair( $base . '/site', $base . '/backup', static function (): void { posix_kill( getmypid(), 9 ); }, static function ( RepairReceipt $receipt ) use ( $base ): bool { return false !== file_put_contents( $base . '/receipt.json', json_encode( $receipt->toArray() ) ); } );
	$bytes = new RepairBytes( 'clean', hash( 'sha256', 'clean' ), 'https://downloads.wordpress.org/plugin/test.zip' );
	$repair->apply( 'file.php', hash( 'sha256', 'changed' ), $bytes->sha256, $bytes );
	exit( 1 );
}
$base = '/tmp/amsec-failure-' . bin2hex( random_bytes( 6 ) );
mkdir( $base, 0700 );
mkdir( $base . '/site', 0700 );
mkdir( $base . '/backup', 0700 );
$root = 'stage-full' === $mode ? '/amsec-full' : $base . '/site';
$backup = 'backup-full' === $mode ? '/amsec-full' : $base . '/backup';
$old = 'backup-full' === $mode ? str_repeat( 'x', 131072 ) : 'changed';
$new = 'stage-full' === $mode ? str_repeat( 'y', 131072 ) : 'clean';
file_put_contents( $root . '/file.php', $old );
try {
	if ( 'crash' === $mode ) {
		$process = proc_open( array( PHP_BINARY, __FILE__, $argv[1], 'child', $base ), array( 0 => array( 'pipe', 'r' ), 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes );
		foreach ( $pipes as $pipe ) { fclose( $pipe ); }
		$code = proc_close( $process );
		$receipt = RepairReceipt::fromArray( json_decode( file_get_contents( $base . '/receipt.json' ), true ) );
		if ( 0 === $code || null === $receipt || 'clean' !== file_get_contents( $root . '/file.php' ) || ! ( new AtomicPluginRepair( $root, $backup ) )->recover( $receipt, hash( 'sha256', 'clean' ) ) ) { throw new RuntimeException( 'Killed replacement did not retain a usable recovery record.' ); }
	} else {
		$warnings = array();
		set_error_handler( static function ( $code, $message ) use ( &$warnings ): bool { $warnings[] = $message; return true; } );
		try {
			$bytes = new RepairBytes( $new, hash( 'sha256', $new ), 'https://downloads.wordpress.org/plugin/test.zip' );
			$result = ( new AtomicPluginRepair( $root, $backup ) )->apply( 'file.php', hash( 'sha256', $old ), $bytes->sha256, $bytes );
		} finally { restore_error_handler(); }
		if ( null !== $result || ! str_contains( implode( ' ', $warnings ), 'No space left' ) ) { throw new RuntimeException( 'Expected actual ENOSPC refusal.' ); }
	}
	if ( $old !== file_get_contents( $root . '/file.php' ) ) { throw new RuntimeException( 'Original bytes were not preserved or recovered.' ); }
	echo $mode . ': original bytes preserved or recovered.' . PHP_EOL;
} finally {
	foreach ( array_unique( array( $root, $backup, $base . '/site', $base . '/backup' ) ) as $dir ) { foreach ( glob( $dir . '/*' ) ?: array() as $file ) { unlink( $file ); } }
	if ( file_exists( $base . '/receipt.json' ) ) { unlink( $base . '/receipt.json' ); }
	rmdir( $base . '/site' ); rmdir( $base . '/backup' ); rmdir( $base );
}
