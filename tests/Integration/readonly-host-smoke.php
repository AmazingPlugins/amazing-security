<?php
// Run in an ephemeral read-only Docker container with the installed WordPress volume mounted read-only.
spl_autoload_register( static function ( string $class ) { $prefix = 'AmazingPlugins\\Security\\'; if ( str_starts_with( $class, $prefix ) ) { require $GLOBALS['argv'][1] . '/src/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php'; } } );
use AmazingPlugins\Security\FileScan\BoundedContentReader;
use AmazingPlugins\Security\Integrity\IntegrityBudget;
use AmazingPlugins\Security\Repair\AtomicPluginRepair;
use AmazingPlugins\Security\Repair\RepairBytes;
$root = $argv[1];
$read = ( new BoundedContentReader() )->read( $root, 'amazing-security.php', new IntegrityBudget() );
if ( 'ok' !== $read->state ) { throw new RuntimeException( 'Read-only host could not inspect a plugin file.' ); }
$backup = '/tmp/amsec-readonly-' . bin2hex( random_bytes( 5 ) );
mkdir( $backup, 0700 );
try {
    $before = hash_file( 'sha256', $root . '/amazing-security.php' );
    $bytes = new RepairBytes( 'fixture', hash( 'sha256', 'fixture' ), 'https://downloads.wordpress.org/plugin/fixture.zip' );
    $result = ( new AtomicPluginRepair( $root, $backup ) )->apply( 'amazing-security.php', $before, $bytes->sha256, $bytes );
    if ( null !== $result || $before !== hash_file( 'sha256', $root . '/amazing-security.php' ) ) { throw new RuntimeException( 'Read-only host repair refusal failed.' ); }
    echo 'Read-only site: file inspection succeeds; repair refuses without changing bytes.' . PHP_EOL;
} finally { rmdir( $backup ); }
