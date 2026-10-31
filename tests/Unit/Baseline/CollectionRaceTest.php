<?php
namespace AmazingPlugins\Security\Tests\Unit\Baseline;

use AmazingPlugins\Security\Baseline\ManifestBuilder;
use PHPUnit\Framework\TestCase;
final class CollectionRaceTest extends TestCase {
	public function test_earlier_file_changed_while_later_file_is_read_refuses_collection(): void {
		$root = realpath( sys_get_temp_dir() ) . '/amsec-collection-race-' . bin2hex( random_bytes( 4 ) );
		mkdir( $root, 0700 );
		file_put_contents( $root . '/a.php', '<?php return 1;' );
		file_put_contents( $root . '/b.php', '<?php return 2;' );
		$callback                     = null;
		$callback                     = static function ( $handle ) use ( $root, &$callback ) {
			if ( str_ends_with( stream_get_meta_data( $handle )['uri'], '/b.php' ) ) {
				file_put_contents( $root . '/a.php', '<?php return 3;' );
				touch( $root . '/a.php', time() + 10 );
			} else {
				$GLOBALS['amsec_reader_race'] = $callback;
			}};
		$GLOBALS['amsec_reader_race'] = $callback;
		try {
			$this->expectException( \RuntimeException::class );
			( new ManifestBuilder() )->collect( $root );
		} finally {
			unset( $GLOBALS['amsec_reader_race'] );
			unlink( $root . '/a.php' );
			unlink( $root . '/b.php' );
			rmdir( $root );}
	}
	public function test_entries_added_during_traversal_refuse_complete_collection(): void {
		$root = realpath( sys_get_temp_dir() ) . '/amsec-collection-race-' . bin2hex( random_bytes( 4 ) );
		mkdir( $root, 0700 );
		file_put_contents( $root . '/a.php', '<?php return 1;' );
		$GLOBALS['amsec_reader_race'] = static function () use ( $root ) {
			file_put_contents( $root . '/added.php', '<?php return 2;' );
		};
		try {
			$this->expectException( \RuntimeException::class );
			( new ManifestBuilder() )->collect( $root );
		} finally {
			unset( $GLOBALS['amsec_reader_race'] );
			unlink( $root . '/a.php' );
			unlink( $root . '/added.php' );
			rmdir( $root );}
	}
}
