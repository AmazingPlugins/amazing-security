<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\Recovery;

use AmazingPlugins\Security\Free\Recovery\Guard;
use PHPUnit\Framework\TestCase;

final class GuardTest extends TestCase {
	public function test_symlink_and_escape_are_refused(): void {
		$dir  = sys_get_temp_dir() . '/amsec-guard-' . bin2hex( random_bytes( 4 ) );
		$sub  = $dir . '/uploads';
		$link = $dir . '/link';
		mkdir( $sub, 0700, true );
		symlink( $sub, $link );
		$real = realpath( $sub );
		self::assertIsString( $real );
		self::assertFalse( Guard::directoryAllowed( $link, $dir, array( $real ) ) );
		self::assertTrue( Guard::directoryAllowed( $sub, $dir, array( $real ) ) );
		self::assertFalse( Guard::directoryAllowed( $dir . '/missing', $dir, array( $real ) ) );
		unlink( $link );
		rmdir( $sub );
		rmdir( $dir );
	}

	public function test_repair_and_delete_paths(): void {
		self::assertFalse( Guard::repairRelative( '../wp-includes/index.php' ) );
		self::assertTrue( Guard::repairRelative( 'wp-includes/index.php' ) );
		self::assertFalse( Guard::deleteRelative( 'wp-content/uploads/a.php', 'delete' ) );
		self::assertFalse( Guard::deleteRelative( '../wp-content/uploads/a.php', 'DELETE' ) );
		self::assertTrue( Guard::deleteRelative( 'wp-content/uploads/a.php', 'DELETE' ) );
	}

	public function test_hash_mismatch_and_table_cap(): void {
		self::assertTrue( Guard::bytesMatch( 'abc', hash( 'sha256', 'abc' ) ) );
		self::assertFalse( Guard::bytesMatch( 'abc', hash( 'sha256', 'nope' ) ) );
		self::assertFalse( Guard::tableCap( 0 ) );
		self::assertFalse( Guard::tableCap( 51 ) );
		self::assertTrue( Guard::tableCap( 50 ) );
	}
}
