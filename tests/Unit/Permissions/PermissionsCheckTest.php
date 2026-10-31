<?php
namespace AmazingPlugins\Security\Tests\Unit\Permissions;

use AmazingPlugins\Security\Checks\FilesystemPermissionsCheck;
use AmazingPlugins\Security\Scan\ScanContext;
use PHPUnit\Framework\TestCase;
final class PermissionsCheckTest extends TestCase {
	public function test_world_write_and_config_read_have_distinct_meanings(): void {
		self::assertSame( 'warn', FilesystemPermissionsCheck::modeState( 0100666, false ) );
		self::assertSame( 'warn', FilesystemPermissionsCheck::modeState( 0100644, true ) );
		self::assertSame( 'pass', FilesystemPermissionsCheck::modeState( 0100644, false ) );
		self::assertSame( 'pass', FilesystemPermissionsCheck::modeState( 0040755, false ) );
		self::assertSame( 'unknown', FilesystemPermissionsCheck::modeState( 0120777, false ) );
		self::assertSame( 'unknown', FilesystemPermissionsCheck::modeState( null, false ) );
	}
	public function test_local_mode_results_do_not_disclose_paths_or_claim_acl_coverage(): void {
		$path = realpath( tempnam( sys_get_temp_dir(), 'amsec-mode-' ) );
		chmod( $path, 0600 );
		try {
			$rows = ( new FilesystemPermissionsCheck( array( 'configuration' => $path ) ) )->run( new ScanContext() );
			self::assertCount( 1, $rows );
			self::assertSame( 'pass', $rows[0]->state );
			self::assertSame( 'partial', $rows[0]->coverage );
			self::assertSame( '0600', $rows[0]->evidence['mode'] );
			self::assertStringNotContainsString( $path, json_encode( $rows[0]->toArray() ) );
		} finally {
			unlink( $path );}
	}
	public function test_symlink_is_unknown_and_never_followed(): void {
		$path = realpath( tempnam( sys_get_temp_dir(), 'amsec-mode-' ) );
		$link = $path . '.link';
		symlink( $path, $link );
		try {
			$row = ( new FilesystemPermissionsCheck( array( 'configuration' => $link ) ) )->run( new ScanContext() )[0];
			self::assertSame( 'unknown', $row->state );
			self::assertNull( $row->evidence['mode'] );
		} finally {
			unlink( $link );
				unlink( $path );}
	}
}
