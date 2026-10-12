<?php
namespace AmazingPlugins\Security\Tests\Unit\Files;

use AmazingPlugins\Security\Files\AtomicWrite;
use PHPUnit\Framework\TestCase;

final class AtomicWriteTest extends TestCase {
	private string $dir = '';

	protected function setUp(): void {
		$this->dir = sys_get_temp_dir() . '/amsec-atomic-' . bin2hex( random_bytes( 4 ) );
		mkdir( $this->dir, 0755 );
	}

	protected function tearDown(): void {
		foreach ( glob( $this->dir . '/{,.}*', GLOB_BRACE ) ?: array() as $item ) {
			if ( is_file( $item ) || is_link( $item ) ) {
				unlink( $item );
			}
		}
		rmdir( $this->dir );
	}

	public function test_replaces_content_keeps_mode_and_leaves_no_temp_file(): void {
		$path = $this->dir . '/.htaccess';
		file_put_contents( $path, 'old' );
		chmod( $path, 0640 );
		self::assertTrue( AtomicWrite::write( $path, 'new' ) );
		self::assertSame( 'new', file_get_contents( $path ) );
		self::assertSame( 0640, fileperms( $path ) & 0777 );
		self::assertSame( array( '.htaccess' ), array_values( array_diff( scandir( $this->dir ), array( '.', '..' ) ) ) );
	}

	public function test_creates_a_new_file_with_normal_permissions(): void {
		$path = $this->dir . '/.htaccess';
		self::assertTrue( AtomicWrite::write( $path, 'rule' ) );
		self::assertSame( 0644, fileperms( $path ) & 0777 );
	}

	public function test_refuses_a_symlink_target_and_leaves_the_real_file_alone(): void {
		$real = $this->dir . '/real.txt';
		file_put_contents( $real, 'keep' );
		$link = $this->dir . '/.htaccess';
		symlink( $real, $link );
		self::assertFalse( AtomicWrite::write( $link, 'changed' ) );
		self::assertSame( 'keep', file_get_contents( $real ) );
	}

	public function test_refuses_oversized_content(): void {
		$path = $this->dir . '/.htaccess';
		file_put_contents( $path, 'small' );
		self::assertFalse( AtomicWrite::write( $path, str_repeat( 'x', AtomicWrite::MAX_BYTES + 1 ) ) );
		self::assertSame( 'small', file_get_contents( $path ) );
	}
}
