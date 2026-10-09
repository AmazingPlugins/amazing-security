<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\Recovery;

use AmazingPlugins\Security\Free\Recovery\Approval;
use AmazingPlugins\Security\Free\Recovery\DirectoryModes;
use PHPUnit\Framework\TestCase;

final class DirectoryModesTest extends TestCase {
	private string $root = '';

	private string $outside = '';

	protected function tearDown(): void {
		if ( '' !== $this->outside ) {
			$this->removeTree( $this->outside );
		}
		if ( '' !== $this->root ) {
			$this->removeTree( $this->root );
		}
	}

	public function test_symlink_is_refused(): void {
		$this->makeContent();
		$plugins = $this->root . '/plugins';
		$uploads = $this->root . '/uploads';
		chmod( $plugins, 0700 );
		rmdir( $uploads );
		symlink( $plugins, $uploads );

		$result = ( new DirectoryModes( $this->root ) )->apply( $uploads, $this->approval(), true );

		self::assertFalse( $result->ok );
		self::assertSame( '', $result->body );
		self::assertSame( 0700, fileperms( $plugins ) & 0777 );
		self::assertTrue( is_link( $uploads ) );
	}

	public function test_path_escape_is_refused(): void {
		$this->makeContent();
		$this->outside = sys_get_temp_dir() . '/amsec-out-' . bin2hex( random_bytes( 4 ) );
		mkdir( $this->outside, 0700 );
		chmod( $this->outside, 0700 );
		$uploads = $this->root . '/uploads';
		rmdir( $uploads );
		symlink( $this->outside, $uploads );
		$modes = new DirectoryModes( $this->root );

		$direct = $modes->apply( $this->outside, $this->approval(), true );
		$linked = $modes->apply( $uploads, $this->approval(), true );
		$dotted = $modes->apply( $this->root . '/uploads/../../' . basename( $this->outside ), $this->approval(), true );

		self::assertFalse( $direct->ok );
		self::assertFalse( $linked->ok );
		self::assertFalse( $dotted->ok );
		self::assertSame( 0700, fileperms( $this->outside ) & 0777 );
	}

	public function test_chmod_only_on_an_allowed_directory(): void {
		$this->makeContent();
		$uploads = $this->root . '/uploads';
		$file    = $uploads . '/note.txt';
		$nested  = $uploads . '/nested';
		file_put_contents( $file, 'x' );
		mkdir( $nested, 0700 );
		chmod( $file, 0640 );
		chmod( $nested, 0700 );
		chmod( $uploads, 0777 );
		$modes = new DirectoryModes( $this->root );

		self::assertFalse( $modes->apply( $file, $this->approval(), true )->ok );
		self::assertFalse( $modes->apply( $nested, $this->approval(), true )->ok );
		self::assertFalse( $modes->apply( $uploads, $this->approval(), false )->ok );
		self::assertFalse( $modes->apply( $uploads, new Approval( false, true, true ), true )->ok );
		self::assertSame( 0777, fileperms( $uploads ) & 0777 );

		$result = $modes->apply( $uploads, $this->approval(), true );

		self::assertTrue( $result->ok );
		self::assertSame( 0755, DirectoryModes::MODE );
		self::assertSame( 0755, fileperms( $uploads ) & 0777 );
		self::assertNotSame( 0777, fileperms( $uploads ) & 0777 );
		self::assertSame( 0640, fileperms( $file ) & 0777 );
		self::assertSame( 0700, fileperms( $nested ) & 0777 );
		self::assertSame(
			array( $this->root, $uploads, $this->root . '/plugins', $this->root . '/themes' ),
			$modes->allowedPaths()
		);
	}

	private function approval(): Approval {
		return new Approval( true, true, true );
	}

	private function makeContent(): void {
		$this->root = sys_get_temp_dir() . '/amsec-perm-' . bin2hex( random_bytes( 4 ) );
		mkdir( $this->root, 0755 );
		foreach ( array( 'uploads', 'plugins', 'themes' ) as $name ) {
			mkdir( $this->root . '/' . $name, 0755 );
		}
	}

	private function removeTree( string $path ): void {
		if ( is_link( $path ) ) {
			unlink( $path );
			return;
		}
		if ( is_file( $path ) ) {
			unlink( $path );
			return;
		}
		if ( ! is_dir( $path ) ) {
			return;
		}
		chmod( $path, 0755 );
		$items = scandir( $path );
		if ( is_array( $items ) ) {
			foreach ( $items as $item ) {
				if ( '.' === $item || '..' === $item ) {
					continue;
				}
				$this->removeTree( $path . '/' . $item );
			}
		}
		rmdir( $path );
	}
}
