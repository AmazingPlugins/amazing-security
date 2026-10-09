<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\Recovery;

use AmazingPlugins\Security\Free\Recovery\Approval;
use AmazingPlugins\Security\Free\Recovery\CoreFileRepair;
use PHPUnit\Framework\TestCase;

final class CoreFileRepairTest extends TestCase {
	private string $root = '';

	private string $backup = '';

	private string $outside = '';

	protected function tearDown(): void {
		foreach ( array( $this->outside, $this->backup, $this->root ) as $path ) {
			if ( '' !== $path ) {
				$this->removeTree( $path );
			}
		}
	}

	public function test_symlink_is_refused(): void {
		$this->makeInstall();
		$this->outside = sys_get_temp_dir() . '/amsec-file-' . bin2hex( random_bytes( 4 ) );
		file_put_contents( $this->outside, 'outside' );
		$link = $this->root . '/wp-includes/version.php';
		unlink( $link );
		symlink( $this->outside, $link );

		$result = $this->repair()->replace( 'wp-includes/version.php', hash( 'sha256', 'new' ), 'new', $this->approval(), true );

		self::assertFalse( $result->ok );
		self::assertSame( 'outside', (string) file_get_contents( $this->outside ) );
		self::assertTrue( is_link( $link ) );
	}

	public function test_path_escape_is_refused(): void {
		$this->makeInstall();
		$config = $this->root . '/wp-config.php';
		file_put_contents( $config, 'config' );

		$result = $this->repair()->replace( 'wp-includes/../../wp-config.php', hash( 'sha256', 'new' ), 'new', $this->approval(), true );

		self::assertFalse( $result->ok );
		self::assertSame( 'config', (string) file_get_contents( $config ) );
	}

	public function test_refuses_hash_mismatch(): void {
		$this->makeInstall();
		$target = $this->root . '/wp-includes/version.php';
		file_put_contents( $target, 'old' );

		$result = $this->repair()->replace( 'wp-includes/version.php', hash( 'sha256', 'new' ), 'different', $this->approval(), true );

		self::assertFalse( $result->ok );
		self::assertSame( 'old', (string) file_get_contents( $target ) );
		self::assertSame( array(), glob( $this->backup . '/*' ) );
	}

	public function test_replaces_file_when_hash_matches_and_keeps_a_backup(): void {
		$this->makeInstall();
		$target = $this->root . '/wp-content/themes/theme/style.css';
		file_put_contents( $target, 'old' );
		$bytes = 'new-theme';

		$result = $this->repair()->replace( 'wp-content/themes/theme/style.css', hash( 'sha256', $bytes ), $bytes, $this->approval(), true );

		self::assertTrue( $result->ok );
		self::assertSame( $bytes, (string) file_get_contents( $target ) );
		$saved = glob( $this->backup . '/*.bak' );
		self::assertIsArray( $saved );
		self::assertCount( 1, $saved );
		self::assertSame( 'old', (string) file_get_contents( (string) $saved[0] ) );
	}

	private function repair(): CoreFileRepair {
		return new CoreFileRepair( $this->root, $this->root . '/wp-content/themes/theme', $this->backup );
	}

	private function approval(): Approval {
		return new Approval( true, true, true );
	}

	private function makeInstall(): void {
		$this->root   = sys_get_temp_dir() . '/amsec-site-' . bin2hex( random_bytes( 4 ) );
		$this->backup = sys_get_temp_dir() . '/amsec-bak-' . bin2hex( random_bytes( 4 ) );
		mkdir( $this->root, 0755 );
		mkdir( $this->backup, 0700 );
		foreach ( array( 'wp-includes', 'wp-admin', 'wp-content/themes/theme', 'wp-content/plugins', 'wp-content/uploads' ) as $dir ) {
			mkdir( $this->root . '/' . $dir, 0755, true );
		}
		file_put_contents( $this->root . '/wp-includes/version.php', 'core' );
		file_put_contents( $this->root . '/wp-content/themes/theme/style.css', 'theme' );
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
