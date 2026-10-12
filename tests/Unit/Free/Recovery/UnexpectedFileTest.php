<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\Recovery;

use AmazingPlugins\Security\Free\Recovery\Approval;
use AmazingPlugins\Security\Free\Recovery\UnexpectedFile;
use PHPUnit\Framework\TestCase;

final class UnexpectedFileTest extends TestCase {
	private string $root = '';

	private string $backup = '';

	protected function tearDown(): void {
		foreach ( array( $this->backup, $this->root ) as $path ) {
			if ( '' !== $path ) {
				$this->removeTree( $path );
			}
		}
	}

	public function test_refuses_a_path_with_parent_segments(): void {
		$this->makeInstall();
		$config = $this->root . '/wp-config.php';
		file_put_contents( $config, 'config' );
		$upload = $this->root . '/wp-content/uploads/note.txt';
		file_put_contents( $upload, 'keep' );

		$result = $this->files()->remove( 'wp-content/uploads/../../wp-config.php', 'DELETE', $this->approval() );

		self::assertFalse( $result->ok );
		self::assertSame( 'config', (string) file_get_contents( $config ) );
		self::assertSame( 'keep', (string) file_get_contents( $upload ) );
		self::assertSame( array(), glob( $this->backup . '/*' ) );
	}

	public function test_refuses_when_the_confirmation_phrase_is_wrong(): void {
		$this->makeInstall();
		$upload = $this->root . '/wp-content/uploads/note.txt';
		file_put_contents( $upload, 'keep' );

		$result = $this->files()->remove( 'wp-content/uploads/note.txt', 'delete', $this->approval() );

		self::assertFalse( $result->ok );
		self::assertSame( 'keep', (string) file_get_contents( $upload ) );
		self::assertSame( array(), glob( $this->backup . '/*' ) );
	}

	public function test_refuses_plugin_main_file_and_leaves_it_when_backup_fails(): void {
		$this->makeInstall();
		$main = $this->root . '/wp-content/plugins/amazing-security/amazing-security.php';
		mkdir( dirname( $main ), 0755, true );
		file_put_contents( $main, '<?php // plugin' );
		$upload = $this->root . '/wp-content/uploads/extra.txt';
		file_put_contents( $upload, 'extra' );
		chmod( $this->backup, 0555 );

		$removed = ( new UnexpectedFile( $this->root, $main, $this->backup ) )->remove( 'wp-content/plugins/amazing-security/amazing-security.php', 'DELETE', $this->approval() );
		$stuck   = ( new UnexpectedFile( $this->root, $main, $this->backup ) )->remove( 'wp-content/uploads/extra.txt', 'DELETE', $this->approval() );

		chmod( $this->backup, 0700 );
		self::assertFalse( $removed->ok );
		self::assertFileExists( $main );
		self::assertFalse( $stuck->ok );
		self::assertSame( 'extra', (string) file_get_contents( $upload ) );
	}

	public function test_moves_file_only_after_backup(): void {
		$this->makeInstall();
		$upload = $this->root . '/wp-content/uploads/extra.txt';
		file_put_contents( $upload, 'extra' );

		$result = $this->files()->remove( 'wp-content/uploads/extra.txt', 'DELETE', $this->approval() );

		self::assertTrue( $result->ok );
		self::assertFileDoesNotExist( $upload );
		$saved = glob( $this->backup . '/*.bak' );
		self::assertIsArray( $saved );
		self::assertCount( 1, $saved );
		self::assertSame( 'extra', (string) file_get_contents( (string) $saved[0] ) );
	}

	public function test_refuses_any_file_inside_this_plugins_own_folder(): void {
		$this->makeInstall();
		mkdir( $this->root . '/wp-content/plugins/amazing-security/src', 0755, true );
		file_put_contents( $this->root . '/wp-content/plugins/amazing-security/amazing-security.php', 'main' );
		$inner = $this->root . '/wp-content/plugins/amazing-security/src/Admin.php';
		file_put_contents( $inner, 'inner' );

		$result = $this->files()->remove( 'wp-content/plugins/amazing-security/src/Admin.php', 'DELETE', $this->approval() );

		self::assertFalse( $result->ok );
		self::assertFileExists( $inner );
	}

	public function test_success_message_names_where_the_backup_went(): void {
		$this->makeInstall();
		$upload = $this->root . '/wp-content/uploads/extra.txt';
		file_put_contents( $upload, 'extra' );

		$result = $this->files()->remove( 'wp-content/uploads/extra.txt', 'DELETE', $this->approval() );

		self::assertTrue( $result->ok );
		self::assertStringContainsString( $this->backup, $result->message );
	}

	private function files(): UnexpectedFile {
		return new UnexpectedFile( $this->root, $this->root . '/wp-content/plugins/amazing-security/amazing-security.php', $this->backup );
	}

	private function approval(): Approval {
		return new Approval( true, true, true );
	}

	private function makeInstall(): void {
		$this->root   = sys_get_temp_dir() . '/amsec-del-' . bin2hex( random_bytes( 4 ) );
		$this->backup = sys_get_temp_dir() . '/amsec-delbak-' . bin2hex( random_bytes( 4 ) );
		mkdir( $this->root, 0755 );
		mkdir( $this->backup, 0700 );
		foreach ( array( 'wp-content/uploads', 'wp-content/themes/theme', 'wp-content/plugins' ) as $dir ) {
			mkdir( $this->root . '/' . $dir, 0755, true );
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
