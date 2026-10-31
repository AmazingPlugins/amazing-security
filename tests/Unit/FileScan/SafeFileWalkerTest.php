<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\FileScan;

use AmazingPlugins\Security\FileScan\FileScanCursor;
use AmazingPlugins\Security\FileScan\FileScanTarget;
use AmazingPlugins\Security\FileScan\SafeFileWalker;
use AmazingPlugins\Security\Integrity\Manifest;
use AmazingPlugins\Security\Scan\ScanContext;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class SafeFileWalkerTest extends TestCase {
	private array $roots = array();

	private function root(): string {
		$root = sys_get_temp_dir() . '/amsec-walk-' . bin2hex( random_bytes( 6 ) );
		mkdir( $root );
		$this->roots[] = $root;
		return $root;
	}

	protected function tearDown(): void {
		foreach ( $this->roots as $root ) {
			$walk = static function ( string $path ) use ( &$walk ): void {
				foreach ( scandir( $path ) as $entry ) {
					if ( '.' === $entry || '..' === $entry ) {
						continue;
					}
					$child = $path . '/' . $entry;
					if ( is_dir( $child ) && ! is_link( $child ) ) {
						$walk( $child );
					} else {
						unlink( $child );
					}
				}
				rmdir( $path );
			};
			$walk( $root );
		}
	}

	private function target( string $root, string $kind, ?array $files = null ): FileScanTarget {
		$manifest = null === $files ? null : new Manifest( $kind, 'demo:1.0', 'https://wordpress.org/', new DateTimeImmutable(), 'sha256', $files );
		return new FileScanTarget( 'demo:1.0', $kind, $root, $manifest );
	}

	public function test_reports_extra_executable_and_asset_in_plugin(): void {
		$root = $this->root();
		mkdir( $root . '/nested' );
		file_put_contents( $root . '/known.php', 'known' );
		file_put_contents( $root . '/nested/extra.php', 'extra' );
		file_put_contents( $root . '/extra.css', 'css' );
		$step = ( new SafeFileWalker() )->step( array( $this->target( $root, 'plugin', array( 'known.php' => array( hash( 'sha256', 'known' ) ) ) ) ), new FileScanCursor( 'scan-1' ), new ScanContext() );
		self::assertTrue( $step->finished );
		self::assertSame( array( 'nested/extra.php' ), $step->extraExecutablePaths() );
		self::assertSame( 2, count( array_filter( $step->observations, static fn( array $item ): bool => $item['extra'] ) ) );
	}

	public function test_core_excludes_configuration_and_content_but_finds_root_extra(): void {
		$root = $this->root();
		mkdir( $root . '/wp-content' );
		file_put_contents( $root . '/wp-content/hidden.php', 'x' );
		file_put_contents( $root . '/wp-config.php', 'secret' );
		file_put_contents( $root . '/extra.php', 'x' );
		$step = ( new SafeFileWalker() )->step( array( $this->target( $root, 'core', array() ) ), new FileScanCursor( 'scan-1' ), new ScanContext() );
		self::assertSame( array( 'extra.php' ), $step->extraExecutablePaths() );
		self::assertSame( 2, $step->cursor->excluded );
	}

	public function test_skips_directory_symlink_without_reading_target(): void {
		$root    = $this->root();
		$outside = $this->root();
		file_put_contents( $outside . '/outside.php', 'secret' );
		symlink( $outside, $root . '/linked' );
		$step = ( new SafeFileWalker() )->step( array( $this->target( $root, 'plugin' ) ), new FileScanCursor( 'scan-1' ), new ScanContext() );
		self::assertSame( array(), $step->observations );
		self::assertSame( 1, $step->cursor->unknown );
	}

	public function test_resumes_after_250_files_without_duplicate(): void {
		$root = $this->root();
		for ( $i = 0; $i < 251; ++$i ) {
			file_put_contents( $root . '/file-' . sprintf( '%03d', $i ) . '.php', 'x' );
		}
		$target = $this->target( $root, 'uploads' );
		$walker = new SafeFileWalker();
		$first  = $walker->step( array( $target ), new FileScanCursor( 'scan-1' ), new ScanContext( null, 250 ) );
		$second = ( new SafeFileWalker() )->step( array( $target ), $first->cursor, new ScanContext() );
		self::assertFalse( $first->finished );
		self::assertTrue( $second->finished );
		self::assertCount( 250, $first->observations );
		self::assertCount( 1, $second->observations );
		self::assertSame( 251, count( array_unique( array_column( array_merge( $first->observations, $second->observations ), 'path' ) ) ) );
	}

	public function test_missing_root_is_unknown(): void {
		$step = ( new SafeFileWalker() )->step( array( $this->target( '/does/not/exist', 'plugin' ) ), new FileScanCursor( 'scan-1' ), new ScanContext() );
		self::assertTrue( $step->cursor->partial );
		self::assertGreaterThan( 0, $step->cursor->unknown );
	}

	public function test_changed_directory_between_steps_cannot_claim_complete_coverage(): void {
		$root = $this->root();
		file_put_contents( $root . '/one.php', 'x' );
		file_put_contents( $root . '/two.php', 'x' );
		$target = $this->target( $root, 'uploads' );
		$walker = new SafeFileWalker();
		$first  = $walker->step( array( $target ), new FileScanCursor( 'scan-1' ), new ScanContext( null, 1 ) );
		file_put_contents( $root . '/three.php', 'x' );
		$second = $walker->step( array( $target ), $first->cursor, new ScanContext() );
		self::assertTrue( $second->cursor->partial );
		self::assertGreaterThan( 0, $second->cursor->unknown );
	}

	public function test_manifest_change_refuses_resume(): void {
		$root = $this->root();
		file_put_contents( $root . '/one.php', 'x' );
		file_put_contents( $root . '/two.php', 'x' );
		$firstTarget   = $this->target( $root, 'plugin', array( 'one.php' => array( hash( 'sha256', 'x' ) ) ) );
		$first         = ( new SafeFileWalker() )->step( array( $firstTarget ), new FileScanCursor( 'scan-1' ), new ScanContext( null, 1 ) );
		$changedTarget = $this->target( $root, 'plugin', array( 'one.php' => array( hash( 'sha256', 'changed' ) ) ) );
		$second        = ( new SafeFileWalker() )->step( array( $changedTarget ), $first->cursor, new ScanContext() );
		self::assertTrue( $second->cursor->partial );
		self::assertSame( array(), $second->observations );
	}

	public function test_single_file_target_reads_only_its_file_once(): void {
		$root = $this->root();
		file_put_contents( $root . '/hello.php', '<?php echo 1;' );
		file_put_contents( $root . '/other.php', '<?php echo 2;' );
		$target = new FileScanTarget( 'hello.php:1.0', 'plugin', $root, null, 'hello.php' );
		$first  = ( new SafeFileWalker() )->step( array( $target ), new FileScanCursor( 'scan-1' ), new ScanContext( null, 1 ) );
		$second = ( new SafeFileWalker() )->step( array( $target ), $first->cursor, new ScanContext() );
		self::assertSame( array( 'hello.php' ), array_column( $first->observations, 'path' ) );
		self::assertSame( array(), $second->observations );
		self::assertSame( 1, $second->cursor->processed );
	}
}
