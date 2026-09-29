<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\FileScan;

use AmazingPlugins\Security\FileScan\BoundedContentReader;
use AmazingPlugins\Security\FileScan\FileScanCursor;
use AmazingPlugins\Security\FileScan\FileScanTarget;
use AmazingPlugins\Security\FileScan\SafeFileWalker;
use AmazingPlugins\Security\Integrity\IntegrityBudget;
use AmazingPlugins\Security\Scan\ScanContext;
use PHPUnit\Framework\TestCase;

final class BoundedContentReaderTest extends TestCase {
	private array $paths = array();

	private function root(): string {
		$root = sys_get_temp_dir() . '/amsec-read-' . bin2hex( random_bytes( 6 ) );
		mkdir( $root );
		$this->paths[] = $root;
		return $root;
	}

	protected function tearDown(): void {
		foreach ( $this->paths as $root ) {
			foreach ( scandir( $root ) as $item ) {
				if ( '.' !== $item && '..' !== $item ) {
					unlink( $root . '/' . $item );
				}
			}
			rmdir( $root );
		}
	}

	public function test_reads_contained_file_and_returns_digest_without_serialized_contents(): void {
		$root = $this->root();
		file_put_contents( $root . '/code.php', '<?php echo 1;' );
		$result = ( new BoundedContentReader() )->read( $root, 'code.php', new IntegrityBudget() );
		self::assertSame( 'ok', $result->state );
		self::assertSame( '<?php echo 1;', $result->bytes );
		self::assertSame( hash( 'sha256', '<?php echo 1;' ), $result->sha256 );
		self::assertStringNotContainsString( '<?php echo 1;', json_encode( $result->toArray() ) );
	}

	public function test_rejects_symlink_and_parent_escape(): void {
		$root = $this->root();
		symlink( '/etc/passwd', $root . '/linked.php' );
		$reader = new BoundedContentReader();
		self::assertSame( 'unsafe', $reader->read( $root, 'linked.php', new IntegrityBudget() )->state );
		self::assertSame( 'unsafe', $reader->read( $root, '../etc/passwd', new IntegrityBudget() )->state );
	}

	public function test_oversized_file_and_step_budget_are_unknown(): void {
		$root = $this->root();
		file_put_contents( $root . '/large.php', str_repeat( 'x', 2097153 ) );
		file_put_contents( $root . '/small.php', 'hello' );
		$reader = new BoundedContentReader();
		self::assertSame( 'oversized', $reader->read( $root, 'large.php', new IntegrityBudget() )->state );
		self::assertSame( 'budget', $reader->read( $root, 'small.php', new IntegrityBudget( 1, 4 ) )->state );
	}

	public function test_file_replaced_after_inventory_is_not_read(): void {
		$root = $this->root();
		file_put_contents( $root . '/code.php', '<?php echo 1;' );
		$step = ( new SafeFileWalker() )->step( array( new FileScanTarget( 'uploads', 'uploads', $root ) ), new FileScanCursor( 'scan-1' ), new ScanContext() );
		self::assertCount( 1, $step->observations );
		unlink( $root . '/code.php' );
		symlink( '/etc/passwd', $root . '/code.php' );
		self::assertSame( 'unsafe', ( new BoundedContentReader() )->read( $root, $step->observations[0]['path'], new IntegrityBudget() )->state );
	}
}
