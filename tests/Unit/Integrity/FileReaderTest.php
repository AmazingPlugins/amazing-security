<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Integrity;

use AmazingPlugins\Security\Integrity\FileReader;
use AmazingPlugins\Security\Integrity\IntegrityBudget;
use PHPUnit\Framework\TestCase;

final class FileReaderTest extends TestCase {
	private string $root;

	protected function setUp(): void {
		$this->root = sys_get_temp_dir() . '/amsec-' . bin2hex( random_bytes( 5 ) );
		mkdir( $this->root );
		file_put_contents( $this->root . '/safe.php', 'safe' );
	}

	protected function tearDown(): void {
		@unlink( $this->root . '/escape.php' );
		@unlink( $this->root . '/safe.php' );
		@rmdir( $this->root );
	}

	public function test_hashes_contained_file_and_rejects_escape(): void {
		$budget = new IntegrityBudget();
		$reader = new FileReader();
		self::assertSame( md5( 'safe' ), $reader->hash( $this->root, 'safe.php', 'md5', $budget )->digest );
		self::assertSame( 'unsafe', $reader->hash( $this->root, '../safe.php', 'md5', $budget )->state );
		self::assertSame( 'missing', $reader->hash( $this->root, 'missing.php', 'md5', $budget )->state );
	}

	public function test_symlink_is_never_hashed(): void {
		symlink( '/etc/passwd', $this->root . '/escape.php' );
		$result = ( new FileReader() )->hash( $this->root, 'escape.php', 'md5', new IntegrityBudget() );
		self::assertSame( 'unsafe', $result->state );
		self::assertNull( $result->digest );
	}

	public function test_package_root_symlink_is_not_followed(): void {
		$link = $this->root . '-link';
		symlink( $this->root, $link );
		try {
			$result = ( new FileReader() )->hash( $link, 'safe.php', 'md5', new IntegrityBudget() );
			self::assertSame( 'unsafe', $result->state );
		} finally {
			unlink( $link );
		}
	}

	public function test_budget_interrupts_large_file(): void {
		file_put_contents( $this->root . '/safe.php', str_repeat( 'x', 150000 ) );
		$budget = new IntegrityBudget( 250, 65536 );
		$result = ( new FileReader() )->hash( $this->root, 'safe.php', 'md5', $budget );
		self::assertSame( 'budget', $result->state );
		self::assertSame( 0, $budget->remainingBytes() );
	}

	public function test_file_exactly_at_byte_limit_can_complete(): void {
		file_put_contents( $this->root . '/safe.php', str_repeat( 'x', 65536 ) );
		$result = ( new FileReader() )->hash( $this->root, 'safe.php', 'md5', new IntegrityBudget( 250, 65536 ) );
		self::assertSame( 'ok', $result->state );
	}
}
