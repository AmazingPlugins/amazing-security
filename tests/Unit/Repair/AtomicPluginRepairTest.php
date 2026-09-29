<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Repair;

use AmazingPlugins\Security\Repair\AtomicPluginRepair;
use AmazingPlugins\Security\Repair\RepairBytes;
use AmazingPlugins\Security\Repair\RepairVerificationFailure;
use PHPUnit\Framework\TestCase;

final class AtomicPluginRepairTest extends TestCase {
	public function test_recovery_receipt_must_be_saved_before_replacing_file(): void {
		$seen = false;
		$repair = new AtomicPluginRepair( $this->site, $this->backup, beforeReplace: function ( $receipt ) use ( &$seen ): bool {
			$seen = true;
			self::assertSame( 'changed', file_get_contents( $this->site . '/hello.php' ) );
			self::assertSame( 'changed', file_get_contents( $receipt->backupPath ) );
			return false;
		} );
		$clean = new RepairBytes( 'clean', hash( 'sha256', 'clean' ), 'https://downloads.wordpress.org/plugin/example.zip' );
		self::assertNull( $repair->apply( 'hello.php', hash( 'sha256', 'changed' ), $clean->sha256, $clean ) );
		self::assertTrue( $seen );
		self::assertSame( 'changed', file_get_contents( $this->site . '/hello.php' ) );
		self::assertSame( array(), glob( $this->backup . '/*' ) );
	}

	public function test_concurrent_change_during_receipt_persistence_refuses_replacement(): void {
		$repair = new AtomicPluginRepair( $this->site, $this->backup, beforeReplace: function (): bool {
			file_put_contents( $this->site . '/hello.php', 'concurrent update' );
			return true;
		} );
		$clean = new RepairBytes( 'clean', hash( 'sha256', 'clean' ), 'https://downloads.wordpress.org/plugin/example.zip' );
		self::assertNull( $repair->apply( 'hello.php', hash( 'sha256', 'changed' ), $clean->sha256, $clean ) );
		self::assertSame( 'concurrent update', file_get_contents( $this->site . '/hello.php' ) );
		self::assertSame( array(), glob( $this->backup . '/*' ) );
	}

	public function test_exception_after_rename_keeps_backup_for_recovery(): void {
		$repair = new AtomicPluginRepair( $this->site, $this->backup, static function (): never { throw new \RuntimeException( 'Interrupted after rename.' ); } );
		$clean = new RepairBytes( 'clean', hash( 'sha256', 'clean' ), 'https://downloads.wordpress.org/plugin/example.zip' );
		try {
			$repair->apply( 'hello.php', hash( 'sha256', 'changed' ), $clean->sha256, $clean );
			self::fail( 'Expected recoverable failure.' );
		} catch ( RepairVerificationFailure $failure ) {
			self::assertFileExists( $failure->receipt->backupPath );
			self::assertTrue( $repair->recover( $failure->receipt, $clean->sha256 ) );
		}
	}
	private string $site;
	private string $backup;

	protected function setUp(): void {
		$base = sys_get_temp_dir() . '/amsec-repair-test-' . bin2hex( random_bytes( 5 ) );
		$this->site = $base . '/site';
		$this->backup = $base . '/backup';
		mkdir( $this->site, 0700, true );
		mkdir( $this->backup, 0700 );
		file_put_contents( $this->site . '/hello.php', 'changed' );
	}

	protected function tearDown(): void {
		foreach ( glob( $this->backup . '/*' ) ?: array() as $path ) { unlink( $path ); }
		foreach ( glob( $this->site . '/*' ) ?: array() as $path ) { unlink( $path ); }
		rmdir( $this->backup );
		rmdir( $this->site );
		rmdir( dirname( $this->site ) );
	}

	public function test_repairs_exact_current_bytes_and_rolls_back(): void {
		$repair = new AtomicPluginRepair( $this->site, $this->backup );
		$clean = new RepairBytes( 'clean', hash( 'sha256', 'clean' ), 'https://downloads.wordpress.org/plugin/hello-dolly.1.7.2.zip' );
		$receipt = $repair->apply( 'hello.php', hash( 'sha256', 'changed' ), $clean->sha256, $clean );
		self::assertNotNull( $receipt );
		self::assertSame( 'clean', file_get_contents( $this->site . '/hello.php' ) );
		self::assertStringStartsWith( realpath( $this->backup ), $receipt->backupPath );
		self::assertTrue( $repair->rollback( $receipt ) );
		self::assertSame( 'changed', file_get_contents( $this->site . '/hello.php' ) );
	}

	public function test_changed_bytes_or_symlink_refuse_repair(): void {
		$repair = new AtomicPluginRepair( $this->site, $this->backup );
		$clean = new RepairBytes( 'clean', hash( 'sha256', 'clean' ), 'https://downloads.wordpress.org/plugin/hello-dolly.1.7.2.zip' );
		self::assertNull( $repair->apply( 'hello.php', str_repeat( 'a', 64 ), $clean->sha256, $clean ) );
		self::assertNull( $repair->apply( 'hello.php', hash( 'sha256', 'changed' ), str_repeat( 'a', 64 ), $clean ) );
		self::assertSame( 'changed', file_get_contents( $this->site . '/hello.php' ) );
		unlink( $this->site . '/hello.php' );
		symlink( $this->backup, $this->site . '/hello.php' );
		self::assertNull( $repair->apply( 'hello.php', hash( 'sha256', 'changed' ), $clean->sha256, $clean ) );
	}

	public function test_rollback_refuses_a_file_changed_after_repair(): void {
		$repair = new AtomicPluginRepair( $this->site, $this->backup );
		$clean = new RepairBytes( 'clean', hash( 'sha256', 'clean' ), 'https://downloads.wordpress.org/plugin/hello-dolly.1.7.2.zip' );
		$receipt = $repair->apply( 'hello.php', hash( 'sha256', 'changed' ), $clean->sha256, $clean );
		self::assertNotNull( $receipt );
		file_put_contents( $this->site . '/hello.php', 'new change' );
		self::assertFalse( $repair->rollback( $receipt ) );
		self::assertSame( 'new change', file_get_contents( $this->site . '/hello.php' ) );
		self::assertFalse( $repair->recover( $receipt, str_repeat( 'a', 64 ) ) );
		self::assertTrue( $repair->recover( $receipt, hash( 'sha256', 'new change' ) ) );
		self::assertSame( 'changed', file_get_contents( $this->site . '/hello.php' ) );
	}

	public function test_rollback_refuses_a_busy_file_lock(): void {
		$repair = new AtomicPluginRepair( $this->site, $this->backup );
		$clean = new RepairBytes( 'clean', hash( 'sha256', 'clean' ), 'https://downloads.wordpress.org/plugin/hello-dolly.1.7.2.zip' );
		$receipt = $repair->apply( 'hello.php', hash( 'sha256', 'changed' ), $clean->sha256, $clean );
		self::assertNotNull( $receipt );
		$handle = fopen( $this->site . '/hello.php', 'r+b' );
		flock( $handle, LOCK_EX );
		try {
			self::assertFalse( $repair->rollback( $receipt ) );
			self::assertSame( 'clean', file_get_contents( $this->site . '/hello.php' ) );
		} finally {
			flock( $handle, LOCK_UN );
			fclose( $handle );
		}
	}

	public function test_world_readable_backup_directory_refuses_repair(): void {
		chmod( $this->backup, 0777 );
		try {
			$repair = new AtomicPluginRepair( $this->site, $this->backup );
			$clean = new RepairBytes( 'clean', hash( 'sha256', 'clean' ), 'https://downloads.wordpress.org/plugin/hello-dolly.1.7.2.zip' );
			self::assertNull( $repair->apply( 'hello.php', hash( 'sha256', 'changed' ), $clean->sha256, $clean ) );
			self::assertSame( 'changed', file_get_contents( $this->site . '/hello.php' ) );
		} finally {
			chmod( $this->backup, 0700 );
		}
	}

	public function test_missing_private_backup_directory_refuses_without_changing_file(): void {
		$missing = dirname( $this->backup ) . '/missing';
		$repair = new AtomicPluginRepair( $this->site, $missing );
		$clean = new RepairBytes( 'clean', hash( 'sha256', 'clean' ), 'https://downloads.wordpress.org/plugin/hello-dolly.1.7.2.zip' );
		self::assertNull( $repair->apply( 'hello.php', hash( 'sha256', 'changed' ), $clean->sha256, $clean ) );
		self::assertSame( 'changed', file_get_contents( $this->site . '/hello.php' ) );
	}

	public function test_symlinked_parent_refuses_repair(): void {
		mkdir( $this->site . '/real', 0700 );
		file_put_contents( $this->site . '/real/file.php', 'changed' );
		symlink( $this->site . '/real', $this->site . '/linked' );
		try {
			$repair = new AtomicPluginRepair( $this->site, $this->backup );
			$clean = new RepairBytes( 'clean', hash( 'sha256', 'clean' ), 'https://downloads.wordpress.org/plugin/hello-dolly.1.7.2.zip' );
			self::assertNull( $repair->apply( 'linked/file.php', hash( 'sha256', 'changed' ), $clean->sha256, $clean ) );
			self::assertSame( 'changed', file_get_contents( $this->site . '/real/file.php' ) );
		} finally {
			unlink( $this->site . '/linked' );
			unlink( $this->site . '/real/file.php' );
			rmdir( $this->site . '/real' );
		}
	}

	public function test_obsolete_backup_requires_a_changed_replacement_before_discard(): void {
		$repair = new AtomicPluginRepair( $this->site, $this->backup );
		$clean = new RepairBytes( 'clean', hash( 'sha256', 'clean' ), 'https://downloads.wordpress.org/plugin/hello-dolly.1.7.2.zip' );
		$receipt = $repair->apply( 'hello.php', hash( 'sha256', 'changed' ), $clean->sha256, $clean );
		self::assertNotNull( $receipt );
		self::assertFalse( $repair->discardBackup( $receipt ) );
		file_put_contents( $this->site . '/hello.php', 'new change' );
		self::assertTrue( $repair->discardBackup( $receipt ) );
		self::assertFileDoesNotExist( $receipt->backupPath );
	}

	public function test_post_replace_verification_failure_retains_recoverable_backup(): void {
		$repair = new AtomicPluginRepair( $this->site, $this->backup, function ( string $path ): void { file_put_contents( $path, 'interrupted' ); } );
		$clean = new RepairBytes( 'clean', hash( 'sha256', 'clean' ), 'https://downloads.wordpress.org/plugin/hello-dolly.1.7.2.zip' );
		try {
			$repair->apply( 'hello.php', hash( 'sha256', 'changed' ), $clean->sha256, $clean );
			self::fail( 'Expected verification failure.' );
		} catch ( RepairVerificationFailure $failure ) {
			self::assertFileExists( $failure->receipt->backupPath );
			self::assertSame( 'interrupted', file_get_contents( $this->site . '/hello.php' ) );
			self::assertTrue( $repair->recover( $failure->receipt, hash( 'sha256', 'interrupted' ) ) );
			self::assertSame( 'changed', file_get_contents( $this->site . '/hello.php' ) );
		}
	}
}
