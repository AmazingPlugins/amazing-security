<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\FileScan;

use AmazingPlugins\Security\FileScan\FileScanCursor;
use AmazingPlugins\Security\FileScan\FileScanRunner;
use AmazingPlugins\Security\FileScan\FileScanTarget;
use AmazingPlugins\Security\Integrity\Manifest;
use AmazingPlugins\Security\Scan\ScanContext;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class FileScanRunnerTest extends TestCase {
	private array $roots = array();

	private function root(): string {
		$root = sys_get_temp_dir() . '/amsec-run-' . bin2hex( random_bytes( 6 ) );
		mkdir( $root );
		$this->roots[] = $root;
		return $root;
	}

	protected function tearDown(): void {
		foreach ( $this->roots as $root ) {
			foreach ( scandir( $root ) as $item ) {
				if ( '.' !== $item && '..' !== $item ) {
					unlink( $root . '/' . $item );
				}
			}
			rmdir( $root );
		}
	}

	public function test_two_steps_find_extra_and_suspected_code(): void {
		$root = $this->root();
		file_put_contents( $root . '/a-known.php', '<?php echo 1;' );
		file_put_contents( $root . '/b-extra.php', '<?php eval(base64_decode("ZWNobyAxOw=="));' );
		file_put_contents( $root . '/c-extra.css', 'css' );
		$manifest = new Manifest( 'plugin', 'demo:1', 'https://wordpress.org/', new DateTimeImmutable(), 'sha256', array( 'a-known.php' => array( hash( 'sha256', '<?php echo 1;' ) ) ) );
		$targets = array( new FileScanTarget( 'demo:1', 'plugin', $root, $manifest ) );
		$runner = new FileScanRunner();
		$first = $runner->step( $targets, new FileScanCursor( 'scan-1' ), new ScanContext( null, 2 ) );
		self::assertFalse( $first->finished );
		self::assertSame( 2, $first->cursor->processed );
		$second = $runner->step( $targets, $first->cursor, new ScanContext() );
		self::assertTrue( $second->finished );
		self::assertSame( 'warn', $second->cursor->state() );
		self::assertSame( 1, $second->cursor->verified );
		self::assertSame( 1, $second->cursor->scanned );
		self::assertContains( 'AS-PHP-001', array_column( $second->cursor->findings, 'rule_id' ) );
		self::assertStringNotContainsString( 'ZWNobyAxOw==', json_encode( $second->cursor->toArray() ) );
	}

	public function test_oversized_file_is_inconclusive_not_pass(): void {
		$root = $this->root();
		file_put_contents( $root . '/large.php', str_repeat( 'x', 2097153 ) );
		$step = ( new FileScanRunner() )->step( array( new FileScanTarget( 'uploads', 'uploads', $root ) ), new FileScanCursor( 'scan-1' ), new ScanContext() );
		self::assertTrue( $step->cursor->partial );
		self::assertSame( 'inconclusive', $step->cursor->state() );
		self::assertSame( 'oversized', $step->cursor->findings[0]['reason'] );
	}

	public function test_manifest_change_refuses_resume(): void {
		$root = $this->root();
		file_put_contents( $root . '/a.php', 'a' );
		file_put_contents( $root . '/b.php', 'b' );
		$old = new Manifest( 'plugin', 'demo:1', 'https://wordpress.org/', new DateTimeImmutable(), 'sha256', array( 'a.php' => array( hash( 'sha256', 'a' ) ) ) );
		$new = new Manifest( 'plugin', 'demo:1', 'https://wordpress.org/', new DateTimeImmutable(), 'sha256', array( 'a.php' => array( hash( 'sha256', 'changed' ) ) ) );
		$runner = new FileScanRunner();
		$first = $runner->step( array( new FileScanTarget( 'demo:1', 'plugin', $root, $old ) ), new FileScanCursor( 'scan-1' ), new ScanContext( null, 1 ) );
		$second = $runner->step( array( new FileScanTarget( 'demo:1', 'plugin', $root, $new ) ), $first->cursor, new ScanContext() );
		self::assertTrue( $second->cursor->partial );
		self::assertSame( 'inconclusive', $second->cursor->state() );
	}

	public function test_finding_limit_marks_partial_and_counts_omitted(): void {
		$root = $this->root();
		for ( $i = 0; $i < 251; ++$i ) {
			file_put_contents( $root . '/extra-' . sprintf( '%03d', $i ) . '.php', '<?php echo 1;' );
		}
		$manifest = new Manifest( 'plugin', 'demo:1', 'https://wordpress.org/', new DateTimeImmutable(), 'sha256', array() );
		$runner = new FileScanRunner();
		$first = $runner->step( array( new FileScanTarget( 'demo:1', 'plugin', $root, $manifest ) ), new FileScanCursor( 'scan-1' ), new ScanContext() );
		$second = $runner->step( array( new FileScanTarget( 'demo:1', 'plugin', $root, $manifest ) ), $first->cursor, new ScanContext() );
		self::assertCount( 250, $second->cursor->findings );
		self::assertGreaterThan( 0, $second->cursor->omitted );
		self::assertTrue( $second->cursor->partial );
	}

	public function test_directory_change_between_requests_cannot_look_complete(): void {
		$root = $this->root();
		file_put_contents( $root . '/a.php', '<?php echo 1;' );
		file_put_contents( $root . '/b.php', '<?php echo 2;' );
		$target = new FileScanTarget( 'uploads', 'uploads', $root );
		$runner = new FileScanRunner();
		$first = $runner->step( array( $target ), new FileScanCursor( 'scan-1' ), new ScanContext( null, 1 ) );
		file_put_contents( $root . '/c.php', '<?php echo 3;' );
		$second = $runner->step( array( $target ), $first->cursor, new ScanContext() );
		self::assertTrue( $second->cursor->partial );
		self::assertSame( 'inconclusive', $second->cursor->state() );
	}

	public function test_exhausted_run_time_is_partial_and_finished(): void {
		$root = $this->root();
		file_put_contents( $root . '/code.php', '<?php echo 1;' );
		$cursor = new FileScanCursor( 'scan-1' );
		$cursor->elapsed = 30.0;
		$step = ( new FileScanRunner() )->step( array( new FileScanTarget( 'uploads', 'uploads', $root ) ), $cursor, new ScanContext() );
		self::assertTrue( $step->finished );
		self::assertTrue( $step->cursor->partial );
		self::assertSame( 'inconclusive', $step->cursor->state() );
	}
}
