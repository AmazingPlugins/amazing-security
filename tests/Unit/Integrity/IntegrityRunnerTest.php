<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Integrity;

use AmazingPlugins\Security\Integrity\FileReader;
use AmazingPlugins\Security\Integrity\IntegrityCursor;
use AmazingPlugins\Security\Integrity\IntegrityRunner;
use AmazingPlugins\Security\Integrity\IntegrityTarget;
use AmazingPlugins\Security\Integrity\Manifest;
use AmazingPlugins\Security\Scan\ScanContext;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class IntegrityRunnerTest extends TestCase {
	public function test_changed_and_missing_files_resume_without_duplicate_findings(): void {
		$root = sys_get_temp_dir() . '/amsec-run-' . bin2hex( random_bytes( 4 ) );
		mkdir( $root );
		file_put_contents( $root . '/good.php', 'good' );
		file_put_contents( $root . '/changed.php', 'changed' );
		$manifest = new Manifest( 'core', '6.6:en_US', 'https://api.wordpress.org/core/checksums/1.0/', new DateTimeImmutable(), 'md5', array( 'good.php' => array( md5( 'good' ) ), 'changed.php' => array( md5( 'original' ) ), 'missing.php' => array( md5( 'missing' ) ) ) );
		$runner = new IntegrityRunner( new FileReader() );
		$target = new IntegrityTarget( $manifest, $root );
		$first = $runner->step( array( $target ), new IntegrityCursor( 'scan-1' ), new ScanContext( null, 2 ) );
		self::assertFalse( $first->finished );
		self::assertSame( 1, $first->cursor->matched );
		self::assertSame( 3, $first->cursor->packages['core:6.6:en_US']['total'] );
		$second = $runner->step( array( $target ), $first->cursor, new ScanContext() );
		self::assertTrue( $second->finished );
		self::assertCount( 2, $second->cursor->findings );
		self::assertSame( 3, $second->cursor->packages['core:6.6:en_US']['checked'] );
		self::assertSame( array( 'warn', 'warn' ), array_map( static fn( $finding ) => $finding->state, $second->cursor->findings ) );
		self::assertStringNotContainsString( $root, json_encode( $second->cursor->toArray() ) );
		unlink( $root . '/good.php' );
		unlink( $root . '/changed.php' );
		rmdir( $root );
	}
}
