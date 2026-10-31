<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit;

use AmazingPlugins\Security\Scan\LocalHardeningScanService;
use AmazingPlugins\Security\Scan\ScanRun;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class LocalHardeningScanServiceTest extends TestCase {
	public function test_returns_only_a_saved_run(): void {
		$run     = new ScanRun( new DateTimeImmutable( '2026-01-01T00:00:00Z' ), new DateTimeImmutable( '2026-01-01T00:00:01Z' ), array(), false );
		$saved   = false;
		$service = new LocalHardeningScanService(
			static fn(): ScanRun => $run,
			static function ( ScanRun $value ) use ( &$saved, $run ): void {
				self::assertSame( $run, $value );
				$saved = true;
			}
		);
		self::assertSame( $run, $service->run() );
		self::assertTrue( $saved );
	}

	public function test_save_failure_is_not_reported_as_success(): void {
		$run     = new ScanRun( new DateTimeImmutable( '2026-01-01T00:00:00Z' ), new DateTimeImmutable( '2026-01-01T00:00:01Z' ), array(), false );
		$service = new LocalHardeningScanService(
			static fn(): ScanRun => $run,
			static function (): void {
				throw new RuntimeException( 'Previous report preserved.' ); }
		);
		$this->expectExceptionMessage( 'Previous report preserved.' );
		$service->run();
	}
}
