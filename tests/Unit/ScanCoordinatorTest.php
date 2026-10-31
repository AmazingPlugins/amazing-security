<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit;

use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\ScanCoordinator;
use AmazingPlugins\Security\Scan\SecurityCheck;
use PHPUnit\Framework\TestCase;

final class ScanCoordinatorTest extends TestCase {
	public function test_rejects_duplicate_check_ids(): void {
		$check = new class() implements SecurityCheck {
			public function id(): string {
				return 'duplicate'; }
			public function run( ScanContext $context ): array {
				return array(); }
		};
		$this->expectException( \InvalidArgumentException::class );
		( new ScanCoordinator() )->run( array( $check, $check ), new ScanContext() );
	}

	public function test_stops_after_deadline_without_claiming_complete_coverage(): void {
		$check = new class() implements SecurityCheck {
			public function id(): string {
				return 'late'; }
			public function run( ScanContext $context ): array {
				throw new \LogicException( 'Should not run' ); }
		};
		$run   = ( new ScanCoordinator() )->run( array( $check ), new ScanContext( microtime( true ) - 1 ) );
		self::assertTrue( $run->partial );
		self::assertSame( 1, $run->unknownCount() );
	}

	public function test_never_exceeds_result_budget(): void {
		$check  = new class() implements SecurityCheck {
			public function id(): string {
				return 'one'; }
			public function run( ScanContext $context ): array {
				return array( new \AmazingPlugins\Security\Findings\CheckResult( 'one', 'pass', 'Observed', 'https://developer.wordpress.org/', new \DateTimeImmutable( 'now' ), 'high', 'complete', array() ) );
			}
		};
		$second = new class() implements SecurityCheck {
			public function id(): string {
				return 'two'; }
			public function run( ScanContext $context ): array {
				return array(); }
		};
		$run    = ( new ScanCoordinator() )->run( array( $check, $second ), new ScanContext( null, 1 ) );
		self::assertCount( 1, $run->results );
		self::assertTrue( $run->partial );
	}
}
