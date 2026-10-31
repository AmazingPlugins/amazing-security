<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Schedule;

use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Schedule\SuiteCycle;
use PHPUnit\Framework\TestCase;

final class SuiteCycleTest extends TestCase {
	public function test_cycle_advances_only_in_order_and_prevents_overlap(): void {
		$cycle = new SuiteCycle( $this->options() );
		self::assertTrue( $cycle->start( 1000 ) );
		self::assertFalse( $cycle->start( 1001 ) );
		self::assertFalse( $cycle->allows( 'files', 1001 ) );
		self::assertTrue( $cycle->allows( 'integrity', 1001 ) );
		self::assertTrue( $cycle->claim( 'integrity', 1001 ) );
		self::assertFalse( $cycle->claim( 'integrity', 1002 ) );
		self::assertTrue( $cycle->continueStage( 'integrity', 1003 ) );
		self::assertTrue( $cycle->claim( 'integrity', 1004 ) );
		self::assertTrue( $cycle->advance( 'integrity', 'files', 1005 ) );
		self::assertFalse( $cycle->allows( 'integrity', 1003 ) );
		self::assertTrue( $cycle->complete( 1004 ) );
		self::assertSame( 'complete', $cycle->status( 1004 )['state'] );
	}

	public function test_a_coverage_gap_keeps_the_file_stage_and_ends_partial(): void {
		$cycle = new SuiteCycle( $this->options() );
		self::assertTrue( $cycle->start( 1000 ) );
		self::assertTrue( $cycle->advance( 'integrity', 'files', 1001 ) );
		self::assertTrue( $cycle->markCoverageGap( 1002 ) );
		self::assertTrue( $cycle->complete( 1003 ) );
		self::assertSame( 'partial', $cycle->status( 1003 )['state'] );
		self::assertSame( 'files', $cycle->status( 1003 )['stage'] );
	}

	public function test_retry_is_bounded_and_stale_cycle_is_partial(): void {
		$cycle = new SuiteCycle( $this->options() );
		self::assertTrue( $cycle->start( 1000 ) );
		self::assertTrue( $cycle->claim( 'integrity', 1000 ) );
		self::assertTrue( $cycle->retry( 'integrity', 1001 ) );
		self::assertTrue( $cycle->retry( 'integrity', 1002 ) );
		self::assertFalse( $cycle->retry( 'integrity', 1003 ) );
		self::assertSame( 'partial', $cycle->status( 1004 )['state'] );
		self::assertTrue( $cycle->start( 2000 ) );
		self::assertSame( 'partial', $cycle->status( 2000 + 86401 )['state'] );
		self::assertFalse( $cycle->allows( 'integrity', 2000 + 86401 ) );
	}

	private function options(): OptionGateway {
		return new class() implements OptionGateway {
			private array $values = array();
			public function get( string $key ): mixed {
				return $this->values[ $key ] ?? null; }
			public function add( string $key, string $value ): bool {
				if ( isset( $this->values[ $key ] ) ) {
					return false;
				} $this->values[ $key ] = $value;
				return true; }
			public function set( string $key, string $value ): bool {
				$this->values[ $key ] = $value;
				return true; }
			public function delete( string $key ): void {
				unset( $this->values[ $key ] ); }
			public function replaceIfSame( string $key, string $expected, string $replacement ): bool {
				if ( ( $this->values[ $key ] ?? null ) !== $expected ) {
					return false;
				} $this->values[ $key ] = $replacement;
				return true; }
			public function deleteIfSame( string $key, string $expected ): bool {
				if ( ( $this->values[ $key ] ?? null ) !== $expected ) {
					return false;
				} unset( $this->values[ $key ] );
				return true; }
		};
	}
}
