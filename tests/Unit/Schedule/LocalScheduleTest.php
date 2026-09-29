<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Schedule;

use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Scan\ScanRun;
use AmazingPlugins\Security\Schedule\LocalSchedule;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class LocalScheduleTest extends TestCase {
	public function test_successful_tick_records_completion_and_next_due_time(): void {
		$options = $this->options();
		$run = new ScanRun( new DateTimeImmutable( '@1000' ), new DateTimeImmutable( '@1001' ), array(), false );
		$schedule = new LocalSchedule( $options, static fn(): ScanRun => $run );
		self::assertSame( 'never', $schedule->status( 1000 )['state'] );
		self::assertTrue( $schedule->tick( 1000 ) );
		self::assertSame( 'complete', $schedule->status( 1001 )['state'] );
		self::assertSame( 1000 + 86400, $schedule->status( 1001 )['next_due'] );
		self::assertSame( 'missed', $schedule->status( 1000 + 86400 + 3601 )['state'] );
	}

	public function test_failed_or_partial_tick_never_reports_a_clean_completion(): void {
		$options = $this->options();
		$schedule = new LocalSchedule( $options, static function (): never { throw new RuntimeException( 'scan unavailable' ); } );
		self::assertFalse( $schedule->tick( 1000 ) );
		self::assertSame( 'partial', $schedule->status( 1001 )['state'] );
		$partial = new ScanRun( new DateTimeImmutable( '@1000' ), new DateTimeImmutable( '@1001' ), array(), true );
		self::assertTrue( ( new LocalSchedule( $options, static fn(): ScanRun => $partial ) )->tick( 2000 ) );
		self::assertSame( 'partial', $schedule->status( 2001 )['state'] );
	}

	public function test_concurrent_tick_does_not_run_twice(): void {
		$options = $this->options();
		$runs = 0;
		$schedule = new LocalSchedule( $options, static function () use ( &$runs ): ScanRun {
			++$runs;
			return new ScanRun( new DateTimeImmutable( '@1000' ), new DateTimeImmutable( '@1001' ), array(), false );
		} );
		$options->values['amsec_schedule_lock'] = json_encode( array( 'scan_id' => 'other', 'expires' => time() + 60 ) );
		self::assertFalse( $schedule->tick( 1000 ) );
		self::assertSame( 0, $runs );
	}

	public function test_state_write_failure_never_runs_or_claims_success(): void {
		$options = $this->options();
		$runs = 0;
		$options->failWrites = true;
		$schedule = new LocalSchedule( $options, static function () use ( &$runs ): ScanRun {
			++$runs;
			return new ScanRun( new DateTimeImmutable( '@1000' ), new DateTimeImmutable( '@1001' ), array(), false );
		} );
		self::assertFalse( $schedule->tick( 1000 ) );
		self::assertSame( 0, $runs );
		self::assertSame( 'never', $schedule->status( 1001 )['state'] );
	}

	private function options(): OptionGateway {
		return new class implements OptionGateway {
			public array $values = array();
			public bool $failWrites = false;
			public function get( string $key ): mixed { return $this->values[ $key ] ?? null; }
			public function add( string $key, string $value ): bool { if ( isset( $this->values[ $key ] ) ) { return false; } $this->values[ $key ] = $value; return true; }
			public function set( string $key, string $value ): bool { if ( $this->failWrites ) { return false; } $this->values[ $key ] = $value; return true; }
			public function delete( string $key ): void { unset( $this->values[ $key ] ); }
			public function replaceIfSame( string $key, string $expected, string $replacement ): bool { if ( ( $this->values[ $key ] ?? null ) !== $expected ) { return false; } $this->values[ $key ] = $replacement; return true; }
			public function deleteIfSame( string $key, string $expected ): bool { if ( ( $this->values[ $key ] ?? null ) !== $expected ) { return false; } unset( $this->values[ $key ] ); return true; }
		};
	}
}
