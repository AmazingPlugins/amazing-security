<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Schedule;

use AmazingPlugins\Security\Schedule\ScheduleHooks;
use PHPUnit\Framework\TestCase;

final class ScheduleHooksTest extends TestCase {
	public function test_schedules_once_and_clears_on_deactivation(): void {
		$existing = false;
		$scheduled = 0;
		$cleared = array();
		$hooks = new ScheduleHooks(
			static function () use ( &$existing ): bool { return $existing; },
			static function ( int $when, string $recurrence, string $hook ) use ( &$existing, &$scheduled ): bool {
				self::assertSame( 'daily', $recurrence );
				self::assertSame( 'amsec_local_daily_scan', $hook );
				self::assertGreaterThan( 0, $when );
				$existing = true;
				++$scheduled;
				return true;
			},
			static function ( string $hook ) use ( &$existing, &$cleared ): void { $existing = false; $cleared[] = $hook; }
		);
		$hooks->ensure();
		$hooks->ensure();
		self::assertSame( 1, $scheduled );
		$hooks->clear();
		self::assertSame( array( 'amsec_local_daily_scan', 'amsec_integrity_tick', 'amsec_file_tick' ), $cleared );
	}
}
